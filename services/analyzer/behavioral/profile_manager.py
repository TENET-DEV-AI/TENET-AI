"""Rolling behavioral profile manager with Redis persistence and memory fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.models import BehavioralProfile, EventSummary

logger = logging.getLogger(__name__)


class BehavioralProfileManager:
    """Manages rolling behavioral profiles per source and tenant with bounded storage.

    When Redis is configured, profiles and coordinated attack windows are shared
    across processes via Redis. In degraded mode or test environments without Redis,
    the manager safely falls back to process-local in-memory storage (cross-process
    coordination is not supported without Redis).
    """

    def __init__(
        self,
        config: BehavioralConfig | None = None,
        redis_client_getter: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config or BehavioralConfig()
        self.redis_client_getter = redis_client_getter
        # In-memory storage for degraded mode or tests without Redis
        self._memory_profiles: dict[tuple[str, str], BehavioralProfile] = {}
        self._memory_coordinated: dict[str, list[dict[str, Any]]] = {}
        self._memory_lock = asyncio.Lock()
        self._update_lock = asyncio.Lock()

    def _profile_key(self, org_id: str, source_id: str) -> str:
        """Construct namespaced Redis key for a source profile."""
        clean_org = (org_id or "").strip() or "default-org"
        clean_source = (source_id or "").strip() or "anonymous"
        return f"tenet:behavioral:profile:{clean_org}:{clean_source}"

    def _coordinated_key(self, org_id: str) -> str:
        """Construct namespaced Redis key for cross-source coordinated attack tracking."""
        clean_org = (org_id or "").strip() or "default-org"
        return f"tenet:behavioral:coordinated:{clean_org}"

    async def record_event(
        self,
        org_id: str,
        source_id: str,
        event_summary: EventSummary,
    ) -> BehavioralProfile:
        """Record an event into the source's behavioral profile and the coordinated attack buffer."""
        clean_org = (org_id or "default-org").strip()
        clean_source = (source_id or "anonymous").strip()

        async with self._update_lock:
            profile = await self.get_profile(clean_org, clean_source)

            # Update profile stats
            profile.total_requests += 1
            if not profile.first_seen:
                profile.first_seen = event_summary.iso_timestamp
            profile.last_seen = event_summary.iso_timestamp

            if event_summary.threat_type:
                profile.threat_type_counts[event_summary.threat_type] = (
                    profile.threat_type_counts.get(event_summary.threat_type, 0) + 1
                )

            # Append new event
            profile.recent_events.append(event_summary)

            # Prune events outside rolling window & enforce bound
            now = event_summary.timestamp
            window_cutoff = now - self.config.window_seconds
            profile.recent_events = [
                e for e in profile.recent_events if e.timestamp >= window_cutoff
            ][-self.config.max_events_per_profile :]

            # Persist profile
            await self._save_profile(clean_org, clean_source, profile)

            # If event is suspicious, record into coordinated window
            if event_summary.risk_score >= self.config.probing_threshold or event_summary.threat_type:
                await self._record_coordinated_event(clean_org, clean_source, event_summary)

            return profile

    async def get_profile(self, org_id: str, source_id: str) -> BehavioralProfile:
        """Retrieve the rolling profile for a source and tenant, or initialize a new one."""
        clean_org = (org_id or "default-org").strip()
        clean_source = (source_id or "anonymous").strip()
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                key = self._profile_key(clean_org, clean_source)
                raw = await redis_client.get(key)
                if raw:
                    data = json.loads(raw)
                    profile = BehavioralProfile.from_dict(data)
                    # Filter events by active rolling window
                    now = time.time()
                    cutoff = now - self.config.window_seconds
                    profile.recent_events = [
                        e for e in profile.recent_events if e.timestamp >= cutoff
                    ]
                    return profile
                # Key is not in Redis (either new or expired by retention TTL)
                return BehavioralProfile(
                    org_id=clean_org,
                    source_id=clean_source,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to retrieve profile from Redis for %s:%s: %s", clean_org, clean_source, exc)

        async with self._memory_lock:
            key_tuple = (clean_org, clean_source)
            if key_tuple not in self._memory_profiles:
                self._memory_profiles[key_tuple] = BehavioralProfile(
                    org_id=clean_org,
                    source_id=clean_source,
                )
            profile = self._memory_profiles[key_tuple]
            now = time.time()
            cutoff = now - self.config.window_seconds
            profile.recent_events = [
                e for e in profile.recent_events if e.timestamp >= cutoff
            ]
            return profile

    async def _save_profile(self, org_id: str, source_id: str, profile: BehavioralProfile) -> None:
        """Save profile to Redis with TTL, falling back to in-memory store."""
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                key = self._profile_key(org_id, source_id)
                payload = json.dumps(profile.to_dict())
                await redis_client.set(key, payload, ex=self.config.retention_seconds)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to save profile to Redis for %s:%s: %s", org_id, source_id, exc)

        async with self._memory_lock:
            self._memory_profiles[(org_id, source_id)] = profile

    async def _record_coordinated_event(
        self,
        org_id: str,
        source_id: str,
        event: EventSummary,
    ) -> None:
        """Record an event into the coordinated attack sliding window."""
        entry = {
            "source_id": source_id,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "risk_score": event.risk_score,
            "threat_type": event.threat_type,
            "prompt_signature": event.prompt_signature,
            "model": event.model,
        }

        redis_client = self.redis_client_getter() if self.redis_client_getter else None
        if redis_client:
            try:
                key = self._coordinated_key(org_id)
                raw = await redis_client.get(key)
                events_list = json.loads(raw) if raw else []
                now = event.timestamp
                cutoff = now - self.config.coordinated_window_seconds
                events_list = [e for e in events_list if e.get("timestamp", 0) >= cutoff]
                events_list.append(entry)
                events_list = events_list[-self.config.max_coordinated_events :]
                await redis_client.set(
                    key,
                    json.dumps(events_list),
                    ex=max(self.config.coordinated_window_seconds * 2, 3600),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to record coordinated event to Redis: %s", exc)

        async with self._memory_lock:
            if org_id not in self._memory_coordinated:
                self._memory_coordinated[org_id] = []
            events_list = self._memory_coordinated[org_id]
            now = event.timestamp
            cutoff = now - self.config.coordinated_window_seconds
            events_list = [e for e in events_list if e.get("timestamp", 0) >= cutoff]
            events_list.append(entry)
            self._memory_coordinated[org_id] = events_list[-self.config.max_coordinated_events :]

    async def get_coordinated_window(self, org_id: str) -> list[dict[str, Any]]:
        """Retrieve recent suspicious events for coordinated attack detection."""
        clean_org = (org_id or "default-org").strip()
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                key = self._coordinated_key(clean_org)
                raw = await redis_client.get(key)
                if raw:
                    events_list = json.loads(raw)
                    now = time.time()
                    cutoff = now - self.config.coordinated_window_seconds
                    return [e for e in events_list if e.get("timestamp", 0) >= cutoff]
                return []
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to get coordinated window from Redis: %s", exc)

        async with self._memory_lock:
            events_list = self._memory_coordinated.get(clean_org, [])
            now = time.time()
            cutoff = now - self.config.coordinated_window_seconds
            return [e for e in events_list if e.get("timestamp", 0) >= cutoff]

    async def clear(self) -> None:
        """Clear in-memory state (useful for test resets)."""
        async with self._memory_lock:
            self._memory_profiles.clear()
            self._memory_coordinated.clear()
