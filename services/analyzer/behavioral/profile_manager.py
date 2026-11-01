"""Rolling behavioral profile manager with Redis persistence, atomic Lua updates, and memory fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.models import BehavioralProfile, EventSummary

logger = logging.getLogger(__name__)

MAX_MEMORY_PROFILES = 1000

# Lua script for atomic profile update (eliminates read-modify-write race in multi-worker deployments)
RECORD_PROFILE_LUA = """
local raw = redis.call('GET', KEYS[1])
local profile
if raw and raw ~= '' then
    profile = cjson.decode(raw)
else
    profile = {
        org_id = ARGV[1],
        source_id = ARGV[2],
        total_requests = 0,
        first_seen = '',
        last_seen = '',
        threat_type_counts = {},
        recent_events = {}
    }
end

local event = cjson.decode(ARGV[3])
profile.total_requests = (profile.total_requests or 0) + 1
if not profile.first_seen or profile.first_seen == '' then
    profile.first_seen = event.iso_timestamp
end
profile.last_seen = event.iso_timestamp

if event.threat_type and event.threat_type ~= '' and event.threat_type ~= 'benign' then
    if not profile.threat_type_counts then
        profile.threat_type_counts = {}
    end
    local current_count = profile.threat_type_counts[event.threat_type] or 0
    profile.threat_type_counts[event.threat_type] = current_count + 1
end

if not profile.recent_events then
    profile.recent_events = {}
end
table.insert(profile.recent_events, event)

local cutoff = tonumber(ARGV[4])
local max_events = tonumber(ARGV[5])
local pruned = {}
for i = 1, #profile.recent_events do
    local ev = profile.recent_events[i]
    if ev.timestamp and tonumber(ev.timestamp) >= cutoff then
        table.insert(pruned, ev)
    end
end

local final_events = {}
local start_idx = 1
if #pruned > max_events then
    start_idx = #pruned - max_events + 1
end
for i = start_idx, #pruned do
    table.insert(final_events, pruned[i])
end
profile.recent_events = final_events

local payload = cjson.encode(profile)
redis.call('SET', KEYS[1], payload, 'EX', tonumber(ARGV[6]))
return payload
"""

# Lua script for atomic coordinated window append and trim
RECORD_COORDINATED_LUA = """
local raw = redis.call('GET', KEYS[1])
local list = {}
if raw and raw ~= '' then
    list = cjson.decode(raw)
end

local entry = cjson.decode(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max_events = tonumber(ARGV[3])

local pruned = {}
for i = 1, #list do
    local e = list[i]
    if e.timestamp and tonumber(e.timestamp) >= cutoff then
        table.insert(pruned, e)
    end
end

table.insert(pruned, entry)

local final_list = {}
local start_idx = 1
if #pruned > max_events then
    start_idx = #pruned - max_events + 1
end
for i = start_idx, #pruned do
    table.insert(final_list, pruned[i])
end

local payload = cjson.encode(final_list)
redis.call('SET', KEYS[1], payload, 'EX', tonumber(ARGV[4]))
return payload
"""


def _safe_encode(val: str) -> str:
    """Safely URL-encode identifier to prevent key collision attacks."""
    return quote(str(val or ""), safe="")


class BehavioralProfileManager:
    """Manages rolling behavioral profiles per source and tenant with bounded storage.

    When Redis is configured, profiles and coordinated attack windows are shared
    across processes via Redis with atomic updates. In degraded mode or test environments
    without Redis, the manager safely falls back to a bounded in-memory LRU store with
    retention-based expiration.
    """

    def __init__(
        self,
        config: BehavioralConfig | None = None,
        redis_client_getter: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config or BehavioralConfig()
        self.redis_client_getter = redis_client_getter

        # In-memory storage for degraded mode or tests without Redis (bounded LRU)
        self._memory_profiles: OrderedDict[tuple[str, str], BehavioralProfile] = OrderedDict()
        self._memory_coordinated: dict[str, list[dict[str, Any]]] = {}
        self._memory_lock = asyncio.Lock()

        # Per-source locks for local fallback to prevent blocking other sources
        self._source_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

    def _profile_key(self, org_id: str, source_id: str) -> str:
        """Construct collision-safe namespaced Redis key for a source profile."""
        clean_org = (org_id or "").strip() or "default-org"
        clean_source = (source_id or "").strip() or "anonymous"
        return f"tenet:behavioral:profile:{_safe_encode(clean_org)}:{_safe_encode(clean_source)}"

    def _coordinated_key(self, org_id: str) -> str:
        """Construct collision-safe namespaced Redis key for cross-source coordinated attack tracking."""
        clean_org = (org_id or "").strip() or "default-org"
        return f"tenet:behavioral:coordinated:{_safe_encode(clean_org)}"

    async def _get_source_lock(self, org_id: str, source_id: str) -> asyncio.Lock:
        """Retrieve or create a fine-grained lock for a specific (org, source) pair."""
        key = (org_id, source_id)
        async with self._locks_lock:
            if key not in self._source_locks:
                if len(self._source_locks) > 2000:
                    self._source_locks.clear()
                self._source_locks[key] = asyncio.Lock()
            return self._source_locks[key]

    def _is_profile_expired(self, profile: BehavioralProfile, now: float) -> bool:
        """Check if an in-memory profile has exceeded retention_seconds."""
        if profile.recent_events:
            last_ts = profile.recent_events[-1].timestamp
            return (now - last_ts) > self.config.retention_seconds
        if not profile.last_seen:
            return False
        try:
            dt = datetime.fromisoformat(profile.last_seen)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return (now - dt.timestamp()) > self.config.retention_seconds
        except (ValueError, TypeError):
            return False

    def _save_to_memory(self, org_id: str, source_id: str, profile: BehavioralProfile) -> None:
        """Save profile to in-memory LRU cache, evicting expired entries and enforcing bounds."""
        key = (org_id, source_id)
        now = time.time()

        # Evict expired profiles
        expired_keys = [k for k, p in self._memory_profiles.items() if self._is_profile_expired(p, now)]
        for k in expired_keys:
            self._memory_profiles.pop(k, None)

        # Enforce LRU capacity limit
        if len(self._memory_profiles) >= MAX_MEMORY_PROFILES:
            self._memory_profiles.popitem(last=False)

        self._memory_profiles[key] = profile
        self._memory_profiles.move_to_end(key)

    async def _reconcile_fallback_to_redis(self, org_id: str, source_id: str) -> None:
        """Merge any in-memory fallback profile state into Redis after a Redis recovery."""
        key_tuple = (org_id, source_id)
        async with self._memory_lock:
            fallback = self._memory_profiles.get(key_tuple)
        if not fallback:
            return

        redis_client = self.redis_client_getter() if self.redis_client_getter else None
        if not redis_client:
            return

        try:
            key = self._profile_key(org_id, source_id)
            raw = await redis_client.get(key)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            if isinstance(raw, str) and raw:
                redis_profile = BehavioralProfile.from_dict(json.loads(raw))
            else:
                redis_profile = BehavioralProfile(org_id=org_id, source_id=source_id)

            # Merge events and stats from fallback into redis_profile
            seen_ids = {e.event_id for e in redis_profile.recent_events}
            for e in fallback.recent_events:
                if e.event_id not in seen_ids:
                    redis_profile.recent_events.append(e)
                    seen_ids.add(e.event_id)
                    redis_profile.total_requests += 1
                    if e.threat_type and e.threat_type != "benign":
                        redis_profile.threat_type_counts[e.threat_type] = (
                            redis_profile.threat_type_counts.get(e.threat_type, 0) + 1
                        )

            redis_profile.recent_events.sort(key=lambda ev: ev.timestamp)
            redis_profile.recent_events = redis_profile.recent_events[-self.config.max_events_per_profile :]
            if redis_profile.recent_events:
                redis_profile.last_seen = redis_profile.recent_events[-1].iso_timestamp
                if not redis_profile.first_seen:
                    redis_profile.first_seen = redis_profile.recent_events[0].iso_timestamp

            payload = json.dumps(redis_profile.to_dict())
            await redis_client.set(key, payload, ex=self.config.retention_seconds)

            async with self._memory_lock:
                self._memory_profiles.pop(key_tuple, None)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to reconcile fallback profile into Redis for %s:%s: %s", org_id, source_id, exc)

    async def record_event(
        self,
        org_id: str,
        source_id: str,
        event_summary: EventSummary,
    ) -> BehavioralProfile:
        """Record an event into the source's behavioral profile and coordinated buffer."""
        clean_org = (org_id or "default-org").strip()
        clean_source = (source_id or "anonymous").strip()
        key = self._profile_key(clean_org, clean_source)

        redis_client = self.redis_client_getter() if self.redis_client_getter else None
        if redis_client:
            await self._reconcile_fallback_to_redis(clean_org, clean_source)

        window_cutoff = event_summary.timestamp - self.config.window_seconds

        # 1. Attempt atomic Redis Lua update if available
        if redis_client and hasattr(redis_client, "eval"):
            try:
                res = await redis_client.eval(
                    RECORD_PROFILE_LUA,
                    1,
                    key,
                    clean_org,
                    clean_source,
                    json.dumps(event_summary.to_dict()),
                    window_cutoff,
                    self.config.max_events_per_profile,
                    self.config.retention_seconds,
                )
                if isinstance(res, bytes):
                    res = res.decode("utf-8")
                if isinstance(res, str):
                    profile = BehavioralProfile.from_dict(json.loads(res))
                    # Clear fallback copy if one existed
                    async with self._memory_lock:
                        self._memory_profiles.pop((clean_org, clean_source), None)

                    if event_summary.risk_score >= self.config.probing_threshold or event_summary.threat_type:
                        await self._record_coordinated_event(clean_org, clean_source, event_summary)

                    return profile
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Redis Lua record_event failed for %s:%s, using fallback: %s",
                    clean_org,
                    clean_source,
                    exc,
                )

        # 2. Local fallback update with per-source lock
        source_lock = await self._get_source_lock(clean_org, clean_source)
        async with source_lock:
            profile = await self.get_profile(clean_org, clean_source)

            profile.total_requests += 1
            if not profile.first_seen:
                profile.first_seen = event_summary.iso_timestamp
            profile.last_seen = event_summary.iso_timestamp

            if event_summary.threat_type and event_summary.threat_type != "benign":
                profile.threat_type_counts[event_summary.threat_type] = (
                    profile.threat_type_counts.get(event_summary.threat_type, 0) + 1
                )

            profile.recent_events.append(event_summary)
            now = event_summary.timestamp
            cutoff = now - self.config.window_seconds
            profile.recent_events = [
                e for e in profile.recent_events if e.timestamp >= cutoff
            ][-self.config.max_events_per_profile :]

            await self._save_profile(clean_org, clean_source, profile)

            if event_summary.risk_score >= self.config.probing_threshold or event_summary.threat_type:
                await self._record_coordinated_event(clean_org, clean_source, event_summary)

            return profile

    async def get_profile(self, org_id: str, source_id: str) -> BehavioralProfile:
        """Retrieve rolling profile for a source and tenant, or return a fresh unsaved profile."""
        clean_org = (org_id or "default-org").strip()
        clean_source = (source_id or "anonymous").strip()
        key_tuple = (clean_org, clean_source)
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            # Reconcile dirty in-memory state accumulated during Redis outage
            await self._reconcile_fallback_to_redis(clean_org, clean_source)

            try:
                key = self._profile_key(clean_org, clean_source)
                raw = await redis_client.get(key)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                if isinstance(raw, str):
                    data = json.loads(raw)
                    profile = BehavioralProfile.from_dict(data)
                    now = time.time()
                    cutoff = now - self.config.window_seconds
                    profile.recent_events = [
                        e for e in profile.recent_events if e.timestamp >= cutoff
                    ]
                    return profile
                # Cache miss / expired in Redis -> return fresh unsaved profile
                return BehavioralProfile(org_id=clean_org, source_id=clean_source)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to retrieve profile from Redis for %s:%s: %s", clean_org, clean_source, exc)

        # In-memory retrieval (read-only misses do not store new profiles)
        async with self._memory_lock:
            now = time.time()
            if key_tuple not in self._memory_profiles:
                return BehavioralProfile(org_id=clean_org, source_id=clean_source)

            profile = self._memory_profiles[key_tuple]
            if self._is_profile_expired(profile, now):
                self._memory_profiles.pop(key_tuple, None)
                return BehavioralProfile(org_id=clean_org, source_id=clean_source)

            self._memory_profiles.move_to_end(key_tuple)
            cutoff = now - self.config.window_seconds
            profile.recent_events = [
                e for e in profile.recent_events if e.timestamp >= cutoff
            ]
            return profile

    async def _save_profile(self, org_id: str, source_id: str, profile: BehavioralProfile) -> None:
        """Save profile to Redis with TTL, falling back to in-memory store only on error."""
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                key = self._profile_key(org_id, source_id)
                payload = json.dumps(profile.to_dict())
                await redis_client.set(key, payload, ex=self.config.retention_seconds)
                # Success: do NOT store duplicate in memory
                async with self._memory_lock:
                    self._memory_profiles.pop((org_id, source_id), None)
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to save profile to Redis for %s:%s: %s", org_id, source_id, exc)

        async with self._memory_lock:
            self._save_to_memory(org_id, source_id, profile)

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
        now = time.time()
        cutoff = now - self.config.coordinated_window_seconds
        ttl = max(self.config.coordinated_window_seconds * 2, 3600)
        key = self._coordinated_key(org_id)

        # 1. Attempt Lua script for atomic coordinated append & trim
        if redis_client and hasattr(redis_client, "eval"):
            try:
                res = await redis_client.eval(
                    RECORD_COORDINATED_LUA,
                    1,
                    key,
                    json.dumps(entry),
                    cutoff,
                    self.config.max_coordinated_events,
                    ttl,
                )
                if isinstance(res, (str, bytes)):
                    async with self._memory_lock:
                        self._memory_coordinated.pop(org_id, None)
                    return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to execute Lua coordinated update on Redis: %s", exc)

        # 2. Redis get/set fallback
        if redis_client:
            try:
                raw = await redis_client.get(key)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                events_list = json.loads(raw) if (isinstance(raw, str) and raw) else []
                events_list = [e for e in events_list if e.get("timestamp", 0) >= cutoff]
                events_list.append(entry)
                events_list = events_list[-self.config.max_coordinated_events :]
                await redis_client.set(
                    key,
                    json.dumps(events_list),
                    ex=ttl,
                )
                async with self._memory_lock:
                    self._memory_coordinated.pop(org_id, None)
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to record coordinated event to Redis: %s", exc)

        # 3. Memory fallback
        async with self._memory_lock:
            if org_id not in self._memory_coordinated:
                self._memory_coordinated[org_id] = []
            events_list = self._memory_coordinated[org_id]
            events_list = [e for e in events_list if e.get("timestamp", 0) >= cutoff]
            events_list.append(entry)
            self._memory_coordinated[org_id] = events_list[-self.config.max_coordinated_events :]

    async def get_coordinated_window(self, org_id: str) -> list[dict[str, Any]]:
        """Retrieve recent suspicious events for coordinated attack detection."""
        clean_org = (org_id or "default-org").strip()
        redis_client = self.redis_client_getter() if self.redis_client_getter else None
        now = time.time()
        cutoff = now - self.config.coordinated_window_seconds
        key = self._coordinated_key(clean_org)

        if redis_client:
            try:
                raw = await redis_client.get(key)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                if isinstance(raw, str) and raw:
                    events_list = json.loads(raw)
                    return [e for e in events_list if e.get("timestamp", 0) >= cutoff]
                return []
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to get coordinated window from Redis: %s", exc)

        async with self._memory_lock:
            events_list = self._memory_coordinated.get(clean_org, [])
            return [e for e in events_list if e.get("timestamp", 0) >= cutoff]

    async def clear(self) -> None:
        """Clear in-memory state (useful for test resets)."""
        async with self._memory_lock:
            self._memory_profiles.clear()
            self._memory_coordinated.clear()
        async with self._locks_lock:
            self._source_locks.clear()
