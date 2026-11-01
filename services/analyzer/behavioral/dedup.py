"""Alert deduplication and cooldown mechanism to prevent incident alert spam."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.models import BehavioralAlert

logger = logging.getLogger(__name__)


def _safe_encode(val: str) -> str:
    """Safely URL-encode identifier to prevent key collision attacks."""
    return quote(str(val or ""), safe="")


class AlertDeduplicator:
    """Manages cooldowns to suppress duplicate alerts for ongoing incidents."""

    def __init__(
        self,
        config: BehavioralConfig | None = None,
        redis_client_getter: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config or BehavioralConfig()
        self.redis_client_getter = redis_client_getter
        self._memory_dedup: dict[str, float] = {}
        self._last_cleanup = time.monotonic()
        self._lock = asyncio.Lock()

    def _dedup_key(self, alert: BehavioralAlert) -> str:
        """Construct fingerprint key for the alert incident."""
        clean_org = (alert.org_id or "").strip() or "default-org"
        detector = alert.detector_type

        if detector == "coordinated_attack":
            pattern = alert.metadata.get("shared_pattern", "all")
            return f"tenet:behavioral:dedup:{_safe_encode(clean_org)}:coord:{_safe_encode(pattern)}"

        clean_source = (alert.source_id or "").strip() or "anonymous"
        pattern = alert.threat_type or "generic"
        return (
            f"tenet:behavioral:dedup:{_safe_encode(clean_org)}:{_safe_encode(detector)}:"
            f"{_safe_encode(clean_source)}:{_safe_encode(pattern)}"
        )

    async def is_duplicate(self, alert: BehavioralAlert) -> bool:
        """Check if an alert for this incident was already emitted within the cooldown window.

        Returns True if this alert is a duplicate and should be suppressed; False if it should be emitted.
        """
        key = self._dedup_key(alert)
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                # Atomically set if Not eXists (NX) with expiration
                acquired = await redis_client.set(
                    key,
                    alert.alert_id,
                    ex=self.config.alert_cooldown_seconds,
                    nx=True,
                )
                # If acquired is True, the key did not exist before -> NOT a duplicate
                return not bool(acquired)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Redis dedup check failed, falling back to memory: %s", exc)

        async with self._lock:
            now = time.monotonic()
            last_emitted = self._memory_dedup.get(key)
            if last_emitted is not None and (now - last_emitted) < self.config.alert_cooldown_seconds:
                return True

            self._memory_dedup[key] = now

            # Cleanup old memory keys periodically rather than on every alert
            if now - self._last_cleanup >= self.config.alert_cooldown_seconds:
                cutoff = now - (self.config.alert_cooldown_seconds * 2)
                self._memory_dedup = {k: v for k, v in self._memory_dedup.items() if v >= cutoff}
                self._last_cleanup = now

            return False

    async def clear_alert(self, alert: BehavioralAlert) -> None:
        """Clear deduplication reservation for an alert if emission failed."""
        key = self._dedup_key(alert)
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                await redis_client.delete(key)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to clear Redis dedup key %s: %s", key, exc)

        async with self._lock:
            self._memory_dedup.pop(key, None)

    async def clear(self) -> None:
        """Clear in-memory deduplication state."""
        async with self._lock:
            self._memory_dedup.clear()
            self._last_cleanup = time.monotonic()
