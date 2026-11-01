"""Behavioral analysis engine orchestrator."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.dedup import AlertDeduplicator
from services.analyzer.behavioral.detectors import (
    BaseBehavioralDetector,
    CoordinatedAttackDetector,
    MultiTurnProbingDetector,
    NoveltyDetector,
    RiskSpikeDetector,
)
from services.analyzer.behavioral.models import (
    BehavioralAlert,
    BehavioralProfile,
    EventSummary,
)
from services.analyzer.behavioral.profile_manager import BehavioralProfileManager
from services.utils.metrics import increment_detection

logger = logging.getLogger(__name__)


class BehavioralEngine:
    """Core behavioral analysis engine orchestrating profiling, anomaly detectors, and alert emission."""

    def __init__(
        self,
        config: BehavioralConfig | None = None,
        redis_client_getter: Callable[[], Any] | None = None,
        detectors: list[BaseBehavioralDetector] | None = None,
    ) -> None:
        self._config = config or BehavioralConfig()
        self.redis_client_getter = redis_client_getter
        self.profile_manager = BehavioralProfileManager(
            config=self._config,
            redis_client_getter=redis_client_getter,
        )
        self.dedup = AlertDeduplicator(
            config=self._config,
            redis_client_getter=redis_client_getter,
        )
        self.detectors = detectors or [
            MultiTurnProbingDetector(self._config),
            RiskSpikeDetector(self._config),
            CoordinatedAttackDetector(self._config),
            NoveltyDetector(self._config),
        ]

    @property
    def config(self) -> BehavioralConfig:
        return self._config

    @config.setter
    def config(self, value: BehavioralConfig) -> None:
        self._config = value
        self.profile_manager.config = value
        self.dedup.config = value
        for detector in self.detectors:
            detector.config = value

    def _extract_prompt_signature(self, event: dict[str, Any], result: Any) -> str | None:
        """Extract a high-level attack signature or matched heuristic rule from the event."""
        # 1. From analysis details matched patterns
        details = getattr(result, "details", None) or event.get("analysis_details", {})
        if isinstance(details, dict):
            matched = details.get("matched_patterns", [])
            if matched and isinstance(matched, list):
                return str(matched[0]).strip().lower()

        # 2. From detected threat type
        threat = getattr(result, "threat_type", None) or event.get("threat_type")
        if threat:
            return str(threat).strip()

        return None

    def _parse_timestamp(self, ts_raw: Any) -> tuple[float, str]:
        """Safely parse timestamp into (epoch_seconds, iso_string)."""
        if isinstance(ts_raw, (int, float)):
            epoch = float(ts_raw)
            iso = datetime.fromtimestamp(epoch, tz=UTC).isoformat()
            return epoch, iso

        if isinstance(ts_raw, str) and ts_raw.strip():
            try:
                # Handle ISO string (Python 3.11+ supports 'Z' natively)
                dt = datetime.fromisoformat(ts_raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt.timestamp(), dt.isoformat()
            except (ValueError, TypeError) as exc:
                logger.debug("Failed to parse ISO timestamp '%s': %s", ts_raw, exc)

        now = time.time()
        return now, datetime.now(UTC).isoformat()

    async def process_event(
        self,
        event: dict[str, Any],
        result: Any,
    ) -> list[BehavioralAlert]:
        """Process an analyzed event through the behavioral engine.

        Updates the source profile, evaluates anomaly detectors, suppresses duplicate alerts,
        and emits genuine behavioral alerts to Redis.
        """
        if not self.config.enabled:
            return []

        # Validate & normalize fields
        event_id = str(event.get("event_id") or f"evt-{int(time.time()*1000)}")
        org_id = (str(event.get("org_id")) if event.get("org_id") is not None else "").strip() or "default-org"
        source_id = (str(event.get("source_id")) if event.get("source_id") is not None else "").strip() or "anonymous"
        model = str(event.get("model") or "unknown")
        source_type = str(event.get("source_type") or "unknown")

        epoch_ts, iso_ts = self._parse_timestamp(event.get("timestamp"))

        risk_score = float(getattr(result, "risk_score", event.get("risk_score", 0.0)))
        verdict = str(getattr(result, "verdict", event.get("verdict", "benign")))
        threat_type = getattr(result, "threat_type", event.get("threat_type"))

        prompt_signature = self._extract_prompt_signature(event, result)

        summary = EventSummary(
            event_id=event_id,
            timestamp=epoch_ts,
            iso_timestamp=iso_ts,
            risk_score=risk_score,
            verdict=verdict,
            threat_type=threat_type,
            model=model,
            source_type=source_type,
            prompt_signature=prompt_signature,
        )

        # 1. Update rolling behavioral profile
        profile = await self.profile_manager.record_event(org_id, source_id, summary)

        # 2. Prepare context for coordinated attack detection
        coordinated_events = await self.profile_manager.get_coordinated_window(org_id)
        extra_context = {
            "coordinated_events": coordinated_events,
            "prompt_signature": prompt_signature,
        }

        # 3. Evaluate anomaly detectors
        emitted_alerts: list[BehavioralAlert] = []
        for detector in self.detectors:
            try:
                alert = await detector.evaluate(profile, summary, extra_context)
                if not alert:
                    continue

                # 4. Deduplicate to prevent alert storms for ongoing incidents
                if await self.dedup.is_duplicate(alert):
                    logger.info(
                        "Behavioral alert suppressed by deduplication cooldown [%s: %s]",
                        alert.detector_type,
                        alert.source_id,
                    )
                    continue

                # 5. Persist and broadcast the alert
                try:
                    await self._emit_alert(alert)
                    emitted_alerts.append(alert)
                except Exception:
                    logger.exception("Failed to emit behavioral alert %s; clearing dedup reservation", alert.alert_id)
                    await self.dedup.clear_alert(alert)

            except Exception:
                logger.exception("Error evaluating detector %s for event %s", detector.__class__.__name__, event_id)

        return emitted_alerts

    async def _emit_alert(self, alert: BehavioralAlert) -> None:
        """Store behavioral alert as an event and push to the alerts queue."""
        alert_event = alert.to_event_dict()
        alert_json = json.dumps(alert_event)
        redis_client = self.redis_client_getter() if self.redis_client_getter else None

        if redis_client:
            try:
                # 1. Store as queryable event with retention TTL
                await redis_client.set(
                    f"tenet:event:{alert.alert_id}",
                    alert_json,
                    ex=self.config.retention_seconds,
                )
                # 2. Push onto alert queue
                await redis_client.lpush("tenet:alerts", alert_json)
                logger.warning(
                    "Behavioral Alert Emitted [%s] %s - reason: %s (contributing: %d events)",
                    alert.severity.upper(),
                    alert.alert_id,
                    alert.detection_reason,
                    len(alert.contributing_events),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to store behavioral alert in Redis: %s", exc)

        # Increment Prometheus metric
        try:
            increment_detection(
                service="behavioral_engine",
                threat_type=alert.threat_type,
                verdict=alert.verdict,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Prometheus metric increment skipped: %s", exc)

    async def get_profile(self, org_id: str, source_id: str) -> BehavioralProfile:
        """Fetch the rolling profile for a source and tenant."""
        return await self.profile_manager.get_profile(org_id, source_id)
