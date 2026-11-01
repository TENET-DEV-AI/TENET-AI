"""Configurable behavioral anomaly detectors for multi-turn and coordinated threats."""

from __future__ import annotations

import uuid
from typing import Any

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.models import (
    BehavioralAlert,
    BehavioralProfile,
    EventSummary,
)


class BaseBehavioralDetector:
    """Base class for all behavioral anomaly detectors."""

    def __init__(self, config: BehavioralConfig | None = None) -> None:
        self.config = config or BehavioralConfig()

    async def evaluate(
        self,
        profile: BehavioralProfile,
        current_event: EventSummary,
        extra_context: dict[str, Any] | None = None,
    ) -> BehavioralAlert | None:
        """Evaluate profile and current event for anomalous behavior."""
        raise NotImplementedError


class MultiTurnProbingDetector(BaseBehavioralDetector):
    """Detects repeated suspicious or near-threshold probing attempts over a rolling window."""

    async def evaluate(
        self,
        profile: BehavioralProfile,
        current_event: EventSummary,
        extra_context: dict[str, Any] | None = None,
    ) -> BehavioralAlert | None:
        # Filter near-threshold attempts within configured window
        now = current_event.timestamp
        cutoff = now - self.config.window_seconds
        probing_events = [
            e
            for e in profile.recent_events
            if e.timestamp >= cutoff and e.risk_score >= self.config.probing_threshold
        ]

        if len(probing_events) >= self.config.probing_min_attempts:
            contributing = [e.event_id for e in probing_events]
            highest_risk = max(e.risk_score for e in probing_events)
            agg_risk = min(0.95, round(highest_risk + 0.05 * (len(probing_events) - 1), 3))

            return BehavioralAlert(
                alert_id=f"alert-probe-{uuid.uuid4().hex[:12]}",
                org_id=profile.org_id,
                source_id=profile.source_id,
                detector_type="multi_turn_probing",
                threat_type="behavioral_multi_turn",
                severity="high" if agg_risk >= 0.80 else "medium",
                verdict="malicious",
                risk_score=agg_risk,
                detection_reason=(
                    f"Detected {len(probing_events)} repeated near-threshold probing attempts "
                    f"(risk >= {self.config.probing_threshold}) within {self.config.window_seconds}s window"
                ),
                time_window_seconds=self.config.window_seconds,
                contributing_events=contributing,
                metadata={
                    "probing_count": len(probing_events),
                    "threshold": self.config.probing_threshold,
                    "target_model": current_event.model,
                },
            )

        return None


class RiskSpikeDetector(BaseBehavioralDetector):
    """Detects sudden significant risk score increases relative to the source's baseline."""

    async def evaluate(
        self,
        profile: BehavioralProfile,
        current_event: EventSummary,
        extra_context: dict[str, Any] | None = None,
    ) -> BehavioralAlert | None:
        now = current_event.timestamp
        cutoff = now - self.config.window_seconds
        prior_events = [
            e
            for e in profile.recent_events
            if e.event_id != current_event.event_id and e.timestamp >= cutoff
        ]

        if len(prior_events) < self.config.spike_min_baseline_samples:
            return None

        baseline = sum(e.risk_score for e in prior_events) / len(prior_events)
        delta = current_event.risk_score - baseline

        # Trigger if current event risk is elevated and delta exceeds threshold
        if (
            current_event.risk_score >= self.config.spike_min_risk
            and delta >= self.config.spike_delta_threshold
        ):
            contributing = [current_event.event_id] + [e.event_id for e in prior_events[-5:]]
            return BehavioralAlert(
                alert_id=f"alert-spike-{uuid.uuid4().hex[:12]}",
                org_id=profile.org_id,
                source_id=profile.source_id,
                detector_type="risk_spike",
                threat_type="behavioral_risk_spike",
                severity="high",
                verdict="malicious",
                risk_score=round(current_event.risk_score, 3),
                detection_reason=(
                    f"Sudden risk spike to {current_event.risk_score:.2f} relative to baseline "
                    f"{baseline:.2f} (delta +{delta:.2f}) over {len(prior_events)} prior requests"
                ),
                time_window_seconds=self.config.window_seconds,
                contributing_events=contributing,
                metadata={
                    "baseline_risk": round(baseline, 3),
                    "current_risk": round(current_event.risk_score, 3),
                    "delta": round(delta, 3),
                    "prior_sample_count": len(prior_events),
                    "target_model": current_event.model,
                },
            )

        return None


class CoordinatedAttackDetector(BaseBehavioralDetector):
    """Identifies coordinated bursts across multiple distinct sources sharing an attack pattern."""

    async def evaluate(
        self,
        profile: BehavioralProfile,
        current_event: EventSummary,
        extra_context: dict[str, Any] | None = None,
    ) -> BehavioralAlert | None:
        if not extra_context:
            return None

        coordinated_events: list[dict[str, Any]] = extra_context.get("coordinated_events", [])
        if not coordinated_events:
            return None

        # Filter strictly for suspicious events within coordinated window
        now = current_event.timestamp
        cutoff = now - self.config.coordinated_window_seconds

        active_suspicious = [
            e
            for e in coordinated_events
            if e.get("timestamp", 0) >= cutoff
            and (
                float(e.get("risk_score", 0.0)) >= self.config.probing_threshold
                or (e.get("threat_type") and e.get("threat_type") != "benign")
            )
        ]

        if not active_suspicious:
            return None

        # Group by shared attack pattern (threat_type or prompt_signature)
        pattern_groups: dict[str, list[dict[str, Any]]] = {}
        for ev in active_suspicious:
            pattern = ev.get("threat_type") or ev.get("prompt_signature")
            if pattern and pattern != "benign":
                pattern_groups.setdefault(pattern, []).append(ev)

        # Check if any shared attack pattern has distinct sources >= threshold
        for pattern, events_in_group in pattern_groups.items():
            distinct_sources = {ev["source_id"] for ev in events_in_group if ev.get("source_id")}
            if len(distinct_sources) >= self.config.coordinated_min_sources:
                contributing = list({ev["event_id"] for ev in events_in_group if ev.get("event_id")})
                avg_risk = sum(float(ev.get("risk_score", 0.0)) for ev in events_in_group) / len(events_in_group)
                alert_risk = max(0.90, round(avg_risk, 3))

                return BehavioralAlert(
                    alert_id=f"alert-coord-{uuid.uuid4().hex[:12]}",
                    org_id=profile.org_id,
                    source_id=f"coordinated-{len(distinct_sources)}-sources",
                    detector_type="coordinated_attack",
                    threat_type="behavioral_coordinated",
                    severity="critical",
                    verdict="malicious",
                    risk_score=alert_risk,
                    detection_reason=(
                        f"Coordinated burst of '{pattern}' attacks detected across "
                        f"{len(distinct_sources)} distinct sources within {self.config.coordinated_window_seconds}s window"
                    ),
                    time_window_seconds=self.config.coordinated_window_seconds,
                    contributing_events=contributing,
                    metadata={
                        "shared_pattern": pattern,
                        "distinct_sources_count": len(distinct_sources),
                        "participating_sources": sorted(distinct_sources),
                        "target_model": current_event.model,
                    },
                )

        return None


class NoveltyDetector(BaseBehavioralDetector):
    """Detects unprecedented threat categories from sources with established benign baselines."""

    async def evaluate(
        self,
        profile: BehavioralProfile,
        current_event: EventSummary,
        extra_context: dict[str, Any] | None = None,
    ) -> BehavioralAlert | None:
        # Must have an active threat type and elevated risk
        if not current_event.threat_type or current_event.threat_type == "benign" or current_event.risk_score < self.config.novelty_min_risk:
            return None

        now = current_event.timestamp
        cutoff = now - self.config.window_seconds
        prior_events = [
            e
            for e in profile.recent_events
            if e.event_id != current_event.event_id and e.timestamp >= cutoff
        ]

        if len(prior_events) < self.config.novelty_min_baseline_samples:
            return None

        # Check if this threat_type was ever observed previously
        seen_threat_types = {e.threat_type for e in prior_events if e.threat_type and e.threat_type != "benign"}
        if current_event.threat_type in seen_threat_types or profile.threat_type_counts.get(current_event.threat_type, 0) > 1:
            return None

        # Check if source history was predominantly benign
        baseline_risk = sum(e.risk_score for e in prior_events) / len(prior_events)
        if baseline_risk > 0.35:
            # Source was already showing mixed/suspicious behavior; not a clean novelty signal
            return None

        return BehavioralAlert(
            alert_id=f"alert-nov-{uuid.uuid4().hex[:12]}",
            org_id=profile.org_id,
            source_id=profile.source_id,
            detector_type="novelty_detected",
            threat_type="behavioral_novelty",
            severity="high",
            verdict="suspicious",
            risk_score=round(current_event.risk_score, 3),
            detection_reason=(
                f"Novel threat category '{current_event.threat_type}' observed from source "
                f"with {len(prior_events)} previously benign interactions (baseline risk {baseline_risk:.2f})"
            ),
            time_window_seconds=self.config.window_seconds,
            contributing_events=[current_event.event_id],
            metadata={
                "novel_threat_type": current_event.threat_type,
                "prior_benign_count": len(prior_events),
                "baseline_risk": round(baseline_risk, 3),
                "target_model": current_event.model,
            },
        )
