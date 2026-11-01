"""Data models for behavioral profiling, events, and anomaly alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class EventSummary:
    """Compact summary of an event for behavioral profile windows (no raw prompt stored)."""

    event_id: str
    timestamp: float  # Unix epoch seconds
    iso_timestamp: str
    risk_score: float
    verdict: str
    threat_type: str | None = None
    model: str = "unknown"
    source_type: str = "unknown"
    prompt_signature: str | None = None  # Matched rule pattern or signature snippet

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EventSummary:
        return cls(
            event_id=str(data.get("event_id", "")),
            timestamp=float(data.get("timestamp", 0.0)),
            iso_timestamp=str(data.get("iso_timestamp", "")),
            risk_score=float(data.get("risk_score", 0.0)),
            verdict=str(data.get("verdict", "benign")),
            threat_type=data.get("threat_type"),
            model=str(data.get("model", "unknown")),
            source_type=str(data.get("source_type", "unknown")),
            prompt_signature=data.get("prompt_signature"),
        )


@dataclass
class BehavioralProfile:
    """Rolling behavioral profile for a given source and tenant."""

    org_id: str
    source_id: str
    total_requests: int = 0
    first_seen: str = ""
    last_seen: str = ""
    threat_type_counts: dict[str, int] = field(default_factory=dict)
    recent_events: list[EventSummary] = field(default_factory=list)

    @property
    def recent_risk_scores(self) -> list[float]:
        return [e.risk_score for e in self.recent_events]

    @property
    def baseline_risk(self) -> float:
        """Calculate average risk score across recent events."""
        scores = self.recent_risk_scores
        return sum(scores) / len(scores) if scores else 0.0

    @property
    def request_rate_per_minute(self) -> float:
        """Calculate recent request rate per minute."""
        if len(self.recent_events) < 2:
            return 0.0
        time_span = self.recent_events[-1].timestamp - self.recent_events[0].timestamp
        if time_span <= 0:
            return 0.0
        return (len(self.recent_events) / time_span) * 60.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "source_id": self.source_id,
            "total_requests": self.total_requests,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "threat_type_counts": dict(self.threat_type_counts),
            "recent_events": [e.to_dict() for e in self.recent_events],
            "baseline_risk": round(self.baseline_risk, 3),
            "request_rate_per_minute": round(self.request_rate_per_minute, 2),
            "active_window_samples": len(self.recent_events),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BehavioralProfile:
        events = [EventSummary.from_dict(e) for e in data.get("recent_events", [])]
        return cls(
            org_id=str(data.get("org_id", "default-org")),
            source_id=str(data.get("source_id", "anonymous")),
            total_requests=int(data.get("total_requests", 0)),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
            threat_type_counts=dict(data.get("threat_type_counts", {})),
            recent_events=events,
        )


@dataclass
class BehavioralAlert:
    """Structured security alert emitted by the behavioral anomaly engine."""

    alert_id: str
    org_id: str
    source_id: str
    detector_type: str  # "multi_turn_probing", "risk_spike", "coordinated_attack", "novelty_detected"
    threat_type: str    # "behavioral_multi_turn", "behavioral_risk_spike", "behavioral_coordinated", "behavioral_novelty"
    severity: str       # "critical", "high", "medium"
    verdict: str        # "malicious", "suspicious"
    risk_score: float
    detection_reason: str
    time_window_seconds: int
    contributing_events: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_event_dict(self) -> dict[str, Any]:
        """Convert alert into standard event format for Redis storage and dashboard feed."""
        return {
            "event_id": self.alert_id,
            "timestamp": self.timestamp,
            "source_type": "behavioral_engine",
            "source_id": self.source_id,
            "org_id": self.org_id,
            "model": self.metadata.get("target_model", "behavioral-analyzer"),
            "prompt": f"[Behavioral Alert: {self.detector_type.replace('_', ' ').title()}] {self.detection_reason}",
            "verdict": self.verdict,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            # Behavioral alerts are post-hoc detections; they never block the request.
            "blocked": False,
            "analyzed": True,
            "analyzed_at": self.timestamp,
            "analysis_details": {
                "method": "behavioral_analysis",
                "detector": self.detector_type,
                "reason": self.detection_reason,
                "time_window_seconds": self.time_window_seconds,
            },
            "metadata": {
                "is_behavioral_alert": True,
                "detector_type": self.detector_type,
                "detection_reason": self.detection_reason,
                "severity": self.severity,
                "time_window_seconds": self.time_window_seconds,
                "contributing_events": self.contributing_events,
                **self.metadata,
            },
        }
