"""Configuration models and defaults for the behavioral analysis engine."""

from dataclasses import dataclass


@dataclass
class BehavioralConfig:
    """Configurable parameters for behavioral analysis and anomaly detection."""

    enabled: bool = True
    # Rolling time window for behavioral analysis (in seconds)
    window_seconds: int = 900  # 15 minutes
    # Profile data retention in Redis (in seconds)
    retention_seconds: int = 86400  # 24 hours

    # Detector A: Multi-turn Probing
    probing_threshold: float = 0.50  # Risk score threshold considered probing/suspicious
    probing_min_attempts: int = 3    # Number of probing attempts within window to alert

    # Detector B: Sudden Risk Spike
    spike_min_baseline_samples: int = 3  # Minimum past requests needed to establish a baseline
    spike_delta_threshold: float = 0.40  # Difference from baseline to trigger spike alert
    spike_min_risk: float = 0.70         # Minimum risk score for current request to be a spike

    # Detector C: Coordinated Attacks
    coordinated_min_sources: int = 3      # Minimum distinct sources required for coordinated alert
    coordinated_window_seconds: int = 300 # Window (5 min) for correlated bursts

    # Detector D: Novelty Signals
    novelty_min_baseline_samples: int = 3 # Minimum baseline samples before flagging novelty
    novelty_min_risk: float = 0.60        # Minimum risk score for a novel attack type

    # Alert deduplication / cooldown
    alert_cooldown_seconds: int = 300     # Suppress duplicate alerts for same incident within 5 min

    # Storage bounds
    max_events_per_profile: int = 100     # Cap rolling events stored per source profile
    max_coordinated_events: int = 500     # Cap global sliding window for coordinated checks

    def __post_init__(self) -> None:
        """Validate configuration bounds, positive invariants, and probability thresholds."""
        # Storage and sample bounds must be positive
        if self.max_events_per_profile <= 0:
            raise ValueError(f"max_events_per_profile must be positive, got {self.max_events_per_profile}")
        if self.max_coordinated_events <= 0:
            raise ValueError(f"max_coordinated_events must be positive, got {self.max_coordinated_events}")
        if self.probing_min_attempts <= 0:
            raise ValueError(f"probing_min_attempts must be positive, got {self.probing_min_attempts}")
        if self.spike_min_baseline_samples <= 0:
            raise ValueError(f"spike_min_baseline_samples must be positive, got {self.spike_min_baseline_samples}")
        if self.novelty_min_baseline_samples <= 0:
            raise ValueError(f"novelty_min_baseline_samples must be positive, got {self.novelty_min_baseline_samples}")
        if self.coordinated_min_sources <= 0:
            raise ValueError(f"coordinated_min_sources must be positive, got {self.coordinated_min_sources}")

        # Invariant: probing_min_attempts cannot exceed max_events_per_profile
        if self.probing_min_attempts > self.max_events_per_profile:
            raise ValueError(
                f"probing_min_attempts ({self.probing_min_attempts}) cannot exceed "
                f"max_events_per_profile ({self.max_events_per_profile})"
            )

        # Time windows and retention values must be positive
        if self.window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {self.window_seconds}")
        if self.retention_seconds <= 0:
            raise ValueError(f"retention_seconds must be positive, got {self.retention_seconds}")
        if self.coordinated_window_seconds <= 0:
            raise ValueError(f"coordinated_window_seconds must be positive, got {self.coordinated_window_seconds}")
        if self.alert_cooldown_seconds <= 0:
            raise ValueError(f"alert_cooldown_seconds must be positive, got {self.alert_cooldown_seconds}")

        # Probability and risk score thresholds must be within [0.0, 1.0]
        thresholds = {
            "probing_threshold": self.probing_threshold,
            "spike_delta_threshold": self.spike_delta_threshold,
            "spike_min_risk": self.spike_min_risk,
            "novelty_min_risk": self.novelty_min_risk,
        }
        for name, val in thresholds.items():
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"{name} must be between 0.0 and 1.0, got {val}")
