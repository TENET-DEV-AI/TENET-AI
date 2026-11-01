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
