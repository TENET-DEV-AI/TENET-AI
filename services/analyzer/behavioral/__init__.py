"""TENET AI - Behavioral Analysis Engine.

Detects multi-turn probing, sudden risk spikes, coordinated bursts, and novelty signals.
"""

from services.analyzer.behavioral.config import BehavioralConfig
from services.analyzer.behavioral.dedup import AlertDeduplicator
from services.analyzer.behavioral.detectors import (
    BaseBehavioralDetector,
    CoordinatedAttackDetector,
    MultiTurnProbingDetector,
    NoveltyDetector,
    RiskSpikeDetector,
)
from services.analyzer.behavioral.engine import BehavioralEngine
from services.analyzer.behavioral.models import (
    BehavioralAlert,
    BehavioralProfile,
    EventSummary,
)
from services.analyzer.behavioral.profile_manager import BehavioralProfileManager

__all__ = [
    "AlertDeduplicator",
    "BaseBehavioralDetector",
    "BehavioralAlert",
    "BehavioralConfig",
    "BehavioralEngine",
    "BehavioralProfile",
    "BehavioralProfileManager",
    "CoordinatedAttackDetector",
    "EventSummary",
    "MultiTurnProbingDetector",
    "NoveltyDetector",
    "RiskSpikeDetector",
]
