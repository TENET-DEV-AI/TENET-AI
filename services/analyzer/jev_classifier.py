"""
Optional Jev (System One decision model) classifier backend for the analyzer.

Two protocols are supported, both off unless ``TENET_JEV_BACKEND`` selects one:

* ``jev_api``: TypeSafe's hosted ``POST /v1/systemone``. Prompts leave your network.
* ``jev_local``: ``POST /v1/decide`` as served by ``serve_decide.py`` from the
  ``autotrust/JEV-27B`` model repository (vLLM).

Jev does not treat the state it judges as hostile, so a prompt can try to steer
its own classification. The caller must only use these answers to raise a
verdict, never to lower one.
"""

import asyncio
import copy
import hashlib
import math
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
from prometheus_client import Counter

from services.utils.env_validator import (
    EnvValidationError,
    SafeValueError,
    positive_float,
    validate_env_vars,
)
from services.utils.logging_config import setup_logging

logger = setup_logging(__name__)

BACKENDS = ("sklearn", "jev_api", "jev_local")
DEFAULT_API_URL = "https://api.typesafe.ai"
# Pinned on purpose: the thresholds below should not move when an alias moves.
DEFAULT_MODEL = "jev-1.14.0"

JEV_REQUESTS = Counter(
    "tenet_jev_requests_total",
    "Jev classifier lookups by backend and outcome",
    ["backend", "outcome"],
)

MALICIOUS_QUESTION = (
    "Is the text in the prompt field trying to manipulate, jailbreak, or extract data "
    "from an AI system, or to phish a person?"
)
THREAT_QUESTION = "Which category fits the text in the prompt field best?"
SEVERITY_QUESTION = "How severe is the security risk of the text in the prompt field?"

THREAT_CATEGORIES = {
    "benign": "An ordinary request with no attempt to attack or deceive",
    "prompt_injection": "Tries to override or replace the instructions an AI system was given",
    "jailbreak": "Tries to get an AI system to drop its safety rules or restrictions",
    "data_extraction": "Tries to reveal system prompts, training data, secrets or private data",
    "phishing": "Tries to trick a person into giving up credentials, money or information",
}
SEVERITY_LEVELS = ("none", "low", "medium", "high", "critical")
# /v1/decide has a fixed 0-5 score scale instead of caller supplied levels.
LOCAL_SCORE_OPTIONS = tuple(str(level) for level in range(6))
LOCAL_SEVERITY_QUESTION = f"{SEVERITY_QUESTION} 0 means no risk and 5 means critical risk."

# Normalized severity (0-1) at which an otherwise benign answer goes to review.
SEVERITY_REVIEW_LEVEL = 0.75
# How far a probability distribution may be from summing to 1.
_SUM_TOLERANCE = 0.05


def _backend(value: str) -> str:
    name = value.lower() or "sklearn"
    if name not in BACKENDS:
        raise SafeValueError(f"must be one of {', '.join(BACKENDS)}")
    return name


def _cache_size(value: str) -> int:
    if not value.isdigit():
        raise SafeValueError("must be an integer of 0 or more")
    return int(value)


@dataclass(frozen=True)
class JevSettings:
    """Validated ``TENET_JEV_*`` settings."""

    backend: str = "sklearn"
    url: str = ""
    api_key: str = field(default="", repr=False)
    model: str = DEFAULT_MODEL
    timeout: float = 3.0
    cache_size: int = 1024


def load_jev_settings() -> JevSettings:
    """Read and validate the ``TENET_JEV_*`` env vars.

    The other variables are only checked when a Jev backend is selected, so a
    leftover value cannot stop a service that runs on the default backend.

    Returns:
        The settings. ``backend`` is ``"sklearn"`` when Jev is not enabled.

    Raises:
        EnvValidationError: If a value is invalid or a required one is missing.
    """
    backend = validate_env_vars(
        [],
        optional_vars={"TENET_JEV_BACKEND": "sklearn"},
        types={"TENET_JEV_BACKEND": _backend},
    )["TENET_JEV_BACKEND"]
    if backend == "sklearn":
        return JevSettings()

    # docker compose passes unset variables through as empty strings.
    numbers = {
        name: converter
        for name, converter in (
            ("TENET_JEV_TIMEOUT", positive_float),
            ("TENET_JEV_CACHE_SIZE", _cache_size),
        )
        if os.environ.get(name, "").strip()
    }
    values = validate_env_vars([], optional_vars=dict.fromkeys(numbers, None), types=numbers)

    url = os.environ.get("TENET_JEV_URL", "").strip()
    api_key = os.environ.get("TENET_JEV_API_KEY", "").strip()
    model = os.environ.get("TENET_JEV_MODEL", "").strip() or DEFAULT_MODEL

    missing = []
    if backend == "jev_api":
        url = url or DEFAULT_API_URL
        if not api_key:
            missing.append("TENET_JEV_API_KEY")
        schemes = ("https",)
    else:
        if not url:
            missing.append("TENET_JEV_URL")
        api_key = ""  # the hosted key is never sent to a local server
        schemes = ("http", "https")
    if missing:
        raise EnvValidationError(missing, {})

    parts = urlsplit(url)
    if parts.scheme not in schemes or not parts.hostname:
        # The URL is not echoed back because it may carry credentials.
        reason = f"must be a {' or '.join(schemes)} URL for {backend}"
        raise EnvValidationError([], {"TENET_JEV_URL": reason})

    return JevSettings(
        backend=backend,
        url=url.rstrip("/"),
        api_key=api_key,
        model=model,
        timeout=values.get("TENET_JEV_TIMEOUT", JevSettings.timeout),
        cache_size=values.get("TENET_JEV_CACHE_SIZE", JevSettings.cache_size),
    )


class JevError(Exception):
    """A Jev call that produced no usable answer.

    Attributes:
        reason: Short code that is safe to log and to return to API callers.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _number(value: object, upper: float = 1.0) -> float:
    """Return ``value`` as a float, rejecting anything outside ``[0, upper]``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevError("invalid_response")
    if not math.isfinite(value) or not 0 <= value <= upper:
        raise JevError("invalid_response")
    return float(value)


def _distribution(probabilities: dict, keys: tuple) -> dict:
    """Check that a probability map covers exactly ``keys`` and sums to about 1."""
    if set(probabilities) != set(keys):
        raise JevError("invalid_response")
    checked = {key: _number(probabilities[key]) for key in keys}
    if abs(sum(checked.values()) - 1.0) > _SUM_TOLERANCE:
        raise JevError("invalid_response")
    return checked


def map_answers(malicious: float, categories: dict, severity: float, threshold: float) -> dict:
    """Turn the three Jev answers into TENET's verdict fields.

    ``risk_score`` is the yes/no probability and uses the same thresholds as the
    sklearn model. If that says benign but the category or severity answer
    disagrees, the verdict is raised to ``"suspicious"``.

    Args:
        malicious: P(yes) from the noul question.
        categories: Probability per threat category from the choice question.
        severity: Expected severity from the score question, scaled to 0-1.
        threshold: Risk score above which the verdict is ``"malicious"``.

    Returns:
        Dict with ``risk_score``, ``verdict``, ``threat_type``, ``confidence``
        and ``escalated_by``.
    """
    threats = {name: p for name, p in categories.items() if name != "benign"}
    top_threat = max(threats, key=threats.get)
    escalated_by = []

    if malicious > threshold:
        verdict = "malicious"
    elif malicious > 0.5:
        verdict = "suspicious"
    else:
        # A tie with "benign" counts as disagreement.
        if threats[top_threat] >= categories["benign"]:
            escalated_by.append("threat_type")
        if severity >= SEVERITY_REVIEW_LEVEL:
            escalated_by.append("severity")
        verdict = "suspicious" if escalated_by else "benign"

    return {
        "risk_score": malicious,
        "verdict": verdict,
        "threat_type": None if verdict == "benign" else top_threat,
        "confidence": 0.6 if escalated_by else max(malicious, 1.0 - malicious),
        "escalated_by": escalated_by,
    }


class JevClassifier:
    """Zero-shot prompt classifier backed by a Jev style decision model."""

    def __init__(
        self,
        settings: JevSettings,
        threshold: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create a client for the configured backend.

        Args:
            settings: Settings with ``backend`` set to ``jev_api`` or ``jev_local``.
            threshold: Risk score above which a prompt counts as malicious.
            transport: Replacement HTTP transport, used by the tests.

        Raises:
            ValueError: If the settings do not select a Jev backend.
        """
        if settings.backend not in ("jev_api", "jev_local"):
            raise ValueError(f"not a Jev backend: {settings.backend}")
        self.settings = settings
        self.threshold = threshold
        self._cache: OrderedDict[str, dict] = OrderedDict()
        headers = {}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        self._client = httpx.AsyncClient(
            base_url=settings.url,
            headers=headers,
            timeout=settings.timeout,
            transport=transport,
            # A local server must not be reached through an outbound proxy.
            trust_env=settings.backend == "jev_api",
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def classify(self, prompt: str) -> dict:
        """Classify one prompt. Failures are reported in the result, not raised.

        Args:
            prompt: Raw prompt text.

        Returns:
            On success a dict with ``status`` ``"ok"``, the fields from
            :func:`map_answers`, ``severity``, ``probabilities``, ``model`` and
            ``cached``. Otherwise ``status`` is ``"unavailable"`` and ``reason``
            says why. A failed result carries no risk score or verdict, so it
            cannot be mistaken for a benign answer.
        """
        backend = self.settings.backend
        try:
            # Lone surrogates cannot be encoded and would otherwise be an easy
            # way to make every request for a prompt fail.
            text = prompt.encode("utf-8", "replace").decode("utf-8")
            key = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if key in self._cache:
                self._cache.move_to_end(key)
                JEV_REQUESTS.labels(backend=backend, outcome="cache_hit").inc()
                return {**copy.deepcopy(self._cache[key]), "cached": True}

            ask = self._ask_api if backend == "jev_api" else self._ask_local
            # httpx timeouts are per read/write, this caps the whole exchange.
            answers = await asyncio.wait_for(ask(text), timeout=self.settings.timeout)
        except (TimeoutError, httpx.TimeoutException):
            return self._unavailable("timeout")
        except httpx.HTTPError:
            return self._unavailable("connection_error")
        except JevError as exc:
            return self._unavailable(exc.reason)
        except Exception as exc:  # noqa: BLE001
            # Anything unexpected still has to leave the other detectors in charge.
            # Only the type is logged: messages can contain prompt text.
            logger.error("Unexpected Jev error: %s", type(exc).__name__)
            return self._unavailable("error")

        result = {
            "status": "ok",
            "backend": backend,
            "model": answers["model"],
            **map_answers(
                answers["malicious"],
                answers["threat_type"],
                answers["severity"],
                self.threshold,
            ),
            "severity": answers["severity"],
            "probabilities": {
                "malicious": answers["malicious"],
                "threat_type": answers["threat_type"],
                "severity": answers["severity_levels"],
            },
        }
        if self.settings.cache_size:
            self._cache[key] = copy.deepcopy(result)
            while len(self._cache) > self.settings.cache_size:
                self._cache.popitem(last=False)
        JEV_REQUESTS.labels(backend=backend, outcome="ok").inc()
        return {**result, "cached": False}

    def _unavailable(self, reason: str) -> dict:
        backend = self.settings.backend
        JEV_REQUESTS.labels(backend=backend, outcome=reason).inc()
        logger.warning(
            "Jev backend %s unavailable (%s), using heuristic and sklearn result only",
            backend,
            reason,
        )
        return {"status": "unavailable", "backend": backend, "reason": reason}

    async def _post(self, path: str, body: dict) -> dict:
        response = await self._client.post(path, json=body)
        if response.status_code != 200:
            raise JevError(f"http_{response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise JevError("invalid_response") from exc
        if not isinstance(data, dict):
            raise JevError("invalid_response")
        return data

    async def _ask_api(self, text: str) -> dict:
        """Ask all three questions in one ``/v1/systemone`` request."""
        data = await self._post(
            "/v1/systemone",
            {
                "model": self.settings.model,
                "state": {"prompt": text},
                "questions": {
                    "malicious": {"type": "noul", "instructions": MALICIOUS_QUESTION},
                    "threat_type": {
                        "type": "choice",
                        "instructions": THREAT_QUESTION,
                        "criteria": THREAT_CATEGORIES,
                    },
                    "severity": {
                        "type": "score",
                        "instructions": SEVERITY_QUESTION,
                        "criteria": list(SEVERITY_LEVELS),
                    },
                },
            },
        )
        try:
            answers = data["answers"]
            top_level = len(SEVERITY_LEVELS) - 1
            levels = _distribution(
                answers["severity"]["probabilities"],
                tuple(str(i) for i in range(len(SEVERITY_LEVELS))),
            )
            return {
                "model": str(data["model"]),
                "malicious": _number(answers["malicious"]["noul"]),
                "threat_type": _distribution(
                    answers["threat_type"]["probabilities"], tuple(THREAT_CATEGORIES)
                ),
                "severity": _number(answers["severity"]["score"], top_level) / top_level,
                "severity_levels": {name: levels[str(i)] for i, name in enumerate(SEVERITY_LEVELS)},
            }
        except (KeyError, TypeError) as exc:
            raise JevError("invalid_response") from exc

    async def _decide(
        self, kind: str, text: str, question: str, options: list | None = None
    ) -> tuple[list, str]:
        """Run one ``/v1/decide`` question and return probabilities in option order."""
        # A JSON state is escaped by the server, so newlines in the prompt cannot
        # start a fake [question] or [options] section in its text template.
        body = {"kind": kind, "state": {"prompt": text}, "question": question}
        if kind == "choice":
            body["options"] = options
            expected = options
        else:
            expected = ["false", "true"] if kind == "noul" else list(LOCAL_SCORE_OPTIONS)
        data = await self._post("/v1/decide", body)
        probabilities = data.get("probabilities")
        if (
            data.get("options") != expected
            or not isinstance(probabilities, list)
            or len(probabilities) != len(expected)
        ):
            raise JevError("invalid_response")
        checked = _distribution(dict(enumerate(probabilities)), tuple(range(len(expected))))
        return list(checked.values()), str(data.get("model", "unknown"))

    async def _ask_local(self, text: str) -> dict:
        """Ask the three questions as separate ``/v1/decide`` requests."""
        options = [f"{name}: {description}" for name, description in THREAT_CATEGORIES.items()]
        noul, choice, score = await asyncio.gather(
            self._decide("noul", text, MALICIOUS_QUESTION),
            self._decide("choice", text, THREAT_QUESTION, options),
            self._decide("score", text, LOCAL_SEVERITY_QUESTION),
        )
        top_level = len(LOCAL_SCORE_OPTIONS) - 1
        expected_level = sum(level * p for level, p in enumerate(score[0]))
        return {
            "model": noul[1],
            "malicious": noul[0][1],
            "threat_type": dict(zip(THREAT_CATEGORIES, choice[0])),
            # The sum can drift past the top level within the tolerance.
            "severity": min(expected_level / top_level, 1.0),
            "severity_levels": dict(zip(LOCAL_SCORE_OPTIONS, score[0])),
        }
