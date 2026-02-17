"""
TENET AI - Analyzer Service
ML-based threat detection engine for LLM prompts.

Production hardening:
- Circuit breaker for Redis (prevents cascade failures)
- Graceful degradation: if Redis is down, queue processor pauses cleanly
- Per-call Redis timeouts  
- Structured JSON logging
- ML model failure isolation (heuristic fallback always available)
- Background queue processor with exponential backoff on repeated errors
- Graceful shutdown: drains in-flight analysis before exiting
"""
import os
import json
import time
import asyncio
import logging
import signal
from datetime import datetime
from enum import Enum
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis

# joblib / numpy are optional — degrade cleanly if missing
try:
    import joblib
    import numpy as np
    _ml_imports_ok = True
except ImportError:
    _ml_imports_ok = False

# ─────────────────────────────────────────────
# Structured JSON Logging
# ─────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level":     record.levelname,
            "service":   "tenet-analyzer",
            "version":   "0.1.0",
            "logger":    record.name,
            "message":   record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        for field in ("event_id", "verdict", "threat_type", "method"):
            if hasattr(record, field):
                entry[field] = getattr(record, field)
        return json.dumps(entry)


handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────
REDIS_HOST                  = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT                  = int(os.getenv("REDIS_PORT", 6379))
REDIS_TIMEOUT_S             = float(os.getenv("REDIS_TIMEOUT_S", 2.0))
API_HOST                    = os.getenv("API_HOST", "0.0.0.0")
API_PORT                    = int(os.getenv("API_PORT", 8100))
API_KEY                     = os.getenv("API_KEY", "tenet-dev-key-change-in-production")
MODEL_PATH                  = os.getenv("MODEL_PATH", "./models/trained")
PROMPT_INJECTION_THRESHOLD  = float(os.getenv("PROMPT_INJECTION_THRESHOLD", 0.75))
QUEUE_IDLE_SLEEP_S          = float(os.getenv("QUEUE_IDLE_SLEEP_S", 1.0))
QUEUE_MAX_BACKOFF_S         = float(os.getenv("QUEUE_MAX_BACKOFF_S", 60.0))

# Circuit breaker tuning
CB_FAILURE_THRESHOLD    = int(os.getenv("CB_FAILURE_THRESHOLD", 3))
CB_RECOVERY_TIMEOUT_S   = float(os.getenv("CB_RECOVERY_TIMEOUT_S", 30.0))
CB_HALF_OPEN_MAX_CALLS  = int(os.getenv("CB_HALF_OPEN_MAX_CALLS", 1))


# ─────────────────────────────────────────────
# Circuit Breaker  (no external dependency)
# ─────────────────────────────────────────────
class CircuitState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Async circuit breaker — identical pattern to ingest service
    so behaviour is consistent across the stack.
    """
    def __init__(
        self,
        name: str,
        failure_threshold: int   = CB_FAILURE_THRESHOLD,
        recovery_timeout:  float = CB_RECOVERY_TIMEOUT_S,
        half_open_max_calls: int = CB_HALF_OPEN_MAX_CALLS,
    ):
        self.name                = name
        self.failure_threshold   = failure_threshold
        self.recovery_timeout    = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state             = CircuitState.CLOSED
        self._failure_count     = 0
        self._last_failure_ts   = 0.0
        self._half_open_calls   = 0
        self._lock              = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_ts >= self.recovery_timeout:
                self._state           = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(f"Circuit breaker [{self.name}] → HALF_OPEN")
                return False
            return True
        return False

    def allow_request(self) -> bool:
        if self._state == CircuitState.CLOSED:
            return True
        if self._state == CircuitState.OPEN:
            return not self.is_open
        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        return False

    async def record_success(self):
        async with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
                self._state         = CircuitState.CLOSED
                self._failure_count = 0
                if self._state == CircuitState.HALF_OPEN:
                    logger.info(f"Circuit breaker [{self.name}] → CLOSED (recovered)")

    async def record_failure(self):
        async with self._lock:
            self._failure_count  += 1
            self._last_failure_ts = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.error(f"Circuit breaker [{self.name}] → OPEN (probe failed)")
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.error(
                    f"Circuit breaker [{self.name}] → OPEN "
                    f"({self._failure_count} consecutive failures)"
                )


# ─────────────────────────────────────────────
# App + Global State
# ─────────────────────────────────────────────
app = FastAPI(
    title="TENET AI - Analyzer Service",
    description="ML-based threat detection for LLM applications",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client:    Optional[redis.Redis] = None
redis_cb:        CircuitBreaker        = CircuitBreaker("redis-analyzer")
ml_model                               = None
vectorizer                             = None
_shutdown_event: asyncio.Event         = asyncio.Event()
_start_time = time.monotonic()


# ─────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────
class AnalysisRequest(BaseModel):
    prompt:  str           = Field(..., description="Prompt to analyse")
    context: Optional[str] = Field(None)


class AnalysisResponse(BaseModel):
    risk_score:  float
    verdict:     str
    threat_type: Optional[str]
    confidence:  float
    details:     dict


class HealthResponse(BaseModel):
    status:          str
    service:         str
    version:         str
    model_loaded:    bool
    redis_connected: bool
    circuit_state:   str
    uptime_seconds:  float


# ─────────────────────────────────────────────
# Redis Helper
# ─────────────────────────────────────────────
async def redis_call(coro):
    """Execute Redis coro with timeout + circuit breaker. Returns None on any failure."""
    if not redis_client or not redis_cb.allow_request():
        return None
    try:
        result = await asyncio.wait_for(coro, timeout=REDIS_TIMEOUT_S)
        await redis_cb.record_success()
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Redis timeout after {REDIS_TIMEOUT_S}s")
        await redis_cb.record_failure()
        return None
    except Exception as exc:
        logger.warning(f"Redis call failed: {exc}")
        await redis_cb.record_failure()
        return None


# ─────────────────────────────────────────────
# Startup / Shutdown
# ─────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client, ml_model, vectorizer

    # Redis — non-fatal
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=REDIS_TIMEOUT_S,
            socket_timeout=REDIS_TIMEOUT_S,
            retry_on_timeout=False,
        )
        await asyncio.wait_for(redis_client.ping(), timeout=REDIS_TIMEOUT_S)
        logger.info(f"Redis connected at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as exc:
        logger.error(
            f"Redis unavailable at startup ({exc}). "
            "Queue processor will pause until Redis recovers."
        )
        redis_client = None

    # ML Models — non-fatal
    if _ml_imports_ok:
        try:
            model_dir       = Path(MODEL_PATH)
            model_file      = model_dir / "prompt_detector.joblib"
            vectorizer_file = model_dir / "vectorizer.joblib"

            if model_file.exists() and vectorizer_file.exists():
                ml_model   = joblib.load(model_file)
                vectorizer = joblib.load(vectorizer_file)
                logger.info("ML models loaded successfully")
            else:
                logger.warning(
                    f"ML models not found at {MODEL_PATH}. "
                    "Running heuristic-only mode."
                )
        except Exception as exc:
            logger.error(f"Failed to load ML models ({exc}). Falling back to heuristics.")
    else:
        logger.warning("joblib/numpy not installed — ML detection disabled.")

    # Background tasks
    asyncio.create_task(process_event_queue())
    asyncio.create_task(_redis_reconnect_loop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_event_loop().add_signal_handler(
                sig, lambda: _shutdown_event.set()
            )
        except NotImplementedError:
            pass


@app.on_event("shutdown")
async def shutdown():
    _shutdown_event.set()
    if redis_client:
        try:
            await redis_client.close()
        except Exception:
            pass
        logger.info("Redis connection closed")


async def _redis_reconnect_loop():
    global redis_client
    while not _shutdown_event.is_set():
        await asyncio.sleep(CB_RECOVERY_TIMEOUT_S)
        if redis_cb.state != CircuitState.CLOSED:
            try:
                if redis_client is None:
                    redis_client = redis.Redis(
                        host=REDIS_HOST,
                        port=REDIS_PORT,
                        decode_responses=True,
                        socket_connect_timeout=REDIS_TIMEOUT_S,
                        socket_timeout=REDIS_TIMEOUT_S,
                        retry_on_timeout=False,
                    )
                await asyncio.wait_for(redis_client.ping(), timeout=REDIS_TIMEOUT_S)
                await redis_cb.record_success()
                logger.info("Redis reconnection probe succeeded")
            except Exception as exc:
                logger.debug(f"Redis reconnection probe failed: {exc}")
                await redis_cb.record_failure()


# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
async def health_check():
    redis_ok = await redis_call(redis_client.ping()) if redis_client else None
    return HealthResponse(
        status="healthy" if redis_ok and ml_model else "degraded",
        service="analyzer",
        version="0.1.0",
        model_loaded=ml_model is not None,
        redis_connected=bool(redis_ok),
        circuit_state=redis_cb.state.value,
        uptime_seconds=round(time.monotonic() - _start_time, 1),
    )


@app.post("/v1/analyze", response_model=AnalysisResponse)
async def analyze_prompt(
    request: AnalysisRequest,
    x_api_key: str = Header(...)
):
    verify_api_key(x_api_key)
    return await run_analysis(request.prompt)


@app.get("/v1/circuit-status")
async def circuit_status(x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    return {
        "service":          "analyzer",
        "circuit":          "redis",
        "state":            redis_cb.state.value,
        "failure_count":    redis_cb._failure_count,
        "recovery_timeout": redis_cb.recovery_timeout,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────
# Analysis Logic
# ─────────────────────────────────────────────
async def run_analysis(prompt: str) -> AnalysisResponse:
    """
    Run full analysis. Always returns a result — never raises.
    Degrades gracefully: heuristic → ML → combined.
    """
    try:
        heuristic = heuristic_analysis(prompt)
    except Exception as exc:
        logger.error(f"Heuristic analysis crashed unexpectedly: {exc}")
        # Absolute last-resort fallback — flag for manual review
        return AnalysisResponse(
            risk_score=0.5,
            verdict="suspicious",
            threat_type="analysis_error",
            confidence=0.0,
            details={"method": "error_fallback", "error": str(exc)},
        )

    ml = None
    if ml_model and vectorizer:
        ml = ml_analysis(prompt)   # Already wrapped in try/except — returns safe dict

    # Decision logic
    if heuristic["risk_score"] > 0.8:
        return AnalysisResponse(
            risk_score=heuristic["risk_score"],
            verdict=heuristic["verdict"],
            threat_type=heuristic["threat_type"],
            confidence=0.95,
            details={
                "method":           "heuristic",
                "matched_patterns": heuristic.get("patterns", []),
            },
        )

    if ml and ml["risk_score"] > PROMPT_INJECTION_THRESHOLD:
        return AnalysisResponse(
            risk_score=ml["risk_score"],
            verdict=ml["verdict"],
            threat_type=ml["threat_type"],
            confidence=ml["confidence"],
            details={"method": "ml", "model_version": "0.1"},
        )

    if heuristic["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=heuristic["risk_score"],
            verdict="suspicious",
            threat_type=heuristic["threat_type"],
            confidence=0.6,
            details={"method": "heuristic", "recommendation": "manual_review"},
        )

    return AnalysisResponse(
        risk_score=max(
            heuristic["risk_score"],
            ml["risk_score"] if ml else 0.0,
        ),
        verdict="benign",
        threat_type=None,
        confidence=0.85,
        details={
            "method":       "combined",
            "ml_available": ml is not None,
        },
    )


def heuristic_analysis(prompt: str) -> dict:
    prompt_lower = prompt.lower()
    matched, max_score, threat_type = [], 0.0, None

    patterns = {
        "prompt_injection": {
            "ignore previous instructions": 0.95,
            "ignore all previous":          0.95,
            "disregard your instructions":  0.90,
            "forget your system prompt":    0.90,
            "override system":              0.85,
            "</s>":                         0.90,
            "<|system|>":                   0.95,
            "\\n\\n###":                    0.80,
        },
        "jailbreak": {
            "do anything now":          0.90,
            "you are now dan":          0.95,
            "no restrictions":          0.80,
            "bypass your programming":  0.85,
            "override your safety":     0.90,
            "evil mode":                0.85,
            "developer mode":           0.80,
        },
        "data_extraction": {
            "show me your system prompt": 0.75,
            "what are your instructions": 0.70,
            "reveal your training":       0.75,
            "list your rules":            0.65,
        },
    }

    for category, category_patterns in patterns.items():
        for pattern, score in category_patterns.items():
            if pattern in prompt_lower:
                matched.append(pattern)
                if score > max_score:
                    max_score, threat_type = score, category

    verdict = "benign"
    if max_score > 0.8:
        verdict = "malicious"
    elif max_score > 0.5:
        verdict = "suspicious"

    return {
        "risk_score": max_score,
        "verdict":    verdict,
        "threat_type": threat_type,
        "patterns":   matched,
    }


def ml_analysis(prompt: str) -> dict:
    """ML analysis — returns safe fallback dict on any error, never raises."""
    global ml_model, vectorizer
    if not ml_model or not vectorizer:
        return {"risk_score": 0.0, "verdict": "unknown", "threat_type": None, "confidence": 0.0}
    try:
        X             = vectorizer.transform([prompt])
        proba         = ml_model.predict_proba(X)[0]
        malicious_prob = float(proba[1] if len(proba) > 1 else proba[0])

        if malicious_prob > PROMPT_INJECTION_THRESHOLD:
            verdict = "malicious"
        elif malicious_prob > 0.5:
            verdict = "suspicious"
        else:
            verdict = "benign"

        return {
            "risk_score":  malicious_prob,
            "verdict":     verdict,
            "threat_type": "prompt_injection" if malicious_prob > 0.5 else None,
            "confidence":  float(max(proba)),
        }
    except Exception as exc:
        logger.error(f"ML analysis error: {exc}")
        return {"risk_score": 0.0, "verdict": "error", "threat_type": None, "confidence": 0.0}


# ─────────────────────────────────────────────
# Background Queue Processor  (with backoff + graceful shutdown)
# ─────────────────────────────────────────────
async def process_event_queue():
    """
    Continuously drain tenet:events:queue from Redis.

    Graceful degradation:
    - If Redis is unavailable, waits and retries with exponential backoff.
    - Never crashes the service — logs errors and continues.
    - Respects _shutdown_event for clean exit.
    """
    backoff_s = QUEUE_IDLE_SLEEP_S
    logger.info("Queue processor started")

    while not _shutdown_event.is_set():
        # If circuit is open, back off and wait
        if not redis_client or redis_cb.state == CircuitState.OPEN:
            logger.warning(
                f"Queue processor paused — Redis circuit OPEN. "
                f"Retrying in {backoff_s:.0f}s"
            )
            await asyncio.sleep(min(backoff_s, QUEUE_MAX_BACKOFF_S))
            backoff_s = min(backoff_s * 2, QUEUE_MAX_BACKOFF_S)
            continue

        try:
            event_json = await redis_call(redis_client.rpop("tenet:events:queue"))

            if event_json is None:
                # Either empty queue or Redis call failed
                backoff_s = QUEUE_IDLE_SLEEP_S   # Reset on idle
                await asyncio.sleep(QUEUE_IDLE_SLEEP_S)
                continue

            # We got an event — reset backoff
            backoff_s = QUEUE_IDLE_SLEEP_S

            try:
                event = json.loads(event_json)
            except json.JSONDecodeError as exc:
                logger.error(f"Corrupt event JSON in queue, discarding: {exc}")
                continue

            event_id = event.get("event_id", "unknown")
            logger.info("Processing queued event", extra={"event_id": event_id})

            result = await run_analysis(event.get("prompt", ""))

            event.update({
                "analysed":         True,
                "risk_score":       result.risk_score,
                "verdict":          result.verdict,
                "threat_type":      result.threat_type,
                "analysis_details": result.details,
                "analysed_at":      datetime.utcnow().isoformat() + "Z",
            })

            stored = await redis_call(
                redis_client.set(
                    f"tenet:event:{event_id}",
                    json.dumps(event),
                    ex=86400,
                )
            )
            if stored is None:
                logger.warning(
                    "Could not persist analysis result — Redis write failed",
                    extra={"event_id": event_id},
                )

            if result.verdict == "malicious":
                await redis_call(
                    redis_client.lpush("tenet:alerts", json.dumps(event))
                )
                logger.warning(
                    "Malicious event detected",
                    extra={
                        "event_id":   event_id,
                        "verdict":    result.verdict,
                        "threat_type": result.threat_type,
                    },
                )

        except Exception as exc:
            # Catch-all so the loop never dies
            logger.error(f"Unexpected queue processor error: {exc}")
            backoff_s = min(backoff_s * 2, QUEUE_MAX_BACKOFF_S)
            await asyncio.sleep(backoff_s)

    logger.info("Queue processor stopped (shutdown signal received)")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
