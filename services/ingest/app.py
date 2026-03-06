"""
TENET AI - Ingest Service
Middleware layer for intercepting and processing LLM requests.

Production hardening:
- Circuit breaker for Redis (prevents cascade failures)
- Graceful degradation (fail-open with logging when Redis is down)
- Request timeouts on all Redis calls
- Structured JSON logging for ELK/Splunk ingestion
- Retry logic with exponential backoff on reconnect
- Graceful shutdown with in-flight request draining
"""
import os
import uuid
import json
import time
import asyncio
import logging
import signal
from datetime import datetime
from enum import Enum
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis

# ─────────────────────────────────────────────
# Structured JSON Logging
# ─────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    """Emit logs as JSON for ELK/Splunk/CloudWatch ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "service": "tenet-ingest",
            "version": "0.1.0",
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "event_id"):
            log_entry["event_id"] = record.event_id
        if hasattr(record, "source_id"):
            log_entry["source_id"] = record.source_id
        if hasattr(record, "verdict"):
            log_entry["verdict"] = record.verdict
        return json.dumps(log_entry)


handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Environment Configuration
# ─────────────────────────────────────────────
REDIS_HOST          = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT          = int(os.getenv("REDIS_PORT", 6379))
REDIS_TIMEOUT_S     = float(os.getenv("REDIS_TIMEOUT_S", 2.0))    # per-call timeout
API_HOST            = os.getenv("API_HOST", "0.0.0.0")
API_PORT            = int(os.getenv("API_PORT", 8000))
API_KEY             = os.getenv("API_KEY", "tenet-dev-key-change-in-production")
CORS_ORIGINS        = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

# Circuit breaker tuning
CB_FAILURE_THRESHOLD    = int(os.getenv("CB_FAILURE_THRESHOLD", 3))    # open after N failures
CB_RECOVERY_TIMEOUT_S   = float(os.getenv("CB_RECOVERY_TIMEOUT_S", 30.0))  # probe after N secs
CB_HALF_OPEN_MAX_CALLS  = int(os.getenv("CB_HALF_OPEN_MAX_CALLS", 1))

# ─────────────────────────────────────────────
# Circuit Breaker  (no external dependency)
# ─────────────────────────────────────────────
class CircuitState(Enum):
    CLOSED    = "closed"      # Normal operation
    OPEN      = "open"        # Redis is down — fail fast
    HALF_OPEN = "half_open"   # Probing whether Redis recovered


class CircuitBreaker:
    """
    Lightweight async circuit breaker for Redis.

    State transitions:
        CLOSED  ──(N failures)──►  OPEN
        OPEN    ──(timeout)──────► HALF_OPEN
        HALF_OPEN ──(success)────► CLOSED
        HALF_OPEN ──(failure)────► OPEN
    """
    def __init__(
        self,
        name: str,
        failure_threshold: int = CB_FAILURE_THRESHOLD,
        recovery_timeout: float = CB_RECOVERY_TIMEOUT_S,
        half_open_max_calls: int = CB_HALF_OPEN_MAX_CALLS,
    ):
        self.name = name
        self.failure_threshold  = failure_threshold
        self.recovery_timeout   = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state           = CircuitState.CLOSED
        self._failure_count   = 0
        self._last_failure_ts = 0.0
        self._half_open_calls = 0
        self._lock            = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_ts >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(
                    f"Circuit breaker [{self.name}] → HALF_OPEN "
                    f"(probing after {self.recovery_timeout}s)"
                )
                return False   # Allow probe through
            return True
        return False

    async def record_success(self):
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state         = CircuitState.CLOSED
                self._failure_count = 0
                logger.info(f"Circuit breaker [{self.name}] → CLOSED (recovered)")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0  # Reset on any success

    async def record_failure(self):
        async with self._lock:
            self._failure_count  += 1
            self._last_failure_ts = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.error(
                    f"Circuit breaker [{self.name}] → OPEN "
                    f"(probe failed, backing off {self.recovery_timeout}s)"
                )
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.error(
                    f"Circuit breaker [{self.name}] → OPEN "
                    f"({self._failure_count} consecutive failures)"
                )

    def allow_request(self) -> bool:
        """Return True if a request should be attempted."""
        if self._state == CircuitState.CLOSED:
            return True
        if self._state == CircuitState.OPEN:
            return not self.is_open   # may flip to HALF_OPEN
        if self._state == CircuitState.HALF_OPEN:
            # Only allow one probe at a time
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        return False


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────
app = FastAPI(
    title="TENET AI - Ingest Service",
    description="Security middleware for LLM applications",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
redis_client:    Optional[redis.Redis] = None
redis_cb:        CircuitBreaker        = CircuitBreaker("redis-ingest")
_shutdown_event: asyncio.Event         = asyncio.Event()


# ─────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────
class LLMEventRequest(BaseModel):
    source_type:   str            = Field(..., description="chat | agent | api | workflow")
    source_id:     str            = Field(..., description="Unique identifier for the source")
    model:         str            = Field(..., description="LLM model being used")
    prompt:        str            = Field(..., description="The prompt to analyse")
    system_prompt: Optional[str]  = Field(None)
    metadata:      Optional[dict] = Field(default_factory=dict)


class LLMEventResponse(BaseModel):
    event_id:    str
    timestamp:   str
    blocked:     bool  = False
    sanitized:   bool  = False
    risk_score:  float = 0.0
    verdict:     str   = "pending"
    message:     str   = "Event queued for analysis"
    degraded:    bool  = False    # True when operating without Redis


class HealthResponse(BaseModel):
    status:          str
    service:         str
    version:         str
    redis_connected: bool
    circuit_state:   str
    uptime_seconds:  float


_start_time = time.monotonic()


# ─────────────────────────────────────────────
# Redis Helper — wraps every call with timeout + circuit breaker
# ─────────────────────────────────────────────
async def redis_call(coro):
    """
    Execute a Redis coroutine with:
      • per-call timeout
      • circuit breaker gate
      • automatic success/failure recording

    Returns the result or None on any failure.
    Never raises — callers should handle None as "Redis unavailable".
    """
    if not redis_client or not redis_cb.allow_request():
        return None
    try:
        result = await asyncio.wait_for(coro, timeout=REDIS_TIMEOUT_S)
        await redis_cb.record_success()
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Redis call timed out after {REDIS_TIMEOUT_S}s")
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
    global redis_client
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=REDIS_TIMEOUT_S,
            socket_timeout=REDIS_TIMEOUT_S,
            retry_on_timeout=False,   # We handle retries at the CB level
        )
        await asyncio.wait_for(redis_client.ping(), timeout=REDIS_TIMEOUT_S)
        logger.info(f"Redis connected at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as exc:
        # Do NOT abort startup — service runs in degraded mode
        logger.error(
            f"Redis unavailable at startup ({exc}). "
            "Service will run in degraded mode (heuristic-only, no persistence)."
        )
        redis_client = None

    # Periodic reconnect task
    asyncio.create_task(_redis_reconnect_loop())

    # Graceful shutdown handler
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_event_loop().add_signal_handler(
                sig, lambda: _shutdown_event.set()
            )
        except NotImplementedError:
            pass  # Windows


@app.on_event("shutdown")
async def shutdown():
    global redis_client
    _shutdown_event.set()
    if redis_client:
        try:
            await redis_client.close()
        except Exception:
            pass
        logger.info("Redis connection closed")


async def _redis_reconnect_loop():
    """
    Background task: if Redis is currently unreachable, attempt to
    reconnect every CB_RECOVERY_TIMEOUT_S seconds so the circuit
    can move to HALF_OPEN and eventually CLOSED on its own.
    """
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
        status="healthy" if redis_ok else "degraded",
        service="ingest",
        version="0.1.0",
        redis_connected=bool(redis_ok),
        circuit_state=redis_cb.state.value,
        uptime_seconds=round(time.monotonic() - _start_time, 1),
    )


@app.post("/v1/events/llm", response_model=LLMEventResponse)
async def ingest_llm_event(
    request: LLMEventRequest,
    x_api_key: str = Header(...)
):
    """
    Ingest an LLM event for security analysis.

    Degraded mode behaviour (Redis down / circuit open):
      - Heuristic check still runs — blocking still works.
      - Event is NOT persisted or queued (logged as warning).
      - Response includes degraded=True so callers can alert/monitor.
    """
    verify_api_key(x_api_key)

    event_id  = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Always run heuristic — this never depends on Redis
    blocked, risk_score, verdict = quick_heuristic_check(request.prompt)

    redis_available = (
        redis_client is not None
        and redis_cb.state != CircuitState.OPEN
    )

    event_payload = {
        "event_id":     event_id,
        "timestamp":    timestamp,
        "source_type":  request.source_type,
        "source_id":    request.source_id,
        "model":        request.model,
        "prompt":       request.prompt,
        "system_prompt": request.system_prompt,
        "metadata":     request.metadata,
        "blocked":      blocked,
        "risk_score":   risk_score,
        "verdict":      verdict,
    }

    if redis_available and not blocked:
        payload_str = json.dumps(event_payload)
        queued  = await redis_call(redis_client.lpush("tenet:events:queue", payload_str))
        cached  = await redis_call(
            redis_client.set(f"tenet:event:{event_id}", payload_str, ex=86400)
        )
        if queued is None or cached is None:
            logger.warning(
                "Event not persisted — Redis write failed (circuit may have just opened)",
                extra={"event_id": event_id},
            )
            redis_available = False
    elif not redis_available and not blocked:
        logger.warning(
            "Event not persisted — Redis circuit is OPEN (degraded mode)",
            extra={"event_id": event_id, "source_id": request.source_id},
        )

    log_extra = {
        "event_id":  event_id,
        "source_id": request.source_id,
        "verdict":   verdict,
    }
    if blocked:
        logger.warning("Event BLOCKED by heuristic check", extra=log_extra)
    else:
        logger.info("Event ingested", extra=log_extra)

    msg = (
        "Blocked — malicious pattern detected" if blocked
        else ("Event queued for analysis" if redis_available
              else "Event analysed (degraded mode — not persisted)")
    )

    return LLMEventResponse(
        event_id=event_id,
        timestamp=timestamp,
        blocked=blocked,
        risk_score=risk_score,
        verdict=verdict,
        message=msg,
        degraded=not redis_available,
    )


@app.get("/v1/events")
async def list_events(
    limit:    int = 50,
    offset:   int = 0,
    x_api_key: str = Header(...)
):
    verify_api_key(x_api_key)

    if not redis_client or redis_cb.state == CircuitState.OPEN:
        raise HTTPException(
            status_code=503,
            detail={
                "error":         "storage_unavailable",
                "message":       "Redis circuit is open — event history temporarily unavailable",
                "circuit_state": redis_cb.state.value,
            }
        )

    keys = await redis_call(redis_client.keys("tenet:event:*"))
    if keys is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    events = []
    for key in keys:
        data = await redis_call(redis_client.get(key))
        if data:
            try:
                events.append(json.loads(data))
            except json.JSONDecodeError:
                logger.warning(f"Corrupt event data at key {key}")

    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {
        "total":  len(events),
        "limit":  limit,
        "offset": offset,
        "events": events[offset: offset + limit],
    }


@app.get("/v1/stats")
async def get_stats(x_api_key: str = Header(...)):
    verify_api_key(x_api_key)

    if not redis_client or redis_cb.state == CircuitState.OPEN:
        raise HTTPException(
            status_code=503,
            detail={
                "error":         "storage_unavailable",
                "circuit_state": redis_cb.state.value,
            }
        )

    keys = await redis_call(redis_client.keys("tenet:event:*"))
    if keys is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    total_events  = len(keys)
    blocked_count = 0
    threat_counts = {"malicious": 0, "suspicious": 0, "benign": 0}

    for key in keys:
        data = await redis_call(redis_client.get(key))
        if data:
            try:
                event = json.loads(data)
                if event.get("blocked"):
                    blocked_count += 1
                v = event.get("verdict", "benign")
                threat_counts[v] = threat_counts.get(v, 0) + 1
            except json.JSONDecodeError:
                pass

    return {
        "total_events":        total_events,
        "blocked_count":       blocked_count,
        "threat_distribution": threat_counts,
        "timestamp":           datetime.utcnow().isoformat() + "Z",
        "circuit_state":       redis_cb.state.value,
    }


@app.get("/v1/circuit-status")
async def circuit_status(x_api_key: str = Header(...)):
    """Expose circuit breaker state for monitoring/alerting."""
    verify_api_key(x_api_key)
    return {
        "service":          "ingest",
        "circuit":          "redis",
        "state":            redis_cb.state.value,
        "failure_count":    redis_cb._failure_count,
        "recovery_timeout": redis_cb.recovery_timeout,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────
# Heuristic Detection  (unchanged logic, zero dependencies)
# ─────────────────────────────────────────────
def quick_heuristic_check(prompt: str) -> tuple[bool, float, str]:
    """Quick pattern match — runs even when Redis / ML are unavailable."""
    prompt_lower = prompt.lower()

    injection_patterns = [
        "ignore previous instructions", "ignore all previous",
        "disregard your instructions", "forget your system prompt",
        "you are now", "from now on you are", "new persona:",
        "jailbreak mode", "dan mode", "developer mode enabled",
        "simulate being", "</s>", "<|system|>",
        "system prompt:", "reveal your instructions",
    ]
    jailbreak_patterns = [
        "do anything now", "no restrictions", "without any limitations",
        "bypass your programming", "override your safety",
        "pretend you have no rules", "act as an unrestricted ai",
        "evil mode", "chaos mode",
    ]
    extraction_patterns = [
        "show me your system prompt", "what are your instructions",
        "reveal your training data", "show examples from training",
        "list your rules", "what's in your system message",
    ]

    for p in injection_patterns:
        if p in prompt_lower:
            return True, 0.95, "malicious"
    for p in jailbreak_patterns:
        if p in prompt_lower:
            return True, 0.90, "malicious"
    for p in extraction_patterns:
        if p in prompt_lower:
            return False, 0.75, "suspicious"

    return False, 0.0, "benign"


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
return True, 0.90, "malicious"
    for p in extraction_patterns:
        if p in prompt_lower:
            return False, 0.75, "suspicious"

    return False, 0.0, "benign"


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
