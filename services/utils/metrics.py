import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware

# Define standard request metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# Define detection specific metrics
DETECTION_COUNT = Counter(
    "tenet_detections_total",
    "Total threats detected by type and verdict",
    ["service", "threat_type", "verdict"]
)

# Action Interposition metrics
ACTION_INGEST_COUNT = Counter(
    "tenet_action_events_ingested_total",
    "Total action events ingested",
    ["service", "provider", "status"],
)

ACTION_INGEST_DROPPED = Counter(
    "tenet_action_events_dropped_total",
    "Action events dropped (circuit breaker or storage failure)",
    ["service", "reason"],
)

ACTION_DUPLICATE_COUNT = Counter(
    "tenet_action_events_duplicate_total",
    "Duplicate action events suppressed by idempotency guard",
    ["service", "provider"],
)

ACTION_OBSERVED_COUNT = Counter(
    "tenet_action_observed_total",
    "Total action events processed and observed by analyzer",
    ["tool_name", "provider"],
)

ACTION_QUEUE_DEPTH = Gauge(
    "tenet_action_queue_depth",
    "Current depth of action event queues",
    ["queue"],
)

ACTION_OLDEST_EVENT_AGE = Gauge(
    "tenet_action_oldest_event_age_seconds",
    "Age of oldest unconsumed action event in seconds",
)

ACTION_OVERFLOW_DRAINED = Counter(
    "tenet_action_overflow_drained_total",
    "Total action events transferred from overflow to primary queue",
)

ACTION_OVERFLOW_DRAIN_FAILURES = Counter(
    "tenet_action_overflow_drain_failures_total",
    "Total failed attempts to drain overflow queue",
)

ACTION_QUEUE_SATURATED = Counter(
    "tenet_action_queue_saturated_total",
    "Total action events rejected due to capacity saturation (429)",
)


def increment_detection(service: str, threat_type: str, verdict: str) -> None:
    """Helper to increment detection counters."""
    if not threat_type:
        threat_type = "none"
    DETECTION_COUNT.labels(service=service, threat_type=threat_type, verdict=verdict).inc()


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware to collect basic HTTP metrics."""
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start_time = time.time()
        
        method = request.method
        try:
            response = await call_next(request)
            status_code = str(response.status_code)
            
            route = request.scope.get("route")
            endpoint = route.path if route else request.url.path
            
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(time.time() - start_time)
            
            return response
        except Exception:
            # If an unhandled exception occurs, assume 500 status code
            status_code = "500"
            route = request.scope.get("route")
            endpoint = route.path if route else request.url.path
            
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(time.time() - start_time)
            raise
