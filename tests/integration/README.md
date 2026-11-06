# TENET AI - Integration Test Suite

This directory contains end-to-end and integration tests that verify the full request/response lifecycle of the TENET AI Ingest and Analyzer APIs.

## Architecture & Test Strategy

TENET AI integration tests execute the complete ASGI request/response cycle using FastAPI's `TestClient` (backed by `httpx` and `starlette`). This tests:
- HTTP request parsing, headers, and body validation
- Middleware execution (including `correlation_id_middleware` and Prometheus metrics)
- Multi-tenant authentication and RBAC permission checks via `SecurityManager`
- Real-time heuristic and machine learning threat detection
- Redis queueing, event persistence, and stats aggregation
- HMAC-signed audit logging and export
- Graceful degradation modes when cache/storage services are unreachable

### Redis Backend Flexibility
Tests automatically detect whether a live Redis instance is available:
- **In CI or with local Redis (`localhost:6379`)**: Tests connect to the live Redis server and clean up test keys on teardown.
- **Without Redis running**: Tests automatically fall back to an in-memory `fakeredis.aioredis.FakeRedis` instance, ensuring tests run seamlessly and deterministically anywhere without external dependencies.

---

## Test Suites

| File | Scope |
|------|-------|
| `conftest.py` | Reusable fixtures: Redis backend, multi-tenant test keys/roles, `ingest_client`, `analyzer_client`, and auth headers. |
| `test_api_endpoints.py` | Full request/response tests for all Ingest endpoints (`/health`, `/v1/events/llm`, `/v1/events`, `/v1/events/{id}`, `/v1/stats`, `/v1/circuit-status`, `/v1/audit/export`) and Analyzer endpoints (`/health`, `/v1/analyze`). |
| `test_auth_rbac.py` | Authentication enforcement, invalid key rejection, blocked keys/orgs, RBAC permissions (`viewer`, `ingest`, `analyst`, `admin`), and cross-tenant data isolation. |
| `test_detection_payloads.py` | Detection accuracy with known prompt injection, jailbreak, data extraction, and legitimate benign payloads across both services. |
| `test_error_handling.py` | Edge cases: empty/whitespace prompts, oversized payloads (>10k chars), missing fields, malformed JSON, 404 lookups, pagination limits, correlation ID propagation, and graceful degradation when Redis is offline. |
| `test_rate_limiting.py` | Rate limiting enforcement: RPM limits, daily quotas, 429 Too Many Requests status codes, and multi-tenant rate limit isolation. |
| `test_e2e.py` | Live containerized end-to-end tests against external running services (`http://localhost:8000` and `http://localhost:8100`). Gracefully skips when external servers are not running. |

---

## Running Integration Tests Locally

### Prerequisites

Ensure you have development dependencies installed (including `fakeredis`, `pytest`, and `httpx` from `requirements-dev.txt`):
```bash
pip install -r requirements-dev.txt
```

### 1. Run Full Integration Test Suite

Run all integration tests with verbose output:
```bash
pytest tests/integration/ -v
```

### 2. Run with a Real Redis Instance (Optional)

If you have Docker installed, start a local Redis container:
```bash
docker run -d --name tenet-redis -p 6379:6379 redis:alpine
```
Then run the tests:
```bash
pytest tests/integration/ -v
```
When finished, stop the container:
```bash
docker stop tenet-redis && docker rm tenet-redis
```

### 3. Run Specific Test Suites

```bash
# Test all API endpoints
pytest tests/integration/test_api_endpoints.py -v

# Test authentication and RBAC permissions
pytest tests/integration/test_auth_rbac.py -v

# Test threat detection with known attack payloads
pytest tests/integration/test_detection_payloads.py -v

# Test error handling and edge cases
pytest tests/integration/test_error_handling.py -v

# Test rate limiting and quotas
pytest tests/integration/test_rate_limiting.py -v
```

### 4. Run with Coverage Report

```bash
pytest tests/integration/ --cov=services --cov-report=term-missing
```

---

## CI Pipeline Integration

Integration tests run automatically on pushes to `main` and `feature/*` branches, and on pull requests targeting `main` via `.github/workflows/ci.yml`. In GitHub Actions:
1. A Redis service container is started at `localhost:6379`.
2. Python dependencies are installed from `requirements-dev.txt` (including `fakeredis`).
3. Unit tests run (`pytest tests/unit/ -v`).
4. Backend services are launched and health-checked.
5. Integration tests run (`pytest tests/integration/ -v`) directly against the live Redis service container.

