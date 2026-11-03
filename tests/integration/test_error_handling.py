"""
Integration tests for Error Handling, Edge Cases, and Degradation Modes.

Tests API input validation, boundaries, malformed requests, correlation ID
middleware propagation, 404 lookups, and graceful degradation behavior.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
import services.ingest.app as ingest_mod


class TestValidationErrorsAndBoundaries:
    """Tests input validation, missing parameters, and boundary limits."""

    def test_empty_prompt_rejected(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Empty prompt string is rejected with 422."""
        resp = ingest_client.post(
            "/v1/events/llm",
            headers=admin_headers,
            json={
                "source_type": "api",
                "source_id": "test",
                "model": "gpt-4",
                "prompt": ""
            }
        )
        assert resp.status_code == 422

    def test_whitespace_prompt_rejected(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Whitespace-only prompt string is rejected with 422."""
        resp = ingest_client.post(
            "/v1/events/llm",
            headers=admin_headers,
            json={
                "source_type": "api",
                "source_id": "test",
                "model": "gpt-4",
                "prompt": "   \n\t   "
            }
        )
        assert resp.status_code == 422
        assert "empty or whitespace" in resp.json()["detail"].lower()

    def test_analyzer_empty_prompt_rejected(self, analyzer_client: TestClient, admin_headers: dict[str, str]):
        """Analyzer rejects empty prompt with 422."""
        resp = analyzer_client.post(
            "/v1/analyze",
            headers=admin_headers,
            json={"prompt": ""}
        )
        assert resp.status_code == 422

    def test_oversized_prompt_rejected(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        admin_headers: dict[str, str]
    ):
        """Prompts exceeding 10,000 characters are rejected with 422."""
        oversized = "A" * 10001

        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=admin_headers,
            json={
                "source_type": "api",
                "source_id": "test",
                "model": "gpt-4",
                "prompt": oversized
            }
        )
        assert resp_ingest.status_code == 422

        resp_analyzer = analyzer_client.post(
            "/v1/analyze",
            headers=admin_headers,
            json={"prompt": oversized}
        )
        assert resp_analyzer.status_code == 422

    @pytest.mark.parametrize("missing_field", ["source_type", "source_id", "model", "prompt"])
    def test_missing_required_fields_rejected(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str],
        missing_field: str
    ):
        """Omitting any mandatory request body field returns 422."""
        payload = {
            "source_type": "api",
            "source_id": "test-src",
            "model": "gpt-4",
            "prompt": "Hello"
        }
        del payload[missing_field]

        resp = ingest_client.post("/v1/events/llm", headers=admin_headers, json=payload)
        assert resp.status_code == 422

    def test_malformed_json_rejected(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Non-JSON or malformed bodies return 422 Unprocessable Entity."""
        headers = dict(admin_headers)
        headers["Content-Type"] = "application/json"
        resp = ingest_client.post("/v1/events/llm", headers=headers, content="{not valid json}")
        assert resp.status_code == 422


class TestResourceLookupsAndPagination:
    """Tests 404 errors on missing entities and pagination range validations."""

    def test_nonexistent_event_returns_404(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Querying an unknown event ID returns 404."""
        resp = ingest_client.get("/v1/events/00000000-0000-0000-0000-000000000000", headers=admin_headers)
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_empty_event_id_rejected(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Querying a blank event_id returns 422."""
        resp = ingest_client.get("/v1/events/%20", headers=admin_headers)
        assert resp.status_code == 422

    def test_invalid_pagination_bounds(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Out of bounds limit (<1 or >500) or offset (<0) returns 422."""
        # limit < 1
        assert ingest_client.get("/v1/events?limit=0", headers=admin_headers).status_code == 422
        # limit > 500
        assert ingest_client.get("/v1/events?limit=501", headers=admin_headers).status_code == 422
        # offset < 0
        assert ingest_client.get("/v1/events?offset=-1", headers=admin_headers).status_code == 422

    def test_invalid_audit_export_bounds(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Audit export limit boundary checks (<1 or >2000)."""
        assert ingest_client.get("/v1/audit/export?limit=0", headers=admin_headers).status_code == 422
        assert ingest_client.get("/v1/audit/export?limit=2001", headers=admin_headers).status_code == 422


class TestCorrelationIdMiddleware:
    """Tests correlation ID extraction and injection across HTTP requests."""

    def test_custom_correlation_id_propagated(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """Custom X-Correlation-ID header provided by client is preserved in response."""
        custom_id = "test-corr-id-12345-abcde"
        headers = dict(admin_headers)
        headers["X-Correlation-ID"] = custom_id

        resp = ingest_client.get("/health", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-Correlation-ID") == custom_id

    def test_generated_correlation_id_when_omitted(self, ingest_client: TestClient, admin_headers: dict[str, str]):
        """When client omits X-Correlation-ID, a new UUID is generated and returned."""
        resp = ingest_client.get("/health", headers=admin_headers)
        assert resp.status_code == 200
        corr_id = resp.headers.get("X-Correlation-ID")
        assert corr_id is not None
        assert len(corr_id) > 10


class TestGracefulDegradation:
    """Tests system resilience when Redis is disconnected or circuit breaker is tripped."""

    def test_ingest_gracefully_degrades_when_redis_down(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str]
    ):
        """When Redis is None, /v1/events/llm returns 200 with degraded=True."""
        orig_client = ingest_mod.redis_client
        try:
            ingest_mod.redis_client = None

            resp = ingest_client.post(
                "/v1/events/llm",
                headers=admin_headers,
                json={
                    "source_type": "api",
                    "source_id": "degraded-test",
                    "model": "gpt-4",
                    "prompt": "Test prompt in degraded mode"
                }
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["degraded"] is True
            assert "event_id" in data
            assert data["verdict"] == "benign"
        finally:
            ingest_mod.redis_client = orig_client

    def test_event_store_endpoints_return_503_when_redis_down(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str]
    ):
        """When Redis is None, read endpoints that require Redis return 503."""
        orig_client = ingest_mod.redis_client
        try:
            ingest_mod.redis_client = None

            # List events
            resp_list = ingest_client.get("/v1/events", headers=admin_headers)
            assert resp_list.status_code == 503
            assert "degraded" in resp_list.json()["detail"].lower()

            # Get event
            resp_get = ingest_client.get("/v1/events/any-id", headers=admin_headers)
            assert resp_get.status_code == 503

            # Stats
            resp_stats = ingest_client.get("/v1/stats", headers=admin_headers)
            assert resp_stats.status_code == 503
        finally:
            ingest_mod.redis_client = orig_client

