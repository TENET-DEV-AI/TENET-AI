"""
Integration tests for API Rate Limiting and Quotas.

Tests rate limiting (requests per minute) and daily quota limits across
the Ingest and Analyzer APIs, verifying 429 responses, error details,
and tenant key isolation.
"""

import pytest
from fastapi.testclient import TestClient


class TestRateLimiting:
    """Tests rate limit enforcement per API key and minute window."""

    def test_rpm_limit_enforced_on_ingest(
        self,
        ingest_client: TestClient,
        rate_limit_headers: dict[str, str]
    ):
        """Requests exceeding rpm_limit (configured to 3) return 429 Too Many Requests."""
        payload = {
            "source_type": "api",
            "source_id": "rate-tester",
            "model": "gpt-4",
            "prompt": "Rate limit test prompt"
        }

        # First 3 requests must succeed
        for i in range(3):
            resp = ingest_client.post("/v1/events/llm", headers=rate_limit_headers, json=payload)
            assert resp.status_code == 200, f"Request {i+1} failed unexpectedly: {resp.text}"

        # 4th request must be rate limited
        blocked_resp = ingest_client.post("/v1/events/llm", headers=rate_limit_headers, json=payload)
        assert blocked_resp.status_code == 429
        data = blocked_resp.json()
        assert "rate limit exceeded" in data["detail"].lower()

    def test_rpm_limit_enforced_on_analyzer(
        self,
        analyzer_client: TestClient,
        rate_limit_headers: dict[str, str]
    ):
        """Requests to Analyzer exceeding rpm_limit return 429."""
        payload = {"prompt": "Analyze rate limit prompt"}

        # First 3 requests succeed
        for i in range(3):
            resp = analyzer_client.post("/v1/analyze", headers=rate_limit_headers, json=payload)
            assert resp.status_code == 200, f"Request {i+1} failed: {resp.text}"

        # 4th request hits rate limit
        blocked_resp = analyzer_client.post("/v1/analyze", headers=rate_limit_headers, json=payload)
        assert blocked_resp.status_code == 429
        assert "rate limit exceeded" in blocked_resp.json()["detail"].lower()

    def test_rate_limit_key_isolation(
        self,
        ingest_client: TestClient,
        rate_limit_headers: dict[str, str],
        admin_headers: dict[str, str]
    ):
        """Exhausting the rate limit on one key does not affect other keys."""
        payload = {
            "source_type": "api",
            "source_id": "isolation-test",
            "model": "gpt-4",
            "prompt": "Test isolation"
        }

        # Exhaust rate_limit_headers (rpm_limit=3)
        for _ in range(3):
            ingest_client.post("/v1/events/llm", headers=rate_limit_headers, json=payload)
        assert ingest_client.post("/v1/events/llm", headers=rate_limit_headers, json=payload).status_code == 429

        # admin_headers (rpm_limit=100) must still succeed
        admin_resp = ingest_client.post("/v1/events/llm", headers=admin_headers, json=payload)
        assert admin_resp.status_code == 200


class TestDailyQuota:
    """Tests daily quota limit enforcement per API key."""

    def test_daily_quota_enforced(
        self,
        ingest_client: TestClient,
        quota_limit_headers: dict[str, str]
    ):
        """Requests exceeding daily_quota (configured to 2) return 429."""
        payload = {
            "source_type": "api",
            "source_id": "quota-tester",
            "model": "gpt-4",
            "prompt": "Daily quota test prompt"
        }

        # Request 1 & 2 succeed
        assert ingest_client.post("/v1/events/llm", headers=quota_limit_headers, json=payload).status_code == 200
        assert ingest_client.post("/v1/events/llm", headers=quota_limit_headers, json=payload).status_code == 200

        # Request 3 exceeds quota
        exceeded_resp = ingest_client.post("/v1/events/llm", headers=quota_limit_headers, json=payload)
        assert exceeded_resp.status_code == 429
        assert "daily quota exceeded" in exceeded_resp.json()["detail"].lower()

