"""
Integration tests for Authentication, RBAC, and Tenant Isolation.

Tests the full authentication and authorization flow across the Ingest
and Analyzer APIs, verifying role permissions, key/org blocking, and
strict multi-tenant boundary isolation.
"""

import pytest
from fastapi.testclient import TestClient


class TestAuthenticationFlows:
    """Tests for API key authentication on Ingest and Analyzer endpoints."""

    def test_missing_api_key_rejected(self, ingest_client: TestClient, analyzer_client: TestClient):
        """Test requests lacking an API key header are rejected."""
        # Ingest endpoint uses Security(api_key_scheme) -> 401
        ingest_resp = ingest_client.post(
            "/v1/events/llm",
            json={
                "source_type": "api",
                "source_id": "anon",
                "model": "gpt-4",
                "prompt": "Test missing key"
            }
        )
        assert ingest_resp.status_code == 401

        # Analyzer endpoint requires Header(...) -> 422 unprocessable entity
        analyzer_resp = analyzer_client.post(
            "/v1/analyze",
            json={"prompt": "Test missing key"}
        )
        assert analyzer_resp.status_code == 422

    def test_invalid_api_key_rejected(self, ingest_client: TestClient, analyzer_client: TestClient):
        """Test unknown or invalid API keys return 401 Unauthorized."""
        bad_headers = {"X-API-Key": "completely-invalid-key-xyz"}

        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=bad_headers,
            json={
                "source_type": "api",
                "source_id": "anon",
                "model": "gpt-4",
                "prompt": "Hello"
            }
        )
        assert resp_ingest.status_code == 401
        assert "Invalid API key" in resp_ingest.json()["detail"]

        resp_analyzer = analyzer_client.post(
            "/v1/analyze",
            headers=bad_headers,
            json={"prompt": "Hello"}
        )
        assert resp_analyzer.status_code == 401
        assert "Invalid API key" in resp_analyzer.json()["detail"]

    def test_blocked_api_key_forbidden(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        blocked_key_headers: dict[str, str]
    ):
        """Test explicitly blocked API key IDs return 403 Forbidden."""
        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=blocked_key_headers,
            json={
                "source_type": "api",
                "source_id": "blocked-user",
                "model": "gpt-4",
                "prompt": "Hello"
            }
        )
        assert resp_ingest.status_code == 403
        assert "blocked" in resp_ingest.json()["detail"].lower()

        resp_analyzer = analyzer_client.post(
            "/v1/analyze",
            headers=blocked_key_headers,
            json={"prompt": "Hello"}
        )
        assert resp_analyzer.status_code == 403
        assert "blocked" in resp_analyzer.json()["detail"].lower()

    def test_blocked_org_forbidden(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        blocked_org_headers: dict[str, str]
    ):
        """Test API keys belonging to blocked organizations return 403 Forbidden."""
        resp_ingest = ingest_client.get("/v1/events", headers=blocked_org_headers)
        assert resp_ingest.status_code == 403
        assert "blocked" in resp_ingest.json()["detail"].lower()

        resp_analyzer = analyzer_client.post(
            "/v1/analyze",
            headers=blocked_org_headers,
            json={"prompt": "Hello"}
        )
        assert resp_analyzer.status_code == 403
        assert "blocked" in resp_analyzer.json()["detail"].lower()


class TestRoleBasedAccessControl:
    """Tests for role-based permissions (viewer, ingest, analyst, admin)."""

    def test_viewer_role_permissions(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        viewer_headers: dict[str, str]
    ):
        """Viewer role has 'read' permission: allowed for reads, denied for ingest/analyze/admin."""
        # Allowed reads
        assert ingest_client.get("/v1/events", headers=viewer_headers).status_code == 200
        assert ingest_client.get("/v1/stats", headers=viewer_headers).status_code == 200
        assert ingest_client.get("/v1/circuit-status", headers=viewer_headers).status_code == 200

        # Denied ingest
        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=viewer_headers,
            json={
                "source_type": "api",
                "source_id": "viewer-user",
                "model": "gpt-4",
                "prompt": "Hello"
            }
        )
        assert resp_ingest.status_code == 403
        assert "Insufficient permissions" in resp_ingest.json()["detail"]

        # Denied analyze
        resp_analyze = analyzer_client.post(
            "/v1/analyze",
            headers=viewer_headers,
            json={"prompt": "Hello"}
        )
        assert resp_analyze.status_code == 403
        assert "Insufficient permissions" in resp_analyze.json()["detail"]

        # Denied admin audit export
        resp_export = ingest_client.get("/v1/audit/export", headers=viewer_headers)
        assert resp_export.status_code == 403

    def test_ingest_role_permissions(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        ingest_headers: dict[str, str]
    ):
        """Ingest role has 'read', 'ingest', 'analyze': denied for admin export."""
        # Allowed ingest
        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=ingest_headers,
            json={
                "source_type": "api",
                "source_id": "ingest-user",
                "model": "gpt-4",
                "prompt": "Hello world"
            }
        )
        assert resp_ingest.status_code == 200

        # Allowed analyze
        assert analyzer_client.post(
            "/v1/analyze",
            headers=ingest_headers,
            json={"prompt": "Hello"}
        ).status_code == 200

        # Allowed read
        assert ingest_client.get("/v1/events", headers=ingest_headers).status_code == 200

        # Denied admin audit export
        assert ingest_client.get("/v1/audit/export", headers=ingest_headers).status_code == 403

    def test_analyst_role_permissions(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        analyst_headers: dict[str, str]
    ):
        """Analyst role has 'read', 'analyze': denied for event ingest and admin export."""
        # Allowed analyze
        assert analyzer_client.post(
            "/v1/analyze",
            headers=analyst_headers,
            json={"prompt": "Hello"}
        ).status_code == 200

        # Allowed read
        assert ingest_client.get("/v1/events", headers=analyst_headers).status_code == 200

        # Denied ingest
        resp_ingest = ingest_client.post(
            "/v1/events/llm",
            headers=analyst_headers,
            json={
                "source_type": "api",
                "source_id": "analyst-user",
                "model": "gpt-4",
                "prompt": "Hello"
            }
        )
        assert resp_ingest.status_code == 403

        # Denied admin audit export
        assert ingest_client.get("/v1/audit/export", headers=analyst_headers).status_code == 403

    def test_admin_role_permissions(
        self,
        ingest_client: TestClient,
        analyzer_client: TestClient,
        admin_headers: dict[str, str]
    ):
        """Admin role has all permissions including audit export."""
        assert ingest_client.get("/v1/audit/export", headers=admin_headers).status_code == 200
        assert analyzer_client.post(
            "/v1/analyze",
            headers=admin_headers,
            json={"prompt": "Admin analysis"}
        ).status_code == 200


class TestTenantIsolation:
    """Tests ensuring strict multi-tenant data isolation between organizations."""

    def test_cross_tenant_event_isolation(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str],
        secondary_headers: dict[str, str]
    ):
        """Events created by Org A cannot be read or retrieved by Org B."""
        # 1. Org A creates an event
        post_resp = ingest_client.post(
            "/v1/events/llm",
            headers=admin_headers,
            json={
                "source_type": "api",
                "source_id": "org-primary-user",
                "model": "gpt-4",
                "prompt": "Org Primary proprietary prompt"
            }
        )
        assert post_resp.status_code == 200
        event_id = post_resp.json()["event_id"]

        # 2. Org A can retrieve it
        get_a = ingest_client.get(f"/v1/events/{event_id}", headers=admin_headers)
        assert get_a.status_code == 200
        assert get_a.json()["event_id"] == event_id

        # 3. Org B attempts to retrieve Org A's event -> 404 Not Found
        get_b = ingest_client.get(f"/v1/events/{event_id}", headers=secondary_headers)
        assert get_b.status_code == 404

        # 4. Org B lists events -> Org A's event is not in the list
        list_b = ingest_client.get("/v1/events", headers=secondary_headers)
        assert list_b.status_code == 200
        org_b_event_ids = [ev["event_id"] for ev in list_b.json()["events"]]
        assert event_id not in org_b_event_ids

    def test_cross_tenant_stats_isolation(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str],
        secondary_headers: dict[str, str]
    ):
        """Stats for Org B do not count Org A's events."""
        # Ingest event for Org A
        ingest_client.post(
            "/v1/events/llm",
            headers=admin_headers,
            json={
                "source_type": "api",
                "source_id": "org-a-item",
                "model": "gpt-4",
                "prompt": "Org A item"
            }
        )

        # Ingest event for Org B
        ingest_client.post(
            "/v1/events/llm",
            headers=secondary_headers,
            json={
                "source_type": "api",
                "source_id": "org-b-item",
                "model": "gpt-4",
                "prompt": "Org B item"
            }
        )

        stats_b = ingest_client.get("/v1/stats", headers=secondary_headers).json()
        # Org B should only see its own events
        assert stats_b["total_events"] == 1

    def test_cross_tenant_audit_isolation(
        self,
        ingest_client: TestClient,
        admin_headers: dict[str, str],
        secondary_headers: dict[str, str]
    ):
        """Audit log exports for Org B only contain Org B's records."""
        # Trigger an action under Org B
        post_resp = ingest_client.post(
            "/v1/events/llm",
            headers=secondary_headers,
            json={
                "source_type": "api",
                "source_id": "org-b-audit",
                "model": "gpt-4",
                "prompt": "Audited prompt under Org B"
            }
        )
        assert post_resp.status_code == 200
        event_id = post_resp.json()["event_id"]

        export_resp = ingest_client.get("/v1/audit/export", headers=secondary_headers)
        assert export_resp.status_code == 200
        export_b = export_resp.json()
        assert export_b["org_id"] == "org-secondary"
        assert len(export_b["records"]) > 0
        assert any(rec.get("metadata", {}).get("event_id") == event_id for rec in export_b["records"])
        for rec in export_b["records"]:
            assert rec.get("org_id") == "org-secondary"

