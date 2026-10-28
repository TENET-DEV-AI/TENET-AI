"""
Unit tests for the SecurityManager (multi-tenant auth, RBAC, quotas, audit log).
"""
import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from services.security.tenant_security import AuthContext, SecurityManager


class TestSecurityManagerInit:
    """Tests for SecurityManager initialization and configuration loading."""

    def test_invalid_api_keys_json_malformed(self, monkeypatch):
        monkeypatch.setenv("TENET_API_KEYS_JSON", "{invalid-json")
        with pytest.raises(RuntimeError, match="Invalid TENET_API_KEYS_JSON"):
            SecurityManager("test-service")

    def test_invalid_api_keys_json_not_a_dict(self, monkeypatch):
        monkeypatch.setenv("TENET_API_KEYS_JSON", '["key1", "key2"]')
        with pytest.raises(RuntimeError, match="Invalid TENET_API_KEYS_JSON"):
            SecurityManager("test-service")

    def test_valid_custom_api_keys_json(self, monkeypatch):
        custom_keys = {
            "custom-secret": {
                "org_id": "custom-org",
                "key_id": "key-custom",
                "role": "analyst",
                "rpm_limit": 60,
                "daily_quota": 1000,
            }
        }
        monkeypatch.setenv("TENET_API_KEYS_JSON", json.dumps(custom_keys))
        sm = SecurityManager("test-service")
        assert "custom-secret" in sm.keys_config
        assert sm.keys_config["custom-secret"]["org_id"] == "custom-org"


class TestSecurityManagerAuth:
    """Tests for authentication, RBAC, and blocked entities."""

    @pytest.mark.asyncio
    async def test_invalid_key_raises_401(self):
        sm = SecurityManager("test-service")
        with pytest.raises(HTTPException) as exc:
            await sm.require_auth("unknown-key", "read")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_blocked_org_raises_403(self, monkeypatch):
        monkeypatch.setenv("BLOCKED_ORGS", "blocked-org,other-org")
        sm = SecurityManager("test-service")
        sm.keys_config["blocked-key"] = {
            "org_id": "blocked-org",
            "key_id": "key-1",
            "role": "admin",
            "permissions": ["read"],
        }
        with pytest.raises(HTTPException) as exc:
            await sm.require_auth("blocked-key", "read")
        assert exc.value.status_code == 403
        assert "blocked" in exc.value.detail

    @pytest.mark.asyncio
    async def test_blocked_key_id_raises_403(self, monkeypatch):
        monkeypatch.setenv("BLOCKED_KEY_IDS", "revoked-key-id")
        sm = SecurityManager("test-service")
        sm.keys_config["bad-key"] = {
            "org_id": "test-org",
            "key_id": "revoked-key-id",
            "role": "admin",
            "permissions": ["read"],
        }
        with pytest.raises(HTTPException) as exc:
            await sm.require_auth("bad-key", "read")
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_insufficient_permissions_raises_403(self):
        sm = SecurityManager("test-service")
        sm.keys_config["viewer-key"] = {
            "org_id": "test-org",
            "key_id": "v1",
            "role": "viewer",
            "permissions": ["read"],
        }
        with pytest.raises(HTTPException) as exc:
            await sm.require_auth("viewer-key", "admin")
        assert exc.value.status_code == 403
        assert "Insufficient permissions" in exc.value.detail

    @pytest.mark.asyncio
    async def test_valid_auth_success(self, monkeypatch):
        test_key = "test-isolated-key"
        monkeypatch.setenv("API_KEY", test_key)
        monkeypatch.delenv("TENET_API_KEYS_JSON", raising=False)
        sm = SecurityManager("test-service")
        context = await sm.require_auth(test_key, "read")
        assert isinstance(context, AuthContext)
        assert "read" in context.permissions


class TestRateLimitingAndQuotas:
    """Tests for in-memory and Redis-backed rate limiting and daily quotas."""

    @pytest.mark.asyncio
    async def test_memory_rate_limit_exceeded(self):
        sm = SecurityManager("test-service")
        context = AuthContext(
            org_id="test-org", key_id="key-rate", role="admin",
            permissions={"read"}, rpm_limit=2, daily_quota=100
        )
        await sm._enforce_rate_limit(context)
        await sm._enforce_rate_limit(context)

        with pytest.raises(HTTPException) as exc:
            await sm._enforce_rate_limit(context)
        assert exc.value.status_code == 429
        assert "Rate limit exceeded" in exc.value.detail

    @pytest.mark.asyncio
    async def test_memory_daily_quota_exceeded(self):
        sm = SecurityManager("test-service")
        context = AuthContext(
            org_id="test-org", key_id="key-quota", role="admin",
            permissions={"read"}, rpm_limit=100, daily_quota=2
        )
        await sm._enforce_daily_quota(context)
        await sm._enforce_daily_quota(context)

        with pytest.raises(HTTPException) as exc:
            await sm._enforce_daily_quota(context)
        assert exc.value.status_code == 429
        assert "Daily quota exceeded" in exc.value.detail

    def test_memory_counter_expiration(self):
        sm = SecurityManager("test-service")
        store = {}
        store["test-key"] = (5, int(time.time()) - 10)

        count = sm._increment_memory_counter("test-key", ttl=60, store=store)
        assert count == 1
        assert store["test-key"][1] > int(time.time())

    @pytest.mark.asyncio
    async def test_redis_counter_first_call_sets_expire(self):
        mock_redis = MagicMock()
        mock_redis.incr = MagicMock(return_value="incr-coro")
        mock_redis.expire = MagicMock(return_value="expire-coro")

        async def mock_call(coro):
            if coro == "incr-coro":
                return 1
            return True

        sm = SecurityManager(
            service_name="test-service",
            redis_call=mock_call,
            redis_client_getter=lambda: mock_redis,
        )

        count = await sm._increment_counter("key", 100, {})
        assert count == 1
        mock_redis.expire.assert_called_once_with("key", 100)

    @pytest.mark.asyncio
    async def test_redis_counter_fallback_on_none_or_bad_type(self):
        mock_redis = MagicMock()

        sm1 = SecurityManager(
            service_name="test-service",
            redis_call=AsyncMock(return_value=None),
            redis_client_getter=lambda: mock_redis,
        )
        count1 = await sm1._increment_counter("key", 100, {})
        assert count1 == 1

        sm2 = SecurityManager(
            service_name="test-service",
            redis_call=AsyncMock(return_value="not-an-int"),
            redis_client_getter=lambda: mock_redis,
        )
        count2 = await sm2._increment_counter("key", 100, {})
        assert count2 == 1


class TestAuditLogging:
    """Tests for HMAC audit trail generation and exporting."""

    def test_audit_record_chaining(self, tmp_path):
        audit_file = tmp_path / "test_audit.log"
        sm = SecurityManager("test-service")
        sm.audit_log_path = audit_file

        rec1 = sm.audit(action="login", result="success")
        assert rec1["prev_hash"] == "0" * 64
        assert "hash" in rec1

        expected_sig = hmac.new(
            sm.audit_secret.encode("utf-8"),
            rec1["hash"].encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert hmac.compare_digest(rec1["signature"], expected_sig)

        rec2 = sm.audit(action="query", result="success")
        assert rec2["prev_hash"] == rec1["hash"]

    def test_export_audit_records_nonexistent_file(self, tmp_path):
        sm = SecurityManager("test-service")
        sm.audit_log_path = tmp_path / "does_not_exist.log"
        assert sm.export_audit_records("any-org") == []

    def test_export_audit_records_filters_and_skips_bad_lines(self, tmp_path):
        audit_file = tmp_path / "audit.log"
        sm = SecurityManager("test-service")
        sm.audit_log_path = audit_file

        lines = [
            json.dumps({"org_id": "org-a", "action": "act-1"}),
            "   ",
            "{broken-json",
            json.dumps({"org_id": "org-b", "action": "act-2"}),
            json.dumps({"org_id": "org-a", "action": "act-3"}),
        ]
        audit_file.write_text("\n".join(lines))

        records = sm.export_audit_records("org-a", limit=10)
        assert len(records) == 2
        assert records[0]["action"] == "act-1"
        assert records[1]["action"] == "act-3"
