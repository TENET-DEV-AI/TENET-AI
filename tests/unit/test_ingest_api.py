"""
Unit tests for the Ingest service CircuitBreaker, endpoints, and helpers.
"""
import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from services.ingest.app import (
    CircuitBreaker,
    CircuitState,
    app,
    circuit_status,
    export_audit_logs,
    get_event,
    get_stats,
    list_events,
    redis_call,
    shutdown,
    startup,
)
from services.security.tenant_security import AuthContext

client = TestClient(app)
VALID_API_KEY = "tenet-dev-key-change-in-production"


@pytest.fixture(autouse=True)
def isolate_ingest_globals():
    """Ensure tests do not leak mutated globals to subsequent tests."""
    import services.ingest.app as app_mod

    orig_redis = app_mod.redis_client
    orig_shutdown = app_mod._shutdown_event
    app_mod._shutdown_event = asyncio.Event()
    try:
        yield
    finally:
        app_mod.redis_client = orig_redis
        app_mod._shutdown_event = orig_shutdown


class TestCircuitBreaker:
    """Comprehensive tests for the CircuitBreaker state machine."""

    def test_initial_state(self):
        cb = CircuitBreaker("test-cb", failure_threshold=2, recovery_timeout=0.1, half_open_max_calls=1)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    @pytest.mark.asyncio
    async def test_transitions_to_open_on_threshold(self):
        cb = CircuitBreaker("test-cb", failure_threshold=2, recovery_timeout=0.1, half_open_max_calls=1)
        await cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    @pytest.mark.asyncio
    async def test_transitions_to_half_open_after_recovery(self):
        cb = CircuitBreaker("test-cb", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=1)
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

        # Wait for recovery timeout to pass
        time.sleep(0.06)
        # The transition call is counted as the probe call (_half_open_calls = 1)
        assert cb.allow_request() is True
        assert cb.state == CircuitState.HALF_OPEN

        # Further calls in HALF_OPEN are rejected once half_open_max_calls is reached
        assert cb.allow_request() is False

    @pytest.mark.asyncio
    async def test_half_open_success_closes_circuit(self):
        cb = CircuitBreaker("test-cb", failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=1)
        await cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # transitions to HALF_OPEN

        await cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_circuit(self):
        cb = CircuitBreaker("test-cb", failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=1)
        await cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # transitions to HALF_OPEN

        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False


class TestRedisCallGuard:
    """Tests for redis_call timeout and circuit breaker protection."""

    @pytest.mark.asyncio
    async def test_redis_call_no_client(self):
        async def dummy_coro():
            return None

        coro = dummy_coro()
        with patch("services.ingest.app.redis_client", None):
            result = await redis_call(coro)
            assert result is None
        coro.close()

    @pytest.mark.asyncio
    async def test_redis_call_circuit_open(self):
        mock_client = MagicMock()
        mock_cb = MagicMock()
        mock_cb.allow_request.return_value = False

        async def dummy_coro():
            return None

        coro = dummy_coro()
        with patch("services.ingest.app.redis_client", mock_client), \
             patch("services.ingest.app.redis_cb", mock_cb):
            result = await redis_call(coro)
            assert result is None
        coro.close()

    @pytest.mark.asyncio
    async def test_redis_call_success(self):
        mock_client = MagicMock()
        mock_cb = MagicMock()
        mock_cb.allow_request.return_value = True
        mock_cb.record_success = AsyncMock()

        async def dummy_coro():
            return "redis-value"

        with patch("services.ingest.app.redis_client", mock_client), \
             patch("services.ingest.app.redis_cb", mock_cb):
            result = await redis_call(dummy_coro())
            assert result == "redis-value"
            mock_cb.record_success.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_redis_call_timeout(self):
        mock_client = MagicMock()
        mock_cb = MagicMock()
        mock_cb.allow_request.return_value = True
        mock_cb.record_failure = AsyncMock()

        async def slow_coro():
            await asyncio.sleep(1.0)
            return "late"

        with patch("services.ingest.app.redis_client", mock_client), \
             patch("services.ingest.app.redis_cb", mock_cb), \
             patch("services.ingest.app.REDIS_TIMEOUT_S", 0.01):
            result = await redis_call(slow_coro())
            assert result is None
            mock_cb.record_failure.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_redis_call_generic_exception(self):
        mock_client = MagicMock()
        mock_cb = MagicMock()
        mock_cb.allow_request.return_value = True
        mock_cb.record_failure = AsyncMock()

        async def failing_coro():
            raise ConnectionResetError("Connection dropped")

        with patch("services.ingest.app.redis_client", mock_client), \
             patch("services.ingest.app.redis_cb", mock_cb):
            result = await redis_call(failing_coro())
            assert result is None
            mock_cb.record_failure.assert_awaited_once()


class TestIngestLifecycle:
    """Tests for ingest startup and shutdown handlers."""

    @pytest.mark.asyncio
    async def test_startup_redis_down(self):
        with patch("services.ingest.app.load_config"), \
             patch("services.ingest.app.redis.Redis") as mock_redis_cls, \
             patch("services.ingest.app._redis_reconnect_loop", return_value=None):
            mock_redis = MagicMock()
            mock_redis.ping = AsyncMock(side_effect=ConnectionError("Down"))
            mock_redis_cls.return_value = mock_redis

            await startup()

            import services.ingest.app as app_mod
            assert app_mod.redis_client is None

    @pytest.mark.asyncio
    async def test_startup_redis_connected(self):
        with patch("services.ingest.app.load_config"), \
             patch("services.ingest.app.redis.Redis") as mock_redis_cls, \
             patch("services.ingest.app._redis_reconnect_loop", return_value=None), \
             patch("services.ingest.app.redis_client", None):
            mock_redis = MagicMock()
            mock_redis.ping = AsyncMock(return_value=True)
            mock_redis_cls.return_value = mock_redis

            await startup()

            import services.ingest.app as app_mod
            assert app_mod.redis_client is mock_redis

    @pytest.mark.asyncio
    async def test_shutdown(self):
        import services.ingest.app as app_mod
        mock_redis = MagicMock()
        mock_redis.close = AsyncMock()

        app_mod._shutdown_event.clear()
        try:
            with patch("services.ingest.app.redis_client", mock_redis):
                await shutdown()
                assert app_mod._shutdown_event.is_set()
                mock_redis.close.assert_awaited_once()
        finally:
            app_mod._shutdown_event.clear()


class TestIngestEndpoints:
    """Tests for list_events, get_event, get_stats, circuit_status, export_audit_logs."""

    @pytest.mark.asyncio
    async def test_list_events_degraded(self):
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock), \
             patch("services.ingest.app.redis_client", None):
            with pytest.raises(HTTPException) as exc:
                await list_events()
            assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_list_events_redis_call_none(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", MagicMock()), \
             patch("services.ingest.app.redis_call", new_callable=AsyncMock, return_value=None):
            with pytest.raises(HTTPException) as exc:
                await list_events()
            assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_list_events_success(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        mock_events = [
            json.dumps({"event_id": "e1", "org_id": "test-org", "timestamp": "2026-01-01T10:00:00"}),
            json.dumps({"event_id": "e2", "org_id": "other-org", "timestamp": "2026-01-01T11:00:00"}),
            json.dumps({"event_id": "e3", "org_id": "test-org", "timestamp": "2026-01-01T12:00:00"}),
        ]

        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", MagicMock()):
            side_effects = [
                ["tenet:event:e1", "tenet:event:e2", "tenet:event:e3"],
                mock_events[0],
                mock_events[1],
                mock_events[2],
            ]
            with patch("services.ingest.app.redis_call", new_callable=AsyncMock, side_effect=side_effects):
                res = await list_events(limit=10, offset=0)
                assert res["total"] == 2
                assert len(res["events"]) == 2
                assert res["events"][0]["event_id"] == "e3"

    @pytest.mark.asyncio
    async def test_get_event_empty_id(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth):
            with pytest.raises(HTTPException) as exc:
                await get_event("   ")
            assert exc.value.status_code == 422

    @pytest.mark.asyncio
    async def test_get_event_degraded(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", None):
            with pytest.raises(HTTPException) as exc:
                await get_event("evt-123")
            assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_get_event_not_found_or_org_mismatch(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", MagicMock()):
            # Test not found
            with patch("services.ingest.app.redis_call", new_callable=AsyncMock, return_value=None):
                with pytest.raises(HTTPException) as exc:
                    await get_event("evt-not-found")
                assert exc.value.status_code == 404

            # Test org mismatch
            other_event = json.dumps({"event_id": "evt-other", "org_id": "other-org"})
            with patch("services.ingest.app.redis_call", new_callable=AsyncMock, return_value=other_event):
                with pytest.raises(HTTPException) as exc:
                    await get_event("evt-other")
                assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_event_success(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        event_dict = {
            "event_id": "evt-123",
            "org_id": "test-org",
            "timestamp": "2026-01-01T12:00:00",
            "source_type": "api",
            "source_id": "client-1",
            "model": "gpt-4",
            "prompt": "Hello",
            "system_prompt": None,
            "metadata": {},
            "blocked": False,
            "risk_score": 0.0,
            "verdict": "benign",
        }
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", MagicMock()), \
             patch("services.ingest.app.redis_call", new_callable=AsyncMock, return_value=json.dumps(event_dict)):
            res = await get_event("evt-123")
            assert res.event_id == "evt-123"
            assert res.verdict == "benign"

    @pytest.mark.asyncio
    async def test_get_stats_degraded(self):
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock), \
             patch("services.ingest.app.redis_client", None):
            with pytest.raises(HTTPException) as exc:
                await get_stats()
            assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_get_stats_success(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        events = [
            json.dumps({"org_id": "test-org", "verdict": "malicious", "blocked": True}),
            json.dumps({"org_id": "test-org", "verdict": "benign", "blocked": False}),
            json.dumps({"org_id": "other-org", "verdict": "malicious", "blocked": True}),
        ]
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.redis_client", MagicMock()):
            side_effects = [
                ["tenet:event:1", "tenet:event:2", "tenet:event:3"],
                events[0],
                events[1],
                events[2],
            ]
            with patch("services.ingest.app.redis_call", new_callable=AsyncMock, side_effect=side_effects):
                res = await get_stats()
                assert res["total_events"] == 2
                assert res["blocked_count"] == 1
                assert res["threat_distribution"]["malicious"] == 1
                assert res["threat_distribution"]["benign"] == 1

    @pytest.mark.asyncio
    async def test_circuit_status(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"read"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth):
            res = await circuit_status()
            assert "name" in res
            assert res["state"] == "closed"

    @pytest.mark.asyncio
    async def test_export_audit_logs(self):
        mock_auth = AuthContext(
            org_id="test-org", key_id="key-1", role="admin",
            permissions={"admin"}, rpm_limit=120, daily_quota=5000
        )
        with patch("services.ingest.app.security.require_auth", new_callable=AsyncMock, return_value=mock_auth), \
             patch("services.ingest.app.security.export_audit_records", return_value=[{"action": "test"}]), \
             patch("services.ingest.app.security.audit"):
            res = await export_audit_logs()
            assert res["exported"] == 1
            assert res["records"] == [{"action": "test"}]
