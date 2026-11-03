"""
Integration test fixtures and configuration for TENET AI.

Provides reusable fixtures for FastAPI TestClients (Ingest and Analyzer),
Redis backend (real Redis on dedicated test database if accessible, otherwise FakeRedis),
and multi-tenant security configurations (roles, permissions, rate limits, quotas).
"""

import asyncio
import os
from typing import AsyncGenerator, Generator
from unittest.mock import patch

import fakeredis.aioredis
import pytest
import redis.asyncio as aioredis
from fastapi.testclient import TestClient

import services.analyzer.app as analyzer_mod
import services.ingest.app as ingest_mod
from services.analyzer.app import app as analyzer_app
from services.ingest.app import app as ingest_app


# Distinct multi-tenant test keys covering all roles, blocked states, and rate limits
TEST_KEYS_CONFIG = {
    "test-admin-key": {
        "org_id": "org-primary",
        "key_id": "key-admin",
        "role": "admin",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-viewer-key": {
        "org_id": "org-primary",
        "key_id": "key-viewer",
        "role": "viewer",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-ingest-key": {
        "org_id": "org-primary",
        "key_id": "key-ingest",
        "role": "ingest",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-analyst-key": {
        "org_id": "org-primary",
        "key_id": "key-analyst",
        "role": "analyst",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-blocked-key": {
        "org_id": "org-primary",
        "key_id": "key-blocked",
        "role": "admin",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-blocked-org-key": {
        "org_id": "org-blocked",
        "key_id": "key-blocked-org",
        "role": "admin",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-secondary-admin-key": {
        "org_id": "org-secondary",
        "key_id": "key-secondary-admin",
        "role": "admin",
        "rpm_limit": 100,
        "daily_quota": 1000,
    },
    "test-rate-limit-key": {
        "org_id": "org-rate",
        "key_id": "key-rate",
        "role": "admin",
        "rpm_limit": 3,
        "daily_quota": 100,
    },
    "test-quota-limit-key": {
        "org_id": "org-quota",
        "key_id": "key-quota",
        "role": "admin",
        "rpm_limit": 100,
        "daily_quota": 2,
    },
    "tenet-dev-key-change-in-production": {
        "org_id": "default-org",
        "key_id": "default-key",
        "role": "admin",
        "rpm_limit": 120,
        "daily_quota": 5000,
    },
}


def is_real_redis_available() -> bool:
    """Check if a real Redis instance is currently reachable."""
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", "6379"))
    require_real = os.getenv("REQUIRE_REAL_REDIS", "").lower() in ("1", "true", "yes")
    try:
        import redis
        client = redis.Redis(host=host, port=port, socket_timeout=0.3, socket_connect_timeout=0.3)
        available = bool(client.ping())
        if not available and require_real:
            pytest.fail(f"Real Redis is required (REQUIRE_REAL_REDIS is set) but ping failed at {host}:{port}")
        return available
    except Exception as exc:
        if require_real:
            pytest.fail(f"Real Redis is required (REQUIRE_REAL_REDIS is set) but connection failed at {host}:{port}: {exc}")
        return False


@pytest.fixture(scope="session")
def use_real_redis() -> bool:
    """Return whether integration tests can connect to a real Redis server."""
    return is_real_redis_available()


@pytest.fixture
def redis_backend(use_real_redis: bool):
    """Provide an isolated Redis client: real Redis on a dedicated test DB (default: db 15),

    otherwise FakeRedis. Cleans only the fixture-owned database before and after each test.
    """
    test_db = int(os.getenv("REDIS_TEST_DB", "15"))

    if use_real_redis:
        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", "6379"))

        # Setup: flush dedicated test DB before test
        setup_client = aioredis.Redis(host=host, port=port, db=test_db, decode_responses=True)
        setup_loop = asyncio.new_event_loop()
        try:
            setup_loop.run_until_complete(setup_client.flushdb())
        finally:
            setup_loop.run_until_complete(setup_client.aclose())
            setup_loop.close()

        client = aioredis.Redis(host=host, port=port, db=test_db, decode_responses=True)
        try:
            yield client
        finally:
            # Replace cleanup through the yielded client with a fresh cleanup client
            cleanup_client = aioredis.Redis(host=host, port=port, db=test_db, decode_responses=True)
            cleanup_loop = asyncio.new_event_loop()
            try:
                cleanup_loop.run_until_complete(cleanup_client.flushdb())
            finally:
                cleanup_loop.run_until_complete(cleanup_client.aclose())
                cleanup_loop.close()
                try:
                    close_loop = asyncio.new_event_loop()
                    close_loop.run_until_complete(client.aclose())
                    close_loop.close()
                except Exception:
                    pass
    else:
        fake_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            yield fake_client
        finally:
            cleanup_loop = asyncio.new_event_loop()
            try:
                cleanup_loop.run_until_complete(fake_client.flushdb())
            finally:
                cleanup_loop.run_until_complete(fake_client.aclose())
                cleanup_loop.close()


@pytest.fixture(autouse=True)
def configure_test_security():
    """Configure security managers on Ingest and Analyzer with test keys and isolation."""
    # Snapshot original configs
    ingest_orig = {
        "keys": dict(ingest_mod.security.keys_config),
        "blocked_keys": set(ingest_mod.security.blocked_key_ids),
        "blocked_orgs": set(ingest_mod.security.blocked_orgs),
        "memory_rate": dict(ingest_mod.security._memory_rate),
        "memory_quota": dict(ingest_mod.security._memory_quota),
    }
    analyzer_orig = {
        "keys": dict(analyzer_mod.security.keys_config),
        "blocked_keys": set(analyzer_mod.security.blocked_key_ids),
        "blocked_orgs": set(analyzer_mod.security.blocked_orgs),
        "memory_rate": dict(analyzer_mod.security._memory_rate),
        "memory_quota": dict(analyzer_mod.security._memory_quota),
    }

    # Apply test config
    for sec in (ingest_mod.security, analyzer_mod.security):
        sec.keys_config = dict(TEST_KEYS_CONFIG)
        sec.blocked_key_ids = {"key-blocked"}
        sec.blocked_orgs = {"org-blocked"}
        sec._memory_rate = {}
        sec._memory_quota = {}

    yield

    # Restore original config
    ingest_mod.security.keys_config = ingest_orig["keys"]
    ingest_mod.security.blocked_key_ids = ingest_orig["blocked_keys"]
    ingest_mod.security.blocked_orgs = ingest_orig["blocked_orgs"]
    ingest_mod.security._memory_rate = ingest_orig["memory_rate"]
    ingest_mod.security._memory_quota = ingest_orig["memory_quota"]

    analyzer_mod.security.keys_config = analyzer_orig["keys"]
    analyzer_mod.security.blocked_key_ids = analyzer_orig["blocked_keys"]
    analyzer_mod.security.blocked_orgs = analyzer_orig["blocked_orgs"]
    analyzer_mod.security._memory_rate = analyzer_orig["memory_rate"]
    analyzer_mod.security._memory_quota = analyzer_orig["memory_quota"]


@pytest.fixture
def ingest_client(redis_backend):
    """Provide a TestClient for the Ingest service backed by the active Redis fixture."""
    orig_client = ingest_mod.redis_client
    orig_cb_state = ingest_mod.redis_cb._state
    orig_cb_failures = ingest_mod.redis_cb._failure_count

    ingest_mod.redis_client = redis_backend
    ingest_mod.redis_cb._state = ingest_mod.CircuitState.CLOSED
    ingest_mod.redis_cb._failure_count = 0

    with (
        patch("redis.asyncio.Redis", return_value=redis_backend),
        patch("services.ingest.app.redis.Redis", return_value=redis_backend),
    ):
        with TestClient(ingest_app) as client:
            ingest_mod.redis_client = redis_backend
            yield client

    ingest_mod.redis_client = orig_client
    ingest_mod.redis_cb._state = orig_cb_state
    ingest_mod.redis_cb._failure_count = orig_cb_failures


@pytest.fixture
def analyzer_client(redis_backend):
    """Provide a TestClient for the Analyzer service backed by the active Redis fixture."""
    orig_client = analyzer_mod.redis_client
    analyzer_mod.redis_client = redis_backend

    with (
        patch("redis.asyncio.Redis", return_value=redis_backend),
        patch("services.analyzer.app.redis.Redis", return_value=redis_backend),
    ):
        with TestClient(analyzer_app) as client:
            analyzer_mod.redis_client = redis_backend
            yield client

    analyzer_mod.redis_client = orig_client


# Auth headers fixtures
@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"X-API-Key": "test-admin-key"}


@pytest.fixture
def viewer_headers() -> dict[str, str]:
    return {"X-API-Key": "test-viewer-key"}


@pytest.fixture
def ingest_headers() -> dict[str, str]:
    return {"X-API-Key": "test-ingest-key"}


@pytest.fixture
def analyst_headers() -> dict[str, str]:
    return {"X-API-Key": "test-analyst-key"}


@pytest.fixture
def secondary_headers() -> dict[str, str]:
    return {"X-API-Key": "test-secondary-admin-key"}


@pytest.fixture
def rate_limit_headers() -> dict[str, str]:
    return {"X-API-Key": "test-rate-limit-key"}


@pytest.fixture
def quota_limit_headers() -> dict[str, str]:
    return {"X-API-Key": "test-quota-limit-key"}


@pytest.fixture
def blocked_key_headers() -> dict[str, str]:
    return {"X-API-Key": "test-blocked-key"}


@pytest.fixture
def blocked_org_headers() -> dict[str, str]:
    return {"X-API-Key": "test-blocked-org-key"}
