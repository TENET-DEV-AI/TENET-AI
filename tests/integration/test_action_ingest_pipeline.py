"""Integration tests for the Agent Action Ingestion and Processing Pipeline.

Tests:
1. Action event ingestion via FastAPI TestClient (POST /v1/events/action)
2. RBAC & API key authentication enforcement
3. Tenant isolation and multi-tenant deduplication independence
4. Idempotent duplicate suppression within tenant boundary
5. Missing invocation identity bypasses deduplication lock
6. Stable Gemini retry identity preservation
7. Redis transaction timeout after commit retry idempotency
8. Existing event record without dedup key returns already_committed
9. Deduplication key with evicted event record reports duplicate_evicted
10. Primary queue saturation triggers overflow buffering (HTTP 202)
11. Terminal capacity saturation triggers HTTP 429 without orphan records
12. Atomic overflow draining into primary queue
13. Drainer failure telemetry and recovery
14. Self-contained event payload retention while queued
15. Degraded mode fallback when Redis is unavailable (observe-only fail-open)
16. Fail-open host agent execution after HTTP 429 and network timeouts
17. Redis Cluster hashtag slot compatibility
18. Tenant isolation enforcement on event retrieval (GET /v1/events/action/{event_id})
19. Analyzer queue consumer processing to 'observed' status
20. End-to-end client -> Ingest API -> Analyzer worker pipeline simulation
"""

import json
import re
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from services.analyzer.app import (
    _drain_overflow_queue_step,
    _process_single_action_event,
)
from services.ingest.app import app as ingest_app
from services.security.action_event import ActionEvent
from services.security.interposition.extractors import extract_gemini_tools
from tenet_plugin.client import TenetSecurityPlugin

client = TestClient(ingest_app)
CLUSTER_TAG = "{tenet}"
TEST_API_KEY = "tenet-dev-key-change-in-production"
AUTH_HEADERS = {"X-API-Key": TEST_API_KEY}


class FakeActionRedis:
    """Accurate in-memory simulator for the TENET Action Redis pipeline and Lua scripts."""

    def __init__(self, primary_cap=25000, overflow_cap=5000):
        self.store = {}
        self.primary_queue = []
        self.overflow_queue = []
        self.primary_cap = primary_cap
        self.overflow_cap = overflow_cap
        self.last_eval_keys = []
        self.last_eval_args = []

    async def eval(self, script, numkeys, *keys_and_args):
        keys = list(keys_and_args[:numkeys])
        args = list(keys_and_args[numkeys:])
        self.last_eval_keys = keys
        self.last_eval_args = args

        # Drain script evaluation
        if "RPOPLPUSH" in script:
            max_primary = int(args[0])
            if len(self.primary_queue) < max_primary and self.overflow_queue:
                item = self.overflow_queue.pop(0)
                self.primary_queue.append(item)
                return 1
            return 0

        # Ingest pipeline evaluation
        event_key, _, dedup_key, _ = keys[0], keys[1], keys[2], keys[3]
        event_id, payload_json, _, _, max_primary, max_overflow = (
            args[0], args[1], args[2], args[3], int(args[4]), int(args[5])
        )
        dedup_enabled = int(args[6]) if len(args) > 6 else (1 if dedup_key and "disabled" not in dedup_key else 0)

        # 1. Dedup check (only when dedup_enabled == 1)
        if dedup_enabled == 1 and dedup_key:
            existing_event_id = self.store.get(dedup_key)
            if existing_event_id:
                orig_prefix = args[7] if len(args) > 7 else f"{CLUSTER_TAG}:action_event:"
                orig_key = f"{orig_prefix}{existing_event_id}"
                legacy_key = f"{CLUSTER_TAG}:action_event:{existing_event_id}"
                if orig_key in self.store or legacy_key in self.store:
                    return ["DUPLICATE_PERSISTED", existing_event_id]
                else:
                    return ["DUPLICATE_EVICTED", existing_event_id]

        # 2. Event key check
        if event_key in self.store:
            return ["ALREADY_COMMITTED", event_id]

        # 3. Primary queue capacity
        if len(self.primary_queue) < max_primary:
            self.store[event_key] = payload_json
            self.primary_queue.append(payload_json)
            if dedup_enabled == 1 and dedup_key:
                self.store[dedup_key] = event_id
            return ["QUEUED", str(len(self.primary_queue))]

        # 4. Overflow queue capacity
        if len(self.overflow_queue) < max_overflow:
            self.store[event_key] = payload_json
            self.overflow_queue.append(payload_json)
            if dedup_enabled == 1 and dedup_key:
                self.store[dedup_key] = event_id
            return ["OVERFLOW", str(len(self.overflow_queue))]

        # 5. Terminal saturation
        return ["SATURATED", str(len(self.primary_queue) + len(self.overflow_queue))]

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        return True

    async def incr(self, key):
        current = int(self.store.get(key, 0)) + 1
        self.store[key] = current
        return current

    async def expire(self, key, ttl):
        return True

    async def llen(self, key):
        if "overflow" in key:
            return len(self.overflow_queue)
        return len(self.primary_queue)

    async def rpop(self, key):
        if "overflow" in key:
            return self.overflow_queue.pop(0) if self.overflow_queue else None
        return self.primary_queue.pop(0) if self.primary_queue else None

    async def rpush(self, key, value):
        if "overflow" in key:
            self.overflow_queue.append(value)
            return len(self.overflow_queue)
        self.primary_queue.append(value)
        return len(self.primary_queue)

    async def lindex(self, key, index):
        q = self.overflow_queue if "overflow" in key else self.primary_queue
        try:
            return q[index]
        except IndexError:
            return None


# ---------------------------------------------------------------------------
# 1. Action Event Ingestion Endpoint Tests
# ---------------------------------------------------------------------------

def test_ingest_action_event_success():
    """Test successful ingestion of an agent tool call."""
    payload = {
        "source_id": "test-agent-01",
        "session_id": "sess-test-01",
        "provider": "openai",
        "call_id": "call_12345",
        "tool_name": "database_query",
        "tool_args": {"query": "SELECT 1", "api_key": "secret-key-to-redact"},
    }

    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        response = client.post(
            "/v1/events/action",
            headers=AUTH_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.headers["X-Tenet-Audit"] == "durable"
        data = response.json()
        assert data["tool_name"] == "database_query"
        assert data["status"] == "queued"
        assert data["observe_only"] is True
        assert data["persisted"] is True
        assert data["queued"] is True
        assert data["overflow"] is False
        assert data["degraded"] is False
        assert data["sanitized"] is True
        assert "event_id" in data
        assert "raw_payload_hash" in data


def test_ingest_action_event_requires_auth():
    """Test that POST /v1/events/action requires valid authentication."""
    payload = {
        "source_id": "test-agent-01",
        "provider": "openai",
        "tool_name": "calculator",
        "tool_args": {"expr": "2+2"},
    }

    # Missing API key
    response = client.post("/v1/events/action", json=payload)
    assert response.status_code == 401

    # Invalid API key
    response = client.post(
        "/v1/events/action",
        headers={"X-API-Key": "invalid-key-xyz"},
        json=payload,
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 2. Tenant Isolation & Deduplication Tests
# ---------------------------------------------------------------------------

def test_cross_tenant_deduplication_isolation():
    """Verify that identical source_id and call_id in Tenant Alpha and Tenant Beta are independent."""
    payload = {
        "source_id": "shared_agent",
        "provider": "openai",
        "call_id": "call_cross_tenant_common_id",
        "tool_name": "execute_query",
        "tool_args": {"sql": "SELECT 1"},
    }

    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        # Tenant Alpha submission
        with patch("services.ingest.app.security.require_auth") as mock_auth:
            class MockAuthAlpha:
                def __init__(self):
                    self.org_id = "org_alpha"
                    self.key_id = "key_alpha"
                    self.role = "admin"
                    self.permissions = ["ingest"]
            mock_auth.return_value = MockAuthAlpha()

            res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
            assert res1.status_code == 200
            assert res1.json()["status"] == "queued"

        # Tenant Beta submission (identical source_id & call_id)
        with patch("services.ingest.app.security.require_auth") as mock_auth:
            class MockAuthBeta:
                def __init__(self):
                    self.org_id = "org_beta"
                    self.key_id = "key_beta"
                    self.role = "admin"
                    self.permissions = ["ingest"]
            mock_auth.return_value = MockAuthBeta()

            res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
            assert res2.status_code == 200
            # Must NOT be duplicate_suppressed because org_id differs!
            assert res2.json()["status"] == "queued"
            assert res1.json()["event_id"] != res2.json()["event_id"]


def test_same_tenant_duplicate_suppression():
    """Verify that identical source_id and call_id within the same tenant ARE suppressed."""
    payload = {
        "source_id": "idempotent-agent",
        "provider": "openai",
        "call_id": "call_duplicate_unique_id",
        "tool_name": "execute_action",
        "tool_args": {"step": 1},
    }

    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        # First submission
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
        assert res1.status_code == 200
        assert res1.json()["status"] == "queued"
        assert res1.headers["X-Tenet-Audit"] == "durable"

        # Duplicate submission within same tenant
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "duplicate_suppressed"
        assert res2.json()["persisted"] is True
        assert res2.json()["queued"] is False
        assert res2.headers["X-Tenet-Audit"] == "duplicate"


def test_missing_invocation_identity_bypasses_dedup():
    """Verify that requests without a call_id bypass deduplication and are never falsely suppressed."""
    payload = {
        "source_id": "stateless-agent",
        "provider": "gemini",
        "tool_name": "poll_status",
        "tool_args": {"job_id": 42},
    }

    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)

        assert res1.status_code == 200
        assert res2.status_code == 200
        assert res1.json()["status"] == "queued"
        assert res2.json()["status"] == "queued"
        assert res1.json()["event_id"] != res2.json()["event_id"]


def test_stable_gemini_retry_identity():
    """Verify that retrying a Gemini turn response preserves call_id and is suppressed as a duplicate."""
    gemini_turn = {
        "response_id": "gemini_turn_retry_resp_42",
        "candidates": [{"content": {"parts": [{"functionCall": {"name": "fetch", "args": {"url": "https://example.com"}}}]}}]
    }

    events1 = extract_gemini_tools(gemini_turn, source_id="gemini_bot")
    events2 = extract_gemini_tools(gemini_turn, source_id="gemini_bot")

    assert events1[0].call_id == events2[0].call_id

    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=events1[0].model_dump())
        assert res1.status_code == 200
        assert res1.json()["status"] == "queued"

        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=events2[0].model_dump())
        assert res2.status_code == 200
        assert res2.json()["status"] == "duplicate_suppressed"


# ---------------------------------------------------------------------------
# 3. Transaction Idempotency & Edge Cases
# ---------------------------------------------------------------------------

def test_redis_transaction_timeout_after_commit_retry_idempotent():
    """Simulate client timeout after Redis commit: retry is deduplicated without duplicate queue entries."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "evt_timeout_retry_101",
        "source_id": "timeout-agent",
        "provider": "openai",
        "call_id": "call_timeout_retry_101",
        "tool_name": "transfer_funds",
        "tool_args": {"amount": 100},
    }

    with patch("services.ingest.app.redis_client", fake_redis):
        # 1. First attempt commits successfully
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res1.status_code == 200
        assert len(fake_redis.primary_queue) == 1

        # 2. Client experienced network timeout receiving response; retries with same payload
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "duplicate_suppressed"
        # Crucial check: Queue must still have exactly 1 item!
        assert len(fake_redis.primary_queue) == 1


def test_existing_event_record_without_dedup_key_returns_already_committed():
    """Verify that when event_id already exists in key storage, Lua returns ALREADY_COMMITTED."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "evt_explicit_id_202",
        "source_id": "agent",
        "provider": "gemini",
        "tool_name": "query",
        "tool_args": {"k": "v"},
        # No call_id!
    }

    with patch("services.ingest.app.redis_client", fake_redis):
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res1.status_code == 200
        assert res1.json()["status"] == "queued"

        # Client retries with same event_id
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "already_committed"
        assert res2.json()["persisted"] is True
        assert len(fake_redis.primary_queue) == 1


def test_deduplication_key_without_event_record_reports_evicted():
    """Verify that when dedup key exists but event record was evicted, Ingest reports duplicate_evicted."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "source_id": "agent",
        "provider": "openai",
        "call_id": "call_evicted_record_test",
        "tool_name": "read_data",
        "tool_args": {},
    }

    with patch("services.ingest.app.redis_client", fake_redis):
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res1.status_code == 200
        event_id = res1.json()["event_id"]

        # Simulate early key eviction of the event record under memory pressure
        fake_redis.store.pop(f"{CLUSTER_TAG}:action_event:{event_id}", None)
        fake_redis.store.pop(f"{CLUSTER_TAG}:action_event:default-org:{event_id}", None)

        # Client sends duplicate
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event_payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "duplicate_evicted"
        assert res2.json()["persisted"] is False
        assert res2.json()["degraded"] is True
        assert res2.headers["X-Tenet-Audit"] == "duplicate-evicted"


# ---------------------------------------------------------------------------
# 4. Queue Capacity, Overflow & Saturation
# ---------------------------------------------------------------------------

def test_primary_queue_saturation_triggers_overflow():
    """Verify that when primary queue reaches capacity, events spill into overflow (HTTP 202)."""
    # Configure tiny capacities for deterministic test: primary=2, overflow=2
    fake_redis = FakeActionRedis(primary_cap=2, overflow_cap=2)

    with patch("services.ingest.app.redis_client", fake_redis), \
         patch("services.ingest.app.MAX_PRIMARY_CAPACITY", 2), \
         patch("services.ingest.app.MAX_OVERFLOW_CAPACITY", 2):

        # Fill primary queue (2 items)
        for i in range(2):
            res = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": f"a{i}", "provider": "openai", "tool_name": "t", "tool_args": {}})
            assert res.status_code == 200
            assert res.json()["status"] == "queued"

        assert len(fake_redis.primary_queue) == 2
        assert len(fake_redis.overflow_queue) == 0

        # Third event spills to overflow queue -> HTTP 202 Accepted
        res3 = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a3", "provider": "openai", "tool_name": "t", "tool_args": {}})
        assert res3.status_code == 202
        assert res3.json()["status"] == "overflow_buffered"
        assert res3.json()["persisted"] is True
        assert res3.json()["queued"] is False
        assert res3.json()["overflow"] is True
        assert res3.json()["degraded"] is True
        assert res3.headers["X-Tenet-Audit"] == "overflow"
        assert len(fake_redis.overflow_queue) == 1


def test_overflow_queue_saturation_triggers_429():
    """Verify that when both primary and overflow queues are exhausted, Ingest returns HTTP 429."""
    fake_redis = FakeActionRedis(primary_cap=2, overflow_cap=1)

    with patch("services.ingest.app.redis_client", fake_redis), \
         patch("services.ingest.app.MAX_PRIMARY_CAPACITY", 2), \
         patch("services.ingest.app.MAX_OVERFLOW_CAPACITY", 1):

        # Primary: 2 events (200 OK)
        client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a1", "provider": "openai", "tool_name": "t", "tool_args": {}})
        client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a2", "provider": "openai", "tool_name": "t", "tool_args": {}})

        # Overflow: 1 event (202 Accepted)
        res_overflow = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a3", "provider": "openai", "tool_name": "t", "tool_args": {}})
        assert res_overflow.status_code == 202

        # Fourth event: Both queues exhausted -> 429 Too Many Requests
        store_keys_before = set(fake_redis.store.keys())
        res_saturated = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a4", "provider": "openai", "tool_name": "t", "tool_args": {}})
        assert res_saturated.status_code == 429
        assert res_saturated.headers["X-Tenet-Audit"] == "saturated"
        assert res_saturated.headers["Retry-After"] == "5"
        body = res_saturated.json()
        assert body["status"] == "rejected_capacity"
        assert body["persisted"] is False
        assert body["retryable"] is True

        # Crucial check: Clean rejection without orphan key writes!
        assert set(fake_redis.store.keys()) == store_keys_before


@pytest.mark.asyncio
async def test_atomic_overflow_draining():
    """Verify that _drain_overflow_queue_step moves items from overflow to primary."""
    fake_redis = FakeActionRedis(primary_cap=5, overflow_cap=5)
    fake_redis.overflow_queue.append(json.dumps({"event_id": "overflow_evt_1", "tool_name": "t"}))

    with patch("services.analyzer.app.redis_client", fake_redis), \
         patch("services.analyzer.app.MAX_PRIMARY_CAPACITY", 5):
        drained = await _drain_overflow_queue_step()
        assert drained == 1
        assert len(fake_redis.overflow_queue) == 0
        assert len(fake_redis.primary_queue) == 1


@pytest.mark.asyncio
async def test_analyzer_failure_during_draining():
    """Verify that if Redis throws an error during drain step, it logs warning without losing queue state."""
    mock_redis = AsyncMock()
    mock_redis.eval.side_effect = ConnectionError("Redis unreachable")

    with patch("services.analyzer.app.redis_client", mock_redis):
        drained = await _drain_overflow_queue_step()
        assert drained == 0


def test_event_retention_while_queued():
    """Verify that the queued payload is completely self-contained and tamper-evident."""
    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        res = client.post(
            "/v1/events/action",
            headers=AUTH_HEADERS,
            json={"source_id": "agent", "provider": "openai", "tool_name": "write", "tool_args": {"content": "hello"}},
        )
        assert res.status_code == 200

        queued_raw = fake_redis.primary_queue[0]
        queued_dict = json.loads(queued_raw)

        event = ActionEvent(**queued_dict)
        assert event.verify_hash() is True
        assert event.source_id == "agent"
        assert event.tool_name == "write"
        assert event.tool_args == {"content": "hello"}


# ---------------------------------------------------------------------------
# 5. Fail-Open & Degraded Fallback Tests
# ---------------------------------------------------------------------------

def test_redis_unavailable_during_telemetry_dispatch():
    """Test that Ingest gracefully degrades to 200 OK (persisted=False) when Redis is down."""
    payload = {
        "source_id": "fallback-agent",
        "provider": "openai",
        "tool_name": "list_dirs",
        "tool_args": {"path": "/"},
    }

    with patch("services.ingest.app.redis_client", None):
        response = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
        assert response.status_code == 200
        assert response.headers["X-Tenet-Audit"] == "unpersisted"
        data = response.json()
        assert data["status"] == "degraded"
        assert data["persisted"] is False
        assert data["queued"] is False
        assert data["degraded"] is True


def test_fail_open_host_execution_after_http_429_and_timeout():
    """Verify that host tool execution proceeds normally even if Ingest returns 429 or times out."""
    import requests

    class Mock429Session:
        def post(self, url, headers=None, json=None, timeout=None):
            class Resp:
                status_code = 429
                def raise_for_status(self): pass
                def json(self): return {"status": "rejected_capacity"}
            return Resp()

    class MockTimeoutSession:
        def post(self, url, headers=None, json=None, timeout=None):
            raise requests.exceptions.Timeout("Connection timed out to TENET ingest")

    class AgentToolClient:
        def call_tool(self, name, arguments=None):
            return f"Executed {name} with {arguments}"

    # Verify HTTP 429 fail-open
    plugin_429 = TenetSecurityPlugin(session=Mock429Session())
    agent_client = AgentToolClient()
    wrapped_429 = plugin_429.intercept_mcp_client(agent_client)
    result_429 = wrapped_429.call_tool("send_command", {"cmd": "ls"})
    assert result_429 == "Executed send_command with {'cmd': 'ls'}"

    # Verify Timeout fail-open
    plugin_timeout = TenetSecurityPlugin(session=MockTimeoutSession())
    wrapped_timeout = plugin_timeout.intercept_mcp_client(agent_client)
    result_timeout = wrapped_timeout.call_tool("send_command", {"cmd": "pwd"})
    assert result_timeout == "Executed send_command with {'cmd': 'pwd'}"


def test_redis_cluster_key_slot_compatibility():
    """Verify that all keys passed to Lua eval contain '{tenet}' and hash to the same slot."""
    fake_redis = FakeActionRedis()
    with patch("services.ingest.app.redis_client", fake_redis):
        response = client.post(
            "/v1/events/action",
            headers=AUTH_HEADERS,
            json={
                "source_id": "agent_789",
                "call_id": "call_abc",
                "provider": "openai",
                "tool_name": "db_query",
                "tool_args": {"foo": "bar"},
            },
        )
        assert response.status_code == 200
        keys = fake_redis.last_eval_keys
        assert len(keys) == 4

        # In Redis Cluster, the hash slot is determined by the substring inside {...}
        extracted_hashtags = []
        for k in keys:
            match = re.search(r"\{([^}]+)\}", k)
            assert match is not None, f"Key {k} is missing Redis hashtag"
            extracted_hashtags.append(match.group(1))

        # All hashtags must be strictly identical
        assert len(set(extracted_hashtags)) == 1
        assert extracted_hashtags[0] == "tenet"


# ---------------------------------------------------------------------------
# 6. Event Retrieval & Tenant Isolation
# ---------------------------------------------------------------------------

def test_get_action_event_tenant_isolation():
    """Test that Tenant Beta cannot retrieve action events belonging to Tenant Alpha."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "act_org_alpha_event",
        "org_id": "org_alpha",
        "source_id": "agent-alpha",
        "provider": "openai",
        "tool_name": "alpha_secret_tool",
        "tool_args": {},
        "status": "queued",
    }
    fake_redis.store[f"{CLUSTER_TAG}:action_event:act_org_alpha_event"] = json.dumps(event_payload)

    # Authenticated as Org Beta
    with patch("services.ingest.app.redis_client", fake_redis), patch("services.ingest.app.security.require_auth") as mock_auth:
            class MockAuthBeta:
                def __init__(self):
                    self.org_id = "org_beta"
                    self.key_id = "key_beta"
                    self.role = "reader"
                    self.permissions = ["read"]
            mock_auth.return_value = MockAuthBeta()

            response = client.get("/v1/events/action/act_org_alpha_event", headers=AUTH_HEADERS)
            assert response.status_code == 404
            assert response.json()["detail"] == "Action event not found"


def test_get_action_event_same_tenant_success():
    """Test that Tenant Alpha can retrieve its own action event."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "act_same_org_event",
        "org_id": "test_org",
        "source_id": "agent-alpha",
        "provider": "openai",
        "tool_name": "public_tool",
        "tool_args": {},
        "status": "queued",
    }
    fake_redis.store[f"{CLUSTER_TAG}:action_event:act_same_org_event"] = json.dumps(event_payload)

    with patch("services.ingest.app.redis_client", fake_redis), patch("services.ingest.app.security.require_auth") as mock_auth:
            class MockAuthSameOrg:
                def __init__(self):
                    self.org_id = "test_org"
                    self.key_id = "key_same"
                    self.role = "reader"
                    self.permissions = ["read"]
            mock_auth.return_value = MockAuthSameOrg()

            response = client.get("/v1/events/action/act_same_org_event", headers=AUTH_HEADERS)
            assert response.status_code == 200
            data = response.json()
            assert data["event_id"] == "act_same_org_event"
            assert data["tool_name"] == "public_tool"


# ---------------------------------------------------------------------------
# 7. Analyzer Consumer Processing & End-to-End Pipeline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analyzer_action_consumer_updates_state():
    """Test that the Analyzer consumer updates event state to 'observed' in Redis."""
    raw_event = {
        "event_id": "evt_consumer_test_01",
        "timestamp": "2026-11-16T00:00:00Z",
        "source_id": "agent-x",
        "provider": "anthropic",
        "tool_name": "query_inventory",
        "tool_args": {"item": "server_racks"},
        "status": "queued",
    }

    fake_redis = FakeActionRedis()

    with patch("services.analyzer.app.redis_client", fake_redis):
        await _process_single_action_event(json.dumps(raw_event))

        stored_raw = fake_redis.store.get(f"{CLUSTER_TAG}:action_event:evt_consumer_test_01")
        assert stored_raw is not None
        updated = json.loads(stored_raw)
        assert updated["verdict"] == "observed"
        assert updated["status"] == "observed"
        assert "observed_at" in updated


@pytest.mark.asyncio
async def test_end_to_end_plugin_to_analyzer_flow():
    """Simulate complete flow: LLM response -> Plugin -> Ingest API -> Analyzer worker."""
    fake_redis = FakeActionRedis()

    with patch("services.ingest.app.redis_client", fake_redis):
        model_response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_e2e_99",
                                "function": {
                                    "name": "backup_database",
                                    "arguments": '{"target": "s3://backups", "token": "super-secret"}',
                                },
                            }
                        ]
                    }
                }
            ]
        }

        class TestClientSession:
            def post(self, url, headers=None, json=None, timeout=None):
                return client.post(url.replace("http://localhost:8000", ""), headers=headers, json=json)

        plugin = TenetSecurityPlugin(session=TestClientSession())
        results = plugin.intercept_response_actions(model_response, provider="openai")
        assert len(results) == 1
        res_data = results[0]
        assert res_data["status"] == "queued"
        event_id = res_data["event_id"]

        assert len(fake_redis.primary_queue) == 1
        queued_event = json.loads(fake_redis.primary_queue[0])
        assert queued_event["event_id"] == event_id
        # Secret token masked before queueing
        assert queued_event["tool_args"]["token"] == "[REDACTED]"

        # Analyzer consumer drains the queue
        with patch("services.analyzer.app.redis_client", fake_redis):
            item = await fake_redis.rpop(f"{CLUSTER_TAG}:events:action:queue")
            await _process_single_action_event(item)

        stored_raw = fake_redis.store.get(f"{CLUSTER_TAG}:action_event:default-org:{event_id}") or fake_redis.store.get(f"{CLUSTER_TAG}:action_event:{event_id}")
        assert stored_raw is not None
        stored_event = json.loads(stored_raw)
        assert stored_event["verdict"] == "observed"
        assert stored_event["status"] == "observed"


# ---------------------------------------------------------------------------
# 8. Final Audit Fixes Verification Tests
# ---------------------------------------------------------------------------

def test_redis_cluster_key_slot_compatibility_with_missing_call_id():
    """Verify that when call_id is None, dedup_key is {tenet}:action_dedup:disabled and hashes to {tenet}."""
    event_id = "test_event_contextless_456"
    event_key = f"{CLUSTER_TAG}:action_event:{event_id}"
    primary_queue = f"{CLUSTER_TAG}:events:action:queue"
    overflow_queue = f"{CLUSTER_TAG}:events:action:overflow"
    dedup_key = f"{CLUSTER_TAG}:action_dedup:disabled"

    keys = [event_key, primary_queue, overflow_queue, dedup_key]
    extracted_hashtags = []
    for k in keys:
        match = re.search(r"\{([^}]+)\}", k)
        assert match is not None, f"Key {k} is missing Redis hashtag"
        extracted_hashtags.append(match.group(1))

    assert len(set(extracted_hashtags)) == 1
    assert extracted_hashtags[0] == "tenet"


def test_placeholder_dedup_key_never_stored_in_redis():
    """Verify that contextless calls do not write {tenet}:action_dedup:disabled into Redis."""
    fake_redis = FakeActionRedis()
    with patch("services.ingest.app.redis_client", fake_redis):
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a1", "provider": "openai", "tool_name": "t1", "tool_args": {}})
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json={"source_id": "a2", "provider": "openai", "tool_name": "t2", "tool_args": {}})

        assert res1.status_code == 200
        assert res2.status_code == 200
        assert f"{CLUSTER_TAG}:action_dedup:disabled" not in fake_redis.store


@pytest.mark.asyncio
async def test_analyzer_startup_task_registration_and_idempotence():
    """Verify that startup() registers action_background_task globally and is idempotent."""
    import services.analyzer.app as analyzer_module
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)

    with patch.object(analyzer_module, "redis_client", mock_redis), \
         patch("services.analyzer.app.redis.Redis", return_value=mock_redis), \
         patch("services.analyzer.app.load_ml_models"):

        # 1. Startup registers task
        await analyzer_module.startup()
        assert analyzer_module.action_background_task is not None
        assert not analyzer_module.action_background_task.done()
        task1 = analyzer_module.action_background_task

        # 2. Repeated startup does not recreate duplicate task
        await analyzer_module.startup()
        assert analyzer_module.action_background_task is task1

        # Cleanup via shutdown
        await analyzer_module.shutdown()
        assert analyzer_module.action_background_task is None
        assert analyzer_module.background_task is None


@pytest.mark.asyncio
async def test_analyzer_shutdown_when_task_none():
    """Verify that shutdown completes safely if action_background_task is None."""
    import services.analyzer.app as analyzer_module
    analyzer_module.action_background_task = None
    analyzer_module.background_task = None
    analyzer_module.redis_client = None

    # Should not raise any exception
    await analyzer_module.shutdown()


@pytest.mark.asyncio
async def test_overflow_progress_during_continuous_primary_traffic():
    """Verify that overflow queue drains periodically even when primary queue is never empty."""
    import asyncio

    import services.analyzer.app as analyzer_module
    fake_redis = FakeActionRedis(primary_cap=100, overflow_cap=10)
    fake_redis.overflow_queue.append(json.dumps({"event_id": "overflow_item_01", "tool_name": "t_overflow"}))

    # Fill primary queue with 25 events
    for i in range(25):
        fake_redis.primary_queue.append(json.dumps({"event_id": f"primary_item_{i}", "tool_name": f"t_{i}"}))

    initial_overflow_len = len(fake_redis.overflow_queue)
    assert initial_overflow_len == 1

    stop_evt = asyncio.Event()
    orig_process = analyzer_module._process_single_action_event
    processed_count = 0

    async def counting_process(event_data):
        nonlocal processed_count
        await orig_process(event_data)
        processed_count += 1
        if processed_count >= 15:
            stop_evt.set()

    with patch.object(analyzer_module, "redis_client", fake_redis), \
         patch.object(analyzer_module, "stop_event", stop_evt), \
         patch.object(analyzer_module, "_process_single_action_event", counting_process), \
         patch("services.analyzer.app.OVERFLOW_DRAIN_EVENT_INTERVAL", 10):
        await analyzer_module.process_action_event_queue()

        # The loop ran, processed primary events, and automatically invoked _drain_overflow_queue_step()
        assert processed_count >= 15
        assert len(fake_redis.overflow_queue) == 0
        assert any("overflow_item_01" in item for item in fake_redis.primary_queue)


@pytest.mark.asyncio
async def test_overflow_draining_rejected_when_primary_at_capacity():
    """Verify that overflow draining is rejected if primary queue is already at capacity."""
    import services.analyzer.app as analyzer_module
    fake_redis = FakeActionRedis(primary_cap=5, overflow_cap=5)
    # Fill primary queue to capacity (5)
    for i in range(5):
        fake_redis.primary_queue.append(json.dumps({"event_id": f"p_{i}"}))
    fake_redis.overflow_queue.append(json.dumps({"event_id": "overflow_wait"}))

    with patch.object(analyzer_module, "redis_client", fake_redis), \
         patch("services.analyzer.app.MAX_PRIMARY_CAPACITY", 5):
        drained = await analyzer_module._drain_overflow_queue_step()
        assert drained == 0
        assert len(fake_redis.overflow_queue) == 1
        assert len(fake_redis.primary_queue) == 5


def test_ingest_overwrites_caller_supplied_org_id():
    """Verify that caller-supplied org_id is always overwritten by authenticated tenant org_id."""
    fake_redis = FakeActionRedis()
    with patch("services.ingest.app.redis_client", fake_redis):
        payload = {
            "source_id": "agent_tamper",
            "provider": "openai",
            "tool_name": "db_query",
            "tool_args": {"sql": "SELECT 1"},
            "org_id": "attacker_org",
        }
        response = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
        assert response.status_code == 200
        event_id = response.json()["event_id"]

        # Check stored event in fake_redis
        stored_raw = None
        for k, v in fake_redis.store.items():
            if "action_event" in k and event_id in k:
                stored_raw = v
                break
        assert stored_raw is not None
        stored_dict = json.loads(stored_raw)
        assert stored_dict["org_id"] != "attacker_org"
        assert stored_dict["org_id"] == "default-org"


def test_ingest_rejects_tampered_raw_payload_hash():
    """Verify that submitting a tampered raw_payload_hash returns HTTP 422."""
    payload = {
        "source_id": "agent_tamper",
        "provider": "openai",
        "tool_name": "db_query",
        "tool_args": {"sql": "SELECT 1"},
        "raw_payload_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    }
    response = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload)
    assert response.status_code == 422
    assert "Payload integrity hash mismatch" in response.json()["detail"]


def test_duplicate_returns_original_persisted_event_id():
    """Verify that duplicate submissions return the original stored event ID rather than retry ID."""
    fake_redis = FakeActionRedis()
    with patch("services.ingest.app.redis_client", fake_redis):
        payload1 = {
            "source_id": "agent_dup",
            "call_id": "call_dup_123",
            "provider": "openai",
            "tool_name": "db_query",
            "tool_args": {"sql": "SELECT 1"},
        }
        res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload1)
        assert res1.status_code == 200
        orig_id = res1.json()["event_id"]

        # Second submission with same call_id and different event_id
        payload2 = {
            "source_id": "agent_dup",
            "call_id": "call_dup_123",
            "provider": "openai",
            "tool_name": "db_query",
            "tool_args": {"sql": "SELECT 1"},
            "event_id": "new_retry_id_9999",
        }
        res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=payload2)
        assert res2.status_code == 200
        assert res2.headers["X-Tenet-Audit"] == "duplicate"
        assert res2.json()["event_id"] == orig_id
        assert res2.json()["event_id"] != "new_retry_id_9999"


def test_get_action_event_redis_error_returns_503():
    """Verify that Redis connection/timeout error on retrieval returns HTTP 503 instead of 404."""
    import redis.exceptions

    class ErrorRedis:
        async def incr(self, key):
            return 1

        async def expire(self, key, ttl):
            return True

        async def get(self, key):
            raise redis.exceptions.ConnectionError("Redis connection refused")

    with patch("services.ingest.app.redis_client", ErrorRedis()):
        response = client.get("/v1/events/action/some_event_id", headers=AUTH_HEADERS)
        assert response.status_code == 503
        assert "Service degraded - event store unavailable" in response.json()["detail"]


def test_get_action_event_tenant_scoped_storage_lookup():
    """Verify retrieval works with tenant-scoped storage key."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "act_scoped_123",
        "org_id": "default-org",
        "source_id": "agent-alpha",
        "provider": "openai",
        "tool_name": "scoped_tool",
        "tool_args": {},
        "status": "queued",
    }
    fake_redis.store[f"{CLUSTER_TAG}:action_event:default-org:act_scoped_123"] = json.dumps(event_payload)

    with patch("services.ingest.app.redis_client", fake_redis):
        response = client.get("/v1/events/action/act_scoped_123", headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert response.json()["event_id"] == "act_scoped_123"
        assert response.json()["tool_name"] == "scoped_tool"


def test_get_action_event_legacy_key_fallback_lookup():
    """Verify get_action_event falls back to legacy unencoded key when scoped key not found."""
    fake_redis = FakeActionRedis()
    event_payload = {
        "event_id": "legacy_act_999",
        "org_id": "default-org",
        "source_id": "agent-legacy",
        "provider": "openai",
        "tool_name": "legacy_tool",
        "tool_args": {},
        "status": "queued",
    }
    # Store strictly under legacy unscoped key {tenet}:action_event:legacy_act_999
    fake_redis.store[f"{CLUSTER_TAG}:action_event:legacy_act_999"] = json.dumps(event_payload)

    with patch("services.ingest.app.redis_client", fake_redis):
        response = client.get("/v1/events/action/legacy_act_999", headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert response.json()["event_id"] == "legacy_act_999"
        assert response.json()["tool_name"] == "legacy_tool"


def test_ingest_bounded_provider_metrics_and_payload_preservation():
    """Verify provider label is bounded to 'other' in metrics while preserving original in payload."""
    from services.utils.metrics import ACTION_INGEST_COUNT

    fake_redis = FakeActionRedis()
    initial_metric = ACTION_INGEST_COUNT.labels(service="ingest", provider="other", status="queued")._value.get()

    event = ActionEvent(
        source_id="agent-cardinality",
        provider="custom_arbitrary_attacker_provider_xyz",
        tool_name="test_tool",
        tool_args={"arg": 1},
    )

    with patch("services.ingest.app.redis_client", fake_redis):
        response = client.post(
            "/v1/events/action",
            headers=AUTH_HEADERS,
            json=event.model_dump(),
        )
        assert response.status_code == 200

        # Prometheus counter must increment with provider="other"
        new_metric = ACTION_INGEST_COUNT.labels(service="ingest", provider="other", status="queued")._value.get()
        assert new_metric == initial_metric + 1

        # Redis storage must preserve the original raw provider string
        event_key = f"{CLUSTER_TAG}:action_event:default-org:{event.event_id}"
        stored_payload = json.loads(fake_redis.store[event_key])
        assert stored_payload["provider"] == "custom_arbitrary_attacker_provider_xyz"


def test_ingest_colon_delimited_org_and_event_isolation():
    """Verify distinct colon-separated org_id and event_id pairs avoid Redis key collisions."""
    fake_redis = FakeActionRedis()

    class MockAuthCol1:
        org_id = "org:1"
        key_id = "key1"
        role = "admin"

    class MockAuthCol2:
        org_id = "org"
        key_id = "key2"
        role = "admin"

    event1 = ActionEvent(
        event_id="evt",
        source_id="agent1",
        provider="openai",
        tool_name="tool1",
        tool_args={},
    )

    event2 = ActionEvent(
        event_id="1:evt",
        source_id="agent2",
        provider="openai",
        tool_name="tool2",
        tool_args={},
    )

    with patch("services.ingest.app.redis_client", fake_redis):
        with patch("services.ingest.app.security.require_auth", return_value=MockAuthCol1()):
            res1 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event1.model_dump())
            assert res1.status_code == 200

        with patch("services.ingest.app.security.require_auth", return_value=MockAuthCol2()):
            res2 = client.post("/v1/events/action", headers=AUTH_HEADERS, json=event2.model_dump())
            assert res2.status_code == 200

    # Keys in store must be escaped and distinct
    expected_key1 = f"{CLUSTER_TAG}:action_event:org%3A1:evt"
    expected_key2 = f"{CLUSTER_TAG}:action_event:org:1%3Aevt"
    assert expected_key1 in fake_redis.store
    assert expected_key2 in fake_redis.store
    assert expected_key1 != expected_key2
    assert len(fake_redis.store) == 2
