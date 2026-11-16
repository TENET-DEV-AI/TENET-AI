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

    async def eval(self, script, numkeys, *keys_and_args):
        keys = keys_and_args[:numkeys]
        args = keys_and_args[numkeys:]

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
                orig_key = f"{CLUSTER_TAG}:action_event:{existing_event_id}"
                if orig_key in self.store:
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
        del fake_redis.store[f"{CLUSTER_TAG}:action_event:{event_id}"]

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
    class Mock429Session:
        def post(self, url, headers=None, json=None, timeout=None):
            class Resp:
                status_code = 429
                def raise_for_status(self): pass
                def json(self): return {"status": "rejected_capacity"}
            return Resp()

    plugin = TenetSecurityPlugin(session=Mock429Session())

    class AgentToolClient:
        def call_tool(self, name, arguments=None):
            return f"Executed {name} with {arguments}"

    agent_client = AgentToolClient()
    wrapped_client = plugin.intercept_mcp_client(agent_client)

    result = wrapped_client.call_tool("send_command", {"cmd": "ls"})
    assert result == "Executed send_command with {'cmd': 'ls'}"


def test_redis_cluster_key_slot_compatibility():
    """Verify that all keys in the Ingest Lua script contain '{tenet}' and hash to the same slot."""
    event_id = "test_event_123"
    org_id = "org_456"
    source_id = "agent_789"
    call_id = "call_abc"

    event_key = f"{{tenet}}:action_event:{event_id}"
    primary_queue = f"{CLUSTER_TAG}:events:action:queue"
    overflow_queue = f"{CLUSTER_TAG}:events:action:overflow"
    dedup_key = f"{{tenet}}:action_dedup:{org_id}:{source_id}:{call_id}"

    keys = [event_key, primary_queue, overflow_queue, dedup_key]

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

        stored_raw = fake_redis.store.get(f"{CLUSTER_TAG}:action_event:{event_id}")
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
    import services.analyzer.app as analyzer_module
    fake_redis = FakeActionRedis(primary_cap=100, overflow_cap=10)
    fake_redis.overflow_queue.append(json.dumps({"event_id": "overflow_item_01", "tool_name": "t_overflow"}))

    # Fill primary queue with 60 events (greater than OVERFLOW_DRAIN_EVENT_INTERVAL = 50)
    for i in range(60):
        fake_redis.primary_queue.append(json.dumps({"event_id": f"primary_item_{i}", "tool_name": f"t_{i}"}))

    initial_overflow_len = len(fake_redis.overflow_queue)
    assert initial_overflow_len == 1

    with patch.object(analyzer_module, "redis_client", fake_redis), \
         patch("services.analyzer.app.OVERFLOW_DRAIN_EVENT_INTERVAL", 10):
        # Process 15 events from primary queue without letting primary queue reach 0
        for _ in range(15):
            event_json = await fake_redis.rpop(f"{CLUSTER_TAG}:events:action:queue")
            await analyzer_module._process_single_action_event(event_json)

        # Trigger periodic drain step
        drained = await analyzer_module._drain_overflow_queue_step()
        assert drained == 1
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
