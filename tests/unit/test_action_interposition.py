"""Comprehensive unit test suite for agent action interposition.

Covers:
- OpenAI, Anthropic, Gemini, and MCP payload extraction
- Malformed argument parsing and fallback handling
- Recursive secret and credential redaction
- Deterministic payload hashing and tamper detection
- ActionEvent immutability
- ActionLedger adapter mapping (PR #318 compatibility)
- TenetSecurityPlugin observe-only interposition & fail-open semantics
- MCP Client session interposition
"""

import pytest
from pydantic import ValidationError

from services.security.action_event import (
    ActionEvent,
    canonical_json,
    sanitize_value,
    verify_hash,
)
from services.security.interposition.extractors import (
    extract_anthropic_tools,
    extract_gemini_tools,
    extract_mcp_tools,
    extract_openai_tools,
    extract_tool_calls,
)
from tenet_plugin.client import TenetSecurityPlugin

# ---------------------------------------------------------------------------
# 1. OpenAI Extraction Tests
# ---------------------------------------------------------------------------

def test_openai_extraction_valid():
    payload = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": '{"city": "Paris", "units": "celsius"}',
                            },
                        }
                    ],
                },
            }
        ],
    }

    events = extract_openai_tools(payload, source_id="agent-01", session_id="sess-1")
    assert len(events) == 1
    ev = events[0]
    assert ev.provider == "openai"
    assert ev.source_id == "agent-01"
    assert ev.session_id == "sess-1"
    assert ev.call_id == "call_abc123"
    assert ev.tool_name == "get_weather"
    assert ev.tool_args == {"city": "Paris", "units": "celsius"}
    assert ev.parse_error is False
    assert ev.observe_only is True
    assert ev.verify_hash() is True


def test_openai_extraction_malformed_json():
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": "call_bad",
                            "function": {
                                "name": "broken_tool",
                                "arguments": '{"broken_json": ',
                            },
                        }
                    ]
                }
            }
        ]
    }

    events = extract_openai_tools(payload, source_id="agent-01")
    assert len(events) == 1
    ev = events[0]
    assert ev.tool_name == "broken_tool"
    assert ev.parse_error is True
    assert ev.tool_args == {"_raw": '{"broken_json": '}
    assert ev.verify_hash() is True


# ---------------------------------------------------------------------------
# 2. Anthropic Extraction Tests
# ---------------------------------------------------------------------------

def test_anthropic_extraction_valid():
    payload = {
        "id": "msg_01",
        "type": "message",
        "content": [
            {"type": "text", "text": "I will search the database."},
            {
                "type": "tool_use",
                "id": "toolu_01",
                "name": "sql_query",
                "input": {"query": "SELECT count(*) FROM users", "limit": 10},
            },
        ],
    }

    events = extract_anthropic_tools(payload, source_id="claude-agent")
    assert len(events) == 1
    ev = events[0]
    assert ev.provider == "anthropic"
    assert ev.call_id == "toolu_01"
    assert ev.tool_name == "sql_query"
    assert ev.tool_args == {"query": "SELECT count(*) FROM users", "limit": 10}
    assert ev.parse_error is False
    assert ev.verify_hash() is True


def test_anthropic_extraction_malformed():
    payload = {
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_bad",
                "name": "calc",
                "input": "{invalid json string",
            }
        ]
    }

    events = extract_anthropic_tools(payload, source_id="claude-agent")
    assert len(events) == 1
    ev = events[0]
    assert ev.parse_error is True
    assert ev.tool_args == {"_raw": "{invalid json string"}


# ---------------------------------------------------------------------------
# 3. Gemini Extraction Tests
# ---------------------------------------------------------------------------

def test_gemini_extraction_valid():
    payload = {
        "response_id": "gemini-turn-resp-001",
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "search_knowledge_base",
                                "args": {"topic": "quantum computing", "depth": 3},
                            }
                        }
                    ]
                }
            }
        ]
    }

    events = extract_gemini_tools(payload, source_id="gemini-bot")
    assert len(events) == 1
    ev = events[0]
    assert ev.provider == "gemini"
    assert ev.call_id.startswith("call_gemini_")
    assert ev.tool_name == "search_knowledge_base"
    assert ev.tool_args == {"topic": "quantum computing", "depth": 3}
    assert ev.verify_hash() is True


def test_gemini_retransmission_same_turn_identical_id():
    """Verify that retransmission of the same Gemini turn produces the exact same call_id."""
    payload = {
        "response_id": "gemini-turn-retry-999",
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "check_status",
                                "args": {"job_id": 42},
                            }
                        }
                    ]
                }
            }
        ]
    }

    events1 = extract_gemini_tools(payload, source_id="bot")
    events2 = extract_gemini_tools(payload, source_id="bot")
    assert events1[0].call_id == events2[0].call_id
    assert events1[0].call_id.startswith("call_gemini_")


def test_gemini_sequential_turns_distinct_ids():
    """Verify that separate sequential turns with identical arguments produce distinct call_ids."""
    payload_turn_1 = {
        "response_id": "turn_1",
        "candidates": [{"content": {"parts": [{"functionCall": {"name": "poll", "args": {"id": 1}}}]}}]
    }
    payload_turn_2 = {
        "response_id": "turn_2",
        "candidates": [{"content": {"parts": [{"functionCall": {"name": "poll", "args": {"id": 1}}}]}}]
    }

    events1 = extract_gemini_tools(payload_turn_1, source_id="bot")
    events2 = extract_gemini_tools(payload_turn_2, source_id="bot")
    assert events1[0].call_id != events2[0].call_id


def test_gemini_contextless_fallback_sets_none_call_id():
    """Verify that a contextless Gemini functionCall payload sets call_id to None to bypass deduplication."""
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "stateless_action",
                                "args": {"param": "val"},
                            }
                        }
                    ]
                }
            }
        ]
    }

    events = extract_gemini_tools(payload, source_id="bot")
    assert len(events) == 1
    assert events[0].call_id is None


def test_gemini_explicit_id_preserved():
    """Verify that if Gemini introduces a native tool call ID, it is preserved directly."""
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "id": "native_gemini_call_777",
                                "name": "run_code",
                                "args": {"code": "print(1)"},
                            }
                        }
                    ]
                }
            }
        ]
    }

    events = extract_gemini_tools(payload, source_id="bot")
    assert len(events) == 1
    assert events[0].call_id == "native_gemini_call_777"


# ---------------------------------------------------------------------------
# 4. MCP Extraction Tests
# ---------------------------------------------------------------------------

def test_mcp_extraction_tools_call():
    payload = {
        "jsonrpc": "2.0",
        "id": "mcp-req-42",
        "method": "tools/call",
        "params": {
            "name": "read_resource",
            "arguments": {"uri": "file:///etc/hosts", "encoding": "utf-8"},
        },
    }

    events = extract_mcp_tools(payload, source_id="mcp-agent")
    assert len(events) == 1
    ev = events[0]
    assert ev.provider == "mcp"
    assert ev.call_id == "mcp-req-42"
    assert ev.tool_name == "read_resource"
    assert ev.tool_args == {"uri": "file:///etc/hosts", "encoding": "utf-8"}
    assert ev.verify_hash() is True


def test_mcp_extraction_non_tools_call():
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/list",
        "params": {},
    }
    events = extract_mcp_tools(payload, source_id="mcp-agent")
    assert events == []


# ---------------------------------------------------------------------------
# 5. Dispatcher Test
# ---------------------------------------------------------------------------

def test_extract_tool_calls_dispatcher():
    openai_payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "f1", "arguments": "{}"}}
                    ]
                }
            }
        ]
    }
    events = extract_tool_calls(openai_payload, provider="openai", source_id="disp-agent")
    assert len(events) == 1
    assert events[0].tool_name == "f1"

    # Unsupported provider returns empty list
    assert extract_tool_calls(openai_payload, provider="unknown_provider") == []


# ---------------------------------------------------------------------------
# 6. Secret Redaction Tests
# ---------------------------------------------------------------------------

def test_secret_redaction():
    raw_payload = {
        "api_key": "sk-1234567890abcdef",
        "user_password": "SuperSecretPassword!",
        "token": "ghp_xxxxxxxxxxxx",
        "header": "Bearer secret-token-value-xyz",
        "safe_field": "public_data",
        "nested": {
            "db_secret": "my-db-pass",
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
        },
    }

    sanitized = sanitize_value(raw_payload)
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["user_password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["header"] == "[REDACTED]"
    assert sanitized["safe_field"] == "public_data"
    assert sanitized["nested"]["db_secret"] == "[REDACTED]"
    assert sanitized["nested"]["aws_key"] == "[REDACTED]"


def test_action_event_automatic_redaction():
    event = ActionEvent(
        source_id="agent-01",
        provider="openai",
        tool_name="database_connect",
        tool_args={
            "host": "localhost",
            "port": 5432,
            "password": "production_root_password",
        },
    )

    assert event.tool_args["host"] == "localhost"
    assert event.tool_args["password"] == "[REDACTED]"
    assert event.verify_hash() is True


# ---------------------------------------------------------------------------
# 7. Immutability & Tamper Detection Tests
# ---------------------------------------------------------------------------

def test_model_immutability():
    event = ActionEvent(
        source_id="agent-01",
        provider="openai",
        tool_name="list_files",
        tool_args={"path": "/home"},
    )

    with pytest.raises(ValidationError):
        event.tool_name = "format_disk"


def test_hash_integrity_and_tamper_detection():
    event = ActionEvent(
        source_id="agent-01",
        provider="openai",
        call_id="call_1",
        tool_name="transfer_funds",
        tool_args={"to": "alice", "amount": 100},
    )

    assert event.verify_hash() is True

    # Tampered clone with modified amount but original hash
    tampered_event = ActionEvent.model_construct(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_id=event.source_id,
        provider=event.provider,
        call_id=event.call_id,
        tool_name=event.tool_name,
        tool_args={"to": "alice", "amount": 1000000},  # Tampered!
        raw_payload_hash=event.raw_payload_hash,  # Stale hash!
    )

    assert tampered_event.verify_hash() is False
    assert verify_hash(tampered_event) is False


def test_canonical_json_determinism():
    dict_a = {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}
    dict_b = {"nested": {"y": 25, "z": 26}, "a": 1, "b": 2}

    assert canonical_json(dict_a) == canonical_json(dict_b)


# ---------------------------------------------------------------------------
# 8. PR #318 ActionLedger Adapter Tests
# ---------------------------------------------------------------------------

def test_to_ledger_params_mapping():
    event = ActionEvent(
        event_id="evt_test_123",
        source_id="finance_bot",
        session_id="sess_456",
        provider="openai",
        tool_name="execute_trade",
        tool_args={"ticker": "AAPL", "qty": 10},
    )

    params = event.to_ledger_params(verdict="allow", reasoning="observe_only")

    assert params["entry_id"] == "evt_test_123"
    assert params["actor"] == "finance_bot"
    assert params["action"] == "tool_call:execute_trade"
    assert params["tool"] == "execute_trade"
    assert params["scope"] == "sess_456"
    assert params["verdict"] == "allow"
    assert params["reasoning"] == "observe_only"
    assert params["timestamp"] == event.timestamp


# ---------------------------------------------------------------------------
# 9. Plugin Interposition & Fail-Open Tests
# ---------------------------------------------------------------------------

class MockSession:
    def __init__(self, responses=None, raise_exc=None):
        self.responses = responses or []
        self.raise_exc = raise_exc
        self.calls = []

    def post(self, url, *args, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        if self.raise_exc:
            raise self.raise_exc
        if self.responses:
            return self.responses.pop(0)
        return MockResponse({"status": "queued"})


class MockResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._data


def test_plugin_intercept_response_actions():
    mock_session = MockSession()
    plugin = TenetSecurityPlugin(
        api_url="http://testserver",
        api_key="test-key",
        session=mock_session,
    )

    openai_response = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": "c1",
                            "function": {"name": "query_db", "arguments": '{"table": "users"}'},
                        }
                    ]
                }
            }
        ]
    }

    results = plugin.intercept_response_actions(openai_response, provider="openai")
    assert len(results) == 1
    assert results[0]["status"] == "queued"
    assert len(mock_session.calls) == 1
    assert mock_session.calls[0]["url"] == "http://testserver/v1/events/action"


def test_plugin_fail_open_on_network_error():
    """Ensure agent execution continues even if TENET ingest network call fails."""
    mock_session = MockSession(raise_exc=RuntimeError("Connection refused"))
    plugin = TenetSecurityPlugin(
        fail_mode="open",
        session=mock_session,
    )

    openai_response = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "tool1", "arguments": "{}"}}
                    ]
                }
            }
        ]
    }

    results = plugin.intercept_response_actions(openai_response, provider="openai")
    assert len(results) == 1
    assert results[0]["status"] == "degraded"
    assert "Connection refused" in results[0]["error"]


def test_plugin_secure_call_with_action_interposition():
    mock_session = MockSession(
        responses=[
            MockResponse({"blocked": False, "verdict": "benign", "risk_score": 0.0}),
            MockResponse({"status": "queued", "event_id": "act_1"}),
        ]
    )
    plugin = TenetSecurityPlugin(session=mock_session)

    def dummy_llm():
        return {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "c_1", "function": {"name": "send_email", "arguments": '{"to": "user@example.com"}'}}
                        ]
                    }
                }
            ]
        }

    res = plugin.secure_call(
        prompt="Send email to user",
        model="gpt-4",
        llm_callable=dummy_llm,
        provider="openai",
        intercept_actions=True,
    )

    assert res["status"] == "success"
    assert "intercepted_actions" in res
    assert len(res["intercepted_actions"]) == 1
    assert res["intercepted_actions"][0]["status"] == "queued"


def test_plugin_mcp_client_interposition():
    mock_session = MockSession()
    plugin = TenetSecurityPlugin(session=mock_session)

    class MockMCPClient:
        def __init__(self):
            self.executed_tools = []

        def call_tool(self, name, arguments=None):
            self.executed_tools.append((name, arguments))
            return {"result": f"Executed {name}"}

    client = MockMCPClient()
    wrapped_client = plugin.intercept_mcp_client(client)

    result = wrapped_client.call_tool("read_file", {"path": "/etc/passwd"})
    assert result == {"result": "Executed read_file"}
    assert client.executed_tools == [("read_file", {"path": "/etc/passwd"})]

    # Verify action was intercepted and emitted
    assert len(mock_session.calls) == 1
    call = mock_session.calls[0]
    assert call["url"].endswith("/v1/events/action")
    payload = call["kwargs"]["json"]
    assert payload["provider"] == "mcp"
    assert payload["tool_name"] == "read_file"
    assert payload["tool_args"] == {"path": "/etc/passwd"}


def test_plugin_emit_action_handles_429_fail_open():
    """Verify that the client absorbs HTTP 429 saturation without raising, returning degraded status."""
    class Mock429Response:
        status_code = 429
        def raise_for_status(self):
            pass
        def json(self):
            return {"status": "rejected_capacity"}

    class Mock429Session:
        def post(self, url, headers=None, json=None, timeout=None):
            return Mock429Response()

    plugin = TenetSecurityPlugin(session=Mock429Session(), fail_mode="closed")
    event = ActionEvent(source_id="agent", provider="openai", tool_name="tool", tool_args={})
    res = plugin.emit_action_event(event)
    assert res["status"] == "rejected_capacity"
    assert res["observe_only"] is True
    assert res["persisted"] is False
    assert res["degraded"] is True


@pytest.mark.asyncio
async def test_plugin_mcp_async_client_interposition_fail_open():
    """Verify that async MCP call_tool executes fail-open even if action telemetry fails."""
    class FailingSession:
        def post(self, url, headers=None, json=None, timeout=None):
            raise ConnectionError("Ingest offline")

    plugin = TenetSecurityPlugin(session=FailingSession())

    class AsyncMockMCPClient:
        def __init__(self):
            self.called = False

        async def call_tool(self, name, arguments=None):
            self.called = True
            return {"result": f"Executed {name}"}

    client = AsyncMockMCPClient()
    wrapped_client = plugin.intercept_mcp_client(client)
    res = await wrapped_client.call_tool("async_action", {"key": "val"})
    assert res == {"result": "Executed async_action"}
    assert client.called is True
