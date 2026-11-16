"""Stateless extraction adapters for agent action and tool-call interposition."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from services.security.action_event import ActionEvent

logger = logging.getLogger(__name__)


def _to_dict(obj: Any) -> Any:
    """Normalize Pydantic models, dataclasses, and custom objects to plain dicts."""
    if obj is None or isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(item) for item in obj]
    if hasattr(obj, "model_dump") and callable(obj.model_dump):
        return _to_dict(obj.model_dump())
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return _to_dict(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return {k: _to_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    return obj


def extract_openai_tool_calls(
    payload: Any,
    source_id: str = "agent",
    session_id: str | None = None,
) -> list[ActionEvent]:
    """Extract proposed tool calls from OpenAI ChatCompletion response shapes."""
    data = _to_dict(payload)
    if not isinstance(data, dict):
        return []

    events: list[ActionEvent] = []
    choices = data.get("choices") or []

    for choice in choices:
        c_dict = _to_dict(choice)
        msg = c_dict.get("message") or {}
        msg_dict = _to_dict(msg)
        tool_calls = msg_dict.get("tool_calls") or []

        for tc in tool_calls:
            tc_dict = _to_dict(tc)
            fn = tc_dict.get("function") or {}
            fn_dict = _to_dict(fn)

            tool_name = str(fn_dict.get("name") or "unknown_tool")
            call_id = tc_dict.get("id") or None
            raw_args = fn_dict.get("arguments")

            tool_args: dict[str, Any] = {}
            parse_error = False

            if isinstance(raw_args, str):
                raw_trimmed = raw_args.strip()
                if raw_trimmed:
                    try:
                        parsed = json.loads(raw_trimmed)
                        if isinstance(parsed, dict):
                            tool_args = parsed
                        else:
                            tool_args = {"_raw": parsed}
                    except (json.JSONDecodeError, TypeError, ValueError):
                        tool_args = {"_raw": raw_args}
                        parse_error = True
                else:
                    tool_args = {}
            elif isinstance(raw_args, dict):
                tool_args = raw_args
            elif raw_args is not None:
                tool_args = {"_raw": str(raw_args)}

            events.append(
                ActionEvent(
                    source_id=source_id,
                    session_id=session_id,
                    provider="openai",
                    call_id=call_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    parse_error=parse_error,
                )
            )

    return events


def extract_anthropic_tool_calls(
    payload: Any,
    source_id: str = "agent",
    session_id: str | None = None,
) -> list[ActionEvent]:
    """Extract proposed tool calls from Anthropic Messages response shapes."""
    data = _to_dict(payload)
    if not isinstance(data, dict):
        return []

    events: list[ActionEvent] = []
    content_blocks = data.get("content") or []

    for block in content_blocks:
        b_dict = _to_dict(block)
        if b_dict.get("type") == "tool_use":
            tool_name = str(b_dict.get("name") or "unknown_tool")
            call_id = b_dict.get("id") or None
            raw_input = b_dict.get("input") or {}

            tool_args: dict[str, Any] = {}
            parse_error = False

            if isinstance(raw_input, dict):
                tool_args = raw_input
            elif isinstance(raw_input, str):
                try:
                    parsed = json.loads(raw_input)
                    tool_args = parsed if isinstance(parsed, dict) else {"_raw": parsed}
                except (json.JSONDecodeError, TypeError, ValueError):
                    tool_args = {"_raw": raw_input}
                    parse_error = True
            elif raw_input is not None:
                tool_args = {"_raw": str(raw_input)}

            events.append(
                ActionEvent(
                    source_id=source_id,
                    session_id=session_id,
                    provider="anthropic",
                    call_id=call_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    parse_error=parse_error,
                )
            )

    return events


def extract_gemini_tool_calls(
    payload: Any,
    source_id: str = "agent",
    session_id: str | None = None,
    turn_id: str | None = None,
) -> list[ActionEvent]:
    """Extract proposed function calls from Google Gemini GenerateContent response shapes.

    Idempotency & Deduplication Guarantees:
    - Tier 1: If a function call has an explicit provider 'id' or 'call_id', it is preserved.
    - Tier 2: If a provider response identifier is present (data.response_id, data.id,
      metadata.request_id, or turn_id argument), the call_id is derived deterministically as:
      `call_gemini_{sha256(response_id:cand_idx:part_idx:tool_name)[:16]}`.
      This preserves identity across retries of the same turn while ensuring separate
      sequential turns with identical arguments receive distinct IDs.
    - Tier 3: Contextless Fallback: If no provider response/turn ID exists and no explicit call ID
      is provided, call_id is set to None. This intentionally signals Ingest to bypass
      deduplication, preventing false duplicate suppression across distinct identical calls.
      Stateless retries without turn context have best-effort idempotency; exactly-once
      delivery is disclaimed.
    """
    data = _to_dict(payload)
    if not isinstance(data, dict):
        return []

    # Extract turn / response identifier
    response_id = (
        turn_id
        or data.get("response_id")
        or data.get("id")
        or data.get("turn_id")
        or (data.get("metadata") or {}).get("request_id")
        or getattr(payload, "response_id", None)
        or getattr(payload, "id", None)
    )
    if response_id is not None:
        response_id = str(response_id).strip()

    events: list[ActionEvent] = []
    candidates = data.get("candidates") or []

    for cand_idx, candidate in enumerate(candidates):
        cand_dict = _to_dict(candidate)
        content = cand_dict.get("content") or {}
        content_dict = _to_dict(content)
        parts = content_dict.get("parts") or []

        for part_idx, part in enumerate(parts):
            p_dict = _to_dict(part)
            # Accept both function_call and functionCall
            fn_call = p_dict.get("function_call") or p_dict.get("functionCall")
            if fn_call and isinstance(fn_call, dict):
                fn_dict = _to_dict(fn_call)
                tool_name = str(fn_dict.get("name") or "unknown_tool")
                raw_args = fn_dict.get("args") or {}

                tool_args: dict[str, Any] = {}
                parse_error = False

                if isinstance(raw_args, dict):
                    tool_args = raw_args
                elif isinstance(raw_args, str):
                    try:
                        parsed = json.loads(raw_args)
                        tool_args = parsed if isinstance(parsed, dict) else {"_raw": parsed}
                    except (json.JSONDecodeError, TypeError, ValueError):
                        tool_args = {"_raw": raw_args}
                        parse_error = True
                elif raw_args is not None:
                    tool_args = {"_raw": str(raw_args)}

                # Identity Derivation Hierarchy:
                explicit_id = fn_dict.get("id") or fn_dict.get("call_id") or p_dict.get("id")
                if explicit_id:
                    call_id = str(explicit_id)
                elif response_id:
                    seed = f"{response_id}:{cand_idx}:{part_idx}:{tool_name}"
                    call_id = f"call_gemini_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
                else:
                    call_id = None

                events.append(
                    ActionEvent(
                        source_id=source_id,
                        session_id=session_id,
                        provider="gemini",
                        call_id=call_id,
                        tool_name=tool_name,
                        tool_args=tool_args,
                        parse_error=parse_error,
                    )
                )

    return events


def extract_mcp_tool_calls(
    payload: Any,
    source_id: str = "agent",
    session_id: str | None = None,
) -> list[ActionEvent]:
    """Extract tool calls from Model Context Protocol (MCP) JSON-RPC 2.0 requests.

    Explicit boundary: evaluates requests where method == 'tools/call'.
    All other JSON-RPC methods (resources, prompts, logging) return an empty list.
    """
    data = _to_dict(payload)
    if not isinstance(data, dict):
        return []

    method = data.get("method")
    if method != "tools/call":
        return []

    params = data.get("params") or {}
    params_dict = _to_dict(params)

    tool_name = str(params_dict.get("name") or "unknown_tool")
    raw_args = params_dict.get("arguments") or {}
    call_id = str(data.get("id")) if data.get("id") is not None else None

    tool_args: dict[str, Any] = {}
    parse_error = False

    if isinstance(raw_args, dict):
        tool_args = raw_args
    elif isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
            tool_args = parsed if isinstance(parsed, dict) else {"_raw": parsed}
        except (json.JSONDecodeError, TypeError, ValueError):
            tool_args = {"_raw": raw_args}
            parse_error = True
    elif raw_args is not None:
        tool_args = {"_raw": str(raw_args)}

    return [
        ActionEvent(
            source_id=source_id,
            session_id=session_id,
            provider="mcp",
            call_id=call_id,
            tool_name=tool_name,
            tool_args=tool_args,
            parse_error=parse_error,
        )
    ]


# Aliases matching both naming conventions
extract_openai_tools = extract_openai_tool_calls
extract_anthropic_tools = extract_anthropic_tool_calls
extract_gemini_tools = extract_gemini_tool_calls
extract_mcp_tools = extract_mcp_tool_calls


def extract_tool_calls(
    payload: Any,
    provider: str = "openai",
    source_id: str = "agent",
    session_id: str | None = None,
    turn_id: str | None = None,
) -> list[ActionEvent]:
    """Dispatch extraction to the appropriate provider parser."""
    provider_lower = (provider or "").strip().lower()
    if provider_lower == "openai":
        return extract_openai_tool_calls(payload, source_id=source_id, session_id=session_id)
    if provider_lower == "anthropic":
        return extract_anthropic_tool_calls(payload, source_id=source_id, session_id=session_id)
    if provider_lower == "gemini":
        return extract_gemini_tool_calls(payload, source_id=source_id, session_id=session_id, turn_id=turn_id)
    if provider_lower == "mcp":
        return extract_mcp_tool_calls(payload, source_id=source_id, session_id=session_id)

    logger.warning("Unsupported action extraction provider: %s", provider)
    return []


__all__ = [
    "extract_anthropic_tool_calls",
    "extract_anthropic_tools",
    "extract_gemini_tool_calls",
    "extract_gemini_tools",
    "extract_mcp_tool_calls",
    "extract_mcp_tools",
    "extract_openai_tool_calls",
    "extract_openai_tools",
    "extract_tool_calls",
]
