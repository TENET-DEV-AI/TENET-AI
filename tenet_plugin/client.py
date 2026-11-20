"""TENET AI plugin utilities for any LLM or agent application."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

import requests
from services.security.action_event import ActionEvent
from services.security.interposition.extractors import extract_tool_calls

logger = logging.getLogger(__name__)


class TenetPluginError(RuntimeError):
    """Raised when TENET plugin behavior fails in strict mode."""


@dataclass
class GuardResult:
    """Result from TENET ingest analysis."""

    blocked: bool
    verdict: str
    risk_score: float
    event_id: str
    raw: dict[str, Any]


class TenetSecurityPlugin:
    """Security middleware client that can wrap any model invocation.

    This class is intentionally framework-agnostic: provide a callback
    that performs the real LLM call, and this plugin handles guard checks.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_key: str = "tenet-dev-key-change-in-production",
        source_type: str = "llm-plugin",
        source_id: str = "default",
        timeout_seconds: float = 5.0,
        fail_mode: str = "open",
        session: requests.Session | None = None,
    ) -> None:
        if fail_mode not in {"open", "closed"}:
            raise ValueError("fail_mode must be 'open' or 'closed'")

        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.source_type = source_type
        self.source_id = source_id
        self.timeout_seconds = timeout_seconds
        self.fail_mode = fail_mode
        self.session = session or requests.Session()

    @property
    def headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def inspect_prompt(
        self,
        prompt: str,
        model: str,
        source_id: str | None = None,
        source_type: str | None = None,
    ) -> GuardResult:
        """Send a prompt to TENET and return a normalized guard result."""
        payload = {
            "source_type": source_type or self.source_type,
            "source_id": source_id or self.source_id,
            "model": model,
            "prompt": prompt,
        }

        try:
            response = self.session.post(
                f"{self.api_url}/v1/events/llm",
                headers=self.headers,
                json=payload,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            body = response.json()
            return GuardResult(
                blocked=bool(body.get("blocked", False)),
                verdict=str(body.get("verdict", "unknown")),
                risk_score=float(body.get("risk_score", 0.0)),
                event_id=str(body.get("event_id", "")),
                raw=body,
            )
        except Exception as exc:
            if self.fail_mode == "closed":
                raise TenetPluginError("TENET inspection failed in fail-closed mode") from exc

            return GuardResult(
                blocked=False,
                verdict="inspection_unavailable",
                risk_score=0.0,
                event_id="",
                raw={"error": str(exc)},
            )

    def emit_action_event(self, action_event: ActionEvent | dict[str, Any]) -> dict[str, Any]:
        """Dispatch a single ActionEvent to the Ingest service in observe mode.

        Observe-only contract: Never halts host execution. Returns degraded status
        on network failures, timeouts, 429 saturation, or storage outages.
        """
        if isinstance(action_event, ActionEvent):
            payload = action_event.model_dump()
        else:
            raw_dict = dict(action_event)
            raw_dict.setdefault("source_id", self.source_id)
            if self.source_type and "source_type" not in raw_dict:
                raw_dict["source_type"] = self.source_type
            normalized = ActionEvent.model_validate(raw_dict)
            payload = normalized.model_dump()

        payload.setdefault("source_id", self.source_id)
        payload.setdefault("source_type", self.source_type)

        try:
            response = self.session.post(
                f"{self.api_url}/v1/events/action",
                headers=self.headers,
                json=payload,
                timeout=self.timeout_seconds,
            )
            # Handle capacity saturation (429) gracefully without throwing
            if response.status_code == 429:
                logger.warning("TENET action queue saturated (429); telemetry dropped fail-open")
                return {
                    "event_id": payload.get("event_id", ""),
                    "status": "rejected_capacity",
                    "observe_only": True,
                    "persisted": False,
                    "queued": False,
                    "overflow": False,
                    "degraded": True,
                    "retryable": True,
                }
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to emit action event to TENET: %s", exc)
            # Action monitoring is strictly observe-only and fail-open
            return {
                "event_id": payload.get("event_id", ""),
                "status": "degraded",
                "error": str(exc),
                "observe_only": True,
                "persisted": False,
                "queued": False,
                "overflow": False,
                "degraded": True,
            }

    def intercept_response_actions(
        self,
        llm_response: Any,
        provider: str = "openai",
        session_id: str | None = None,
        source_id: str | None = None,
        turn_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Extract tool calls from model response and emit them to Ingest service.

        Operates in observe-only mode with strict fail-open semantics: errors do not
        prevent caller execution under any circumstance.
        """
        try:
            extracted_actions = extract_tool_calls(
                llm_response,
                provider=provider,
                session_id=session_id,
                source_id=source_id or self.source_id,
                turn_id=turn_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tool-call extraction failed for provider %s: %s", provider, exc)
            return []

        results: list[dict[str, Any]] = []
        for action in extracted_actions:
            result = self.emit_action_event(action)
            results.append(result)
        return results

    def intercept_mcp_session(self, session: Any) -> Any:
        """Wrap an MCP client session's call_tool method for observe-only monitoring.

        Extracts proposed MCP tool executions before transmission over stdio or HTTP.
        Guarantees that tool execution ALWAYS proceeds fail-open even if telemetry fails.
        """
        original_call_tool = getattr(session, "call_tool", None)
        if not callable(original_call_tool):
            logger.warning("Session does not expose callable 'call_tool'; returning session unmodified")
            return session

        plugin = self

        if asyncio.iscoroutinefunction(original_call_tool):
            async def wrapped_call_tool(name: str, arguments: dict[str, Any] | None = None, *args: Any, **kwargs: Any) -> Any:
                try:
                    mcp_request: dict[str, Any] = {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments or {}},
                    }
                    call_id = kwargs.get("call_id")
                    if call_id is not None:
                        mcp_request["id"] = call_id
                    await asyncio.to_thread(plugin.intercept_response_actions, mcp_request, "mcp")
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MCP action interception telemetry error (continuing fail-open): %s", exc)
                return await original_call_tool(name, arguments, *args, **kwargs)
            session.call_tool = wrapped_call_tool
        else:
            def wrapped_call_tool(name: str, arguments: dict[str, Any] | None = None, *args: Any, **kwargs: Any) -> Any:
                try:
                    mcp_request: dict[str, Any] = {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments or {}},
                    }
                    call_id = kwargs.get("call_id")
                    if call_id is not None:
                        mcp_request["id"] = call_id
                    plugin.intercept_response_actions(mcp_request, provider="mcp")
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MCP action interception telemetry error (continuing fail-open): %s", exc)
                return original_call_tool(name, arguments, *args, **kwargs)
            session.call_tool = wrapped_call_tool

        return session

    # Alias for client convention
    intercept_mcp_client = intercept_mcp_session

    def secure_call(
        self,
        *,
        prompt: str,
        model: str,
        llm_callable: Callable[..., Any],
        llm_kwargs: dict[str, Any] | None = None,
        source_id: str | None = None,
        source_type: str | None = None,
        session_id: str | None = None,
        provider: str | None = None,
        intercept_actions: bool = False,
    ) -> dict[str, Any]:
        """Guard a single LLM call, run it if allowed, and inspect response actions."""
        analysis = self.inspect_prompt(
            prompt=prompt,
            model=model,
            source_id=source_id,
            source_type=source_type,
        )

        if analysis.blocked:
            return {
                "status": "blocked",
                "message": "Blocked by TENET AI policy.",
                "analysis": analysis.raw,
            }

        kwargs = dict(llm_kwargs or {})
        llm_response = llm_callable(**kwargs)

        result: dict[str, Any] = {
            "status": "success",
            "analysis": analysis.raw,
            "llm_response": llm_response,
        }

        if intercept_actions or provider is not None:
            detected_provider = provider or "openai"
            result["intercepted_actions"] = self.intercept_response_actions(
                llm_response=llm_response,
                provider=detected_provider,
                session_id=session_id,
                source_id=source_id,
            )

        return result

    def secure_messages_call(
        self,
        *,
        messages: Iterable[dict[str, Any]],
        model: str,
        llm_callable: Callable[..., Any],
        llm_kwargs: dict[str, Any] | None = None,
        source_id: str | None = None,
        source_type: str | None = None,
        session_id: str | None = None,
        provider: str | None = None,
        intercept_actions: bool = False,
    ) -> dict[str, Any]:
        """Guard a chat-style messages payload before model execution."""
        flattened_prompt = self._extract_prompt_from_messages(messages)
        return self.secure_call(
            prompt=flattened_prompt,
            model=model,
            llm_callable=llm_callable,
            llm_kwargs=llm_kwargs,
            source_id=source_id,
            source_type=source_type,
            session_id=session_id,
            provider=provider,
            intercept_actions=intercept_actions,
        )

    @staticmethod
    def _extract_prompt_from_messages(messages: Iterable[dict[str, Any]]) -> str:
        parts: list[str] = []
        for message in messages:
            role = message.get("role", "unknown")
            content = message.get("content", "")
            parts.append(f"[{role}] {content}")
        return "\n".join(parts)
