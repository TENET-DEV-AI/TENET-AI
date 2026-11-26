"""TENET AI plugin utilities for any LLM or agent application."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

import requests


class TenetPluginError(RuntimeError):
    """Raised when TENET plugin behavior fails in strict mode."""


@dataclass
class GuardResult:
    """Result from TENET ingest analysis."""

    blocked: bool
    verdict: str
    risk_score: float
    event_id: str
    raw: Dict[str, Any]


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
        session: Optional[requests.Session] = None,
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
    def headers(self) -> Dict[str, str]:
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def inspect_prompt(
        self,
        prompt: str,
        model: str,
        source_id: Optional[str] = None,
        source_type: Optional[str] = None,
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

    def secure_call(
        self,
        *,
        prompt: str,
        model: str,
        llm_callable: Callable[..., Any],
        llm_kwargs: Optional[Dict[str, Any]] = None,
        source_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Guard a single LLM call and run it only when allowed."""
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
        return {
            "status": "success",
            "analysis": analysis.raw,
            "llm_response": llm_response,
        }

    def secure_messages_call(
        self,
        *,
        messages: Iterable[Dict[str, Any]],
        model: str,
        llm_callable: Callable[..., Any],
        llm_kwargs: Optional[Dict[str, Any]] = None,
        source_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Guard a chat-style messages payload before model execution."""
        flattened_prompt = self._extract_prompt_from_messages(messages)
        return self.secure_call(
            prompt=flattened_prompt,
            model=model,
            llm_callable=llm_callable,
            llm_kwargs=llm_kwargs,
            source_id=source_id,
            source_type=source_type,
        )

    @staticmethod
    def _extract_prompt_from_messages(messages: Iterable[Dict[str, Any]]) -> str:
        parts: List[str] = []
        for message in messages:
            role = message.get("role", "unknown")
            content = message.get("content", "")
            parts.append(f"[{role}] {content}")
        return "\n".join(parts)
