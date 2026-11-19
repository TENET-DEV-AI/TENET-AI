"""Normalized action event schema for agent tool-call interposition."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

SENSITIVE_KEYS: set[str] = {
    "password", "token", "secret", "api_key", "apikey",
    "auth", "private_key", "access_token", "refresh_token",
    "authorization", "credentials", "webhook_url"
}

# Regex for common raw secret values in strings
SENSITIVE_VALUE_REGEXES = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
    # Match full PEM private key block across multiple lines
    re.compile(r"-----BEGIN [A-Z0-9_-]* ?PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]* ?PRIVATE KEY-----"),
    # Match sensitive key-value pairs in strings (e.g. malformed JSON or query parameters)
    re.compile(
        r"""(?i)(['"]?(?:password|token|secret|api[_-]?key|auth|private[_-]?key|access[_-]?token|refresh[_-]?token|authorization|credentials|webhook[_-]?url)['"]?\s*[:=]\s*['"]?)([^'"\s,}{]+)(['"]?)"""
    ),
]


def canonical_json(data: Any) -> str:
    """Deterministic, whitespace-free JSON encoding for cryptographic hashing."""
    def _default_serializer(obj: Any) -> Any:
        if isinstance(obj, (set, frozenset)):
            return sorted(obj)
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_default_serializer,
    )


def sanitize_value(val: Any) -> Any:
    """Recursively mask sensitive keys and token patterns in nested structures."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            k_str = str(k).lower()
            k_norm = k_str.replace("-", "_")
            k_clean = k_norm.replace("_", "").replace(" ", "")
            if any(sub in k_str or sub in k_norm or sub.replace("_", "") in k_clean for sub in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_value(v)
        return sanitized

    if isinstance(val, (list, tuple)):
        return [sanitize_value(item) for item in val]

    if isinstance(val, str):
        masked = val
        for pattern in SENSITIVE_VALUE_REGEXES:
            masked = pattern.sub(r"\1[REDACTED]\3" if pattern.groups == 3 else "[REDACTED]", masked)
        return masked

    return val


def verify_hash(event: ActionEvent) -> bool:
    """Standalone validator verifying the SHA-256 payload integrity hash."""
    return event.verify_hash()


class ActionExtractionError(ValueError):
    """Raised when tool extraction encounters malformed or unparseable payload structure."""


class ActionEvent(BaseModel):
    """Normalized, tamper-evident record of an intercepted agent tool call."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique event UUID")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp",
    )
    source_id: str = Field(..., description="Agent or caller identifier", min_length=1, max_length=128)
    session_id: str | None = Field(None, description="Agent session identifier", max_length=128)
    provider: str = Field(..., description="Provider: openai | anthropic | gemini | mcp")
    call_id: str | None = Field(None, description="Native provider tool-call identifier", max_length=128)
    tool_name: str = Field(..., description="Normalized tool identifier", min_length=1, max_length=256)
    tool_args: dict[str, Any] = Field(default_factory=dict, description="Sanitized tool arguments")
    raw_payload_hash: str = Field(default="", description="SHA-256 digest of normalized tool payload")
    observe_only: bool = Field(True, description="Observe-only execution mode flag")
    org_id: str | None = Field(None, description="Tenant organization identifier", max_length=64)
    parse_error: bool = Field(False, description="Flag indicating argument JSON parsing failure")

    @model_validator(mode="before")
    @classmethod
    def sanitize_and_hash(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Enforce observe_only is always True (fail-open observation contract)
            data["observe_only"] = True

            # Normalize event_id if present
            if data.get("event_id") and isinstance(data["event_id"], str):
                data["event_id"] = data["event_id"].strip()

            # 1. Sanitize tool_args
            raw_args = data.get("tool_args") or {}
            sanitized_args = sanitize_value(raw_args)
            if not isinstance(sanitized_args, dict):
                sanitized_args = {"_raw": sanitized_args}
            data["tool_args"] = sanitized_args

            # 2. Compute raw_payload_hash if not provided or empty
            if not data.get("raw_payload_hash"):
                hash_input = canonical_json({
                    "provider": str(data.get("provider", "")),
                    "tool_name": str(data.get("tool_name", "")),
                    "call_id": data.get("call_id"),
                    "tool_args": sanitized_args,
                })
                data["raw_payload_hash"] = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        return data

    def verify_hash(self) -> bool:
        """Verify that the tool payload matches the recorded SHA-256 digest."""
        expected_input = canonical_json({
            "provider": self.provider,
            "tool_name": self.tool_name,
            "call_id": self.call_id,
            "tool_args": self.tool_args,
        })
        expected_hash = hashlib.sha256(expected_input.encode("utf-8")).hexdigest()
        return self.raw_payload_hash == expected_hash

    def to_ledger_params(self, verdict: str = "allow", reasoning: str = "observe_only") -> dict[str, Any]:
        """Adapter mapping ActionEvent to PR #318's ActionLedger.append() schema."""
        return {
            "entry_id": self.event_id,
            "actor": self.source_id,
            "action": f"tool_call:{self.tool_name}",
            "tool": self.tool_name,
            "scope": self.session_id or "default",
            "verdict": verdict,
            "reasoning": reasoning,
            "timestamp": self.timestamp,
        }
