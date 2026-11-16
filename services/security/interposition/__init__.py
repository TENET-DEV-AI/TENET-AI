"""Interposition adapters for extracting agent actions across LLM and MCP providers."""

from .extractors import (
    extract_anthropic_tool_calls,
    extract_gemini_tool_calls,
    extract_mcp_tool_calls,
    extract_openai_tool_calls,
    extract_tool_calls,
)

__all__ = [
    "extract_anthropic_tool_calls",
    "extract_gemini_tool_calls",
    "extract_mcp_tool_calls",
    "extract_openai_tool_calls",
    "extract_tool_calls",
]
