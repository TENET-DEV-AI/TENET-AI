"""Micro-benchmark suite for agent action interposition.

Measures p50, p90, p95, and p99 latencies across 1,000 iterations for:
- Small payload extraction (~500 B)
- Medium payload extraction (~4 KB)
- Anthropic Messages tool_use extraction
- Gemini GenerateContent functionCall extraction
- MCP JSON-RPC tools/call extraction
- Canonical JSON serialization & SHA-256 integrity hashing
"""

import json
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Ensure TENET-AI root is in path
ROOT_DIR = str(Path(__file__).parent.parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from services.security.action_event import ActionEvent, canonical_json, sanitize_value
from services.security.interposition.extractors import (
    extract_anthropic_tools,
    extract_gemini_tools,
    extract_mcp_tools,
    extract_openai_tools,
)


def run_latency_benchmark(
    name: str,
    func: Callable[[], Any],
    iterations: int = 1000,
    warmup: int = 50,
) -> dict[str, float]:
    """Measure latency distribution across iterations in microseconds."""
    # Warmup
    for _ in range(warmup):
        func()

    latencies_us: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        func()
        t1 = time.perf_counter_ns()
        latencies_us.append((t1 - t0) / 1000.0)

    latencies_us.sort()
    n = len(latencies_us)

    return {
        "benchmark": name,
        "iterations": iterations,
        "mean_us": statistics.mean(latencies_us),
        "min_us": latencies_us[0],
        "p50_us": latencies_us[int(n * 0.50)],
        "p90_us": latencies_us[int(n * 0.90)],
        "p95_us": latencies_us[int(n * 0.95)],
        "p99_us": latencies_us[int(n * 0.99)],
        "max_us": latencies_us[-1],
    }


def main():
    print("=" * 80)
    print(" TENET-AI Issue #311 — Action Interposition Latency Benchmark")
    print("=" * 80)

    # 1. Payloads setup
    # Small OpenAI Payload (~500 B)
    small_openai = {
        "id": "chatcmpl-bench-01",
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": "call_weather_1",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": '{"location": "San Francisco, CA", "unit": "fahrenheit"}',
                            },
                        }
                    ]
                }
            }
        ],
    }

    # Medium OpenAI Payload (~4 KB)
    medium_openai = {
        "id": "chatcmpl-bench-02",
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": f"call_db_{i}",
                            "type": "function",
                            "function": {
                                "name": f"query_records_{i}",
                                "arguments": json.dumps({
                                    "filters": {"user_id": 1000 + i, "active": True, "tags": ["tagA", "tagB", "tagC"]},
                                    "columns": ["id", "username", "email", "created_at", "updated_at", "roles"],
                                    "pagination": {"limit": 100, "offset": 0, "sort": "created_at:desc"},
                                    "api_token": "secret-token-redact-me",
                                }),
                            },
                        }
                        for i in range(4)
                    ]
                }
            }
        ],
    }

    # Anthropic Tool Payload
    anthropic_payload = {
        "id": "msg_anthropic_bench",
        "type": "message",
        "content": [
            {"type": "text", "text": "Initiating search query"},
            {
                "type": "tool_use",
                "id": "toolu_bench_01",
                "name": "search_enterprise_docs",
                "input": {
                    "query": "Kubernetes cluster security ingress rules",
                    "namespace": "production",
                    "max_results": 25,
                },
            },
        ],
    }

    # Gemini Function Call Payload
    gemini_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "execute_code",
                                "args": {
                                    "language": "python",
                                    "code": "print('benchmark test')",
                                },
                            }
                        }
                    ]
                }
            }
        ]
    }

    # MCP tools/call Payload
    mcp_payload = {
        "jsonrpc": "2.0",
        "id": 1001,
        "method": "tools/call",
        "params": {
            "name": "execute_command",
            "arguments": {"cmd": "kubectl get pods -n kube-system", "timeout": 30},
        },
    }

    # Pre-parsed dictionary for hashing benchmark
    sample_args = {
        "query": "SELECT * FROM transactions WHERE amount > 500",
        "user_id": 9942,
        "api_key": "secret_key_to_be_masked",
    }

    benchmarks = [
        ("OpenAI Extraction (Small ~500B)", lambda: extract_openai_tools(small_openai, "agent-1")),
        ("OpenAI Extraction (Med ~4KB, 4 calls)", lambda: extract_openai_tools(medium_openai, "agent-1")),
        ("Anthropic Extraction", lambda: extract_anthropic_tools(anthropic_payload, "agent-1")),
        ("Gemini Extraction", lambda: extract_gemini_tools(gemini_payload, "agent-1")),
        ("MCP tools/call Extraction", lambda: extract_mcp_tools(mcp_payload, "agent-1")),
        ("Recursive Secret Redaction", lambda: sanitize_value(sample_args)),
        ("Canonical JSON Encoding", lambda: canonical_json(sample_args)),
        (
            "Full ActionEvent Construction",
            lambda: ActionEvent(
                source_id="bench-agent",
                provider="openai",
                tool_name="test_tool",
                tool_args=sample_args,
            ),
        ),
    ]

    results = []
    for name, fn in benchmarks:
        res = run_latency_benchmark(name, fn, iterations=1000)
        results.append(res)

    # Format table
    header = f"{'Benchmark Name':<38} | {'p50 (µs)':>10} | {'p90 (µs)':>10} | {'p95 (µs)':>10} | {'p99 (µs)':>10} | {'Mean (µs)':>10}"
    sep = "-" * len(header)
    print("\n" + header)
    print(sep)

    for r in results:
        print(
            f"{r['benchmark']:<38} | "
            f"{r['p50_us']:>10.2f} | "
            f"{r['p90_us']:>10.2f} | "
            f"{r['p95_us']:>10.2f} | "
            f"{r['p99_us']:>10.2f} | "
            f"{r['mean_us']:>10.2f}"
        )
    print(sep)
    print("* 1,000 iterations per benchmark | Warmup: 50 iterations | Precision: 1 µs = 0.001 ms\n")


if __name__ == "__main__":
    main()
