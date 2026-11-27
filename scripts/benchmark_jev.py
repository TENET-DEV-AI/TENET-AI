#!/usr/bin/env python3
"""
Compare the Jev backend with the current classifier on the benchmark dataset.

Needs ``TENET_JEV_BACKEND`` set to ``jev_api`` or ``jev_local``. With
``jev_api`` every dataset prompt is sent to the hosted service.
"""

import argparse
import asyncio
import dataclasses
import json
import math
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.analyzer import app as analyzer
from services.analyzer.benchmark.metrics import calculate_metrics
from services.analyzer.benchmark.runner import DetectionBenchmarkRunner
from services.analyzer.jev_classifier import JevClassifier

COLUMNS = ("precision", "recall", "f1_score", "accuracy")


async def compare(dataset: list, classifier: JevClassifier, threshold: float = 0.5) -> dict:
    """Score every dataset item with the local detectors, Jev and both together.

    All systems are measured on the prompts Jev answered, so the numbers are
    comparable when some Jev calls fail.

    Args:
        dataset: Items from ``DetectionBenchmarkRunner.load_dataset``.
        classifier: Configured Jev classifier.
        threshold: Risk score threshold, as in ``run_benchmark.py``.

    Returns:
        Report dict with sample counts, failure reasons, latency and metrics.
    """
    y_true = []
    outputs: dict[str, list] = {}
    latencies = []
    failures: dict[str, int] = {}

    for item in dataset:
        prompt = item["prompt"]
        baseline = analyzer.run_analysis(prompt)

        start = time.perf_counter()
        jev = await classifier.classify(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if jev["status"] != "ok":
            failures[jev["reason"]] = failures.get(jev["reason"], 0) + 1
            continue

        # Same rule as the service: a malicious local verdict does not use Jev.
        used = jev
        if baseline.verdict == "malicious":
            used = {"status": "skipped", "reason": "already_malicious"}
        combined = analyzer.apply_jev_result(baseline, used)

        scored = {
            "current": (baseline.risk_score, baseline.verdict),
            "jev": (jev["risk_score"], jev["verdict"]),
            "current+jev": (combined.risk_score, combined.verdict),
        }
        if analyzer.ml_model:
            ml = analyzer.ml_analysis(prompt)
            scored = {"sklearn": (ml["risk_score"], ml["verdict"]), **scored}

        y_true.append(1 if item["label"] == "malicious" else 0)
        latencies.append(elapsed_ms)
        for name, output in scored.items():
            outputs.setdefault(name, []).append(output)

    systems = {}
    for name, rows in outputs.items():
        flagged = [0.0 if verdict == "benign" else 1.0 for _, verdict in rows]
        systems[name] = {
            "risk_score": calculate_metrics(
                y_true, [score for score, _ in rows], threshold=threshold
            ),
            "verdict": calculate_metrics(y_true, flagged, threshold=0.5),
        }

    p95_index = max(0, math.ceil(0.95 * len(latencies)) - 1)
    return {
        "backend": classifier.settings.backend,
        "total_samples": len(dataset),
        "answered_samples": len(y_true),
        "failures": failures,
        "threshold": threshold,
        "jev_avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "jev_p95_latency_ms": round(sorted(latencies)[p95_index], 2) if latencies else None,
        "systems": systems,
    }


def to_markdown(report: dict) -> str:
    """Render the comparison report as Markdown."""
    lines = [
        "# Jev vs current classifier",
        f"Backend: `{report['backend']}`  ",
        f"Jev answered {report['answered_samples']} of {report['total_samples']} prompts.  ",
        "Every row is measured on the answered prompts only.  ",
        f"Failures: {report['failures'] or 'none'}  ",
        f"Jev latency (ms): avg {report['jev_avg_latency_ms']}, p95 {report['jev_p95_latency_ms']}",
    ]
    titles = {
        "risk_score": f"Flagged when risk_score >= {report['threshold']}",
        "verdict": "Flagged when verdict is not benign",
    }
    for view, title in titles.items():
        lines += [
            "",
            f"## {title}",
            "| System | Precision | Recall | F1 | Accuracy |",
            "| --- | --- | --- | --- | --- |",
        ]
        for name, metrics in report["systems"].items():
            values = " | ".join(f"{metrics[view][column]:.4f}" for column in COLUMNS)
            lines.append(f"| {name} | {values} |")
    return "\n".join(lines) + "\n"


async def run(args: argparse.Namespace) -> int:
    """Run the comparison and write the reports. Returns the exit code."""
    runner = DetectionBenchmarkRunner(dataset_path=args.dataset)
    if analyzer.JEV_SETTINGS.backend == "sklearn":
        print("Set TENET_JEV_BACKEND to jev_api or jev_local first.", file=sys.stderr)
        return 2

    # No cache, so every latency is a real call.
    settings = dataclasses.replace(analyzer.JEV_SETTINGS, cache_size=0)
    classifier = JevClassifier(settings, analyzer.PROMPT_INJECTION_THRESHOLD)
    try:
        report = await compare(runner.load_dataset(), classifier, args.threshold)
    finally:
        await classifier.close()

    if not report["answered_samples"]:
        print(f"No Jev answers, nothing to compare: {report['failures']}", file=sys.stderr)
        return 1

    markdown = to_markdown(report)
    for path, content in (
        (Path(args.output_json), json.dumps(report, indent=2)),
        (Path(args.output_md), markdown),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(markdown)
    return 0


def main() -> None:
    """Parse arguments and run the comparison."""
    parser = argparse.ArgumentParser(description="Compare Jev with the current classifier")
    parser.add_argument("--dataset", default="data/benchmark_dataset.json")
    parser.add_argument("--output-json", default="reports/benchmark_jev.json")
    parser.add_argument("--output-md", default="reports/benchmark_jev.md")
    parser.add_argument("--threshold", type=float, default=0.5)
    sys.exit(asyncio.run(run(parser.parse_args())))


if __name__ == "__main__":
    main()
