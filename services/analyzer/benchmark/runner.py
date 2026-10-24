"""
Benchmark runner for TENET AI Detection Engine.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from services.analyzer.app import run_analysis, load_ml_models, load_config
from services.analyzer.benchmark.metrics import calculate_metrics


class DetectionBenchmarkRunner:
    """Runner to evaluate detection engine performance on a labeled benchmark dataset."""

    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)
        # The benchmark skips FastAPI startup, so apply env settings (MODEL_PATH,
        # PROMPT_INJECTION_THRESHOLD) here before loading the model.
        load_config()
        load_ml_models()

    def load_dataset(self) -> List[Dict[str, Any]]:
        """Load and validate dataset from JSON file."""
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Dataset file not found at {self.dataset_path}")

        with open(self.dataset_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("Dataset JSON must contain a list of test case objects.")

        validated = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict) or "prompt" not in item or "label" not in item:
                raise ValueError(f"Invalid dataset item at index {idx}: missing 'prompt' or 'label'")
            
            prompt_val = item["prompt"]
            if not isinstance(prompt_val, str) or not prompt_val.strip():
                raise ValueError(f"Invalid dataset item at index {idx}: 'prompt' must be a non-empty string.")

            category_val = item.get("category")
            if category_val is not None and not isinstance(category_val, str):
                raise ValueError(f"Invalid dataset item at index {idx}: 'category' must be a string if provided.")

            label_str = str(item["label"]).lower().strip()
            if label_str not in ("malicious", "benign"):
                raise ValueError(f"Invalid label '{item['label']}' at index {idx}. Must be 'malicious' or 'benign'")
            
            validated.append({
                "prompt": prompt_val,
                "label": label_str,
                "category": category_val if category_val else ("malicious" if label_str == "malicious" else "benign")
            })

        return validated

    def run(self, threshold: float = 0.5) -> Dict[str, Any]:
        """Execute benchmark evaluation across all dataset items."""
        dataset = self.load_dataset()

        y_true: List[int] = []
        y_scores: List[float] = []
        detailed_results: List[Dict[str, Any]] = []
        latencies_ms: List[float] = []
        category_breakdown: Dict[str, Dict[str, List[Any]]] = {}

        # Collect pure benign negative controls (items with label 'benign')
        benign_true: List[int] = []
        benign_scores: List[float] = []

        for item in dataset:
            prompt = item["prompt"]
            ground_truth_label = item["label"]
            category = item["category"]
            binary_true = 1 if ground_truth_label == "malicious" else 0

            start_time = time.perf_counter()
            response = run_analysis(prompt)
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            latencies_ms.append(latency_ms)
            y_true.append(binary_true)
            y_scores.append(response.risk_score)

            if ground_truth_label == "benign":
                benign_true.append(0)
                benign_scores.append(response.risk_score)

            predicted_label = response.verdict

            if category not in category_breakdown:
                category_breakdown[category] = {"y_true": [], "y_scores": [], "is_benign_cat": True}
            category_breakdown[category]["y_true"].append(binary_true)
            category_breakdown[category]["y_scores"].append(response.risk_score)
            if binary_true == 1:
                category_breakdown[category]["is_benign_cat"] = False

            detailed_results.append({
                "prompt": prompt,
                "ground_truth": ground_truth_label,
                "category": category,
                "risk_score": round(response.risk_score, 4),
                "predicted_verdict": predicted_label,
                "threat_type": response.threat_type,
                "method": response.details.get("method", "unknown"),
                "latency_ms": round(latency_ms, 2),
            })

        overall_metrics = calculate_metrics(y_true, y_scores, threshold=threshold)

        avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        # Nearest-rank P95 index: ceil(0.95 * n) - 1
        import math
        p95_index = max(0, math.ceil(0.95 * len(latencies_ms)) - 1) if latencies_ms else 0
        p95_latency = sorted(latencies_ms)[p95_index] if latencies_ms else 0.0

        per_category_metrics = {}
        for cat, data in category_breakdown.items():
            is_benign_slice = data.get("is_benign_cat", False)
            if is_benign_slice or not benign_true:
                cat_m = calculate_metrics(data["y_true"], data["y_scores"], threshold=threshold)
                cat_m["category_samples"] = len(data["y_true"])
                cat_m["is_benign_cat"] = is_benign_slice
                per_category_metrics[cat] = cat_m
            else:
                # Filter out benign items tagged with this category to prevent double counting
                category_malicious_true = [yt for yt in data["y_true"] if yt == 1]
                category_malicious_scores = [ys for yt, ys in zip(data["y_true"], data["y_scores"]) if yt == 1]
                
                combined_y_true = category_malicious_true + benign_true
                combined_y_scores = category_malicious_scores + benign_scores
                cat_metrics = calculate_metrics(combined_y_true, combined_y_scores, threshold=threshold)
                cat_metrics["category_samples"] = len(category_malicious_true)
                cat_metrics["is_benign_cat"] = False
                per_category_metrics[cat] = cat_metrics


        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dataset_path": str(self.dataset_path),
            "summary": {
                **overall_metrics,
                "avg_latency_ms": round(avg_latency, 2),
                "p95_latency_ms": round(p95_latency, 2),
            },
            "per_category": per_category_metrics,
            "detailed_results": detailed_results,
        }

        return report


    @staticmethod
    def generate_markdown_report(report: Dict[str, Any]) -> str:
        """Convert a benchmark report dictionary into a clean Markdown string."""
        summary = report["summary"]
        cm = summary["confusion_matrix"]

        md = []
        md.append("# 📏 TENET AI Detection Engine Benchmark Report")
        md.append(f"**Generated At:** `{report['timestamp']}`  ")
        md.append(f"**Dataset:** `{report['dataset_path']}`  ")
        md.append(f"**Total Samples:** {summary['total_samples']}\n")

        md.append("## 📊 Summary Performance Metrics")
        md.append("| Metric | Value |")
        md.append("| --- | --- |")
        md.append(f"| **Precision** | `{summary['precision']:.4f}` |")
        md.append(f"| **Recall** | `{summary['recall']:.4f}` |")
        md.append(f"| **F1 Score** | `{summary['f1_score']:.4f}` |")
        md.append(f"| **Accuracy** | `{summary['accuracy']:.4f}` |")
        md.append(f"| **AUC-ROC** | `{summary['auc_roc']:.4f}` |")
        md.append(f"| **Avg Latency** | `{summary['avg_latency_ms']} ms` |")
        md.append(f"| **P95 Latency** | `{summary['p95_latency_ms']} ms` |\n")

        md.append("## 🧩 Confusion Matrix")
        md.append("| | Predicted Benign | Predicted Malicious |")
        md.append("| --- | --- | --- |")
        md.append(f"| **Actual Benign** | True Negative (TN): **{cm['tn']}** | False Positive (FP): **{cm['fp']}** |")
        md.append(f"| **Actual Malicious** | False Negative (FN): **{cm['fn']}** | True Positive (TP): **{cm['tp']}** |\n")

        if "per_category" in report and report["per_category"]:
            md.append("## 📂 Per-Category Metrics")
            md.append("| Category | Samples | Precision | Recall | F1 Score | Accuracy |")
            md.append("| --- | --- | --- | --- | --- | --- |")
            for cat, cat_m in report["per_category"].items():
                samples_cnt = cat_m.get("category_samples", cat_m["total_samples"])
                if cat == "benign" or cat_m.get("is_benign_cat", False):
                    # Benign slice contains no positive ground truth samples; Precision/Recall/F1 are undefined/N/A
                    md.append(
                        f"| `{cat}` | {samples_cnt} | `N/A` | "
                        f"`N/A` | `N/A` | `{cat_m['accuracy']:.4f}` |"
                    )
                else:
                    md.append(
                        f"| `{cat}` | {samples_cnt} | `{cat_m['precision']:.4f}` | "
                        f"`{cat_m['recall']:.4f}` | `{cat_m['f1_score']:.4f}` | `{cat_m['accuracy']:.4f}` |"
                    )
            md.append("")


        return "\n".join(md)

    @staticmethod
    def check_regression(
        current_report: Dict[str, Any], baseline_path: Optional[str] = None, min_f1: float = 0.85, min_precision: float = 0.85
    ) -> List[str]:

        """Compare current report against baseline or absolute thresholds for regression detection."""
        regressions: List[str] = []
        summary = current_report["summary"]

        if summary["f1_score"] < min_f1:
            regressions.append(f"F1 score {summary['f1_score']:.4f} is below minimum threshold {min_f1:.4f}")

        if summary["precision"] < min_precision:
            regressions.append(f"Precision {summary['precision']:.4f} is below minimum threshold {min_precision:.4f}")

        if baseline_path and Path(baseline_path).exists():
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline_report = json.load(f)

            base_summary = baseline_report.get("summary", {})
            if "f1_score" in base_summary and summary["f1_score"] < base_summary["f1_score"]:
                diff = base_summary["f1_score"] - summary["f1_score"]
                regressions.append(f"F1 score regressed by {diff:.4f} (baseline: {base_summary['f1_score']:.4f}, current: {summary['f1_score']:.4f})")

            if "precision" in base_summary and summary["precision"] < base_summary["precision"]:
                diff = base_summary["precision"] - summary["precision"]
                regressions.append(f"Precision regressed by {diff:.4f} (baseline: {base_summary['precision']:.4f}, current: {summary['precision']:.4f})")

        return regressions


