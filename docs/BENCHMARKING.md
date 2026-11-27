# 📏 Detection Engine Benchmarking and Evaluation Framework

This document describes how to evaluate, benchmark, and track performance of TENET AI's threat detection engine across model versions and heuristic updates.

## 🎯 Overview

The benchmarking framework provides a reproducible evaluation pipeline that measures:
- **Precision**: Proportion of flagged prompts that are actually malicious.
- **Recall (Sensitivity)**: Proportion of actual malicious prompts correctly identified.
- **F1 Score**: Harmonic mean of precision and recall.
- **Accuracy**: Proportion of overall correct classifications.
- **AUC-ROC**: Area Under Receiver Operating Characteristic curve.
- **Latency**: Average and P95 latency per prompt analysis in milliseconds.
- **Confusion Matrix**: Counts for True Positive (TP), False Positive (FP), True Negative (TN), and False Negative (FN).

---

## 🚀 Running Benchmarks

Run the benchmark evaluation script from the repository root:

```bash
python scripts/run_benchmark.py
```

### Command Line Options

| Argument | Description | Default |
| --- | --- | --- |
| `--dataset` | Path to labeled evaluation dataset | `data/benchmark_dataset.json` |
| `--output-json` | Output JSON report file path | `reports/benchmark_latest.json` |
| `--output-md` | Output Markdown report file path | `reports/benchmark_latest.md` |
| `--baseline` | Path to baseline JSON report for regression comparison | `None` |
| `--threshold` | Decision threshold for risk score | `0.5` |
| `--fail-on-regression` | Exit with code `1` if quality regressions are found | `Disabled` |
| `--min-f1` | Minimum allowed F1 score threshold | `0.85` |
| `--min-precision` | Minimum allowed Precision threshold | `0.85` |

---

## Comparing the Jev Backend

`scripts/benchmark_jev.py` scores the same dataset with sklearn alone, the current pipeline,
Jev alone and the pipeline plus Jev. It needs a working
[Jev backend](../services/analyzer/README.md#jev-classifier-backend-optional):

```bash
TENET_JEV_BACKEND=jev_local TENET_JEV_URL=http://your-vllm-host:8000 \
  python scripts/benchmark_jev.py
```

With `TENET_JEV_BACKEND=jev_api` (and `TENET_JEV_API_KEY`) every dataset prompt is sent to
TypeSafe. The reports go to `reports/benchmark_jev.json` and `reports/benchmark_jev.md`.
Prompts Jev did not answer are listed as failures and left out of every row, and no report is
written if it answered none. The script accepts `--dataset`, `--output-json`, `--output-md` and
`--threshold`.

---

## 📈 CI Integration & Regression Guarding

Benchmarking runs automatically in GitHub Actions CI whenever a Pull Request modifies detection logic:
- `services/analyzer/**`
- `models/**`
- `data/**`
- `scripts/run_benchmark.py`

If detection precision or F1 score falls below threshold (`0.85`), CI checks will fail, preventing performance regressions.



---

## ➕ Contributing New Test Cases

We encourage adding diverse benign and adversarial test prompts to keep the evaluation dataset robust!

1. Open `data/benchmark_dataset.json`.
2. Add your test case in the following JSON format:

```json
{
  "prompt": "Your test prompt text here",
  "label": "malicious",
  "category": "prompt_injection"
}
```

- **`prompt`**: Non-empty string containing the prompt text.
- **`label`**: Must be either `"malicious"` or `"benign"`.
- **`category`**: One of `"prompt_injection"`, `"jailbreak"`, `"data_extraction"`, or `"benign"`.


3. Run `python scripts/run_benchmark.py` and ensure unit tests pass:

```bash
pytest tests/unit/test_benchmark.py -v
```
