"""Evaluate the runtime ML injection classifier on a held-out JSONL set."""

from __future__ import annotations

import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sentinel_agent.benchmark.generator import DEFAULT_CLASSIFIER_PATH, write_classifier_dataset
from sentinel_agent.security.ml_injection_model import MLInjectionClassifier


RESULT_DIR = PROJECT_ROOT / "experiments" / "results" / "latest"
TABLE_DIR = RESULT_DIR / "tables"
CLASSIFIER = MLInjectionClassifier(
    transformer_model_name="local-transformer-disabled",
    backend_mode="ngram",
)


def main() -> int:
    dataset_path = PROJECT_ROOT / DEFAULT_CLASSIFIER_PATH
    if not dataset_path.exists():
        write_classifier_dataset(dataset_path)
    rows = load_jsonl(dataset_path)
    test_rows = [row for row in rows if row.get("split") == "test"]
    predictions = [predict(row["text"]) for row in test_rows]
    metrics = compute_metrics(test_rows, predictions)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    (RESULT_DIR / "classifier_metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_confusion_matrix(metrics)
    write_latex(metrics)
    print(f"Wrote classifier metrics to {RESULT_DIR.relative_to(PROJECT_ROOT)}")
    return 0


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def predict(text: str) -> Dict[str, Any]:
    prediction = CLASSIFIER.predict(text)
    return {
        "label": prediction.label,
        "score": prediction.malicious_probability,
        "confidence": prediction.confidence,
        "backend": prediction.backend,
        "model_name": prediction.model_name,
        "details": prediction.details,
    }


def compute_metrics(rows: Sequence[Dict[str, Any]], predictions: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    y_true = []
    y_score = []
    for row, prediction in zip(rows, predictions):
        actual = row["label"] == "malicious"
        predicted = prediction["label"] == "malicious"
        y_true.append(1 if actual else 0)
        y_score.append(float(prediction["score"]))
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    return {
        "total_test_examples": len(rows),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "auroc": round(auroc(y_true, y_score), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
        },
        "model": CLASSIFIER.get_status(),
        "notes": (
            "Evaluation uses the test split only. The evaluated detector is the "
            "runtime n-gram Naive Bayes classifier trained from bundled fixtures, "
            "not from this classifier test split."
        ),
    }


def write_confusion_matrix(metrics: Dict[str, Any]) -> None:
    matrix = metrics["confusion_matrix"]
    with (RESULT_DIR / "classifier_confusion_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["cell", "count"])
        writer.writeheader()
        for cell, count in matrix.items():
            writer.writerow({"cell": cell, "count": count})


def write_latex(metrics: Dict[str, Any]) -> None:
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Injection Classifier Test-Split Results}",
        "\\begin{tabular}{lrrrrrr}",
        "\\toprule",
        "Accuracy & Precision & Recall & F1 & AUROC & FPR & FNR \\\\",
        "\\midrule",
        f"{pct(metrics['accuracy'])} & {pct(metrics['precision'])} & {pct(metrics['recall'])} & "
        f"{pct(metrics['f1'])} & {metrics['auroc']:.3f} & {pct(metrics['false_positive_rate'])} & "
        f"{pct(metrics['false_negative_rate'])} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]
    (TABLE_DIR / "classifier_results.tex").write_text("\n".join(lines), encoding="utf-8")


def auroc(y_true: Sequence[int], y_score: Sequence[float]) -> float:
    positives = [(score, label) for score, label in zip(y_score, y_true) if label == 1]
    negatives = [(score, label) for score, label in zip(y_score, y_true) if label == 0]
    if not positives or not negatives:
        return 0.0
    wins = 0.0
    for p_score, _ in positives:
        for n_score, _ in negatives:
            if p_score > n_score:
                wins += 1
            elif p_score == n_score:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def pct(value: float) -> str:
    return f"{float(value) * 100:.1f}\\%"


if __name__ == "__main__":
    raise SystemExit(main())
