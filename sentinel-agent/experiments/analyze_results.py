"""Statistical analysis and table export for SentinelAgent experiments."""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = PROJECT_ROOT / "experiments" / "results" / "latest"
TABLE_DIR = RESULT_DIR / "tables"
FIGURE_DIR = RESULT_DIR / "figures"
PROFILES = [
    "no_defense",
    "prompt_only",
    "rules_only",
    "ml_only",
    "policy_only",
    "full_sentinelagent",
    "no_retrieval_screening",
    "no_tool_risk_classifier",
    "no_exfiltration_detector",
    "no_policy_engine",
]


def main() -> int:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    rows = load_per_task()
    metrics = load_aggregate()
    stats = build_statistical_summary(rows, metrics)
    write_tables(stats, metrics)
    write_figures(metrics)
    (RESULT_DIR / "statistical_analysis.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        table_label = TABLE_DIR.relative_to(PROJECT_ROOT)
    except ValueError:
        table_label = TABLE_DIR
    print(f"Wrote statistical tables to {table_label}")
    return 0


def load_per_task() -> List[Dict[str, Any]]:
    path = RESULT_DIR / "per_task_results.jsonl"
    if not path.exists():
        raise SystemExit("Missing per_task_results.jsonl. Run experiments/run_evaluation.py first.")
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_aggregate() -> List[Dict[str, Any]]:
    path = RESULT_DIR / "aggregate_metrics.csv"
    with path.open("r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build_statistical_summary(
    rows: Sequence[Dict[str, Any]],
    metrics: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["profile"], row["dataset"])].append(row)

    ci = {}
    for profile in PROFILES:
        for dataset in ["benchmark", "adaptive", "all"]:
            items = grouped.get((profile, dataset), [])
            if not items:
                continue
            ci[f"{profile}:{dataset}"] = {
                "attack_success_rate": bootstrap_ci(items, "attack_success", adversarial_only=True),
                "secret_leakage_rate": bootstrap_ci(items, "secret_leaked", adversarial_only=True),
                "benign_success_rate": bootstrap_ci(items, "benign_success", benign_only=True),
                "false_positive_rate": bootstrap_ci(items, "false_positive", benign_only=True),
            }

    comparisons = paired_comparisons(rows, "no_defense", "full_sentinelagent")
    return {"confidence_intervals": ci, "paired_comparisons": comparisons}


def bootstrap_ci(
    rows: Sequence[Dict[str, Any]],
    field: str,
    *,
    adversarial_only: bool = False,
    benign_only: bool = False,
    iterations: int = 1000,
    seed: int = 1337,
) -> Dict[str, float]:
    subset = [
        row
        for row in rows
        if (not adversarial_only or row["is_adversarial"])
        and (not benign_only or not row["is_adversarial"])
    ]
    if not subset:
        return {"mean": 0.0, "ci_low": 0.0, "ci_high": 0.0}
    rng = random.Random(seed + len(subset) + len(field))
    samples = []
    for _ in range(iterations):
        draw = [rng.choice(subset) for _ in subset]
        samples.append(sum(1 for row in draw if row[field]) / len(draw))
    samples.sort()
    return {
        "mean": round(sum(1 for row in subset if row[field]) / len(subset), 4),
        "ci_low": round(samples[int(0.025 * iterations)], 4),
        "ci_high": round(samples[int(0.975 * iterations) - 1], 4),
    }


def paired_comparisons(
    rows: Sequence[Dict[str, Any]],
    baseline: str,
    treatment: str,
) -> Dict[str, Any]:
    by_key: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for row in rows:
        if not row["is_adversarial"]:
            continue
        key = (row["dataset"], row["scenario_id"], row["profile"])
        by_key[key] = row

    pairs = []
    for dataset in ["benchmark", "adaptive", "all"]:
        base_rows = [
            row
            for row in rows
            if row["profile"] == baseline
            and row["is_adversarial"]
            and (dataset == "all" or row["dataset"] == dataset)
        ]
        b_success_t_fail = 0
        b_fail_t_success = 0
        effects = []
        for base in base_rows:
            treat = by_key.get((base["dataset"], base["scenario_id"], treatment))
            if not treat:
                continue
            base_success = bool(base["attack_success"])
            treat_success = bool(treat["attack_success"])
            if base_success and not treat_success:
                b_success_t_fail += 1
            elif (not base_success) and treat_success:
                b_fail_t_success += 1
            effects.append(float(base_success) - float(treat_success))
        chi2, p_value = mcnemar(b_success_t_fail, b_fail_t_success)
        pairs.append(
            {
                "dataset": dataset,
                "baseline": baseline,
                "treatment": treatment,
                "baseline_success_treatment_failure": b_success_t_fail,
                "baseline_failure_treatment_success": b_fail_t_success,
                "mcnemar_chi2": round(chi2, 4),
                "p_value": round(p_value, 6),
                "effect_size_asr_reduction": round(statistics.mean(effects), 4) if effects else 0.0,
            }
        )
    return {"baseline_vs_full": pairs}


def mcnemar(b: int, c: int) -> Tuple[float, float]:
    if b + c == 0:
        return 0.0, 1.0
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    p_value = math.erfc(math.sqrt(chi2 / 2.0))
    return chi2, p_value


def write_tables(stats: Dict[str, Any], metrics: Sequence[Dict[str, Any]]) -> None:
    benchmark_metrics = [row for row in metrics if row["dataset"] == "benchmark"]
    adaptive_metrics = [row for row in metrics if row["dataset"] == "adaptive"]
    all_metrics = [row for row in metrics if row["dataset"] == "all"]
    write_main_results(TABLE_DIR / "main_results.tex", benchmark_metrics, stats)
    write_main_results(TABLE_DIR / "ablation_results.tex", benchmark_metrics, stats, title="Ablation Results")
    write_main_results(TABLE_DIR / "adaptive_attack_results.tex", adaptive_metrics, stats, title="Adaptive Attack Results")
    write_latency(TABLE_DIR / "latency_results.tex", benchmark_metrics)


def write_main_results(
    path: Path,
    rows: Sequence[Dict[str, Any]],
    stats: Dict[str, Any],
    title: str = "Main Results",
) -> None:
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        f"\\caption{{{latex_escape(title)}}}",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Profile & ASR & Leak & Benign & FPR \\\\",
        "\\midrule",
    ]
    for row in rows:
        key = f"{row['profile']}:{row['dataset']}"
        ci = stats["confidence_intervals"].get(key, {})
        asr_ci = ci.get("attack_success_rate", {})
        asr = format_rate(row["attack_success_rate"])
        if asr_ci:
            asr = f"{asr} [{asr_ci['ci_low']:.2f},{asr_ci['ci_high']:.2f}]"
        lines.append(
            f"{latex_escape(row['profile'])} & {asr} & {format_rate(row['secret_leakage_rate'])} & "
            f"{format_rate(row['benign_task_success_rate'])} & {format_rate(row['false_positive_rate'])} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_latency(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Latency Results}",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Profile & Mean ms & P50 ms & P95 ms & Throughput \\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            f"{latex_escape(row['profile'])} & {float(row['average_latency_ms']):.2f} & "
            f"{float(row['p50_latency_ms']):.2f} & {float(row['p95_latency_ms']):.2f} & "
            f"{float(row['throughput_tasks_per_second']):.1f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_figures(metrics: Sequence[Dict[str, Any]]) -> None:
    benchmark = [row for row in metrics if row["dataset"] == "benchmark"]
    write_bar_png(
        FIGURE_DIR / "asr_by_profile.png",
        [float(row["attack_success_rate"]) for row in benchmark],
    )
    write_bar_png(
        FIGURE_DIR / "benign_success_by_profile.png",
        [float(row["benign_task_success_rate"]) for row in benchmark],
        color=(67, 142, 219),
    )
    write_bar_png(
        FIGURE_DIR / "latency_overhead.png",
        normalize([float(row["average_latency_ms"]) for row in benchmark]),
        color=(221, 126, 48),
    )


def write_bar_png(path: Path, values: Sequence[float], color: Tuple[int, int, int] = (42, 110, 79)) -> None:
    width, height = 900, 420
    pixels = bytearray([255, 255, 255] * width * height)
    margin = 50
    chart_w = width - margin * 2
    chart_h = height - margin * 2
    if not values:
        values = [0.0]
    max_value = max(max(values), 1.0)
    bar_w = max(8, chart_w // (len(values) * 2))
    gap = max(4, (chart_w - bar_w * len(values)) // max(len(values), 1))
    for idx, value in enumerate(values):
        x0 = margin + idx * (bar_w + gap)
        bar_h = int((value / max_value) * chart_h)
        y0 = height - margin - bar_h
        draw_rect(pixels, width, height, x0, y0, x0 + bar_w, height - margin, color)
    draw_rect(pixels, width, height, margin - 2, margin, margin, height - margin, (0, 0, 0))
    draw_rect(pixels, width, height, margin, height - margin, width - margin, height - margin + 2, (0, 0, 0))
    path.write_bytes(encode_png(width, height, bytes(pixels)))


def draw_rect(
    pixels: bytearray,
    width: int,
    height: int,
    x0: int,
    y0: int,
    x1: int,
    y1: int,
    color: Tuple[int, int, int],
) -> None:
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(width, x1), min(height, y1)
    for y in range(y0, y1):
        for x in range(x0, x1):
            offset = (y * width + x) * 3
            pixels[offset : offset + 3] = bytes(color)


def encode_png(width: int, height: int, rgb: bytes) -> bytes:
    rows = b"".join(b"\x00" + rgb[y * width * 3 : (y + 1) * width * 3] for y in range(height))
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def normalize(values: Sequence[float]) -> List[float]:
    if not values:
        return []
    minimum = min(values)
    maximum = max(values)
    if maximum == minimum:
        return [0.0 for _ in values]
    return [(value - minimum) / (maximum - minimum) for value in values]


def latex_escape(value: str) -> str:
    return str(value).replace("_", "\\_").replace("%", "\\%")


def format_rate(value: str | float) -> str:
    return f"{float(value) * 100:.1f}\\%"


if __name__ == "__main__":
    raise SystemExit(main())
