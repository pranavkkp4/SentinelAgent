"""Shared utilities for deterministic SentinelAgent research scripts."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "results" / "research"

CORE_DEFENSE_CONFIGS = (
    "no-defense",
    "prompt-only",
    "rule-based",
    "ml-assisted",
    "embedding-similarity",
    "llm-as-judge",
    "hybrid",
)
ABLATION_DEFENSE_CONFIGS = (
    "full-sentinelagent",
    "no-ml-classifier",
    "no-rule-guardrails",
    "no-exfiltration-detector",
    "no-tool-risk-classifier",
    "detection-only",
)
DEFENSE_CONFIGS = CORE_DEFENSE_CONFIGS
ALL_DEFENSE_CONFIGS = CORE_DEFENSE_CONFIGS + ABLATION_DEFENSE_CONFIGS
ATTACK_TYPE_ORDER = ("injection", "exfiltration", "tool_misuse", "benign")
DETERMINISTIC_RUN_LABEL = "offline-deterministic-ngram-v1"

RESULT_FIELDNAMES = [
    "case_id",
    "attack_index",
    "run_index",
    "defense_config",
    "attack_name",
    "attack_type",
    "category",
    "difficulty",
    "success",
    "defense_triggered",
    "leaked_secret_count",
    "unsafe_tool_count",
    "unsafe_tools_called",
    "execution_time_ms",
    "payload_sha256",
    "payload",
    "expected_behavior",
    "description",
    "response",
]

METRIC_FIELDNAMES = [
    "defense_config",
    "total_tasks",
    "successful_tasks",
    "total_attacks",
    "blocked_attacks",
    "attack_success_rate",
    "attack_block_rate",
    "leakage_rate",
    "secret_leakage_rate",
    "unsafe_tool_rate",
    "unsafe_tool_invocation_rate",
    "benign_task_success_rate",
    "false_positive_rate",
    "false_negative_rate",
    "precision",
    "recall",
    "f1_score",
    "avg_latency_ms",
    "latency_overhead_ms",
    "throughput_qps",
]

BY_TYPE_FIELDNAMES = [
    "defense_config",
    "attack_type",
    "total_cases",
    "success_count",
    "defense_triggered_count",
    "leakage_events",
    "unsafe_tool_events",
    "success_rate",
    "defense_trigger_rate",
]

COMPARISON_FIELDNAMES = [
    "defense_config",
    "baseline_config",
    "asr_reduction",
    "leakage_reduction",
    "unsafe_tool_reduction",
    "utility_delta",
    "avg_latency_delta_ms",
]


def configure_deterministic_environment() -> None:
    """Force local, repeatable backend behavior before importing SentinelAgent."""

    os.environ["SENTINEL_INJECTION_MODEL_BACKEND"] = "ngram"
    os.environ["SENTINEL_REQUIRE_TRANSFORMER"] = "false"
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


def ensure_backend_importable() -> None:
    configure_deterministic_environment()
    backend_path = str(BACKEND_ROOT)
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)


def ensure_output_dir(output_dir: Path | str = DEFAULT_OUTPUT_DIR) -> Path:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def normalize_defense_configs(
    value: str | Sequence[str],
    allowed_configs: Sequence[str] = ALL_DEFENSE_CONFIGS,
) -> list[str]:
    if isinstance(value, str):
        raw_values = allowed_configs if value.lower() == "all" else value.split(",")
    else:
        raw_values = value

    normalized = [item.strip() for item in raw_values if str(item).strip()]
    unknown = [item for item in normalized if item not in allowed_configs]
    if unknown:
        valid = ", ".join(allowed_configs)
        raise ValueError(f"Unknown defense config(s): {', '.join(unknown)}. Valid values: {valid}")
    return normalized


def stable_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def stable_case_id(defense_config: str, attack_name: str, run_index: int) -> str:
    slug = attack_name.lower().replace(" ", "-")
    slug = "".join(char for char in slug if char.isalnum() or char == "-")
    return f"{defense_config}-{run_index:02d}-{slug}-{stable_hash(defense_config + attack_name + str(run_index), 8)}"


def stable_latency_ms(defense_config: str, attack_type: str, attack_name: str, run_index: int) -> float:
    """Produce deterministic timing values for reproducible artifact diffs."""

    type_base = {
        "injection": 42.0,
        "exfiltration": 47.0,
        "tool_misuse": 53.0,
        "benign": 35.0,
    }.get(attack_type, 40.0)
    defense_overhead = {
        "no-defense": 0.0,
        "prompt-only": 2.0,
        "rule-based": 7.0,
        "ml-assisted": 11.0,
        "embedding-similarity": 13.0,
        "llm-as-judge": 15.0,
        "hybrid": 17.0,
        "full-sentinelagent": 17.0,
        "no-ml-classifier": 8.0,
        "no-rule-guardrails": 10.0,
        "no-exfiltration-detector": 9.0,
        "no-tool-risk-classifier": 9.0,
        "detection-only": 12.0,
    }.get(defense_config, 0.0)
    jitter = int(stable_hash(f"{defense_config}:{attack_type}:{attack_name}", 2), 16) % 7
    return round(type_base + defense_overhead + jitter + ((run_index - 1) * 0.25), 2)


def result_to_row(
    attack: Any,
    result: Any,
    defense_config: str,
    attack_index: int,
    run_index: int,
    include_response: bool = False,
) -> dict[str, Any]:
    leaked_secrets = list(getattr(result, "leaked_secrets", []) or [])
    unsafe_tools = list(getattr(result, "unsafe_tools_called", []) or [])
    payload = getattr(attack, "payload", "")

    return {
        "case_id": stable_case_id(defense_config, attack.name, run_index),
        "attack_index": attack_index,
        "run_index": run_index,
        "defense_config": defense_config,
        "attack_name": attack.name,
        "attack_type": attack.attack_type,
        "category": getattr(attack, "category", "general"),
        "difficulty": attack.difficulty,
        "success": bool(result.success),
        "defense_triggered": bool(result.defense_triggered),
        "leaked_secret_count": len(leaked_secrets),
        "unsafe_tool_count": len(unsafe_tools),
        "unsafe_tools_called": ";".join(unsafe_tools),
        "execution_time_ms": round(float(result.execution_time_ms), 2),
        "payload_sha256": stable_hash(payload, 16),
        "payload": payload,
        "expected_behavior": attack.expected_behavior,
        "description": attack.description,
        "response": getattr(result, "response", "") if include_response else "",
    }


def metric_to_row(defense_config: str, metrics: Any) -> dict[str, Any]:
    return {
        "defense_config": defense_config,
        "total_tasks": metrics.total_tasks,
        "successful_tasks": metrics.successful_tasks,
        "total_attacks": metrics.total_attacks,
        "blocked_attacks": metrics.blocked_attacks,
        "attack_success_rate": round(metrics.attack_success_rate, 3),
        "attack_block_rate": round(1.0 - metrics.attack_success_rate, 3),
        "leakage_rate": round(metrics.leakage_rate, 3),
        "secret_leakage_rate": round(getattr(metrics, "secret_leakage_rate", metrics.leakage_rate), 3),
        "unsafe_tool_rate": round(metrics.unsafe_tool_rate, 3),
        "unsafe_tool_invocation_rate": round(
            getattr(metrics, "unsafe_tool_invocation_rate", metrics.unsafe_tool_rate), 3
        ),
        "benign_task_success_rate": round(metrics.benign_task_success_rate, 3),
        "false_positive_rate": round(metrics.false_positive_rate, 3),
        "false_negative_rate": round(getattr(metrics, "false_negative_rate", 0.0), 3),
        "precision": round(getattr(metrics, "precision", 0.0), 3),
        "recall": round(getattr(metrics, "recall", 0.0), 3),
        "f1_score": round(getattr(metrics, "f1_score", 0.0), 3),
        "avg_latency_ms": round(metrics.avg_latency_ms, 2),
        "latency_overhead_ms": round(getattr(metrics, "latency_overhead_ms", 0.0), 2),
        "throughput_qps": round(getattr(metrics, "throughput_qps", 0.0), 3),
    }


def summarize_by_attack_type(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["defense_config"]), str(row["attack_type"]))].append(row)

    summaries: list[dict[str, Any]] = []
    defense_order = [config for config in ALL_DEFENSE_CONFIGS if any(key[0] == config for key in grouped)]
    for defense_config in defense_order:
        for attack_type in ATTACK_TYPE_ORDER:
            items = grouped.get((defense_config, attack_type), [])
            if not items:
                continue
            total = len(items)
            success_count = sum(1 for row in items if row["success"])
            defense_triggered_count = sum(1 for row in items if row["defense_triggered"])
            leakage_events = sum(1 for row in items if int(row["leaked_secret_count"]) > 0)
            unsafe_tool_events = sum(1 for row in items if int(row["unsafe_tool_count"]) > 0)
            summaries.append({
                "defense_config": defense_config,
                "attack_type": attack_type,
                "total_cases": total,
                "success_count": success_count,
                "defense_triggered_count": defense_triggered_count,
                "leakage_events": leakage_events,
                "unsafe_tool_events": unsafe_tool_events,
                "success_rate": round(success_count / max(total, 1), 3),
                "defense_trigger_rate": round(defense_triggered_count / max(total, 1), 3),
            })
    return summaries


def compare_against_baseline(
    metrics_rows: Sequence[dict[str, Any]],
    baseline_config: str = "no-defense",
) -> list[dict[str, Any]]:
    by_defense = {str(row["defense_config"]): row for row in metrics_rows}
    baseline = by_defense.get(baseline_config)
    if baseline is None:
        return []

    comparisons = []
    for defense_config in by_defense:
        row = by_defense.get(defense_config)
        if row is None:
            continue
        comparisons.append({
            "defense_config": defense_config,
            "baseline_config": baseline_config,
            "asr_reduction": round(float(baseline["attack_success_rate"]) - float(row["attack_success_rate"]), 3),
            "leakage_reduction": round(float(baseline["leakage_rate"]) - float(row["leakage_rate"]), 3),
            "unsafe_tool_reduction": round(float(baseline["unsafe_tool_rate"]) - float(row["unsafe_tool_rate"]), 3),
            "utility_delta": round(float(row["benign_task_success_rate"]) - float(baseline["benign_task_success_rate"]), 3),
            "avg_latency_delta_ms": round(float(row["avg_latency_ms"]) - float(baseline["avg_latency_ms"]), 2),
        })
    return comparisons


async def run_research_suite(
    defense_configs: Sequence[str],
    output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    num_runs: int = 1,
    include_benign: bool = True,
    include_response: bool = False,
    deterministic_timings: bool = True,
) -> dict[str, Any]:
    """Run the existing evaluator/orchestrator and return serializable artifacts."""

    ensure_backend_importable()
    output_path = ensure_output_dir(output_dir)

    from sentinel_agent.agent import AgentOrchestrator
    from sentinel_agent.benchmark.evaluator import EvaluationConfig, SentinelEvaluator
    from sentinel_agent.retrieval import RetrievalSubsystem

    rows: list[dict[str, Any]] = []
    metrics_rows: list[dict[str, Any]] = []
    normalized_defenses = normalize_defense_configs(defense_configs)

    retrieval = RetrievalSubsystem(store_path=str(output_path))
    orchestrator = AgentOrchestrator(retrieval_subsystem=retrieval)
    evaluator = SentinelEvaluator(orchestrator)
    test_suite = evaluator.benchmark.get_test_suite(include_benign=include_benign)

    for defense_config in normalized_defenses:
        profile_results = []
        eval_config = EvaluationConfig(
            defense_config=defense_config,
            num_runs=1,
            enable_logging=False,
            save_results=False,
        )

        for attack_index, attack in enumerate(test_suite, start=1):
            for run_index in range(1, num_runs + 1):
                result = await evaluator.evaluate_attack(attack, eval_config)
                if deterministic_timings:
                    result.execution_time_ms = stable_latency_ms(
                        defense_config,
                        attack.attack_type,
                        attack.name,
                        run_index,
                    )
                profile_results.append(result)
                rows.append(result_to_row(
                    attack=attack,
                    result=result,
                    defense_config=defense_config,
                    attack_index=attack_index,
                    run_index=run_index,
                    include_response=include_response,
                ))

        metrics_rows.append(metric_to_row(defense_config, evaluator.compute_metrics(profile_results)))

    by_type_rows = summarize_by_attack_type(rows)
    baseline_config = "no-defense" if "no-defense" in normalized_defenses else normalized_defenses[0]
    comparison_rows = compare_against_baseline(metrics_rows, baseline_config=baseline_config)
    metadata = {
        "run_label": DETERMINISTIC_RUN_LABEL,
        "deterministic_mode": True,
        "timing_mode": "normalized" if deterministic_timings else "wall_clock",
        "num_runs": num_runs,
        "include_benign": include_benign,
        "defense_configs": normalized_defenses,
        "backend_path": str(BACKEND_ROOT),
        "api_keys_required": False,
    }
    return {
        "metadata": metadata,
        "results": rows,
        "metrics": metrics_rows,
        "by_attack_type": by_type_rows,
        "comparisons": comparison_rows,
    }


def run_research_suite_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_research_suite(**kwargs))


def write_csv(path: Path, rows: Sequence[dict[str, Any]], fieldnames: Sequence[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(fieldnames or (rows[0].keys() if rows else []))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def format_percent(value: Any) -> str:
    return f"{float(value) * 100:.1f}%"


def format_number(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_table(
    rows: Sequence[dict[str, Any]],
    columns: Sequence[tuple[str, str]],
    percent_columns: Iterable[str] = (),
) -> str:
    percent_set = set(percent_columns)
    headers = [label for _, label in columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key, "")
            if key in percent_set and value != "":
                value = format_percent(value)
            elif isinstance(value, float):
                value = f"{value:.2f}"
            cells.append(markdown_escape(value))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def build_summary_markdown(
    title: str,
    artifact: dict[str, Any],
    notes: Sequence[str] = (),
) -> str:
    metadata = artifact.get("metadata", {})
    metrics_rows = artifact.get("metrics", [])
    by_type_rows = artifact.get("by_attack_type", [])
    comparison_rows = artifact.get("comparisons", [])

    lines = [
        f"# {title}",
        "",
        "## Run Configuration",
        "",
        markdown_table(
            [
                {"key": "Run label", "value": metadata.get("run_label", "")},
                {"key": "Defense configs", "value": ", ".join(metadata.get("defense_configs", []))},
                {"key": "Runs per case", "value": metadata.get("num_runs", "")},
                {"key": "API keys required", "value": metadata.get("api_keys_required", False)},
                {"key": "Timing mode", "value": metadata.get("timing_mode", "")},
            ],
            [("key", "Field"), ("value", "Value")],
        ),
        "",
        "## Defense Metrics",
        "",
        markdown_table(
            metrics_rows,
            [
                ("defense_config", "Defense"),
                ("total_tasks", "Tasks"),
                ("attack_success_rate", "ASR"),
                ("attack_block_rate", "Attack Block"),
                ("leakage_rate", "Leakage"),
                ("unsafe_tool_rate", "Unsafe Tool"),
                ("benign_task_success_rate", "Benign Success"),
                ("false_positive_rate", "FPR"),
                ("false_negative_rate", "FNR"),
                ("precision", "Precision"),
                ("recall", "Recall"),
                ("f1_score", "F1"),
                ("avg_latency_ms", "Latency ms"),
                ("latency_overhead_ms", "Overhead ms"),
                ("throughput_qps", "Throughput qps"),
            ],
            percent_columns={
                "attack_success_rate",
                "attack_block_rate",
                "leakage_rate",
                "unsafe_tool_rate",
                "benign_task_success_rate",
                "false_positive_rate",
                "false_negative_rate",
                "precision",
                "recall",
                "f1_score",
            },
        ),
        "",
        "## By Attack Type",
        "",
        markdown_table(
            by_type_rows,
            [
                ("defense_config", "Defense"),
                ("attack_type", "Type"),
                ("total_cases", "Cases"),
                ("success_rate", "Success"),
                ("defense_trigger_rate", "Defense Trigger"),
                ("leakage_events", "Leaks"),
                ("unsafe_tool_events", "Unsafe Tools"),
            ],
            percent_columns={"success_rate", "defense_trigger_rate"},
        ),
    ]

    if comparison_rows:
        lines.extend([
            "",
            "## Baseline Comparison",
            "",
            markdown_table(
                comparison_rows,
                [
                    ("defense_config", "Defense"),
                    ("baseline_config", "Baseline"),
                    ("asr_reduction", "ASR Reduction"),
                    ("leakage_reduction", "Leakage Reduction"),
                    ("unsafe_tool_reduction", "Unsafe Tool Reduction"),
                    ("utility_delta", "Utility Delta"),
                    ("avg_latency_delta_ms", "Latency Delta ms"),
                ],
                percent_columns={
                    "asr_reduction",
                    "leakage_reduction",
                    "unsafe_tool_reduction",
                    "utility_delta",
                },
            ),
        ])

    if notes:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {note}" for note in notes)

    return "\n".join(lines) + "\n"


def write_artifact_bundle(
    prefix: str,
    output_dir: Path | str,
    artifact: dict[str, Any],
    title: str,
    notes: Sequence[str] = (),
) -> dict[str, Path]:
    output_path = ensure_output_dir(output_dir)
    paths = {
        "results_csv": output_path / f"{prefix}_results.csv",
        "metrics_csv": output_path / f"{prefix}_metrics.csv",
        "by_type_csv": output_path / f"{prefix}_by_attack_type.csv",
        "json": output_path / f"{prefix}_results.json",
        "markdown": output_path / f"{prefix}_summary.md",
    }
    write_csv(paths["results_csv"], artifact.get("results", []), RESULT_FIELDNAMES)
    write_csv(paths["metrics_csv"], artifact.get("metrics", []), METRIC_FIELDNAMES)
    write_csv(paths["by_type_csv"], artifact.get("by_attack_type", []), BY_TYPE_FIELDNAMES)
    write_json(paths["json"], artifact)
    paths["markdown"].write_text(build_summary_markdown(title, artifact, notes), encoding="utf-8")
    return paths
