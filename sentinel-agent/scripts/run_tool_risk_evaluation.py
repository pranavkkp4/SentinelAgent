"""Run the offline SentinelAgent tool-risk evaluation."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "results" / "tool_risk"


def configure_offline_environment() -> None:
    """Keep the benchmark local and API-key free."""

    os.environ.setdefault("SENTINEL_ENABLE_LLM_EVAL", "false")
    os.environ.setdefault("SENTINEL_INJECTION_MODEL_BACKEND", "ngram")
    os.environ.setdefault("SENTINEL_REQUIRE_TRANSFORMER", "false")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


def ensure_backend_importable() -> None:
    configure_offline_environment()
    backend_path = str(BACKEND_ROOT)
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SentinelAgent offline tool-risk benchmark."
    )
    parser.add_argument(
        "--defense-configs",
        default="ml-assisted",
        help="Comma-separated defense profiles, or all.",
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=1,
        help="Repeat count per tool/risk/case pair.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for CSV, JSON, and Markdown artifacts.",
    )
    parser.add_argument(
        "--attack-only",
        action="store_true",
        help="Skip benign comparison cases.",
    )
    parser.add_argument(
        "--wall-clock-timing",
        action="store_true",
        help="Use measured local timings instead of deterministic normalized timings.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.num_runs < 1:
        raise SystemExit("--num-runs must be at least 1")

    ensure_backend_importable()

    from sentinel_agent.benchmark.tool_risk_benchmark import (
        normalize_defense_configs,
        run_tool_risk_suite,
        write_tool_risk_artifacts,
    )

    try:
        defense_configs = normalize_defense_configs(args.defense_configs)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    artifact = run_tool_risk_suite(
        defense_configs=defense_configs,
        num_runs=args.num_runs,
        include_benign=not args.attack_only,
        deterministic_timings=not args.wall_clock_timing,
    )
    paths = write_tool_risk_artifacts(artifact, args.output_dir)

    print("Wrote offline tool-risk evaluation artifacts:")
    for path in paths.values():
        print(f"- {path.resolve().relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
