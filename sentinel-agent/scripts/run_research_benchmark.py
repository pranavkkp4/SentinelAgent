"""Run the deterministic SentinelAgent research benchmark.

This script uses the existing backend evaluator and orchestrator, forces the
portable n-gram detector backend, and writes CSV, JSON, and markdown artifacts
under results/research by default.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from research_common import (
    CORE_DEFENSE_CONFIGS,
    DEFAULT_OUTPUT_DIR,
    PROJECT_ROOT,
    normalize_defense_configs,
    run_research_suite_sync,
    write_artifact_bundle,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelAgent deterministic research benchmark.")
    parser.add_argument(
        "--defense-config",
        default="all",
        help=(
            "Defense profile to evaluate. Use one of "
            "no-defense, prompt-only, rule-based, ml-assisted, "
            "embedding-similarity, llm-as-judge, hybrid, or all."
        ),
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=1,
        help="Repeat count per benchmark case.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for benchmark artifacts.",
    )
    parser.add_argument(
        "--include-responses",
        action="store_true",
        help="Include agent responses in CSV/JSON result rows.",
    )
    parser.add_argument(
        "--wall-clock-timing",
        action="store_true",
        help="Keep measured latencies instead of deterministic normalized timing values.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.num_runs < 1:
        raise SystemExit("--num-runs must be at least 1")

    try:
        defense_configs = normalize_defense_configs(
            args.defense_config,
            allowed_configs=CORE_DEFENSE_CONFIGS,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    artifact = run_research_suite_sync(
        defense_configs=defense_configs,
        output_dir=args.output_dir,
        num_runs=args.num_runs,
        include_benign=True,
        include_response=args.include_responses,
        deterministic_timings=not args.wall_clock_timing,
    )
    paths = write_artifact_bundle(
        prefix="research_benchmark",
        output_dir=args.output_dir,
        artifact=artifact,
        title="SentinelAgent Research Benchmark",
        notes=[
            "The benchmark runs offline and does not require API keys.",
            "Default timing values are normalized for reproducible artifact diffs.",
        ],
    )

    print("Wrote deterministic research benchmark artifacts:")
    for path in paths.values():
        print(f"- {path.resolve().relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
