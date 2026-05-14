"""Run deterministic defense-profile ablations for SentinelAgent."""

from __future__ import annotations

import argparse
from pathlib import Path

from research_common import (
    ABLATION_DEFENSE_CONFIGS,
    COMPARISON_FIELDNAMES,
    DEFAULT_OUTPUT_DIR,
    PROJECT_ROOT,
    normalize_defense_configs,
    run_research_suite_sync,
    write_artifact_bundle,
    write_csv,
)


PROFILE_DESCRIPTIONS = {
    "full-sentinelagent": "All SentinelAgent detectors and enforcement gates enabled.",
    "no-ml-classifier": "Injection detection without the supervised ML classifier.",
    "no-rule-guardrails": "Injection detection without deterministic rule guardrails.",
    "no-exfiltration-detector": "Response and tool-argument exfiltration detector disabled.",
    "no-tool-risk-classifier": "Tool-risk classifier disabled after schema validation.",
    "detection-only": "Detectors run and log findings without enforcement.",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelAgent deterministic ablation study.")
    parser.add_argument(
        "--defense-configs",
        default="all",
        help="Comma-separated defense profiles, or all.",
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=1,
        help="Repeat count per ablation case.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for ablation artifacts.",
    )
    parser.add_argument(
        "--include-responses",
        action="store_true",
        help="Include agent responses in CSV/JSON result rows.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.num_runs < 1:
        raise SystemExit("--num-runs must be at least 1")

    try:
        defense_configs = normalize_defense_configs(
            args.defense_configs,
            allowed_configs=ABLATION_DEFENSE_CONFIGS,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    artifact = run_research_suite_sync(
        defense_configs=defense_configs,
        output_dir=args.output_dir,
        num_runs=args.num_runs,
        include_benign=True,
        include_response=args.include_responses,
        deterministic_timings=True,
    )
    artifact["metadata"]["ablation_axis"] = "defense_config"
    artifact["metadata"]["profile_descriptions"] = {
        name: PROFILE_DESCRIPTIONS[name]
        for name in defense_configs
    }

    paths = write_artifact_bundle(
        prefix="ablation_study",
        output_dir=args.output_dir,
        artifact=artifact,
        title="SentinelAgent Defense Ablation Study",
        notes=[
            "Ablations use existing evaluator defense profiles rather than a separate benchmark harness.",
            "no-defense is the default baseline for delta metrics when present.",
        ],
    )
    comparison_path = Path(args.output_dir) / "ablation_study_comparisons.csv"
    write_csv(comparison_path, artifact.get("comparisons", []), COMPARISON_FIELDNAMES)
    paths["comparison_csv"] = comparison_path

    print("Wrote deterministic ablation study artifacts:")
    for path in paths.values():
        print(f"- {path.resolve().relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
