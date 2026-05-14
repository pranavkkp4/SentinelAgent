# SentinelAgent Test Report

**Date:** May 13, 2026  
**Project:** SentinelAgent research artifact  
**Status:** Current verification snapshot

## Verification Results

| Area | Result | Notes |
| --- | --- | --- |
| Backend unit and API tests | `72/72` passed | Verified with `python -m pytest tests -q -p no:cacheprovider` |
| Research reproduction script | Passed | `.\scripts\reproduce_paper.ps1 -SkipInstall` completed tests, dataset generation, evaluation, analysis, classifier evaluation, and LaTeX compilation |
| Benchmark generation | Passed | Wrote `experiments/datasets/sentinelagent_benchmark_v1.jsonl` with 500 adversarial and 300 benign scenarios |
| Adaptive attack generation | Passed | Wrote `experiments/datasets/sentinelagent_adaptive_v1.jsonl` with 440 adaptive scenarios |
| Evaluation runner | Passed | Wrote JSONL, CSV, JSON, error-analysis, environment, and manifest outputs under `experiments/results/latest/` |
| Statistical analysis | Passed | Wrote LaTeX tables and PNG figures under `experiments/results/latest/` |
| Classifier evaluation | Passed | Test-split metrics written to `classifier_metrics.json` and `classifier_results.tex` |
| Final report compilation | Passed | `report/final_report.pdf` and `report/SentinelAgent.pdf` generated |
| Frontend | Not rerun | The frontend was not touched by this research upgrade |

## Latest Backend Test Output

```text
72 passed, 3 warnings in 17.22s
```

## Research Outputs

- `experiments/datasets/sentinelagent_benchmark_v1.jsonl`
- `experiments/datasets/sentinelagent_adaptive_v1.jsonl`
- `experiments/datasets/injection_classifier_eval_v1.jsonl`
- `experiments/results/latest/per_task_results.jsonl`
- `experiments/results/latest/aggregate_metrics.csv`
- `experiments/results/latest/aggregate_metrics.json`
- `experiments/results/latest/ablation_table.csv`
- `experiments/results/latest/latency_table.csv`
- `experiments/results/latest/error_analysis.md`
- `experiments/results/latest/environment.json`
- `experiments/results/latest/reproducibility_manifest.json`
- `experiments/results/latest/tables/*.tex`
- `experiments/results/latest/figures/*.png`

## Result Scope

The reported paper results are generated local artifact results. They support bounded claims about the deterministic SentinelAgent policy simulator and generated benchmark, not production security guarantees. The adaptive suite still exposes residual leakage, and the full profile has a high false-positive rate on some benign high-risk tool contexts.
