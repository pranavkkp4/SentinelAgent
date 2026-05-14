#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
VENV_DIR="$BACKEND_DIR/.venv"
PYTEST_BASETEMP="$BACKEND_DIR/pytest-cache-files-repro"

echo "[SentinelAgent] root: $ROOT_DIR"

if [ ! -d "$VENV_DIR" ]; then
  python -m venv "$VENV_DIR"
fi

if [ -x "$VENV_DIR/bin/python" ]; then
  PYTHON="$VENV_DIR/bin/python"
else
  PYTHON="$VENV_DIR/Scripts/python.exe"
fi

"$PYTHON" -m pip install --upgrade pip setuptools wheel
"$PYTHON" -m pip install -r "$BACKEND_DIR/requirements.txt"

echo "[SentinelAgent] running backend tests"
(cd "$BACKEND_DIR" && "$PYTHON" -m pytest tests -q -p no:cacheprovider --basetemp "$PYTEST_BASETEMP")

echo "[SentinelAgent] generating datasets"
(cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" -m sentinel_agent.benchmark.generator)
(cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" -m sentinel_agent.benchmark.adaptive_attacks)

echo "[SentinelAgent] running evaluation"
(cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" experiments/run_evaluation.py)

echo "[SentinelAgent] running statistical analysis"
(cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" experiments/analyze_results.py)
(cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" experiments/evaluate_classifier.py)

if (cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" -c "from sentinel_agent.agent.llm_agent import provider_from_env; raise SystemExit(0 if provider_from_env().name != 'mock' else 1)"); then
  echo "[SentinelAgent] running optional real LLM evaluation"
  if ! (cd "$ROOT_DIR" && PYTHONPATH="$BACKEND_DIR" "$PYTHON" experiments/run_llm_evaluation.py); then
    echo "[SentinelAgent] optional real LLM evaluation failed or hit provider quota; continuing with deterministic artifacts"
  fi
else
  echo "[SentinelAgent] skipping optional real LLM evaluation; no configured provider key found"
fi

echo "[SentinelAgent] compiling final paper"
(cd "$ROOT_DIR/report" && pdflatex -interaction=nonstopmode -halt-on-error final_report.tex)
(cd "$ROOT_DIR/report" && bibtex final_report)
(cd "$ROOT_DIR/report" && pdflatex -interaction=nonstopmode -halt-on-error final_report.tex)
(cd "$ROOT_DIR/report" && pdflatex -interaction=nonstopmode -halt-on-error final_report.tex)
cp "$ROOT_DIR/report/final_report.pdf" "$ROOT_DIR/report/SentinelAgent.pdf"

echo "[SentinelAgent] outputs:"
echo "- $ROOT_DIR/experiments/results/latest"
echo "- $ROOT_DIR/report/final_report.pdf"
