# SentinelAgent Research Artifact

This artifact reproduces the local, deterministic evaluation for:

**SentinelAgent: Risk-Adaptive Policy Enforcement for Tool-Using LLM Agents Under Indirect Prompt Injection**

## System Requirements

- Python 3.11 or newer
- `pip` and virtual environment support
- A LaTeX distribution with `pdflatex` and BibTeX
- Optional: Docker with Docker Compose

No external LLM API key is required. The default mode uses deterministic policy simulation and the mock LLM provider.

Real LLM validation is optional. The current paper artifact includes a small Gemini-backed run using `gemini-2.5-flash-lite`; reproducing that run requires valid Gemini API keys and available provider quota.

## Expected Runtime

On a laptop-class machine, the default reproduction run usually takes a few minutes:

- dependency install: environment-dependent
- backend tests: under 1 minute after dependencies are installed
- dataset generation and evaluation: under 1 minute
- statistical analysis and classifier evaluation: under 1 minute
- LaTeX compilation: under 1 minute

## Setup

From the `sentinel-agent` directory:

```powershell
python -m venv backend\.venv
.\backend\.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel
.\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

On macOS/Linux:

```bash
python -m venv backend/.venv
backend/.venv/bin/python -m pip install --upgrade pip setuptools wheel
backend/.venv/bin/python -m pip install -r backend/requirements.txt
```

## Exact Reproduction Commands

Windows PowerShell:

```powershell
cd sentinel-agent
.\scripts\reproduce_paper.ps1
```

macOS/Linux:

```bash
cd sentinel-agent
bash scripts/reproduce_paper.sh
```

Optional Gemini-backed validation, after placing keys in an ignored `.env` file:

```env
SENTINEL_AGENT_MODE=llm
SENTINEL_LLM_PROVIDER=gemini
SENTINEL_LLM_MODEL=gemini-2.5-flash-lite
GEMINI_API_KEY=<key>
GEMINI_API_KEY_2=<optional-second-key>
GEMINI_API_KEY_3=<optional-third-key>
```

```powershell
python experiments\run_llm_evaluation.py
```

Docker:

```bash
cd sentinel-agent
docker compose -f docker-compose.research.yml up --build
```

## Expected Outputs

The reproduction scripts write:

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
- `report/final_report.pdf`

When the optional Gemini validation runs, it also writes:

- `experiments/results/latest/llm_gemini_results.jsonl`
- `experiments/results/latest/llm_gemini_metrics.json`
- `experiments/results/latest/llm_gemini_metrics.csv`
- `experiments/results/latest/tables/gemini_results.tex`
- `experiments/results/latest/figures/gemini_real_eval.png`

## Inspecting Per-Task Failures

Open `experiments/results/latest/per_task_results.jsonl` and filter rows where:

- `profile == "full_sentinelagent"`
- `attack_success == true`, or
- `secret_leaked == true`, or
- `false_positive == true`

The summary file `experiments/results/latest/error_analysis.md` lists the first residual full-profile failures.

## Regenerating Paper Tables

Run:

```powershell
.\backend\.venv\Scripts\python.exe experiments\run_evaluation.py
.\backend\.venv\Scripts\python.exe experiments\analyze_results.py
.\backend\.venv\Scripts\python.exe experiments\evaluate_classifier.py
```

Then rebuild the paper:

```powershell
cd report
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
bibtex final_report
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
```

## Real LLM Mode

The artifact does not require real LLM calls. To evaluate with Gemini, set the following in an ignored `.env` file or in your shell:

```powershell
$env:SENTINEL_AGENT_MODE = "llm"
$env:SENTINEL_LLM_PROVIDER = "gemini"
$env:SENTINEL_LLM_MODEL = "gemini-2.5-flash-lite"
$env:GEMINI_API_KEY = "<key>"
$env:GEMINI_API_KEY_2 = "<optional-second-key>"
$env:GEMINI_API_KEY_3 = "<optional-third-key>"
```

SentinelAgent rotates Gemini keys during the real-model validation so short quota windows do not discard completed rows. Without an API key, SentinelAgent falls back to the mock provider. The implementation also keeps an OpenAI-compatible provider path for future experiments through `SENTINEL_LLM_PROVIDER=openai` and `OPENAI_API_KEY`.

## Known Limitations

- The benchmark is generated and deterministic, not a deployment trace.
- The default evaluation does not call a real LLM planner; the Gemini-backed validation is intentionally small and quota-dependent.
- The adaptive attack results show residual leakage under the current policy simulator.
- The false-positive rate is high for some conservative tool-confirmation policies.
- Simulated tools avoid real external side effects; production tools would require stronger authorization and sandboxing.
