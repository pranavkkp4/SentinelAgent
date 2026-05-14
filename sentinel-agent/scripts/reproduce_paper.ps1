param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Backend = Join-Path $Root "backend"
$Venv = Join-Path $Backend ".venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$PytestBaseTemp = Join-Path $Backend "pytest-cache-files-repro"

function Assert-LastCommand {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[SentinelAgent] root: $Root"

if (-not (Test-Path $Python)) {
    python -m venv $Venv
    Assert-LastCommand "Create virtual environment"
}

if (-not $SkipInstall) {
    & $Python -m pip install --upgrade pip setuptools wheel
    Assert-LastCommand "Install pip tooling"
    & $Python -m pip install -r (Join-Path $Backend "requirements.txt")
    Assert-LastCommand "Install backend requirements"
}

Write-Host "[SentinelAgent] running backend tests"
Push-Location $Backend
& $Python -m pytest tests -q -p no:cacheprovider --basetemp $PytestBaseTemp
Assert-LastCommand "Backend tests"
Pop-Location

Write-Host "[SentinelAgent] generating datasets"
Push-Location $Root
$OldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = $Backend
& $Python -m sentinel_agent.benchmark.generator
Assert-LastCommand "Benchmark generation"
& $Python -m sentinel_agent.benchmark.adaptive_attacks
Assert-LastCommand "Adaptive attack generation"

Write-Host "[SentinelAgent] running evaluation"
& $Python experiments\run_evaluation.py
Assert-LastCommand "Evaluation"

Write-Host "[SentinelAgent] running statistical analysis"
& $Python experiments\analyze_results.py
Assert-LastCommand "Statistical analysis"
& $Python experiments\evaluate_classifier.py
Assert-LastCommand "Classifier evaluation"

& $Python -c "import sys; sys.path.insert(0, r'$Backend'); from sentinel_agent.agent.llm_agent import provider_from_env; raise SystemExit(0 if provider_from_env().name != 'mock' else 1)"
if ($LASTEXITCODE -eq 0) {
    Write-Host "[SentinelAgent] running optional real LLM evaluation"
    & $Python experiments\run_llm_evaluation.py
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Optional real LLM evaluation failed or hit provider quota; continuing with deterministic artifacts."
        $global:LASTEXITCODE = 0
    }
} else {
    Write-Host "[SentinelAgent] skipping optional real LLM evaluation; no configured provider key found"
    $global:LASTEXITCODE = 0
}
$env:PYTHONPATH = $OldPythonPath
Pop-Location

Write-Host "[SentinelAgent] compiling final paper"
Push-Location (Join-Path $Root "report")
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
Assert-LastCommand "First LaTeX compile"
bibtex final_report
Assert-LastCommand "BibTeX compile"
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
Assert-LastCommand "Second LaTeX compile"
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
Assert-LastCommand "Third LaTeX compile"
Copy-Item -Force final_report.pdf SentinelAgent.pdf
Pop-Location

Write-Host "[SentinelAgent] outputs:"
Write-Host "- $(Join-Path $Root 'experiments\results\latest')"
Write-Host "- $(Join-Path $Root 'report\final_report.pdf')"
