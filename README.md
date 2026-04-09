# SentinelAgent

Submission and rerun guide for the current workspace.

**Author:** Pranav Kumar Kaliaperumal  
**Institution:** University of Colorado Denver  
**Course:** CSCI 5742 - Cybersecurity Programming  
**Semester:** Spring 2026

## What Is In This Workspace

The repository root contains two separate project trees:

- `sentinel-agent/` for the FastAPI backend, Docker config, tests, and report sources
- `app/` for the React + Vite frontend

If you create the submission zip, include the workspace root so both trees stay together. Zipping `sentinel-agent/` alone will omit the frontend.

## Requirements

Backend:

- Python 3.11 or newer
- `pip`
- Optional: Docker and Docker Compose

Frontend:

- Node.js 20.19.0 or newer
- npm

## Quick Setup

From the workspace root:

```powershell
cd "C:\Users\Pranav\Desktop\CU Denver\Cybersecurity\SentinelAgent"
```

### 1. Backend Setup

```powershell
cd sentinel-agent\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

The backend installs directly from `requirements.txt`. There is no editable-package install (`pip install -e .`) in this repo.

### 2. Frontend Setup

```powershell
cd ..\..\app
npm install
```

The frontend `package.json` expects Node 20.19.0 or newer. The current Vite toolchain is not meant to run on the older Node 18 guidance from the earlier draft.

## Environment Variables

### Backend

Create `sentinel-agent/backend/.env` if you want to override defaults:

```env
INJECTION_THRESHOLD=0.7
RISK_THRESHOLD=0.8
MAX_STEPS=20
LOG_LEVEL=INFO
```

These are the only environment variables currently consumed by `sentinel_agent/config.py`.

### Frontend

Create `app/.env` with the API base URL used by the Vite client:

```env
VITE_API_BASE_URL=http://localhost:8000
```

Use `VITE_API_BASE_URL`, not `VITE_API_URL`.

## Run Locally

### Backend

```powershell
cd sentinel-agent\backend
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```powershell
cd app
npm run dev
```

Open `http://localhost:5173`.

### Full Stack

Run the backend and frontend in separate terminals. The frontend talks to the backend through `VITE_API_BASE_URL`.

## API Surface

The canonical backend routes live under `/api/*`. Backward-compatible aliases still exist for a few older demo, security, and document endpoints, but new work should use the `/api/*` routes listed below.

| Method | Route | Notes |
| --- | --- | --- |
| `GET` | `/` | Service metadata |
| `GET` | `/health` | Health check |
| `GET` | `/api/stats` | System statistics |
| `GET` | `/stats` | Compatibility alias |
| `POST` | `/api/query` | Agent query with optional defense |
| `POST` | `/query` | Compatibility alias |
| `POST` | `/api/demo/evaluate` | Compare a payload with and without defense |
| `GET` | `/api/demo/attack-types` | Demo attack catalog |
| `GET` | `/api/metrics` | Current metrics payload |
| `POST` | `/api/security/screen` | Screen text, tool args, or responses |
| `GET` | `/api/security/decisions` | Security decision summary |
| `POST` | `/api/documents/index` | Index a document using a JSON request body |
| `GET` | `/api/documents/search` | Search indexed documents |

Important detail: `POST /api/documents/index` expects JSON with `content`, `source`, and optional `metadata`.

Example:

```powershell
curl -X POST "http://localhost:8000/api/documents/index" `
  -H "Content-Type: application/json" `
  -d "{\"content\":\"Test document\",\"source\":\"test.txt\",\"metadata\":{\"category\":\"test\"}}"
```

## Testing

Backend security tests:

```powershell
cd sentinel-agent\backend
python -m pytest tests\test_security.py -q
```

API tests:

```powershell
python -m pytest tests\test_api.py -q
```

Current status:

- `python run_tests.py` currently passes all 30 backend tests
- `tests/test_security.py` contains 16 security-focused checks
- `tests/test_api.py` contains 14 API checks aligned with the current `/api/*` surface
- `cmd /c npm run lint` passes in `app/`
- `cmd /c npm run build` passes in `app/`

The older README claims about mismatched API routes and stale test counts were from earlier drafts and should not be treated as the current state of the repo.

## Docker

From `sentinel-agent/`:

```powershell
docker-compose up --build
```

The compose health check uses Python's standard library, so it does not depend on `curl`.

To stop the stack:

```powershell
docker-compose down
```

## PDF Regeneration

The report sources live in `sentinel-agent/report/`.

To regenerate the proposal and final PDF files:

```powershell
cd sentinel-agent\report
pdflatex -interaction=nonstopmode -halt-on-error proposal.tex
pdflatex -interaction=nonstopmode -halt-on-error proposal.tex
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
pdflatex -interaction=nonstopmode -halt-on-error final_report.tex
```

If `latexmk` is installed, it can replace the repeated manual runs:

```powershell
latexmk -pdf proposal.tex
latexmk -pdf final_report.tex
```

## Packaging Notes

- Include both `app/` and `sentinel-agent/` in the final zip
- Exclude generated folders such as `app\node_modules`, `app\dist`, `backend\tests\__pycache__`, and `.pytest_cache` if you want a source-first archive
- The repository currently does not include a `LICENSE` file
- `gunicorn` is not required by the current backend setup

## Known Limitations

- The benchmark suite in `backend/sentinel_agent/benchmark/attacks.py` currently contains 14 attack payloads and 5 benign tasks, not the larger draft counts from the older documentation
- `GET /api/metrics` currently returns a hard-coded comparison payload
- The frontend and backend documentation should be treated as a single package because the frontend lives outside `sentinel-agent/`
- The old stock Vite README in `app/README.md` is not the authoritative project guide

## Submission Checklist

1. Verify both project trees are present in the zip
2. Regenerate `report/proposal.pdf` and `report/final_report.pdf` after any LaTeX edits
3. Confirm the README matches the current `app/` and `sentinel-agent/backend/` layout
4. Double-check that no generated artifacts or `__pycache__` directories are included unless your instructor explicitly wants them
