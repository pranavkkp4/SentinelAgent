# SentinelAgent Test Report

**Date:** April 9, 2026  
**Project:** SentinelAgent - ML-Based Defense Against Prompt Injection  
**Status:** Current verification snapshot

## Executive Summary

The repository now has an aligned backend test suite, a reproducible frontend verification path, and a smaller benchmark harness than the earliest draft documents claimed. This report reflects the state of the checked-in code after the latest repair pass.

## Verification Results

| Area | Result | Notes |
| --- | --- | --- |
| Backend unit and API tests | `30/30` passed | Verified with `python run_tests.py` and `python -m pytest tests -q -p no:cacheprovider` |
| Security tests | `16/16` passed | Detector, classifier, exfiltration, and middleware checks |
| API tests | `14/14` passed | Routes aligned to the canonical `/api/*` surface, with legacy aliases preserved |
| Frontend lint | Passed | Verified with `cmd /c npm run lint` |
| Frontend production build | Passed | Verified with `cmd /c npm run build` |
| Benchmark payloads | Present | 14 attack payloads and 5 benign tasks in `backend/sentinel_agent/benchmark/attacks.py` |
| Metrics endpoint | Static payload | `GET /api/metrics` still returns a hard-coded comparison response |

## Backend Test Coverage

### API Coverage

- `GET /`
- `GET /health`
- `GET /api/stats`
- `POST /api/query`
- `POST /api/demo/evaluate`
- `GET /api/demo/payloads`
- `GET /api/demo/attack-comparison`
- `POST /api/documents/index`
- `GET /api/documents/search`
- `POST /api/security/screen`
- `GET /api/security/decisions`

### Security Coverage

- Injection detection for benign, direct injection, role-change, and fake-system-tag inputs
- Tool risk classification for safe calculator calls, destructive commands, canary-token exfiltration, and non-allowlisted domains
- Response exfiltration detection for canary tokens and API-key-like patterns
- Middleware integration for retrieval screening, tool evaluation, and response screening

## Latest Backend Test Output

```text
============================= test session starts =============================
collected 30 items

tests/test_api.py ..............                                         [ 46%]
tests/test_security.py ................                                  [100%]

======================= 30 passed, 0 failed =======================
```

## Frontend Verification

The frontend was verified after installing dependencies with `npm ci`.

Successful checks:

- `cmd /c npm run lint`
- `cmd /c npm run build`

The frontend now consumes live backend payloads in the metrics dashboard and attack demo instead of substituting canned success/failure content.

## What This Report Does Not Claim

- It does not claim a large benchmark run beyond the checked-in 14 attack payloads and 5 benign tasks
- It does not claim that `GET /api/metrics` is generated from a live benchmark run
- It does not treat generated build artifacts as source code; those can be excluded from the submission zip if a source-first archive is preferred

## Recommended Submission State

1. Include the workspace root so both `app/` and `sentinel-agent/` are present
2. Keep `sentinel-agent/report/final_report.pdf` and `sentinel-agent/report/proposal.pdf` with the source tree
3. Exclude `app/node_modules`, `app/dist`, `backend/tests/__pycache__`, and `.pytest_cache` from the zip unless your instructor explicitly wants generated artifacts
4. Regenerate the PDF report after any further LaTeX edits
