# SentinelAgent Failure Analysis

This document summarizes observed and residual failure modes for SentinelAgent under the report threat model.

## Result Labels

Prototype result: On the original 14-payload prototype smoke benchmark, the ML-assisted configuration recorded no successful attacks.

Expanded research result: On the expanded benchmark, SentinelAgent reduces attack success rate under the evaluated threat model.

The two labels are intentionally separate. The prototype smoke harness is the original prototype benchmark. The expanded benchmark statement should not be collapsed into the smaller live metrics endpoint.

## Observed Prototype Failures

| Configuration | Failure pattern | Likely cause |
| --- | --- | --- |
| No defense | Injection and tool-misuse payloads can pass through execution. | No middleware enforcement is active. |
| Prompt-only | Outcomes match the no-defense path in the deterministic prototype. | The prototype does not run a production LLM prompt loop for this baseline. |
| Rule-based | Some semantic or wrapped injection attempts can remain successful. | Fixed signatures and statistical features are brittle against paraphrase. |
| ML-assisted | No successful attacks on the original prototype harness. | The bundled classifier plus policy gates cover the prototype payload set. |

## Residual Failure Classes

- Adaptive paraphrase: attackers can express malicious intent without matching current signatures or training examples.
- Context smuggling: separate benign-looking chunks may combine into a harmful instruction after retrieval.
- Format hiding: markdown tables, comments, metadata fields, alternate encodings, or structured data may hide instructions.
- Benign over-blocking: security, incident-response, or administrative text can resemble attack language.
- Tool realism gap: simulated tools avoid real side effects but do not expose all production tool risks.
- Planner realism gap: deterministic planning does not capture every way a production LLM could respond to authority claims or long-context pressure.
- Metrics persistence gap: live benchmark metrics are cached in memory and are not yet signed, versioned, or repeated with confidence intervals.

## Failure Handling

SentinelAgent records structured security decisions for injection screening, tool-risk gating, and exfiltration scanning. A useful failure triage asks:

1. Did malicious content enter through the user prompt, retrieved context, tool output, or final response?
2. Which detector or policy layer saw the content?
3. Was the decision allow, sanitize, quarantine, or block?
4. Did the evaluation label count the outcome as attack success, false positive, or benign success?
5. Does the failure require a new signature, more training examples, stricter policy, a tool-scope change, or a benchmark-label update?

## Boundary-Based Diagnosis

The attack-to-tool taxonomy gives each failure a concrete location:

| Failure location | Example symptom | Likely follow-up |
| --- | --- | --- |
| Input boundary | Direct override prompt reaches planning. | Add detector examples or tighten input blocking. |
| Context boundary | Retrieved text steers the response as if it were an instruction. | Improve document/web-content screening and chunk-level quarantine. |
| Action boundary | A risky tool destination or argument is allowed. | Tighten permission rules, destination policy, and argument-risk scoring. |
| Release boundary | Canary or sensitive-looking content appears in the final response. | Expand release scanning and covert-channel tests. |
| Evaluation boundary | A benchmark label hides the true failure source. | Relabel the case by attack family, tool boundary, and expected policy response. |

## Production Follow-Up

Before production use, SentinelAgent would need a broader adversarial corpus, repeated benchmark runs, persistent result artifacts, a model-backed planner evaluation, realistic tool integrations with per-tool authorization, and monitoring for post-deployment drift.
