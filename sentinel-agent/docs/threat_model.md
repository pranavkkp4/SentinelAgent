# SentinelAgent Threat Model

This document records the formal threat model used by the SentinelAgent report and evaluation.

## System Boundary

SentinelAgent is a retrieval-augmented, tool-using agent prototype. A user request enters the FastAPI backend, the orchestrator retrieves documents or proposes tool calls, the security middleware checks untrusted content and actions, and the backend returns a safe, sanitized, or blocked response.

The research framing centers on attack-to-tool risk mapping for policy-driven middleware defense in tool-using AI agents. Under this framing, an attack is evaluated by the tool boundary it tries to influence: context admission, action execution, outbound communication, or response release.

The threat model covers content-layer attacks against this pipeline. It does not cover direct compromise of the host, repository, Python runtime, dependency chain, model weights, or cloud infrastructure.

## Protected Assets

| Asset | Security relevance |
| --- | --- |
| System and policy instructions | Hidden instructions define allowed behavior and must not be overridden or disclosed. |
| Private retrieved content | Internal documents may be useful evidence but may contain sensitive information. |
| Canary tokens | Synthetic secrets make leakage observable during evaluation. |
| Tool boundary | Tool execution converts text-level planning into actions and must be policy-gated. |
| Security decisions and logs | Decision records support debugging, regression checks, and failure analysis. |

## Adversary Capabilities

The adversary may:

- Submit direct prompts containing malicious instructions.
- Place malicious instructions in documents later indexed or retrieved by the agent.
- Embed malicious instructions in tool-returned or web-like content.
- Request unsafe tool use, external transmission, or canary disclosure.
- Rephrase attacks using social engineering, fake system tags, markdown, code blocks, encoding language, or administrative framing.

The adversary may not:

- Modify source code or backend configuration.
- Control the Python process, operating system, network infrastructure, or dependencies.
- Access hidden prompts, canary tokens, private logs, or model weights unless the agent leaks them.
- Bypass API authentication or authorization mechanisms outside the prototype scope.

## Trust Boundaries

1. Input boundary: user requests enter the API and are treated as untrusted.
2. Context boundary: retrieved chunks and tool observations are screened before becoming agent context.
3. Action boundary: tool calls are classified and checked before execution.
4. Release boundary: final responses are scanned before returning to the user.

## Attack-to-Tool Risk Mapping

The standalone taxonomy in `sentinel-agent/docs/attack_tool_taxonomy.md` maps attack families to tool permissions and policy responses. The short version is:

| Attack family | Primary tool boundary | Policy response |
| --- | --- | --- |
| Direct prompt injection | Input and planner boundary | Block malicious requests before execution. |
| Indirect document or web injection | Context boundary for `document_search` and `web_fetch` | Quarantine or sanitize untrusted content before it reaches the agent context. |
| Direct and encoded exfiltration | Release boundary | Block or sanitize canary tokens and sensitive-looking output. |
| Tool-mediated exfiltration | Action boundary for `send_message`, `web_fetch`, and future connectors | Score destination and arguments; block high-risk calls. |
| Unauthorized network access | Action boundary for `web_fetch` | Enforce exact-domain and subdomain allowlists. |
| Argument injection and destructive requests | Action boundary for computation, retrieval, and absent privileged tools | Block dangerous arguments and keep privileged tools outside the prototype registry. |

## Security Goals

- G1: Prevent malicious user or retrieved content from being treated as trusted system instructions.
- G2: Block or constrain tool calls whose name, arguments, destination, or context violate policy.
- G3: Prevent canary tokens and sensitive-looking values from appearing in user-visible output or outbound tool arguments.
- G4: Preserve benign task success for normal retrieval, calculation, analysis, allowed web fetch, and simulated message workflows.
- G5: Produce audit-friendly security decisions for allowed, blocked, and sanitized behavior.

## Out-of-Scope Risks

The prototype does not model direct host compromise, malicious dependencies, credential theft outside the agent context, prompt leakage from external providers, real browser exploitation, real email delivery abuse, or attacks against model training data. These risks would require additional controls in a production deployment.

## Result Scope

The evaluated claims apply only under this threat model. The prototype and expanded benchmark results are evidence of reduced attack success under evaluated conditions, not comprehensive protection against all prompt-injection or agent-security failures.
