# Attack-to-Tool Risk Taxonomy

SentinelAgent now treats prompt-injection risk as a relationship between text, source, tool capability, and policy. A malicious instruction is not equally dangerous in every setting. The same sentence is lower risk when the agent can only use a calculator, but it becomes high or critical risk when the agent can read private files, send messages, write memory, mutate databases, call external APIs, or execute code.

We present a prototype and evaluation of policy-driven middleware for reducing attack success under a defined threat model.

## Taxonomy Fields

| Field | Values |
| --- | --- |
| `attack_type` | `PROMPT_INJECTION`, `INDIRECT_PROMPT_INJECTION`, `DATA_EXFILTRATION`, `TOOL_MISUSE`, `PRIVILEGE_ESCALATION`, `PERSISTENCE_ATTACK`, `OBFUSCATED_ATTACK`, `MULTI_STEP_ATTACK` |
| `attack_source` | `USER_PROMPT`, `RETRIEVED_DOCUMENT`, `TOOL_OUTPUT`, `WEB_CONTENT`, `EMAIL_CONTENT`, `MEMORY_CONTEXT`, `SYSTEM_INTEGRATION` |
| `target_tool` | `CALCULATOR`, `WEB_SEARCH`, `DOCUMENT_RETRIEVER`, `FILE_READER`, `EMAIL_SENDER`, `DATABASE_WRITER`, `MEMORY_WRITER`, `SHELL_EXECUTOR`, `EXTERNAL_API` |
| `risk_level` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `enforcement_action` | `ALLOW`, `ALLOW_WITH_REDACTION`, `ASK_USER_CONFIRMATION`, `BLOCK_TOOL_CALL`, `BLOCK_SESSION` |

## Permission Model

| Permission | Risk | Example tools |
| --- | --- | --- |
| `READ_PUBLIC` | Low | calculator, public web search |
| `READ_PRIVATE` | High | private file reader, restricted document retriever |
| `WRITE_EXTERNAL` | High | email sender, external API |
| `SEND_MESSAGE` | High | email sender |
| `EXECUTE_CODE` | Critical | shell executor, high-impact API executor |
| `DATABASE_WRITE` | High | database writer |
| `MEMORY_WRITE` | High | memory writer |

Prompt injection alone is not equally dangerous in all contexts. Its risk depends on the tool permissions available to the agent.

## Example Attack-to-Tool Mappings

| Attack | Source | Tool | Permissions | Risk | Action |
| --- | --- | --- | --- | --- | --- |
| Direct injection | User prompt | Calculator | `READ_PUBLIC` | Low | Ask user confirmation |
| Indirect injection | Retrieved document | Private document retriever | `READ_PRIVATE` | High | Block tool call |
| Exfiltration | Web content | Email sender | `SEND_MESSAGE`, `WRITE_EXTERNAL` | High | Block tool call |
| Persistence | Memory context | Memory writer | `MEMORY_WRITE` | High | Block tool call |
| Tool misuse | Tool output | Shell executor | `EXECUTE_CODE`, `WRITE_EXTERNAL` | Critical | Block session |

## Policy Interpretation

The detector estimates whether text is benign, suspicious, or malicious. The policy engine then asks a different question: what can the agent do if it follows that text? Low-risk tools can sometimes proceed after confirmation. External-write, private-read, memory-write, database-write, and code-execution tools require stronger enforcement because the consequences change.

The current implementation is a prototype. It does not solve prompt injection and does not claim universal protection. It provides a reproducible framework for studying how middleware decisions change when the same attack is paired with different tool permissions.
