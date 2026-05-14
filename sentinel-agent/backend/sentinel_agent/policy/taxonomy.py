"""Formal attack-to-tool risk taxonomy for SentinelAgent."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List


class AttackType(str, Enum):
    """Attack classes understood by the policy engine."""

    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    INJECTION = "injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    EXFILTRATION = "exfiltration"
    TOOL_MISUSE = "tool_misuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESTRUCTIVE_ACTION = "destructive_action"
    PERSISTENCE_ATTACK = "persistence_attack"
    OBFUSCATED_ATTACK = "obfuscated_attack"
    MULTI_STEP_ATTACK = "multi_step_attack"
    UNKNOWN = "unknown"


class AttackSource(str, Enum):
    """Where a suspicious instruction or payload entered the agent."""

    USER = "user"
    USER_PROMPT = "user_prompt"
    RETRIEVED_CONTENT = "retrieved_content"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEB_CONTENT = "web_content"
    TOOL_OUTPUT = "tool_output"
    EMAIL_CONTENT = "email_content"
    MEMORY = "memory"
    MEMORY_CONTEXT = "memory_context"
    SYSTEM = "system"
    SYSTEM_INTEGRATION = "system_integration"
    UNKNOWN = "unknown"


class TargetTool(str, Enum):
    """Canonical tool families used in risk mapping."""

    CALCULATOR = "calculator"
    DOCUMENT_SEARCH = "document_search"
    DOCUMENT_RETRIEVER = "document_retriever"
    WEB_FETCH = "web_fetch"
    WEB_SEARCH = "web_search"
    SEND_MESSAGE = "send_message"
    EMAIL_SENDER = "email_sender"
    ANALYZE_DATA = "analyze_data"
    FILE_READER = "file_reader"
    CODE_EXECUTION = "code_execution"
    SHELL_EXECUTOR = "shell_executor"
    DATABASE = "database"
    DATABASE_WRITER = "database_writer"
    MEMORY = "memory"
    MEMORY_WRITER = "memory_writer"
    EXTERNAL_API = "external_api"
    FILE_SYSTEM = "file_system"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Ordinal risk levels for permissions, tools, and policy decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementAction(str, Enum):
    """Possible enforcement outcomes at the tool boundary."""

    ALLOW = "allow"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    ASK_USER_CONFIRMATION = "ask_user_confirmation"
    BLOCK_TOOL_CALL = "block_tool_call"
    BLOCK_SESSION = "block_session"


ATTACK_TYPE_DESCRIPTIONS: Dict[AttackType, str] = {
    AttackType.PROMPT_INJECTION: "Direct instructions that try to override policy or hierarchy.",
    AttackType.INDIRECT_PROMPT_INJECTION: "Instructions hidden in retrieved or third-party content.",
    AttackType.DATA_EXFILTRATION: "Attempts to reveal, transmit, encode, or summarize protected data.",
    AttackType.TOOL_MISUSE: "Attempts to use tools outside the user's benign task intent.",
    AttackType.PRIVILEGE_ESCALATION: "Attempts to obtain authority or permissions the user/tool does not have.",
    AttackType.PERSISTENCE_ATTACK: "Attempts to store malicious instructions for later execution.",
    AttackType.OBFUSCATED_ATTACK: "Attacks hidden through encoding, spacing, typos, markdown, or Unicode.",
    AttackType.MULTI_STEP_ATTACK: "Attacks that split reconnaissance, tool use, and exfiltration across steps.",
}


ATTACK_SOURCE_DESCRIPTIONS: Dict[AttackSource, str] = {
    AttackSource.USER_PROMPT: "Text submitted directly by a user.",
    AttackSource.RETRIEVED_DOCUMENT: "Text introduced through retrieval-augmented context.",
    AttackSource.TOOL_OUTPUT: "Text returned by a tool before subsequent reasoning.",
    AttackSource.WEB_CONTENT: "Untrusted web content fetched during an agent task.",
    AttackSource.EMAIL_CONTENT: "Email body, headers, or attachments processed by an agent.",
    AttackSource.MEMORY_CONTEXT: "Long-term or session memory available to the agent.",
    AttackSource.SYSTEM_INTEGRATION: "Text from connected workflow systems or SaaS integrations.",
}


TARGET_TOOL_DESCRIPTIONS: Dict[TargetTool, str] = {
    TargetTool.CALCULATOR: "Read-only arithmetic or data transformation.",
    TargetTool.WEB_SEARCH: "Read-only web search or fetch.",
    TargetTool.DOCUMENT_RETRIEVER: "Document retrieval over public or private corpora.",
    TargetTool.FILE_READER: "Private local or enterprise file access.",
    TargetTool.EMAIL_SENDER: "Message sending to external or internal recipients.",
    TargetTool.DATABASE_WRITER: "Database mutation capability.",
    TargetTool.MEMORY_WRITER: "Persistent memory or instruction storage.",
    TargetTool.SHELL_EXECUTOR: "Shell, code execution, or operating-system command access.",
    TargetTool.EXTERNAL_API: "External API calls with side effects or data transfer.",
}


def canonical_mappings() -> List[AttackToolMapping]:
    """Representative attack-to-tool mappings used in docs and tests."""
    from .models import AttackToolMapping
    from .permissions import Permission

    return [
        AttackToolMapping(
            AttackType.PROMPT_INJECTION,
            AttackSource.USER_PROMPT,
            TargetTool.CALCULATOR,
            [Permission.READ_PUBLIC],
            RiskLevel.LOW,
            EnforcementAction.ASK_USER_CONFIRMATION,
            "Suspicious text has little tool leverage when only arithmetic is available.",
        ),
        AttackToolMapping(
            AttackType.INDIRECT_PROMPT_INJECTION,
            AttackSource.RETRIEVED_DOCUMENT,
            TargetTool.DOCUMENT_RETRIEVER,
            [Permission.READ_PRIVATE],
            RiskLevel.HIGH,
            EnforcementAction.BLOCK_TOOL_CALL,
            "Retrieved instructions touching private documents can redirect context access.",
        ),
        AttackToolMapping(
            AttackType.DATA_EXFILTRATION,
            AttackSource.WEB_CONTENT,
            TargetTool.EMAIL_SENDER,
            [Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL],
            RiskLevel.HIGH,
            EnforcementAction.BLOCK_TOOL_CALL,
            "External-write tools can turn a leaked secret into an actual disclosure.",
        ),
        AttackToolMapping(
            AttackType.PERSISTENCE_ATTACK,
            AttackSource.MEMORY_CONTEXT,
            TargetTool.MEMORY_WRITER,
            [Permission.MEMORY_WRITE],
            RiskLevel.HIGH,
            EnforcementAction.BLOCK_TOOL_CALL,
            "Injected instructions should not be stored for future agent runs.",
        ),
        AttackToolMapping(
            AttackType.TOOL_MISUSE,
            AttackSource.TOOL_OUTPUT,
            TargetTool.SHELL_EXECUTOR,
            [Permission.EXECUTE_CODE, Permission.WRITE_EXTERNAL],
            RiskLevel.CRITICAL,
            EnforcementAction.BLOCK_SESSION,
            "Code execution gives malicious tool output direct operational leverage.",
        ),
    ]


def taxonomy_table() -> List[Dict[str, str]]:
    """Return canonical mappings as plain dictionaries for API/documentation."""
    return [mapping.to_dict() for mapping in canonical_mappings()]
