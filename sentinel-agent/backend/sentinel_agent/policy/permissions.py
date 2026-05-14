"""Permission taxonomy and tool-to-risk mapping utilities."""

from __future__ import annotations

from enum import Enum
from typing import Iterable, List, Optional, Set

from .taxonomy import RiskLevel


class Permission(str, Enum):
    """Atomic capabilities that can be granted to tools."""

    READ_NONE = "read_none"
    READ_PUBLIC = "read_public"
    READ_PRIVATE = "read_private"
    NETWORK_READ = "network_read"
    WRITE_PRIVATE = "write_private"
    WRITE_EXTERNAL = "write_external"
    SEND_MESSAGE = "send_message"
    DATABASE_READ = "database_read"
    EXECUTE_CODE = "execute_code"
    DATABASE_WRITE = "database_write"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"


READ_PUBLIC = Permission.READ_PUBLIC
READ_PRIVATE = Permission.READ_PRIVATE
WRITE_EXTERNAL = Permission.WRITE_EXTERNAL
SEND_MESSAGE = Permission.SEND_MESSAGE
EXECUTE_CODE = Permission.EXECUTE_CODE
DATABASE_WRITE = Permission.DATABASE_WRITE
MEMORY_WRITE = Permission.MEMORY_WRITE


RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


RISK_SCORES = {
    RiskLevel.LOW: 0.15,
    RiskLevel.MEDIUM: 0.4,
    RiskLevel.HIGH: 0.7,
    RiskLevel.CRITICAL: 0.9,
}


PERMISSION_RISK = {
    Permission.READ_NONE: RiskLevel.LOW,
    Permission.READ_PUBLIC: RiskLevel.LOW,
    Permission.NETWORK_READ: RiskLevel.MEDIUM,
    Permission.READ_PRIVATE: RiskLevel.HIGH,
    Permission.DATABASE_READ: RiskLevel.HIGH,
    Permission.MEMORY_READ: RiskLevel.HIGH,
    Permission.WRITE_PRIVATE: RiskLevel.HIGH,
    Permission.WRITE_EXTERNAL: RiskLevel.HIGH,
    Permission.SEND_MESSAGE: RiskLevel.HIGH,
    Permission.EXECUTE_CODE: RiskLevel.CRITICAL,
    Permission.DATABASE_WRITE: RiskLevel.CRITICAL,
    Permission.MEMORY_WRITE: RiskLevel.HIGH,
}


TOOL_PERMISSION_MAP = {
    "calculator": {Permission.READ_PUBLIC},
    "calculate": {Permission.READ_PUBLIC},
    "math": {Permission.READ_PUBLIC},
    "document_search": {Permission.READ_PRIVATE},
    "document_retriever": {Permission.READ_PRIVATE},
    "search_documents": {Permission.READ_PRIVATE},
    "retrieval": {Permission.READ_PRIVATE},
    "rag_search": {Permission.READ_PRIVATE},
    "web_fetch": {Permission.READ_PUBLIC},
    "web_search": {Permission.READ_PUBLIC},
    "fetch_url": {Permission.READ_PUBLIC},
    "browser": {Permission.READ_PUBLIC},
    "analyze_data": {Permission.READ_PRIVATE},
    "data_analysis": {Permission.READ_PRIVATE},
    "send_message": {Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL},
    "email_sender": {Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL},
    "email": {Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL},
    "send_email": {Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL},
    "post_webhook": {Permission.WRITE_EXTERNAL},
    "external_api": {Permission.WRITE_EXTERNAL},
    "execute": {Permission.EXECUTE_CODE},
    "code_execution": {Permission.EXECUTE_CODE},
    "shell_executor": {Permission.EXECUTE_CODE, Permission.WRITE_EXTERNAL},
    "exec": {Permission.EXECUTE_CODE},
    "run_command": {Permission.EXECUTE_CODE},
    "shell": {Permission.EXECUTE_CODE},
    "python": {Permission.EXECUTE_CODE},
    "database": {Permission.DATABASE_READ, Permission.READ_PRIVATE},
    "database_writer": {Permission.READ_PRIVATE, Permission.DATABASE_WRITE},
    "database_write": {Permission.READ_PRIVATE, Permission.DATABASE_WRITE},
    "sql_write": {Permission.READ_PRIVATE, Permission.DATABASE_WRITE},
    "memory": {Permission.READ_PRIVATE},
    "memory_writer": {Permission.MEMORY_WRITE},
    "memory_write": {Permission.MEMORY_WRITE},
    "file_reader": {Permission.READ_PRIVATE},
    "file_system": {Permission.READ_PRIVATE},
    "file_write": {Permission.MEMORY_WRITE},
}


TOOL_BASE_RISK = {
    "calculator": RiskLevel.LOW,
    "calculate": RiskLevel.LOW,
    "math": RiskLevel.LOW,
    "web_fetch": RiskLevel.LOW,
    "web_search": RiskLevel.LOW,
    "fetch_url": RiskLevel.LOW,
    "browser": RiskLevel.MEDIUM,
    "document_search": RiskLevel.MEDIUM,
    "document_retriever": RiskLevel.MEDIUM,
    "search_documents": RiskLevel.MEDIUM,
    "retrieval": RiskLevel.MEDIUM,
    "rag_search": RiskLevel.MEDIUM,
    "analyze_data": RiskLevel.MEDIUM,
    "data_analysis": RiskLevel.MEDIUM,
    "send_message": RiskLevel.HIGH,
    "email_sender": RiskLevel.HIGH,
    "email": RiskLevel.HIGH,
    "send_email": RiskLevel.HIGH,
    "post_webhook": RiskLevel.HIGH,
    "external_api": RiskLevel.HIGH,
    "execute": RiskLevel.CRITICAL,
    "code_execution": RiskLevel.CRITICAL,
    "shell_executor": RiskLevel.CRITICAL,
    "exec": RiskLevel.CRITICAL,
    "run_command": RiskLevel.CRITICAL,
    "shell": RiskLevel.CRITICAL,
    "python": RiskLevel.CRITICAL,
    "database_write": RiskLevel.CRITICAL,
    "database_writer": RiskLevel.CRITICAL,
    "sql_write": RiskLevel.CRITICAL,
    "memory_write": RiskLevel.HIGH,
    "memory_writer": RiskLevel.HIGH,
    "file_reader": RiskLevel.MEDIUM,
    "file_system": RiskLevel.HIGH,
    "file_write": RiskLevel.HIGH,
}


def normalize_tool_name(tool_name: object) -> str:
    """Normalize a tool enum, class, or string to a mapping key."""

    value = getattr(tool_name, "value", tool_name)
    return str(value or "").strip().lower().replace("-", "_")


def coerce_permission(permission: object) -> Permission:
    """Convert a permission enum or string to a Permission value."""

    if isinstance(permission, Permission):
        return permission

    value = getattr(permission, "value", permission)
    normalized = str(value or "").strip().lower()
    for candidate in Permission:
        if normalized in {candidate.value, candidate.name.lower()}:
            return candidate
    raise ValueError(f"Unknown permission: {permission!r}")


def get_tool_permissions(tool_name: object, **metadata: object) -> List[Permission]:
    """Return the declared permissions for a tool name."""

    normalized = normalize_tool_name(tool_name)
    if normalized in TOOL_PERMISSION_MAP:
        permissions = set(TOOL_PERMISSION_MAP[normalized])
        if metadata.get("document_class") in {"confidential", "private", "internal"}:
            permissions.add(Permission.READ_PRIVATE)
        return sorted(permissions, key=lambda permission: permission.value)

    if any(token in normalized for token in ("send", "email", "message")):
        return sorted({Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL}, key=lambda permission: permission.value)
    if any(token in normalized for token in ("exec", "shell", "command", "python", "code")):
        return [Permission.EXECUTE_CODE]
    if any(token in normalized for token in ("db_write", "database_write", "sql_write")):
        return sorted({Permission.READ_PRIVATE, Permission.DATABASE_WRITE}, key=lambda permission: permission.value)
    if any(token in normalized for token in ("memory_write", "save_memory", "file_write")):
        return [Permission.MEMORY_WRITE]
    if any(token in normalized for token in ("search", "document", "retriev")):
        return [Permission.READ_PRIVATE]
    if any(token in normalized for token in ("web", "fetch", "http", "url", "browser")):
        return [Permission.READ_PUBLIC]
    if any(token in normalized for token in ("analy", "summar", "extract")):
        return [Permission.READ_PRIVATE]

    return []


def get_permission_risk(permission: object) -> RiskLevel:
    """Return the base risk for a single permission."""

    return PERMISSION_RISK[coerce_permission(permission)]


def max_risk(risks: Iterable[RiskLevel], default: RiskLevel = RiskLevel.LOW) -> RiskLevel:
    """Return the highest ordinal risk level in an iterable."""

    highest = default
    for risk in risks:
        if RISK_ORDER[risk] > RISK_ORDER[highest]:
            highest = risk
    return highest


def compute_tool_risk(
    tool_name: object,
    permissions: Optional[Iterable[object]] = None,
) -> RiskLevel:
    """Compute the static risk implied by a tool and its permissions."""

    normalized = normalize_tool_name(tool_name)
    permission_set = {
        coerce_permission(permission)
        for permission in (get_tool_permissions(normalized) if permissions is None else permissions)
    }
    permission_risk = max_risk(
        (get_permission_risk(permission) for permission in permission_set),
        default=RiskLevel.LOW,
    )
    tool_risk = TOOL_BASE_RISK.get(normalized, RiskLevel.HIGH if not permission_set else RiskLevel.LOW)
    return max_risk((permission_risk, tool_risk))


def risk_score(risk_level: RiskLevel) -> float:
    """Map an ordinal risk level to a stable numeric score."""

    return RISK_SCORES[risk_level]
