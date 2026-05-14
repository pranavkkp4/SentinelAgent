"""Permission registry for risk-adaptive tool enforcement."""

from __future__ import annotations

from typing import Dict, Iterable, List

from ..research.taxonomy import RiskLevel, ToolPermission, ToolPermissionProfile


RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

PERMISSION_RISK = {
    ToolPermission.READ_NONE: RiskLevel.LOW,
    ToolPermission.READ_PUBLIC: RiskLevel.LOW,
    ToolPermission.NETWORK_READ: RiskLevel.MEDIUM,
    ToolPermission.READ_PRIVATE: RiskLevel.HIGH,
    ToolPermission.DATABASE_READ: RiskLevel.HIGH,
    ToolPermission.MEMORY_READ: RiskLevel.HIGH,
    ToolPermission.WRITE_PRIVATE: RiskLevel.HIGH,
    ToolPermission.MEMORY_WRITE: RiskLevel.HIGH,
    ToolPermission.WRITE_EXTERNAL: RiskLevel.CRITICAL,
    ToolPermission.SEND_MESSAGE: RiskLevel.CRITICAL,
    ToolPermission.DATABASE_WRITE: RiskLevel.CRITICAL,
    ToolPermission.EXECUTE_CODE: RiskLevel.CRITICAL,
}


TOOL_PERMISSION_REGISTRY: Dict[str, ToolPermissionProfile] = {
    "calculator": ToolPermissionProfile(
        tool_name="calculator",
        permissions=[ToolPermission.READ_NONE],
        default_risk=RiskLevel.LOW,
        description="Pure computation without private reads, network, or side effects.",
    ),
    "web_fetcher": ToolPermissionProfile(
        tool_name="web_fetcher",
        permissions=[ToolPermission.READ_PUBLIC, ToolPermission.NETWORK_READ],
        default_risk=RiskLevel.MEDIUM,
        description="Public network read constrained by the domain allowlist.",
    ),
    "web_fetch": ToolPermissionProfile(
        tool_name="web_fetch",
        permissions=[ToolPermission.READ_PUBLIC, ToolPermission.NETWORK_READ],
        default_risk=RiskLevel.MEDIUM,
        description="Alias for web_fetcher.",
    ),
    "document_search": ToolPermissionProfile(
        tool_name="document_search",
        permissions=[ToolPermission.READ_PRIVATE],
        default_risk=RiskLevel.HIGH,
        description="Private retrieval over indexed documents.",
    ),
    "message_sender": ToolPermissionProfile(
        tool_name="message_sender",
        permissions=[ToolPermission.WRITE_EXTERNAL, ToolPermission.SEND_MESSAGE],
        default_risk=RiskLevel.CRITICAL,
        description="External message write capability.",
    ),
    "send_message": ToolPermissionProfile(
        tool_name="send_message",
        permissions=[ToolPermission.WRITE_EXTERNAL, ToolPermission.SEND_MESSAGE],
        default_risk=RiskLevel.CRITICAL,
        description="Alias for message_sender.",
    ),
    "data_analysis": ToolPermissionProfile(
        tool_name="data_analysis",
        permissions=[ToolPermission.READ_PRIVATE],
        default_risk=RiskLevel.HIGH,
        description="Analysis over private user-provided or retrieved data.",
    ),
    "analyze_data": ToolPermissionProfile(
        tool_name="analyze_data",
        permissions=[ToolPermission.READ_PRIVATE],
        default_risk=RiskLevel.HIGH,
        description="Alias for data_analysis.",
    ),
    "database_read": ToolPermissionProfile(
        tool_name="database_read",
        permissions=[ToolPermission.DATABASE_READ, ToolPermission.READ_PRIVATE],
        default_risk=RiskLevel.HIGH,
        description="Read access to private database rows.",
    ),
    "database_write": ToolPermissionProfile(
        tool_name="database_write",
        permissions=[ToolPermission.DATABASE_WRITE, ToolPermission.WRITE_PRIVATE],
        default_risk=RiskLevel.CRITICAL,
        description="Private database mutation capability.",
    ),
    "shell_executor": ToolPermissionProfile(
        tool_name="shell_executor",
        permissions=[ToolPermission.EXECUTE_CODE],
        default_risk=RiskLevel.CRITICAL,
        description="Code or shell execution capability.",
    ),
}


def normalize_tool_name(tool_name: object) -> str:
    value = getattr(tool_name, "value", tool_name)
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def coerce_permission(permission: object) -> ToolPermission:
    return ToolPermission.coerce(permission)


def get_tool_permissions(tool_name: object) -> List[ToolPermission]:
    """Return declared permissions for a tool, using conservative aliases."""

    normalized = normalize_tool_name(tool_name)
    profile = TOOL_PERMISSION_REGISTRY.get(normalized)
    if profile:
        return list(profile.permissions)

    if any(token in normalized for token in ("shell", "exec", "command", "code")):
        return [ToolPermission.EXECUTE_CODE]
    if any(token in normalized for token in ("send", "email", "message", "webhook")):
        return [ToolPermission.WRITE_EXTERNAL, ToolPermission.SEND_MESSAGE]
    if any(token in normalized for token in ("database_write", "sql_write", "db_write")):
        return [ToolPermission.DATABASE_WRITE, ToolPermission.WRITE_PRIVATE]
    if any(token in normalized for token in ("database", "sql", "db")):
        return [ToolPermission.DATABASE_READ, ToolPermission.READ_PRIVATE]
    if any(token in normalized for token in ("document", "retriev", "search", "file")):
        return [ToolPermission.READ_PRIVATE]
    if any(token in normalized for token in ("web", "fetch", "http", "url", "browser")):
        return [ToolPermission.READ_PUBLIC, ToolPermission.NETWORK_READ]
    if any(token in normalized for token in ("memory_write", "remember", "persist")):
        return [ToolPermission.MEMORY_WRITE]
    if "memory" in normalized:
        return [ToolPermission.MEMORY_READ]
    if any(token in normalized for token in ("calc", "math")):
        return [ToolPermission.READ_NONE]
    return []


def get_tool_risk(tool_name: object) -> RiskLevel:
    """Return the default risk for a tool name."""

    normalized = normalize_tool_name(tool_name)
    profile = TOOL_PERMISSION_REGISTRY.get(normalized)
    if profile:
        return profile.default_risk
    permissions = get_tool_permissions(normalized)
    return classify_permission_risk(permissions) if permissions else RiskLevel.MEDIUM


def has_permission(tool_name: object, permission: object) -> bool:
    """Check whether a tool has a specific permission."""

    required = coerce_permission(permission)
    return required in set(get_tool_permissions(tool_name))


def classify_permission_risk(permissions: Iterable[object]) -> RiskLevel:
    """Classify risk as the highest risk implied by a permission set."""

    highest = RiskLevel.LOW
    for permission in permissions:
        risk = PERMISSION_RISK.get(coerce_permission(permission), RiskLevel.MEDIUM)
        if RISK_ORDER[risk] > RISK_ORDER[highest]:
            highest = risk
    return highest


def explain_tool_permissions(tool_name: object) -> str:
    """Return a compact human-readable explanation for logs and reports."""

    normalized = normalize_tool_name(tool_name)
    permissions = get_tool_permissions(normalized)
    risk = get_tool_risk(normalized)
    if not permissions:
        return f"{normalized}: no registered permissions; default risk {risk.value}"
    permission_text = ", ".join(permission.value for permission in permissions)
    profile = TOOL_PERMISSION_REGISTRY.get(normalized)
    description = f" {profile.description}" if profile and profile.description else ""
    return f"{normalized}: {permission_text}; default risk {risk.value}.{description}"
