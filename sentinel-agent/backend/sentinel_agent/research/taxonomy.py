"""Formal threat and enforcement taxonomy for SentinelAgent research.

The taxonomy separates where an attack enters the agent, what it tries to
accomplish, which boundary it targets, and which tool permissions give it
operational leverage. The dataclasses are intentionally small JSON-friendly
records so benchmark rows, policy decisions, and paper tables can share the
same vocabulary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional


class _SerializableEnum(str, Enum):
    """Enum with stable lowercase values and tolerant string coercion."""

    @classmethod
    def coerce(cls, value: object) -> "_SerializableEnum":
        if isinstance(value, cls):
            return value
        raw = getattr(value, "value", value)
        normalized = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
        for candidate in cls:
            if normalized in {candidate.value, candidate.name.lower()}:
                return candidate
        valid = ", ".join(item.value for item in cls)
        raise ValueError(f"Unknown {cls.__name__}: {value!r}. Expected one of: {valid}")


class AttackSource(_SerializableEnum):
    USER_PROMPT = "user_prompt"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEB_CONTENT = "web_content"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    MULTI_TURN_CONTEXT = "multi_turn_context"


class AttackGoal(_SerializableEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    SECRET_EXFILTRATION = "secret_exfiltration"
    UNSAFE_TOOL_USE = "unsafe_tool_use"
    POLICY_BYPASS = "policy_bypass"
    PERSISTENCE = "persistence"
    DATA_CORRUPTION = "data_corruption"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class TargetBoundary(_SerializableEnum):
    INPUT_SCREENING = "input_screening"
    RETRIEVAL_CONTEXT = "retrieval_context"
    AGENT_PLANNER = "agent_planner"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    FINAL_RESPONSE = "final_response"


class ToolPermission(_SerializableEnum):
    READ_NONE = "read_none"
    READ_PUBLIC = "read_public"
    READ_PRIVATE = "read_private"
    NETWORK_READ = "network_read"
    WRITE_PRIVATE = "write_private"
    WRITE_EXTERNAL = "write_external"
    SEND_MESSAGE = "send_message"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    EXECUTE_CODE = "execute_code"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"


class RiskLevel(_SerializableEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementAction(_SerializableEnum):
    ALLOW = "allow"
    ALLOW_WITH_MONITORING = "allow_with_monitoring"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    REQUIRE_USER_CONFIRMATION = "require_user_confirmation"
    BLOCK_TOOL_CALL = "block_tool_call"
    BLOCK_RESPONSE = "block_response"
    BLOCK_SESSION = "block_session"


def _enum_list(values: Optional[Iterable[object]], enum_cls: type[_SerializableEnum]) -> List[_SerializableEnum]:
    return [enum_cls.coerce(value) for value in (values or [])]


@dataclass(frozen=True)
class AttackScenario:
    """One labeled attack or benign-equivalent scenario."""

    scenario_id: str
    attack_source: AttackSource
    attack_goal: AttackGoal
    target_boundary: TargetBoundary
    tool_context: str
    required_tool_permissions: List[ToolPermission]
    expected_enforcement_action: EnforcementAction
    difficulty: str
    payload: str
    benign_equivalent_task: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attack_source", AttackSource.coerce(self.attack_source))
        object.__setattr__(self, "attack_goal", AttackGoal.coerce(self.attack_goal))
        object.__setattr__(self, "target_boundary", TargetBoundary.coerce(self.target_boundary))
        object.__setattr__(
            self,
            "required_tool_permissions",
            _enum_list(self.required_tool_permissions, ToolPermission),
        )
        object.__setattr__(
            self,
            "expected_enforcement_action",
            EnforcementAction.coerce(self.expected_enforcement_action),
        )

    def to_dict(self) -> Dict[str, Any]:
        row = asdict(self)
        row["attack_source"] = self.attack_source.value
        row["attack_goal"] = self.attack_goal.value
        row["target_boundary"] = self.target_boundary.value
        row["required_tool_permissions"] = [
            permission.value for permission in self.required_tool_permissions
        ]
        row["expected_enforcement_action"] = self.expected_enforcement_action.value
        return row

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> "AttackScenario":
        return cls(
            scenario_id=str(row["scenario_id"]),
            attack_source=AttackSource.coerce(row["attack_source"]),
            attack_goal=AttackGoal.coerce(row["attack_goal"]),
            target_boundary=TargetBoundary.coerce(row["target_boundary"]),
            tool_context=str(row["tool_context"]),
            required_tool_permissions=_enum_list(
                row.get("required_tool_permissions", row.get("required_permissions", [])),
                ToolPermission,
            ),
            expected_enforcement_action=EnforcementAction.coerce(
                row["expected_enforcement_action"]
            ),
            difficulty=str(row["difficulty"]),
            payload=str(row["payload"]),
            benign_equivalent_task=str(
                row.get("benign_equivalent_task", row.get("benign_task", ""))
            ),
            metadata=dict(row.get("metadata", {})),
        )


@dataclass(frozen=True)
class ToolPermissionProfile:
    """Static permission profile for one tool context."""

    tool_name: str
    permissions: List[ToolPermission]
    default_risk: RiskLevel
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", _enum_list(self.permissions, ToolPermission))
        object.__setattr__(self, "default_risk", RiskLevel.coerce(self.default_risk))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "permissions": [permission.value for permission in self.permissions],
            "default_risk": self.default_risk.value,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyDecisionRecord:
    """Serializable policy decision emitted by the research policy engine."""

    allow: bool
    action: EnforcementAction
    risk_level: RiskLevel
    confidence: float
    reasons: List[str] = field(default_factory=list)
    triggered_rules: List[str] = field(default_factory=list)
    permissions_considered: List[ToolPermission] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    requires_user_confirmation: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", EnforcementAction.coerce(self.action))
        object.__setattr__(self, "risk_level", RiskLevel.coerce(self.risk_level))
        object.__setattr__(
            self,
            "permissions_considered",
            _enum_list(self.permissions_considered, ToolPermission),
        )
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow": self.allow,
            "action": self.action.value,
            "risk_level": self.risk_level.value,
            "confidence": round(self.confidence, 3),
            "reasons": list(self.reasons),
            "triggered_rules": list(self.triggered_rules),
            "permissions_considered": [
                permission.value for permission in self.permissions_considered
            ],
            "sanitized_content": self.sanitized_content,
            "requires_user_confirmation": self.requires_user_confirmation,
            "metadata": dict(self.metadata),
        }
