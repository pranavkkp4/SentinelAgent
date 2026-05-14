"""Policy request, context, mapping, and decision models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .permissions import Permission, coerce_permission, get_tool_permissions
from .taxonomy import AttackSource, AttackType, EnforcementAction, RiskLevel, TargetTool


RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def _coerce_enum(enum_cls: type, value: object, default: object):
    """Coerce strings to enum values while accepting enum instances."""

    if isinstance(value, enum_cls):
        return value

    raw = getattr(value, "value", value)
    normalized = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    for candidate in enum_cls:
        if normalized in {candidate.value, candidate.name.lower()}:
            return candidate
    return default


def coerce_attack_type(value: object) -> AttackType:
    """Coerce user input into an AttackType."""

    return _coerce_enum(AttackType, value, AttackType.UNKNOWN)


def coerce_attack_source(value: object) -> AttackSource:
    """Coerce user input into an AttackSource."""

    return _coerce_enum(AttackSource, value, AttackSource.UNKNOWN)


def coerce_target_tool(value: object) -> TargetTool:
    """Coerce user input into a TargetTool."""

    coerced = _coerce_enum(TargetTool, value, TargetTool.UNKNOWN)
    if coerced is not TargetTool.UNKNOWN:
        return coerced

    raw = str(getattr(value, "value", value) or "").strip().lower().replace("-", "_")
    if any(token in raw for token in ("calc", "math")):
        return TargetTool.CALCULATOR
    if any(token in raw for token in ("send", "email", "message")):
        return TargetTool.SEND_MESSAGE
    if any(token in raw for token in ("web", "fetch", "browser", "url")):
        return TargetTool.WEB_FETCH
    if any(token in raw for token in ("document", "retriev", "search")):
        return TargetTool.DOCUMENT_SEARCH
    if any(token in raw for token in ("exec", "shell", "command", "python", "code")):
        return TargetTool.CODE_EXECUTION
    if any(token in raw for token in ("database", "sql", "db")):
        return TargetTool.DATABASE
    if "memory" in raw:
        return TargetTool.MEMORY
    if any(token in raw for token in ("api", "webhook", "post")):
        return TargetTool.EXTERNAL_API
    if any(token in raw for token in ("file", "fs", "path")):
        return TargetTool.FILE_SYSTEM
    if any(token in raw for token in ("analy", "summar", "extract")):
        return TargetTool.ANALYZE_DATA
    return TargetTool.UNKNOWN


@dataclass(frozen=True)
class AttackToolMapping:
    """Canonical relationship between an attack class and tool capability."""

    attack_type: AttackType
    attack_source: AttackSource
    target_tool: TargetTool
    tool_permissions: List[Permission]
    risk_level: RiskLevel
    enforcement_action: EnforcementAction
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize a mapping for reports, APIs, or tests."""

        return {
            "attack_type": self.attack_type.value,
            "attack_source": self.attack_source.value,
            "target_tool": self.target_tool.value,
            "tool_permissions": [permission.value for permission in self.tool_permissions],
            "risk_level": self.risk_level.value,
            "enforcement_action": self.enforcement_action.value,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class PolicyContext:
    """Backward-compatible context object for policy decisions."""

    detector_score: float = 0.0
    detector_label: str = ""
    detector_scores: Mapping[str, float] = field(default_factory=dict)
    attack_type: object = AttackType.BENIGN
    attack_source: object = AttackSource.USER_PROMPT
    target_tool: object = TargetTool.UNKNOWN
    tool_permissions: Optional[Iterable[object]] = None
    user_intent: object = "benign"
    user_intent_aligned: Optional[bool] = None
    private_data_involved: bool = False
    contains_private_data: Optional[bool] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "PolicyContext":
        """Return a context with enums, scores, and permissions normalized."""

        private_data = (
            self.private_data_involved
            if self.contains_private_data is None
            else bool(self.contains_private_data)
        )
        intent = self.user_intent
        if self.user_intent_aligned is not None:
            intent = "explicit" if self.user_intent_aligned else "ambiguous"
        detector_scores = normalize_detector_scores(self.detector_scores)
        if self.detector_score and not detector_scores:
            detector_scores = {"detector": clamp_score(self.detector_score)}
        permissions = (
            freeze_permissions(self.tool_permissions)
            if self.tool_permissions is not None
            else freeze_permissions(get_tool_permissions(coerce_target_tool(self.target_tool)))
        )

        return PolicyContext(
            detector_score=clamp_score(self.detector_score),
            detector_label=str(self.detector_label or ""),
            detector_scores=detector_scores,
            attack_type=coerce_attack_type(self.attack_type),
            attack_source=coerce_attack_source(self.attack_source),
            target_tool=coerce_target_tool(self.target_tool),
            tool_permissions=permissions,
            user_intent=intent,
            user_intent_aligned=self.user_intent_aligned,
            private_data_involved=private_data,
            contains_private_data=private_data,
            metadata=dict(self.metadata),
        )


@dataclass(frozen=True)
class PolicyRequest:
    """Inputs needed to decide whether a tool call may proceed."""

    detector_scores: Mapping[str, float] = field(default_factory=dict)
    attack_type: AttackType = AttackType.BENIGN
    attack_source: AttackSource = AttackSource.USER_PROMPT
    target_tool: TargetTool = TargetTool.UNKNOWN
    permissions: Optional[Iterable[Permission]] = None
    user_intent: object = "benign"
    contains_private_data: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Structured output from the policy engine."""

    action: EnforcementAction
    risk_level: RiskLevel
    risk_score: float = 0.0
    reasons: tuple[str, ...] = field(default_factory=tuple)
    attack_type: AttackType = AttackType.UNKNOWN
    attack_source: AttackSource = AttackSource.UNKNOWN
    target_tool: TargetTool = TargetTool.UNKNOWN
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    detector_scores: Mapping[str, float] = field(default_factory=dict)
    requires_redaction: bool = False
    reason: str = ""
    confidence: float = 0.0
    mapping: Optional[AttackToolMapping] = None
    detector_score: float = 0.0
    private_data_involved: bool = False

    @property
    def allowed(self) -> bool:
        """Whether the tool call may proceed immediately."""

        return self.action in {
            EnforcementAction.ALLOW,
            EnforcementAction.ALLOW_WITH_REDACTION,
        }

    @property
    def blocked(self) -> bool:
        """Whether the request is blocked rather than delayed for confirmation."""

        return self.action in {
            EnforcementAction.BLOCK_TOOL_CALL,
            EnforcementAction.BLOCK_SESSION,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the decision for logs or API responses."""

        return {
            "action": self.action.value,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "reason": self.reason,
            "reasons": list(self.reasons),
            "confidence": round(self.confidence, 3),
            "attack_type": self.attack_type.value,
            "attack_source": self.attack_source.value,
            "target_tool": self.target_tool.value,
            "permissions": sorted(permission.value for permission in self.permissions),
            "detector_scores": dict(self.detector_scores),
            "detector_score": round(self.detector_score, 3),
            "private_data_involved": self.private_data_involved,
            "mapping": self.mapping.to_dict() if self.mapping else None,
            "requires_redaction": self.requires_redaction,
            "allowed": self.allowed,
            "blocked": self.blocked,
        }


def freeze_permissions(permissions: Iterable[object]) -> frozenset[Permission]:
    """Normalize permissions for stable decision objects."""

    return frozenset(coerce_permission(permission) for permission in permissions)


def risk_from_score(score: float) -> RiskLevel:
    """Convert a policy score to the public risk taxonomy."""

    if score >= 0.85:
        return RiskLevel.CRITICAL
    if score >= 0.65:
        return RiskLevel.HIGH
    if score >= 0.35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def clamp_score(score: float) -> float:
    """Clamp untrusted numeric inputs to the detector score range."""

    try:
        parsed = float(score)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))


def normalize_detector_scores(scores: Optional[Mapping[str, object]]) -> Dict[str, float]:
    """Normalize detector score mappings without relying on external services."""

    return {
        str(name).strip().lower(): clamp_score(score)
        for name, score in (scores or {}).items()
    }


def intent_label(user_intent: object) -> str:
    """Normalize caller intent into explicit, ambiguous, or malicious."""

    if isinstance(user_intent, bool):
        return "explicit" if user_intent else "ambiguous"

    normalized = str(user_intent or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {
        "explicit",
        "authorized",
        "approved",
        "benign",
        "normal",
        "user_requested",
        "expected",
        "safe",
    }:
        return "explicit"
    if normalized in {
        "malicious",
        "attack",
        "bypass",
        "unauthorized",
        "policy_evasion",
        "exfiltrate",
    }:
        return "malicious"
    return "ambiguous"
