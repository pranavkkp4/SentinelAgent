"""Risk-adaptive policy engine for tool-using LLM agents."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import urlparse

from ..config import config
from ..research.taxonomy import (
    AttackGoal,
    AttackSource,
    EnforcementAction,
    PolicyDecisionRecord,
    RiskLevel,
    TargetBoundary,
    ToolPermission,
)
from .permissions import classify_permission_risk, get_tool_permissions, get_tool_risk


RISK_SCORE = {
    RiskLevel.LOW: 0.15,
    RiskLevel.MEDIUM: 0.4,
    RiskLevel.HIGH: 0.7,
    RiskLevel.CRITICAL: 0.92,
}

RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

BLOCKING_ACTIONS = {
    EnforcementAction.BLOCK_TOOL_CALL,
    EnforcementAction.BLOCK_RESPONSE,
    EnforcementAction.BLOCK_SESSION,
}

PRIVATE_PERMISSIONS = {
    ToolPermission.READ_PRIVATE,
    ToolPermission.DATABASE_READ,
    ToolPermission.MEMORY_READ,
}

OUTBOUND_PERMISSIONS = {
    ToolPermission.SEND_MESSAGE,
    ToolPermission.WRITE_EXTERNAL,
}

WRITE_PERMISSIONS = {
    ToolPermission.WRITE_PRIVATE,
    ToolPermission.WRITE_EXTERNAL,
    ToolPermission.DATABASE_WRITE,
    ToolPermission.MEMORY_WRITE,
}

CRITICAL_PERMISSIONS = {
    ToolPermission.EXECUTE_CODE,
    ToolPermission.DATABASE_WRITE,
    ToolPermission.SEND_MESSAGE,
    ToolPermission.WRITE_EXTERNAL,
}


@dataclass(frozen=True)
class PolicyDecision:
    """Structured decision returned by every policy boundary."""

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

    def to_record(self) -> PolicyDecisionRecord:
        return PolicyDecisionRecord(
            allow=self.allow,
            action=self.action,
            risk_level=self.risk_level,
            confidence=self.confidence,
            reasons=list(self.reasons),
            triggered_rules=list(self.triggered_rules),
            permissions_considered=list(self.permissions_considered),
            sanitized_content=self.sanitized_content,
            requires_user_confirmation=self.requires_user_confirmation,
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.to_record().to_dict()


class RiskAdaptivePolicyEngine:
    """Deterministic policy that combines detector scores and tool permissions."""

    def __init__(
        self,
        allowed_domains: Optional[Sequence[str]] = None,
        canary_tokens: Optional[Sequence[str]] = None,
    ) -> None:
        self.allowed_domains = tuple(allowed_domains or config.security.allowed_domains)
        self.canary_tokens = tuple(canary_tokens or config.security.canary_tokens)

    def decide_input(
        self,
        content: str,
        *,
        injection_score: float = 0.0,
        exfiltration_score: float = 0.0,
        attack_source: object = AttackSource.USER_PROMPT,
        attack_goal: Optional[object] = None,
        sensitive_data_present: bool = False,
        canary_token_present: Optional[bool] = None,
        user_confirmation_required: bool = False,
    ) -> PolicyDecision:
        return self._decide(
            boundary=TargetBoundary.INPUT_SCREENING,
            content=content,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            attack_source=attack_source,
            attack_goal=attack_goal,
            sensitive_data_present=sensitive_data_present,
            canary_token_present=canary_token_present,
            user_confirmation_required=user_confirmation_required,
        )

    def decide_retrieved_context(
        self,
        content: str,
        *,
        tool_name: str = "document_search",
        injection_score: float = 0.0,
        exfiltration_score: float = 0.0,
        attack_source: object = AttackSource.RETRIEVED_DOCUMENT,
        attack_goal: Optional[object] = None,
        sensitive_data_present: bool = False,
        canary_token_present: Optional[bool] = None,
    ) -> PolicyDecision:
        return self._decide(
            boundary=TargetBoundary.RETRIEVAL_CONTEXT,
            content=content,
            tool_name=tool_name,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            attack_source=attack_source,
            attack_goal=attack_goal,
            sensitive_data_present=sensitive_data_present,
            canary_token_present=canary_token_present,
        )

    def decide_tool_call(
        self,
        tool_name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        injection_score: float = 0.0,
        exfiltration_score: float = 0.0,
        attack_source: object = AttackSource.USER_PROMPT,
        attack_goal: Optional[object] = None,
        sensitive_data_present: bool = False,
        canary_token_present: Optional[bool] = None,
        domain_allowed: Optional[bool] = None,
        user_confirmation_required: bool = False,
    ) -> PolicyDecision:
        content = json.dumps(arguments or {}, sort_keys=True, default=str)
        return self._decide(
            boundary=TargetBoundary.TOOL_CALL,
            content=content,
            tool_name=tool_name,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            attack_source=attack_source,
            attack_goal=attack_goal,
            sensitive_data_present=sensitive_data_present,
            canary_token_present=canary_token_present,
            domain_allowed=domain_allowed,
            user_confirmation_required=user_confirmation_required,
        )

    def decide_tool_output(
        self,
        tool_name: str,
        output: str,
        *,
        injection_score: float = 0.0,
        exfiltration_score: float = 0.0,
        attack_source: object = AttackSource.TOOL_OUTPUT,
        attack_goal: Optional[object] = None,
        sensitive_data_present: bool = False,
        canary_token_present: Optional[bool] = None,
    ) -> PolicyDecision:
        return self._decide(
            boundary=TargetBoundary.TOOL_OUTPUT,
            content=output,
            tool_name=tool_name,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            attack_source=attack_source,
            attack_goal=attack_goal,
            sensitive_data_present=sensitive_data_present,
            canary_token_present=canary_token_present,
        )

    def decide_final_response(
        self,
        response: str,
        *,
        injection_score: float = 0.0,
        exfiltration_score: float = 0.0,
        attack_source: object = AttackSource.USER_PROMPT,
        attack_goal: Optional[object] = None,
        sensitive_data_present: bool = False,
        canary_token_present: Optional[bool] = None,
    ) -> PolicyDecision:
        return self._decide(
            boundary=TargetBoundary.FINAL_RESPONSE,
            content=response,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            attack_source=attack_source,
            attack_goal=attack_goal,
            sensitive_data_present=sensitive_data_present,
            canary_token_present=canary_token_present,
        )

    def _decide(
        self,
        *,
        boundary: object,
        content: str,
        tool_name: str = "",
        injection_score: float,
        exfiltration_score: float,
        attack_source: object,
        attack_goal: Optional[object],
        sensitive_data_present: bool,
        canary_token_present: Optional[bool] = None,
        domain_allowed: Optional[bool] = None,
        user_confirmation_required: bool = False,
    ) -> PolicyDecision:
        boundary = TargetBoundary.coerce(boundary)
        source = AttackSource.coerce(attack_source)
        goal = AttackGoal.coerce(attack_goal) if attack_goal else None
        injection = self._clamp(injection_score)
        exfiltration = self._clamp(exfiltration_score)
        permissions = get_tool_permissions(tool_name) if tool_name else []
        permission_risk = classify_permission_risk(permissions)
        tool_risk = get_tool_risk(tool_name) if tool_name else RiskLevel.LOW
        content = content or ""

        canary_present = (
            self._contains_canary(content)
            if canary_token_present is None
            else bool(canary_token_present)
        )
        sensitive_present = sensitive_data_present or self._contains_sensitive_marker(content)
        obfuscated = self._looks_obfuscated(content)
        detected_injection = injection >= 0.5 or self._has_injection_language(content)
        detected_exfiltration = exfiltration >= 0.45 or self._has_exfiltration_language(content)
        urls = self._extract_urls(content)
        domain_ok = self._domains_allowed(urls) if domain_allowed is None else bool(domain_allowed)

        score = max(injection, exfiltration, RISK_SCORE[permission_risk], RISK_SCORE[tool_risk])
        reasons = [f"boundary={boundary.value}", f"source={source.value}"]
        triggered: List[str] = []

        if permissions:
            reasons.append(
                "permissions="
                + ",".join(permission.value for permission in permissions)
            )
        if goal:
            reasons.append(f"goal={goal.value}")
            score = max(score, self._goal_score(goal))
        if canary_present:
            score = 1.0
            reasons.append("canary token present")
            triggered.append("canary_exfiltration")
        if sensitive_present:
            score = max(score, 0.7)
            reasons.append("sensitive data marker present")
            triggered.append("sensitive_data")
        if obfuscated:
            score = min(1.0, score + 0.12)
            reasons.append("encoded or obfuscated payload signal")
            triggered.append("obfuscation_risk")
        if detected_injection:
            score = max(score, 0.62)
            reasons.append(f"injection score {injection:.2f}")
            triggered.append("injection_detected")
        if detected_exfiltration:
            score = max(score, 0.72)
            reasons.append(f"exfiltration score {exfiltration:.2f}")
            triggered.append("exfiltration_detected")
        if urls and not domain_ok:
            score = max(score, 0.92)
            reasons.append("off-allowlist network destination")
            triggered.append("off_allowlist_network")

        action = self._choose_action(
            boundary=boundary,
            permissions=permissions,
            score=score,
            signal_score=max(injection, exfiltration),
            canary_present=canary_present,
            detected_injection=detected_injection,
            detected_exfiltration=detected_exfiltration,
            sensitive_present=sensitive_present,
            domain_ok=domain_ok,
            user_confirmation_required=user_confirmation_required,
            goal=goal,
        )
        risk_level = self._risk_from_score(score)
        sanitized = self._sanitize(content) if action is EnforcementAction.ALLOW_WITH_REDACTION else None
        allow = action not in BLOCKING_ACTIONS and action is not EnforcementAction.REQUIRE_USER_CONFIRMATION
        requires_confirmation = action is EnforcementAction.REQUIRE_USER_CONFIRMATION

        if action is EnforcementAction.ALLOW_WITH_MONITORING:
            triggered.append("monitoring_required")
        if requires_confirmation:
            triggered.append("user_confirmation_required")
        if action in BLOCKING_ACTIONS:
            triggered.append("policy_block")

        return PolicyDecision(
            allow=allow,
            action=action,
            risk_level=risk_level,
            confidence=round(max(score, 0.55 if triggered else 0.35), 3),
            reasons=reasons,
            triggered_rules=sorted(set(triggered)),
            permissions_considered=permissions,
            sanitized_content=sanitized,
            requires_user_confirmation=requires_confirmation,
            metadata={
                "tool_name": tool_name,
                "injection_score": round(injection, 3),
                "exfiltration_score": round(exfiltration, 3),
                "domain_allowed": domain_ok,
                "urls": urls,
            },
        )

    def _choose_action(
        self,
        *,
        boundary: TargetBoundary,
        permissions: List[ToolPermission],
        score: float,
        signal_score: float,
        canary_present: bool,
        detected_injection: bool,
        detected_exfiltration: bool,
        sensitive_present: bool,
        domain_ok: bool,
        user_confirmation_required: bool,
        goal: Optional[AttackGoal],
    ) -> EnforcementAction:
        permission_set = set(permissions)

        if canary_present:
            if boundary in {TargetBoundary.FINAL_RESPONSE, TargetBoundary.TOOL_OUTPUT}:
                return EnforcementAction.BLOCK_RESPONSE
            if boundary is TargetBoundary.TOOL_CALL and permission_set & OUTBOUND_PERMISSIONS:
                return EnforcementAction.BLOCK_TOOL_CALL
            return EnforcementAction.BLOCK_SESSION

        if permission_set & {ToolPermission.NETWORK_READ} and not domain_ok:
            return EnforcementAction.BLOCK_TOOL_CALL

        if ToolPermission.EXECUTE_CODE in permission_set and detected_injection:
            return EnforcementAction.BLOCK_TOOL_CALL

        if goal in {AttackGoal.DATA_CORRUPTION, AttackGoal.PRIVILEGE_ESCALATION} and permission_set & WRITE_PERMISSIONS:
            return EnforcementAction.BLOCK_TOOL_CALL

        if permission_set & OUTBOUND_PERMISSIONS and detected_injection:
            return (
                EnforcementAction.BLOCK_TOOL_CALL
                if signal_score >= 0.82 or detected_exfiltration
                else EnforcementAction.REQUIRE_USER_CONFIRMATION
            )

        if user_confirmation_required or (permission_set & OUTBOUND_PERMISSIONS and score >= 0.45):
            return EnforcementAction.REQUIRE_USER_CONFIRMATION

        if boundary is TargetBoundary.FINAL_RESPONSE and (detected_exfiltration or sensitive_present):
            return (
                EnforcementAction.BLOCK_RESPONSE
                if score >= 0.82
                else EnforcementAction.ALLOW_WITH_REDACTION
            )

        if permission_set & PRIVATE_PERMISSIONS and (detected_injection or score >= 0.55):
            return EnforcementAction.ALLOW_WITH_MONITORING

        if permissions == [ToolPermission.READ_NONE]:
            return (
                EnforcementAction.BLOCK_TOOL_CALL
                if detected_injection and score >= 0.92
                else EnforcementAction.ALLOW
            )

        if score >= 0.9 and (detected_injection or detected_exfiltration):
            return (
                EnforcementAction.BLOCK_RESPONSE
                if boundary is TargetBoundary.FINAL_RESPONSE
                else EnforcementAction.BLOCK_TOOL_CALL
            )

        if score >= 0.55 and (detected_injection or detected_exfiltration):
            return EnforcementAction.ALLOW_WITH_MONITORING

        return EnforcementAction.ALLOW

    def _domains_allowed(self, urls: Sequence[str]) -> bool:
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(":")[0]
            if not domain:
                continue
            allowed = any(
                domain == allowed_domain.lower()
                or domain.endswith(f".{allowed_domain.lower()}")
                for allowed_domain in self.allowed_domains
            )
            if not allowed:
                return False
        return True

    @staticmethod
    def _extract_urls(content: str) -> List[str]:
        return re.findall(r"https?://[^\s\"'<>]+", content or "")

    def _contains_canary(self, content: str) -> bool:
        lowered = content.lower()
        return any(token.lower() in lowered for token in self.canary_tokens)

    @staticmethod
    def _contains_sensitive_marker(content: str) -> bool:
        return bool(
            re.search(
                r"\b(api[_ -]?key|secret|password|credential|token)\b\s*[:=]",
                content or "",
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _has_injection_language(content: str) -> bool:
        return bool(
            re.search(
                r"(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|system|developer|policy)|"
                r"(system|developer)\s*[:>\]]|jailbreak|do\s+anything\s+now",
                content or "",
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _has_exfiltration_language(content: str) -> bool:
        return bool(
            re.search(
                r"(send|email|forward|transmit|post|upload|leak|reveal|display|print)\b.*"
                r"(secret|token|credential|api[_ -]?key|password|canary)",
                content or "",
                re.IGNORECASE | re.DOTALL,
            )
        )

    @staticmethod
    def _looks_obfuscated(content: str) -> bool:
        text = content or ""
        if re.search(r"\b(base64|hex|rot13|decode|encoded)\b", text, re.IGNORECASE):
            return True
        if re.search(r"<!--.*?(ignore|system|secret|token).*?-->", text, re.IGNORECASE | re.DOTALL):
            return True
        if re.search(r"\b[A-Za-z0-9+/]{48,}={0,2}\b", text):
            try:
                decoded = base64.b64decode(re.search(r"\b[A-Za-z0-9+/]{48,}={0,2}\b", text).group(0))
                return bool(decoded)
            except Exception:
                return True
        if re.search(r"\b[0-9a-fA-F]{48,}\b", text):
            return True
        spaced = re.sub(r"\s+", "", text.lower())
        return "ignoreallprevious" in spaced or "revealsecret" in spaced

    @staticmethod
    def _sanitize(content: str) -> str:
        sanitized = re.sub(
            r"(?i)(api[_ -]?key|secret|password|credential|token)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            content,
        )
        sanitized = re.sub(r"SENTINEL_CANARY_[A-Za-z0-9_]+", "[REDACTED_CANARY]", sanitized)
        return sanitized

    @staticmethod
    def _clamp(score: float) -> float:
        try:
            return max(0.0, min(1.0, float(score)))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _risk_from_score(score: float) -> RiskLevel:
        if score >= 0.85:
            return RiskLevel.CRITICAL
        if score >= 0.65:
            return RiskLevel.HIGH
        if score >= 0.35:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _goal_score(goal: AttackGoal) -> float:
        return {
            AttackGoal.INSTRUCTION_OVERRIDE: 0.62,
            AttackGoal.SECRET_EXFILTRATION: 0.82,
            AttackGoal.UNSAFE_TOOL_USE: 0.72,
            AttackGoal.POLICY_BYPASS: 0.78,
            AttackGoal.PERSISTENCE: 0.7,
            AttackGoal.DATA_CORRUPTION: 0.82,
            AttackGoal.PRIVILEGE_ESCALATION: 0.88,
        }[goal]
