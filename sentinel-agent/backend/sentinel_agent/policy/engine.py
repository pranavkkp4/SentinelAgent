"""Deterministic policy engine for attack-to-tool risk enforcement."""

from __future__ import annotations

from typing import Iterable, Mapping, Optional, Union

from .models import (
    AttackToolMapping,
    PolicyContext,
    PolicyDecision,
    PolicyRequest,
    clamp_score,
    coerce_attack_source,
    coerce_attack_type,
    coerce_target_tool,
    freeze_permissions,
    intent_label,
    normalize_detector_scores,
    risk_from_score,
)
from .permissions import (
    DATABASE_WRITE,
    EXECUTE_CODE,
    MEMORY_WRITE,
    READ_PRIVATE,
    SEND_MESSAGE,
    WRITE_EXTERNAL,
    compute_tool_risk,
    get_tool_permissions,
    risk_score,
)
from .taxonomy import AttackSource, AttackType, EnforcementAction, TargetTool


EXFILTRATION_TYPES = {AttackType.DATA_EXFILTRATION, AttackType.EXFILTRATION}
INJECTION_TYPES = {
    AttackType.PROMPT_INJECTION,
    AttackType.INJECTION,
    AttackType.INDIRECT_PROMPT_INJECTION,
    AttackType.OBFUSCATED_ATTACK,
}
TOOL_MISUSE_TYPES = {
    AttackType.TOOL_MISUSE,
    AttackType.PRIVILEGE_ESCALATION,
    AttackType.DESTRUCTIVE_ACTION,
    AttackType.PERSISTENCE_ATTACK,
    AttackType.MULTI_STEP_ATTACK,
}
UNTRUSTED_SOURCES = {
    AttackSource.RETRIEVED_CONTENT,
    AttackSource.RETRIEVED_DOCUMENT,
    AttackSource.WEB_CONTENT,
    AttackSource.TOOL_OUTPUT,
    AttackSource.EMAIL_CONTENT,
    AttackSource.MEMORY,
    AttackSource.MEMORY_CONTEXT,
    AttackSource.SYSTEM_INTEGRATION,
    AttackSource.UNKNOWN,
}
SIDE_EFFECT_PERMISSIONS = {
    WRITE_EXTERNAL,
    SEND_MESSAGE,
    EXECUTE_CODE,
    DATABASE_WRITE,
    MEMORY_WRITE,
}
CRITICAL_PERMISSIONS = {EXECUTE_CODE, DATABASE_WRITE}
OUTBOUND_PERMISSIONS = {WRITE_EXTERNAL, SEND_MESSAGE}


ATTACK_BASE_SCORE = {
    AttackType.BENIGN: 0.0,
    AttackType.PROMPT_INJECTION: 0.55,
    AttackType.INJECTION: 0.55,
    AttackType.INDIRECT_PROMPT_INJECTION: 0.65,
    AttackType.DATA_EXFILTRATION: 0.7,
    AttackType.EXFILTRATION: 0.7,
    AttackType.TOOL_MISUSE: 0.65,
    AttackType.PRIVILEGE_ESCALATION: 0.8,
    AttackType.DESTRUCTIVE_ACTION: 0.82,
    AttackType.PERSISTENCE_ATTACK: 0.72,
    AttackType.OBFUSCATED_ATTACK: 0.6,
    AttackType.MULTI_STEP_ATTACK: 0.72,
    AttackType.UNKNOWN: 0.2,
}


class PolicyEngine:
    """Map detector signals and tool capabilities to enforcement actions."""

    confirm_threshold = 0.45
    block_tool_threshold = 0.7
    block_session_threshold = 0.9

    def evaluate(
        self,
        context: Optional[Union[PolicyContext, Mapping[str, object]]] = None,
        *,
        detector_scores: Optional[Mapping[str, object]] = None,
        detector_score: Optional[float] = None,
        detector_label: str = "",
        attack_type: object = AttackType.BENIGN,
        attack_source: object = AttackSource.USER_PROMPT,
        target_tool: object = TargetTool.UNKNOWN,
        permissions: Optional[Iterable[object]] = None,
        tool_permissions: Optional[Iterable[object]] = None,
        user_intent: object = "benign",
        contains_private_data: bool = False,
        private_data: Optional[bool] = None,
        private_data_involved: Optional[bool] = None,
        **metadata,
    ) -> PolicyDecision:
        """Evaluate a tool call against the formal policy rules."""

        if isinstance(context, PolicyContext):
            return self._decide_context(context)
        if isinstance(context, Mapping):
            return self.evaluate_dict(dict(context))

        if private_data is not None:
            contains_private_data = private_data
        if private_data_involved is not None:
            contains_private_data = private_data_involved

        normalized_scores = normalize_detector_scores(detector_scores)
        if detector_score is not None:
            label_key = str(detector_label or "detector").strip().lower() or "detector"
            normalized_scores.setdefault(label_key, clamp_score(detector_score))

        request = PolicyRequest(
            detector_scores=normalized_scores,
            attack_type=coerce_attack_type(attack_type),
            attack_source=coerce_attack_source(attack_source),
            target_tool=coerce_target_tool(target_tool),
            permissions=permissions if permissions is not None else tool_permissions,
            user_intent=user_intent,
            contains_private_data=bool(contains_private_data),
            metadata=metadata,
        )
        return self.decide(request)

    def evaluate_dict(self, payload: Mapping[str, object]) -> PolicyDecision:
        """Evaluate an API-style dictionary payload."""

        if "context" in payload and len(payload) == 1:
            nested = payload["context"]
            if isinstance(nested, PolicyContext):
                return self._decide_context(nested)
            if isinstance(nested, Mapping):
                payload = nested

        return self.evaluate(
            detector_scores=payload.get("detector_scores"),
            detector_score=payload.get("detector_score"),
            detector_label=str(payload.get("detector_label", "")),
            attack_type=payload.get("attack_type", AttackType.BENIGN),
            attack_source=payload.get("attack_source", AttackSource.USER_PROMPT),
            target_tool=payload.get("target_tool", TargetTool.UNKNOWN),
            permissions=payload.get("permissions", payload.get("tool_permissions")),
            user_intent=payload.get("user_intent", payload.get("user_intent_aligned", "benign")),
            contains_private_data=bool(
                payload.get("contains_private_data", payload.get("private_data_involved", False))
            ),
        )

    def decide(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate a PolicyRequest and return an enforcement decision."""

        attack_type = coerce_attack_type(request.attack_type)
        attack_source = coerce_attack_source(request.attack_source)
        target_tool = coerce_target_tool(request.target_tool)
        detector_scores = normalize_detector_scores(request.detector_scores)
        permissions = freeze_permissions(
            get_tool_permissions(target_tool)
            if request.permissions is None
            else request.permissions
        )
        intent = intent_label(request.user_intent)
        detector_max = max(detector_scores.values(), default=0.0)
        injection_score = detector_scores.get("injection", detector_scores.get("prompt_injection", 0.0))
        exfiltration_score = detector_scores.get(
            "exfiltration",
            detector_scores.get("data_exfiltration", 0.0),
        )
        tool_score = detector_scores.get("tool", detector_scores.get("tool_misuse", 0.0))

        static_tool_risk = compute_tool_risk(target_tool, permissions)
        attack_base_score = ATTACK_BASE_SCORE.get(
            attack_type, ATTACK_BASE_SCORE[AttackType.UNKNOWN]
        )
        if (
            target_tool is TargetTool.CALCULATOR
            and attack_type in {AttackType.PROMPT_INJECTION, AttackType.INJECTION}
            and detector_max < self.confirm_threshold
            and attack_source is AttackSource.USER_PROMPT
        ):
            attack_base_score = 0.0

        score = max(
            risk_score(static_tool_risk),
            detector_max,
            attack_base_score,
        )
        reasons = [f"static tool risk is {static_tool_risk.value}"]

        if detector_max:
            reasons.append(f"max detector score {detector_max:.2f}")
        if attack_type is not AttackType.BENIGN:
            reasons.append(f"attack type {attack_type.value}")
        if attack_source in UNTRUSTED_SOURCES:
            score = max(score, clamp_score(score + 0.08))
            reasons.append(f"untrusted source {attack_source.value}")
        if request.contains_private_data:
            score = max(score, clamp_score(score + 0.1))
            reasons.append("private data present")
        if permissions & OUTBOUND_PERMISSIONS:
            reasons.append("outbound permission present")
        if permissions & CRITICAL_PERMISSIONS:
            reasons.append("critical permission present")
        if intent == "malicious":
            score = max(score, 0.86)
            reasons.append("malicious or unauthorized user intent")
        elif intent == "ambiguous":
            score = max(score, clamp_score(score + 0.06))
            reasons.append("ambiguous user intent")

        action = self._choose_action(
            attack_type=attack_type,
            attack_source=attack_source,
            target_tool=target_tool,
            permissions=permissions,
            contains_private_data=request.contains_private_data,
            detector_max=detector_max,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
            tool_score=tool_score,
            intent=intent,
            score=score,
        )

        if action is EnforcementAction.BLOCK_SESSION:
            score = max(score, self.block_session_threshold)
            reasons.append("session-level compromise risk")
        elif action is EnforcementAction.BLOCK_TOOL_CALL:
            score = max(score, self.block_tool_threshold)
            reasons.append("tool call blocked by policy")
        elif action is EnforcementAction.ASK_USER_CONFIRMATION:
            score = max(score, self.confirm_threshold)
            reasons.append("explicit confirmation required")
        elif action is EnforcementAction.ALLOW_WITH_REDACTION:
            score = max(score, 0.35)
            reasons.append("private data must be redacted before use")
        else:
            reasons.append("policy allows the tool call")

        score = round(clamp_score(score), 3)
        risk_level = risk_from_score(score)
        if (
            target_tool is TargetTool.CALCULATOR
            and action in {EnforcementAction.ALLOW, EnforcementAction.ASK_USER_CONFIRMATION}
            and detector_max <= self.confirm_threshold
        ):
            risk_level = static_tool_risk
        reason = "; ".join(reasons)
        detector_score = detector_max
        mapping = AttackToolMapping(
            attack_type=attack_type,
            attack_source=attack_source,
            target_tool=target_tool,
            tool_permissions=sorted(permissions, key=lambda permission: permission.value),
            risk_level=risk_level,
            enforcement_action=action,
            rationale=reason,
        )
        return PolicyDecision(
            action=action,
            risk_level=risk_level,
            risk_score=score,
            reasons=tuple(reasons),
            reason=reason,
            confidence=self._confidence(detector_score, score, action),
            mapping=mapping,
            detector_score=detector_score,
            private_data_involved=request.contains_private_data,
            attack_type=attack_type,
            attack_source=attack_source,
            target_tool=target_tool,
            permissions=permissions,
            detector_scores=detector_scores,
            requires_redaction=action is EnforcementAction.ALLOW_WITH_REDACTION,
        )

    def _decide_context(self, context: PolicyContext) -> PolicyDecision:
        """Evaluate a legacy PolicyContext object."""

        ctx = context.normalized()
        detector_scores = normalize_detector_scores(ctx.detector_scores)
        if ctx.detector_score and not detector_scores:
            detector_scores = {"detector": ctx.detector_score}
        if ctx.detector_label:
            detector_scores.setdefault(ctx.detector_label.lower(), ctx.detector_score)

        return self.decide(
            PolicyRequest(
                detector_scores=detector_scores,
                attack_type=ctx.attack_type,
                attack_source=ctx.attack_source,
                target_tool=ctx.target_tool,
                permissions=ctx.tool_permissions,
                user_intent=ctx.user_intent,
                contains_private_data=ctx.private_data_involved,
                metadata=ctx.metadata,
            )
        )

    def _choose_action(
        self,
        *,
        attack_type: AttackType,
        attack_source: AttackSource,
        target_tool: TargetTool,
        permissions: frozenset,
        contains_private_data: bool,
        detector_max: float,
        injection_score: float,
        exfiltration_score: float,
        tool_score: float,
        intent: str,
        score: float,
    ) -> EnforcementAction:
        """Apply ordered policy rules from most severe to least severe."""

        if intent == "malicious" and (permissions & SIDE_EFFECT_PERMISSIONS or contains_private_data):
            return EnforcementAction.BLOCK_TOOL_CALL

        if EXECUTE_CODE in permissions and detector_max >= self.block_session_threshold:
            return EnforcementAction.BLOCK_SESSION

        if (
            attack_type in INJECTION_TYPES
            and attack_source in UNTRUSTED_SOURCES
            and (injection_score >= 0.8 or detector_max >= self.block_session_threshold)
        ):
            return EnforcementAction.BLOCK_SESSION

        if (
            attack_type in INJECTION_TYPES
            and permissions & CRITICAL_PERMISSIONS
            and detector_max >= 0.7
        ):
            return EnforcementAction.BLOCK_SESSION

        if detector_max >= 0.97 and (permissions & CRITICAL_PERMISSIONS or attack_source in UNTRUSTED_SOURCES):
            return EnforcementAction.BLOCK_SESSION

        if attack_type in EXFILTRATION_TYPES and (
            contains_private_data
            or permissions & OUTBOUND_PERMISSIONS
            or exfiltration_score >= 0.55
        ):
            return EnforcementAction.BLOCK_TOOL_CALL

        if attack_type in TOOL_MISUSE_TYPES and (
            permissions & SIDE_EFFECT_PERMISSIONS
            or target_tool in {TargetTool.UNKNOWN, TargetTool.EXTERNAL_API, TargetTool.FILE_SYSTEM}
            or tool_score >= 0.6
        ):
            return EnforcementAction.BLOCK_TOOL_CALL

        if permissions & CRITICAL_PERMISSIONS:
            if detector_max >= 0.45 or attack_type is not AttackType.BENIGN:
                return EnforcementAction.BLOCK_TOOL_CALL
            return EnforcementAction.ASK_USER_CONFIRMATION

        if contains_private_data and permissions & OUTBOUND_PERMISSIONS:
            if detector_max >= 0.35 or attack_type is not AttackType.BENIGN:
                return EnforcementAction.BLOCK_TOOL_CALL
            return EnforcementAction.ALLOW_WITH_REDACTION

        if detector_max >= self.block_tool_threshold and (
            attack_type is not AttackType.BENIGN or permissions & SIDE_EFFECT_PERMISSIONS
        ):
            return EnforcementAction.BLOCK_TOOL_CALL

        if contains_private_data and READ_PRIVATE in permissions:
            if attack_type is AttackType.BENIGN and detector_max < self.confirm_threshold:
                return EnforcementAction.ALLOW_WITH_REDACTION
            return EnforcementAction.BLOCK_TOOL_CALL

        if permissions & SIDE_EFFECT_PERMISSIONS:
            if intent == "explicit" and detector_max < self.confirm_threshold and attack_type is AttackType.BENIGN:
                return EnforcementAction.ASK_USER_CONFIRMATION
            return EnforcementAction.BLOCK_TOOL_CALL

        if score >= self.block_tool_threshold and attack_type is not AttackType.BENIGN:
            return EnforcementAction.BLOCK_TOOL_CALL

        if score >= self.confirm_threshold or intent == "ambiguous":
            return EnforcementAction.ASK_USER_CONFIRMATION

        return EnforcementAction.ALLOW

    def _confidence(
        self,
        detector_score: float,
        policy_score: float,
        action: EnforcementAction,
    ) -> float:
        """Stable confidence score for audit logs."""

        action_bonus = {
            EnforcementAction.ALLOW: 0.55,
            EnforcementAction.ALLOW_WITH_REDACTION: 0.65,
            EnforcementAction.ASK_USER_CONFIRMATION: 0.7,
            EnforcementAction.BLOCK_TOOL_CALL: 0.84,
            EnforcementAction.BLOCK_SESSION: 0.92,
        }[action]
        return round(min(0.99, action_bonus + detector_score * 0.04 + policy_score * 0.04), 3)


def evaluate_policy(context: PolicyContext) -> PolicyDecision:
    """Convenience wrapper for simple call sites."""

    return PolicyEngine().evaluate(context)
