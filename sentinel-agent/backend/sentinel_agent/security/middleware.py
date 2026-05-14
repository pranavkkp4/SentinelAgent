"""Security Middleware for SentinelAgent.

Integrates three enforcement boundaries:
1. Retrieval-time injection detection
2. Tool-call risk classification with deterministic policy gating
3. Response-level exfiltration detection
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from .injection_detector import InjectionDetector
from .tool_risk_classifier import ToolRiskClassifier
from .exfiltration_detector import ExfiltrationDetector
from .defense_profiles import DefenseProfile, resolve_defense_profile
from ..models import SecurityCheck, SecurityLevel, ToolCall, Document, RiskLevel
from ..config import config


@dataclass
class SecurityDecision:
    """Represents a security middleware decision."""
    allow: bool
    action: str  # allow, block, quarantine, flag
    reason: str
    confidence: float
    checks: List[SecurityCheck] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow": self.allow,
            "action": self.action,
            "reason": self.reason,
            "confidence": round(self.confidence, 3),
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp.isoformat()
        }


class SecurityMiddleware:
    """
    Defense-in-depth security middleware.
    
    Enforces security at three boundaries:
    - Context Construction: What goes into the LLM prompt
    - Action Execution: Which tool calls are allowed
    - Response Release: What information is shared with users
    """
    
    def __init__(self):
        self.injection_detector = InjectionDetector()
        self.tool_risk_classifier = ToolRiskClassifier()
        self.exfiltration_detector = ExfiltrationDetector()
        self.decision_log: List[SecurityDecision] = []

    def _resolve_profile(
        self,
        defense_config: Optional[str] = None,
        profile: Optional[DefenseProfile] = None,
    ) -> DefenseProfile:
        """Resolve a profile while preserving existing default behavior."""
        return profile or resolve_defense_profile(defense_config or "ml-assisted")
    
    # ========================================================================
    # BOUNDARY 1: Context Construction (Retrieval-time Injection Detection)
    # ========================================================================
    
    def screen_retrieved_content(
        self,
        documents: List[Document],
        detector_mode: str = "ml-assisted",
        enforce: bool = True,
        defense_config: Optional[str] = None,
        profile: Optional[DefenseProfile] = None,
    ) -> tuple[List[Document], List[SecurityCheck]]:
        """
        Screen retrieved documents before adding to LLM context.
        
        Args:
            documents: List of retrieved documents
            
        Returns:
            Tuple of (filtered documents, security checks)
        """
        active_profile = self._resolve_profile(defense_config or detector_mode, profile)
        if not active_profile.runs_detection or not active_profile.injection_enabled:
            return documents, []

        enforce = enforce and active_profile.enforce
        filtered_docs = []
        checks = []
        
        for doc in documents:
            # Run injection detection
            check = self.injection_detector.detect(
                doc.content,
                context=active_profile.to_detection_context(source="retrieved_document"),
            )
            checks.append(check)
            
            security_level = check.details.get("security_level", "benign")
            
            if not enforce:
                doc.security_level = SecurityLevel(security_level)
                filtered_docs.append(doc)
            elif security_level == SecurityLevel.MALICIOUS.value:
                # Quarantine malicious content
                doc.security_level = SecurityLevel.MALICIOUS
                doc.content = self.injection_detector.sanitize_content(doc.content, check)
                # Don't add to context
                
            elif security_level == SecurityLevel.SUSPICIOUS.value:
                # Flag but include with warnings
                doc.security_level = SecurityLevel.SUSPICIOUS
                doc.content = self.injection_detector.sanitize_content(doc.content, check)
                filtered_docs.append(doc)
                
            else:
                # Benign content
                doc.security_level = SecurityLevel.BENIGN
                filtered_docs.append(doc)
        
        return filtered_docs, checks
    
    def screen_web_content(
        self,
        url: str,
        content: str,
        detector_mode: str = "ml-assisted",
        enforce: bool = True,
        defense_config: Optional[str] = None,
        profile: Optional[DefenseProfile] = None,
    ) -> tuple[str, SecurityCheck]:
        """
        Screen web content before adding to LLM context.
        
        Args:
            url: Source URL
            content: Web page content
            
        Returns:
            Tuple of (sanitized content, security check)
        """
        active_profile = self._resolve_profile(defense_config or detector_mode, profile)
        if not active_profile.runs_detection or not active_profile.injection_enabled:
            return content, SecurityCheck(
                check_type="injection_detection",
                passed=True,
                confidence=1.0,
                details={
                    "reason": "injection_detection_disabled",
                    "defense_config": active_profile.name,
                },
            )

        enforce = enforce and active_profile.enforce
        check = self.injection_detector.detect(
            content,
            context=active_profile.to_detection_context(source="web_content", url=url),
        )
        
        security_level = check.details.get("security_level", "benign")
        
        if not enforce:
            sanitized = content
        elif security_level == SecurityLevel.MALICIOUS.value:
            sanitized = f"[Web content from {url} blocked: Potential injection detected]"
        elif security_level == SecurityLevel.SUSPICIOUS.value:
            sanitized = self.injection_detector.sanitize_content(content, check)
        else:
            sanitized = content
        
        return sanitized, check
    
    # ========================================================================
    # BOUNDARY 2: Action Execution (Tool-Call Risk Classification)
    # ========================================================================
    
    def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any],
                          context: Optional[Dict] = None,
                          use_exfiltration_detector: bool = True,
                          enforce: bool = True,
                          use_tool_risk_classifier: bool = True,
                          defense_config: Optional[str] = None,
                          profile: Optional[DefenseProfile] = None) -> ToolCall:
        """
        Evaluate and classify a proposed tool call.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            context: Optional execution context
            
        Returns:
            ToolCall with risk assessment
        """
        active_profile = self._resolve_profile(
            defense_config or (context or {}).get("defense_config"),
            profile,
        )
        enforce = enforce and active_profile.enforce
        use_tool_risk_classifier = (
            use_tool_risk_classifier
            and active_profile.runs_detection
            and active_profile.tool_risk_enabled
        )
        use_exfiltration_detector = (
            use_exfiltration_detector
            and active_profile.runs_detection
            and active_profile.exfiltration_enabled
        )

        # Classify risk unless the selected ablation disables this component.
        if use_tool_risk_classifier:
            tool_call = self.tool_risk_classifier.classify(tool_name, arguments, context)
        else:
            tool_call = ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                allowed=True,
                reason=f"Tool risk classifier disabled for profile {active_profile.name}",
                risk_score=0.0,
                metadata={"tool_risk_classifier_disabled": True},
            )
        
        # Also check for exfiltration in arguments
        exfil_check = None
        if use_exfiltration_detector:
            exfil_check = self.exfiltration_detector.scan_tool_arguments(tool_name, arguments)

        # If exfiltration detected, upgrade risk
        if exfil_check is not None and not exfil_check.passed:
            tool_call.risk_score = max(min(tool_call.risk_score + 0.3, 1.0), 0.85)
            if tool_call.risk_score > config.security.high_risk_threshold:
                tool_call.allowed = False
                tool_call.risk_level = (
                    RiskLevel.CRITICAL if tool_call.risk_score > 0.9 else RiskLevel.HIGH
                )
                tool_call.reason = (
                    f"{tool_call.reason}; Exfiltration attempt detected in arguments"
                    if tool_call.reason
                    else "Exfiltration attempt detected in arguments"
                )
            elif tool_call.risk_score >= config.security.medium_risk_threshold:
                tool_call.risk_level = RiskLevel.MEDIUM

        if not enforce and not tool_call.allowed:
            tool_call.metadata["policy_allowed_before_detection_only"] = False
            tool_call.allowed = True
            tool_call.reason += "; Detection-only profile allowed execution after logging risk"

        tool_call.metadata.setdefault("defense_profile", active_profile.name)
        tool_call.metadata.setdefault(
            "component_flags",
            {
                "tool_risk_enabled": use_tool_risk_classifier,
                "exfiltration_enabled": use_exfiltration_detector,
                "enforcement_enabled": enforce,
            },
        )
        
        return tool_call
    
    def make_tool_decision(self, tool_calls: List[ToolCall]) -> SecurityDecision:
        """
        Make security decision for multiple tool calls.
        
        Args:
            tool_calls: List of tool calls to evaluate
            
        Returns:
            SecurityDecision with overall decision
        """
        checks = []
        blocked_calls = []
        allowed_calls = []
        
        for tc in tool_calls:
            check = self.tool_risk_classifier.evaluate_policy_compliance(tc)
            checks.append(check)
            
            if tc.allowed:
                allowed_calls.append(tc)
            else:
                blocked_calls.append(tc)
        
        # Decision logic
        if blocked_calls:
            # Some calls blocked
            critical_blocked = any(
                tc.risk_level.value in ["high", "critical"]
                for tc in blocked_calls
            )
            
            if critical_blocked:
                decision = SecurityDecision(
                    allow=False,
                    action="block",
                    reason=f"Critical risk tool calls blocked: {len(blocked_calls)}",
                    confidence=0.9,
                    checks=checks
                )
            else:
                decision = SecurityDecision(
                    allow=True,
                    action="flag",
                    reason=f"Some tool calls blocked, others allowed",
                    confidence=0.7,
                    checks=checks
                )
        else:
            # All calls allowed
            avg_risk = sum(tc.risk_score for tc in tool_calls) / max(len(tool_calls), 1)
            decision = SecurityDecision(
                allow=True,
                action="allow",
                reason="All tool calls within acceptable risk",
                confidence=1.0 - avg_risk,
                checks=checks
            )
        
        self.decision_log.append(decision)
        return decision
    
    # ========================================================================
    # BOUNDARY 3: Response Release (Exfiltration Detection)
    # ========================================================================
    
    def screen_response(
        self,
        response: str,
        tool_calls: List[ToolCall] = None,
        use_exfiltration_detector: bool = True,
        enforce: bool = True,
        defense_config: Optional[str] = None,
        profile: Optional[DefenseProfile] = None,
    ) -> tuple[str, SecurityCheck]:
        """
        Screen agent response before releasing to user.
        
        Args:
            response: Agent response text
            tool_calls: Associated tool calls
            
        Returns:
            Tuple of (sanitized response, security check)
        """
        active_profile = self._resolve_profile(defense_config, profile)
        enforce = enforce and active_profile.enforce
        use_exfiltration_detector = (
            use_exfiltration_detector
            and active_profile.runs_detection
            and active_profile.exfiltration_enabled
        )

        if not use_exfiltration_detector:
            return response, SecurityCheck(
                check_type="exfiltration_detection",
                passed=True,
                confidence=1.0,
                details={
                    "reason": "exfiltration_detector_disabled",
                    "defense_config": active_profile.name,
                },
            )

        # Check response content
        check = self.exfiltration_detector.scan(response, scan_type="output")
        
        # Also check tool call arguments for exfiltration
        if tool_calls:
            for tc in tool_calls:
                arg_check = self.exfiltration_detector.scan_tool_arguments(
                    tc.tool_name, tc.arguments
                )
                if not arg_check.passed:
                    check.passed = False
                    check.details["tool_exfiltration"] = arg_check.details
        
        # Sanitize if needed
        check.details["defense_config"] = active_profile.name
        check.details["enforcement_enabled"] = enforce

        if not enforce:
            sanitized = response
        elif not check.passed:
            sanitized = self.exfiltration_detector.sanitize_output(response, check)
        else:
            sanitized = response
        
        return sanitized, check
    
    def make_release_decision(
        self,
        response: str,
        check: SecurityCheck,
        enforce: bool = True,
        profile: Optional[DefenseProfile] = None,
    ) -> SecurityDecision:
        """
        Make final decision on response release.
        
        Args:
            response: Agent response
            check: Exfiltration check result
            
        Returns:
            SecurityDecision on release
        """
        active_profile = profile or resolve_defense_profile(check.details.get("defense_config", "ml-assisted"))
        enforce = enforce and active_profile.enforce
        critical_findings = check.details.get("critical_findings", 0)
        
        if not enforce and not check.passed:
            decision = SecurityDecision(
                allow=True,
                action="flag",
                reason="Detection-only profile recorded leakage finding without enforcement",
                confidence=check.confidence,
                checks=[check]
            )
        elif critical_findings > 0:
            decision = SecurityDecision(
                allow=False,
                action="block",
                reason=f"Critical data leakage detected: {critical_findings} findings",
                confidence=check.confidence,
                checks=[check]
            )
        elif not check.passed:
            decision = SecurityDecision(
                allow=True,
                action="quarantine",
                reason="Potential leakage detected - response sanitized",
                confidence=check.confidence,
                checks=[check]
            )
        else:
            decision = SecurityDecision(
                allow=True,
                action="allow",
                reason="No leakage detected",
                confidence=check.confidence,
                checks=[check]
            )
        
        self.decision_log.append(decision)
        return decision
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def get_decision_summary(self) -> Dict[str, Any]:
        """Get summary of security decisions."""
        total = len(self.decision_log)
        allowed = sum(1 for d in self.decision_log if d.allow)
        blocked = total - allowed
        
        action_counts = {}
        for d in self.decision_log:
            action_counts[d.action] = action_counts.get(d.action, 0) + 1
        
        return {
            "total_decisions": total,
            "allowed": allowed,
            "blocked": blocked,
            "action_breakdown": action_counts,
            "block_rate": round(blocked / max(total, 1), 3)
        }
    
    def reset_logs(self):
        """Reset decision logs."""
        self.decision_log = []
