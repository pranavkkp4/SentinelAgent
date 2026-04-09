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
    
    # ========================================================================
    # BOUNDARY 1: Context Construction (Retrieval-time Injection Detection)
    # ========================================================================
    
    def screen_retrieved_content(self, documents: List[Document]) -> tuple[List[Document], List[SecurityCheck]]:
        """
        Screen retrieved documents before adding to LLM context.
        
        Args:
            documents: List of retrieved documents
            
        Returns:
            Tuple of (filtered documents, security checks)
        """
        filtered_docs = []
        checks = []
        
        for doc in documents:
            # Run injection detection
            check = self.injection_detector.detect(doc.content)
            checks.append(check)
            
            security_level = check.details.get("security_level", "benign")
            
            if security_level == SecurityLevel.MALICIOUS.value:
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
    
    def screen_web_content(self, url: str, content: str) -> tuple[str, SecurityCheck]:
        """
        Screen web content before adding to LLM context.
        
        Args:
            url: Source URL
            content: Web page content
            
        Returns:
            Tuple of (sanitized content, security check)
        """
        check = self.injection_detector.detect(content)
        
        security_level = check.details.get("security_level", "benign")
        
        if security_level == SecurityLevel.MALICIOUS.value:
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
                          context: Optional[Dict] = None) -> ToolCall:
        """
        Evaluate and classify a proposed tool call.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            context: Optional execution context
            
        Returns:
            ToolCall with risk assessment
        """
        # Classify risk
        tool_call = self.tool_risk_classifier.classify(tool_name, arguments, context)
        
        # Also check for exfiltration in arguments
        exfil_check = self.exfiltration_detector.scan_tool_arguments(tool_name, arguments)
        
        # If exfiltration detected, upgrade risk
        if not exfil_check.passed:
            tool_call.risk_score = min(tool_call.risk_score + 0.3, 1.0)
            if tool_call.risk_score > config.security.high_risk_threshold:
                tool_call.allowed = False
                tool_call.risk_level = (
                    RiskLevel.CRITICAL if tool_call.risk_score > 0.9 else RiskLevel.HIGH
                )
                tool_call.reason += "; Exfiltration attempt detected in arguments"
            elif tool_call.risk_score >= config.security.medium_risk_threshold:
                tool_call.risk_level = RiskLevel.MEDIUM
        
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
    
    def screen_response(self, response: str, tool_calls: List[ToolCall] = None) -> tuple[str, SecurityCheck]:
        """
        Screen agent response before releasing to user.
        
        Args:
            response: Agent response text
            tool_calls: Associated tool calls
            
        Returns:
            Tuple of (sanitized response, security check)
        """
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
        if not check.passed:
            sanitized = self.exfiltration_detector.sanitize_output(response, check)
        else:
            sanitized = response
        
        return sanitized, check
    
    def make_release_decision(self, response: str, check: SecurityCheck) -> SecurityDecision:
        """
        Make final decision on response release.
        
        Args:
            response: Agent response
            check: Exfiltration check result
            
        Returns:
            SecurityDecision on release
        """
        critical_findings = check.details.get("critical_findings", 0)
        
        if critical_findings > 0:
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
