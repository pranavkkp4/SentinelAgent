"""Tool-Call Risk Classifier for SentinelAgent.

This module evaluates whether a proposed tool call is consistent with
system policy and task intent.
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from ..models import RiskLevel, ToolCall, SecurityCheck
from ..config import config


@dataclass
class RiskPattern:
    """Represents a risk pattern for tool calls."""
    pattern: str
    risk_type: str
    severity: str
    description: str


class ToolRiskClassifier:
    """
    Evaluates tool call risk using multiple signals:
    1. Tool name and argument analysis
    2. Policy rule matching
    3. Context-aware risk scoring
    """
    
    # High-risk tool patterns
    HIGH_RISK_TOOLS = [
        "execute", "run", "eval", "exec", "system", "shell",
        "delete", "remove", "drop", "truncate"
    ]
    
    # Risk patterns in arguments
    RISK_PATTERNS = [
        RiskPattern(
            r"(http|https|ftp)://[^\s]+",
            "external_url",
            "medium",
            "External URL in arguments"
        ),
        RiskPattern(
            r"[A-Za-z0-9+/]{40,}=?=?",
            "encoded_data",
            "high",
            "Potential encoded data (base64)"
        ),
        RiskPattern(
            r"(password|secret|key|token|credential)",
            "sensitive_keyword",
            "high",
            "Sensitive keyword in arguments"
        ),
        RiskPattern(
            r"(SENTINEL_CANARY|SECRET_TOKEN|API_KEY)",
            "canary_token",
            "critical",
            "Canary token detected - potential exfiltration"
        ),
        RiskPattern(
            r"(rm\s+-rf|del\s+/f|format\s+|drop\s+table)",
            "destructive_command",
            "critical",
            "Destructive command pattern"
        ),
        RiskPattern(
            r"(send|email|transmit|forward)\s+.*\s+(to|@)",
            "data_transmission",
            "high",
            "Data transmission attempt"
        ),
    ]
    
    def __init__(self):
        self.policy_rules = self._load_policy_rules()
    
    def _load_policy_rules(self) -> Dict[str, Any]:
        """Load policy rules from configuration."""
        return {
            "allowed_domains": config.security.allowed_domains,
            "blocked_tools": config.security.blocked_tools,
            "max_argument_length": config.security.max_argument_length,
            "require_justification_for": ["web_fetch", "send_email", "api_call"]
        }

    def _is_allowed_domain(self, domain: str) -> bool:
        """Allow exact matches or true subdomains, but not suffix lookalikes."""
        normalized = domain.lower().split(":")[0]
        return any(
            normalized == allowed_domain.lower() or normalized.endswith(f".{allowed_domain.lower()}")
            for allowed_domain in self.policy_rules["allowed_domains"]
        )
    
    def _check_tool_name_risk(self, tool_name: str) -> float:
        """Check risk based on tool name."""
        tool_lower = tool_name.lower()
        
        # Check if tool is in blocked list
        if tool_name in self.policy_rules["blocked_tools"]:
            return 1.0
        
        # Check for high-risk tool patterns
        risk_score = 0.0
        for pattern in self.HIGH_RISK_TOOLS:
            if pattern in tool_lower:
                risk_score += 0.6
        
        return min(risk_score, 1.0)
    
    def _check_argument_risk(self, arguments: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check risk in tool arguments."""
        arg_str = json.dumps(arguments, default=str).lower()
        total_risk = 0.0
        detected_patterns = []
        
        # Check argument length
        if len(arg_str) > self.policy_rules["max_argument_length"]:
            total_risk = max(total_risk, 0.2)
            detected_patterns.append(f"Argument length ({len(arg_str)}) exceeds limit")
        
        # Check for risk patterns
        for pattern in self.RISK_PATTERNS:
            matches = re.findall(pattern.pattern, arg_str, re.IGNORECASE)
            if matches:
                if pattern.severity == "critical":
                    total_risk = max(total_risk, 1.0)
                elif pattern.severity == "high":
                    total_risk = max(total_risk, 0.8)
                else:
                    total_risk = max(total_risk, 0.35)
                detected_patterns.append(f"{pattern.description}: {pattern.risk_type}")
        
        # Check for canary tokens specifically
        for canary in config.security.canary_tokens:
            if canary.lower() in arg_str:
                total_risk = 1.0
                detected_patterns.append(f"CANARY TOKEN DETECTED: {canary[:20]}...")
        
        return min(total_risk, 1.0), detected_patterns
    
    def _check_domain_policy(self, arguments: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check if URLs in arguments comply with domain policy."""
        arg_str = json.dumps(arguments, default=str)
        urls = re.findall(r'https?://[^\s"\'>]+', arg_str)
        
        if not urls:
            return 0.0, []
        
        violations = []
        risk_score = 0.0
        
        for url in urls:
            domain = re.sub(r'^https?://', '', url).split('/')[0]
            allowed = self._is_allowed_domain(domain)
            if not allowed:
                risk_score = max(risk_score, config.security.high_risk_threshold + 0.05)
                violations.append(f"Domain not in allowlist: {domain}")
        
        return min(risk_score, 1.0), violations
    
    def _assess_context_risk(self, tool_name: str, arguments: Dict[str, Any], 
                             context: Optional[Dict] = None) -> float:
        """Assess risk based on execution context."""
        if not context:
            return 0.0
        
        risk_score = 0.0
        
        # Check tool call frequency
        tool_calls_in_session = context.get("tool_calls_in_session", 0)
        if tool_calls_in_session > config.security.max_tool_calls_per_task:
            risk_score += 0.3
        
        # Check for repeated similar calls
        recent_calls = context.get("recent_tool_calls", [])
        similar_calls = sum(
            1 for call in recent_calls
            if call.get("tool_name") == tool_name
        )
        if similar_calls > 3:
            risk_score += 0.2
        
        # Check if tool matches task intent
        task_type = context.get("task_type", "")
        if task_type and not self._tool_matches_task(tool_name, task_type):
            risk_score += 0.15
        
        return min(risk_score, 1.0)
    
    def _tool_matches_task(self, tool_name: str, task_type: str) -> bool:
        """Check if tool is appropriate for task type."""
        task_tool_mapping = {
            "search": ["search", "fetch", "retrieve"],
            "calculation": ["calculate", "compute", "math"],
            "communication": ["send", "email", "message"],
            "analysis": ["analyze", "process", "extract"]
        }
        
        appropriate_tools = task_tool_mapping.get(task_type, [])
        return any(t in tool_name.lower() for t in appropriate_tools) or not appropriate_tools
    
    def classify(self, tool_name: str, arguments: Dict[str, Any], 
                 context: Optional[Dict] = None) -> ToolCall:
        """
        Classify the risk of a proposed tool call.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            context: Optional execution context
            
        Returns:
            ToolCall with risk assessment
        """
        # Calculate various risk scores
        name_risk = self._check_tool_name_risk(tool_name)
        arg_risk, arg_patterns = self._check_argument_risk(arguments)
        domain_risk, domain_violations = self._check_domain_policy(arguments)
        context_risk = self._assess_context_risk(tool_name, arguments, context)
        
        # Combine risk scores with weights
        weighted_risk = (
            name_risk * 0.2 +
            arg_risk * 0.4 +
            domain_risk * 0.25 +
            context_risk * 0.15
        )
        total_risk = max(weighted_risk, name_risk, arg_risk, domain_risk, context_risk)
        
        # Determine risk level
        if total_risk >= config.security.high_risk_threshold:
            risk_level = RiskLevel.CRITICAL if total_risk > 0.9 else RiskLevel.HIGH
            allowed = False
            reason = "High risk tool call blocked by policy"
        elif total_risk >= config.security.medium_risk_threshold:
            risk_level = RiskLevel.MEDIUM
            allowed = True
            reason = "Medium risk - execution allowed with monitoring"
        else:
            risk_level = RiskLevel.LOW
            allowed = True
            reason = "Low risk - execution permitted"
        
        # Build detailed reason
        all_issues = arg_patterns + domain_violations
        if all_issues:
            reason += f". Issues: {'; '.join(all_issues[:3])}"
        
        return ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            risk_level=risk_level,
            risk_score=total_risk,
            allowed=allowed,
            reason=reason
        )
    
    def evaluate_policy_compliance(self, tool_call: ToolCall) -> SecurityCheck:
        """
        Evaluate policy compliance for a tool call.
        
        Args:
            tool_call: The tool call to evaluate
            
        Returns:
            SecurityCheck with compliance results
        """
        passed = tool_call.allowed
        confidence = 1.0 - abs(0.5 - tool_call.risk_score) * 2
        
        return SecurityCheck(
            check_type="tool_risk_classification",
            passed=passed,
            confidence=confidence,
            details={
                "risk_level": tool_call.risk_level.value,
                "risk_score": round(tool_call.risk_score, 3),
                "reason": tool_call.reason,
                "tool_name": tool_call.tool_name
            }
        )
