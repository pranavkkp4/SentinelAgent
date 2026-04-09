"""Exfiltration Detection Module for SentinelAgent.

This module scans agent outputs and tool-call arguments for potential
data exfiltration attempts, including canary token leakage and
sensitive pattern disclosure.
"""

import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass

from ..models import SecurityCheck
from ..config import config


@dataclass
class LeakageFinding:
    """Represents a potential data leakage finding."""
    leak_type: str
    pattern: str
    location: str
    severity: str
    matched_text: str


class ExfiltrationDetector:
    """
    Detects potential data exfiltration in outputs.
    
    Detection methods:
    1. Canary token matching
    2. Sensitive pattern detection (API keys, passwords)
    3. Unusual output patterns
    4. Tool argument analysis
    """
    
    def __init__(self):
        self.canary_tokens = set(config.security.canary_tokens)
        self.sensitive_patterns = config.security.sensitive_patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled_patterns = []
        for pattern in self.sensitive_patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                continue
    
    def _detect_canary_tokens(self, text: str) -> List[LeakageFinding]:
        """Detect canary token leakage."""
        findings = []
        text_upper = text.upper()
        
        for canary in self.canary_tokens:
            if canary.upper() in text_upper:
                # Find the exact match location
                pattern = re.compile(re.escape(canary), re.IGNORECASE)
                for match in pattern.finditer(text):
                    findings.append(LeakageFinding(
                        leak_type="canary_token",
                        pattern=f"Canary: {canary[:20]}...",
                        location=f"position_{match.start()}",
                        severity="critical",
                        matched_text=match.group()[:50]
                    ))
        
        return findings
    
    def _detect_sensitive_patterns(self, text: str) -> List[LeakageFinding]:
        """Detect sensitive pattern leakage."""
        findings = []
        
        for compiled_pattern in self.compiled_patterns:
            matches = compiled_pattern.finditer(text)
            for match in matches:
                # Determine severity based on pattern
                matched = match.group()
                if "sk-" in matched.lower():
                    severity = "critical"
                elif "password" in matched.lower() or "secret" in matched.lower():
                    severity = "high"
                else:
                    severity = "medium"
                
                findings.append(LeakageFinding(
                    leak_type="sensitive_pattern",
                    pattern=compiled_pattern.pattern[:50],
                    location=f"position_{match.start()}",
                    severity=severity,
                    matched_text=matched[:50]
                ))
        
        return findings
    
    def _detect_encoding_attempts(self, text: str) -> List[LeakageFinding]:
        """Detect potential encoding-based exfiltration."""
        findings = []
        
        # Check for base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{40,}=?=?'
        matches = re.finditer(base64_pattern, text)
        
        for match in matches:
            matched = match.group()
            # Filter out common false positives
            if len(matched) > 50 and not self._is_likely_false_positive(matched):
                findings.append(LeakageFinding(
                    leak_type="encoded_data",
                    pattern="base64-like",
                    location=f"position_{match.start()}",
                    severity="medium",
                    matched_text=matched[:50]
                ))
        
        # Check for hex encoding
        hex_pattern = r'[0-9a-fA-F]{32,}'
        hex_matches = re.finditer(hex_pattern, text)
        
        for match in hex_matches:
            matched = match.group()
            if len(matched) >= 32:
                findings.append(LeakageFinding(
                    leak_type="hex_encoded",
                    pattern="hex-string",
                    location=f"position_{match.start()}",
                    severity="low",
                    matched_text=matched[:50]
                ))
        
        return findings
    
    def _is_likely_false_positive(self, text: str) -> bool:
        """Check if a match is likely a false positive."""
        # Common false positive patterns
        false_positive_patterns = [
            r'^https?://',  # URLs
            r'^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$',  # Filenames
            r'^[0-9]+$',  # Pure numbers
        ]
        
        for pattern in false_positive_patterns:
            if re.match(pattern, text):
                return True
        
        return False
    
    def _calculate_leakage_score(self, findings: List[LeakageFinding]) -> float:
        """Calculate overall leakage risk score."""
        if not findings:
            return 0.0
        
        severity_weights = {
            "critical": 1.0,
            "high": 0.7,
            "medium": 0.4,
            "low": 0.2
        }
        
        total_score = sum(
            severity_weights.get(f.severity, 0.1)
            for f in findings
        )
        
        # Cap at 1.0 but consider multiple findings
        return min(total_score, 1.0)
    
    def scan(self, text: str, scan_type: str = "output") -> SecurityCheck:
        """
        Scan text for potential exfiltration.
        
        Args:
            text: The text to scan
            scan_type: Type of scan (output, tool_argument, etc.)
            
        Returns:
            SecurityCheck with scan results
        """
        if not text:
            return SecurityCheck(
                check_type="exfiltration_detection",
                passed=True,
                confidence=1.0,
                details={"reason": "Empty text"}
            )
        
        # Run all detection methods
        all_findings = []
        all_findings.extend(self._detect_canary_tokens(text))
        all_findings.extend(self._detect_sensitive_patterns(text))
        all_findings.extend(self._detect_encoding_attempts(text))
        
        # Calculate leakage score
        leakage_score = self._calculate_leakage_score(all_findings)
        
        # Determine if passed
        critical_findings = [f for f in all_findings if f.severity == "critical"]
        high_findings = [f for f in all_findings if f.severity == "high"]
        
        passed = len(critical_findings) == 0 and len(high_findings) < 2
        
        return SecurityCheck(
            check_type="exfiltration_detection",
            passed=passed,
            confidence=1.0 - leakage_score,
            details={
                "leakage_score": round(leakage_score, 3),
                "findings_count": len(all_findings),
                "critical_findings": len(critical_findings),
                "high_findings": len(high_findings),
                "findings": [
                    {
                        "type": f.leak_type,
                        "severity": f.severity,
                        "location": f.location,
                        "matched": f.matched_text[:30] + "..." if len(f.matched_text) > 30 else f.matched_text
                    }
                    for f in all_findings[:5]  # Limit to first 5 findings
                ],
                "scan_type": scan_type
            }
        )
    
    def scan_tool_arguments(self, tool_name: str, arguments: Dict) -> SecurityCheck:
        """
        Scan tool arguments for exfiltration attempts.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments dictionary
            
        Returns:
            SecurityCheck with scan results
        """
        import json
        arg_text = json.dumps(arguments, default=str)
        check = self.scan(arg_text, scan_type="tool_argument")
        check.details["tool_name"] = tool_name
        return check
    
    def sanitize_output(self, text: str, check: SecurityCheck) -> str:
        """
        Sanitize output by removing or masking leaked content.
        
        Args:
            text: Original output text
            check: Security check results
            
        Returns:
            Sanitized text
        """
        if check.passed:
            return text
        
        sanitized = text
        
        # Mask canary tokens
        for canary in self.canary_tokens:
            sanitized = re.sub(
                re.escape(canary),
                "[REDACTED_CANARY]",
                sanitized,
                flags=re.IGNORECASE
            )
        
        # Mask detected patterns
        findings = check.details.get("findings", [])
        for finding in findings:
            matched = finding.get("matched", "")
            if matched and len(matched) > 5:
                sanitized = sanitized.replace(matched, "[REDACTED]")
        
        if sanitized != text:
            sanitized += "\n\n[Note: Sensitive content has been redacted]"
        
        return sanitized
    
    def get_leakage_summary(self, checks: List[SecurityCheck]) -> Dict:
        """Get summary of leakage detection across multiple checks."""
        total_findings = 0
        critical_count = 0
        high_count = 0
        
        for check in checks:
            if check.check_type == "exfiltration_detection":
                total_findings += check.details.get("findings_count", 0)
                critical_count += check.details.get("critical_findings", 0)
                high_count += check.details.get("high_findings", 0)
        
        return {
            "total_scans": len(checks),
            "total_findings": total_findings,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "leakage_detected": critical_count > 0 or high_count > 0
        }
