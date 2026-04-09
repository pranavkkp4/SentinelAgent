"""Injection Detection Model for SentinelAgent.

This module implements a supervised classifier that detects prompt injection
attempts in retrieved content before it reaches the LLM context.
"""

import re
from typing import Dict, List, Tuple, Optional
import numpy as np
from dataclasses import dataclass

from ..models import SecurityLevel, SecurityCheck
from ..config import config


@dataclass
class InjectionPattern:
    """Represents a known injection pattern."""
    pattern: str
    description: str
    severity: str
    weight: float = 1.0


class InjectionDetector:
    """
    ML-based injection detection model.
    
    Uses a combination of:
    1. Rule-based pattern matching for known attacks
    2. Statistical features for anomaly detection
    3. ML classifier (when trained) for semantic understanding
    """
    
    # Known injection patterns
    INJECTION_PATTERNS = [
        InjectionPattern(
            r"ignore\b.*?(instructions?|rules?|constraints?)",
            "Instruction override attempt",
            "high",
            1.0
        ),
        InjectionPattern(
            r"forget\s+(everything|all|your|previous)",
            "Memory wipe attempt",
            "high",
            0.9
        ),
        InjectionPattern(
            r"(system|developer|admin)\s*:\s*",
            "Role impersonation",
            "high",
            0.95
        ),
        InjectionPattern(
            r"\[\s*system\s*\]|\{\s*system\s*\}",
            "System tag injection",
            "high",
            0.9
        ),
        InjectionPattern(
            r"you\s+(are|should|must)\s+now\s+(be|act\s+as)",
            "Role change attempt",
            "medium",
            0.7
        ),
        InjectionPattern(
            r"(new|updated)\s+(instruction|rule|command)",
            "New instruction injection",
            "medium",
            0.75
        ),
        InjectionPattern(
            r"disregard\s+(the|all|any|previous)",
            "Disregard instruction attempt",
            "medium",
            0.7
        ),
        InjectionPattern(
            r"(reveal|show|tell|display)\s+(me\s+|us\s+)?(your|the)\s+(system|prompt|instruction)",
            "Prompt extraction attempt",
            "high",
            0.95
        ),
        InjectionPattern(
            r"(base64|encode|decode|url\s*encode)",
            "Encoding attempt",
            "medium",
            0.6
        ),
        InjectionPattern(
            r"DAN|jailbreak|do\s+anything\s+now",
            "Jailbreak attempt",
            "high",
            0.95
        ),
        InjectionPattern(
            r"(send|email|transmit|forward)\s+(this|the|all|data|information)",
            "Data exfiltration attempt",
            "high",
            0.9
        ),
        InjectionPattern(
            r"(api\s*key|password|secret|token)\s*[=:]",
            "Secret extraction attempt",
            "high",
            0.85
        ),
        InjectionPattern(
            r"```\s*(system|instruction|prompt)",
            "Code block injection",
            "medium",
            0.75
        ),
        InjectionPattern(
            r"<\s*(system|instruction|prompt)\s*>",
            "XML tag injection",
            "medium",
            0.75
        ),
    ]
    
    def __init__(self):
        self.patterns = self.INJECTION_PATTERNS
        self.ml_model = None
        self.vectorizer = None
        self._load_ml_model()
    
    def _load_ml_model(self):
        """Load pre-trained ML model if available."""
        try:
            # In a real implementation, this would load a trained transformer model
            # For demo purposes, we'll use the rule-based approach with statistical features
            self.ml_model = None
        except Exception:
            self.ml_model = None
    
    def _extract_statistical_features(self, text: str) -> Dict[str, float]:
        """Extract statistical features from text."""
        features = {
            "length": len(text),
            "uppercase_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "special_char_ratio": sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1),
            "digit_ratio": sum(1 for c in text if c.isdigit()) / max(len(text), 1),
            "newline_count": text.count("\n"),
            "quote_count": text.count('"') + text.count("'") + text.count("`"),
            "bracket_count": text.count("[") + text.count("]") + text.count("{") + text.count("}"),
            "instruction_words": sum(1 for word in ["ignore", "forget", "disregard", "new", "updated"] if word in text.lower()),
            "system_words": sum(1 for word in ["system", "admin", "developer", "prompt"] if word in text.lower()),
        }
        return features
    
    def _calculate_pattern_score(self, text: str) -> Tuple[float, List[str], int, int]:
        """Calculate pattern matching score."""
        text_lower = text.lower()
        total_score = 0.0
        matched_patterns = []
        high_severity_matches = 0
        medium_severity_matches = 0
        
        for pattern in self.patterns:
            matches = len(re.findall(pattern.pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                score = pattern.weight * min(matches, 3)  # Cap at 3 matches
                total_score += score
                matched_patterns.append(f"{pattern.description} (x{matches})")
                if pattern.severity == "high":
                    high_severity_matches += matches
                else:
                    medium_severity_matches += matches
        
        # Normalize score
        normalized_score = min(total_score / 3.0, 1.0)
        return normalized_score, matched_patterns, high_severity_matches, medium_severity_matches
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * np.log2(p) if p > 0 else 0
        
        # Normalize to 0-1 range (typical English text has entropy ~4-5)
        return min(entropy / 6.0, 1.0)
    
    def detect(self, text: str, context: Optional[Dict] = None) -> SecurityCheck:
        """
        Detect injection attempts in text.
        
        Args:
            text: The text to analyze
            context: Optional context information
            
        Returns:
            SecurityCheck with detection results
        """
        if not text or len(text.strip()) == 0:
            return SecurityCheck(
                check_type="injection_detection",
                passed=True,
                confidence=1.0,
                details={"reason": "Empty text"}
            )
        
        # Pattern-based detection
        pattern_score, matched_patterns, high_matches, medium_matches = self._calculate_pattern_score(text)
        
        # Statistical features
        features = self._extract_statistical_features(text)
        entropy = self._calculate_entropy(text)
        
        # Combine scores
        # High entropy + pattern matches = more suspicious
        statistical_score = (
            features["special_char_ratio"] * 0.3 +
            features["instruction_words"] * 0.2 +
            features["system_words"] * 0.2 +
            entropy * 0.3
        )
        
        # Final score weighted combination
        final_score = pattern_score * 0.7 + statistical_score * 0.3

        if high_matches:
            final_score = max(final_score, 0.85)
        elif medium_matches >= 2:
            final_score = max(final_score, config.security.injection_threshold * 0.7)
        
        # Determine security level
        if high_matches >= 1 or final_score >= config.security.injection_threshold:
            security_level = SecurityLevel.MALICIOUS
            passed = False
        elif medium_matches >= 1 or final_score >= config.security.injection_threshold * 0.6:
            security_level = SecurityLevel.SUSPICIOUS
            passed = True  # Suspicious content is flagged but allowed with warnings
        else:
            security_level = SecurityLevel.BENIGN
            passed = True
        
        return SecurityCheck(
            check_type="injection_detection",
            passed=passed,
            confidence=final_score,
            details={
                "security_level": security_level.value,
                "pattern_score": round(pattern_score, 3),
                "statistical_score": round(statistical_score, 3),
                "matched_patterns": matched_patterns,
                "features": {k: round(v, 3) if isinstance(v, float) else v for k, v in features.items()},
                "entropy": round(entropy, 3)
            }
        )
    
    def batch_detect(self, texts: List[str]) -> List[SecurityCheck]:
        """Detect injection in multiple texts."""
        return [self.detect(text) for text in texts]
    
    def sanitize_content(self, text: str, check: SecurityCheck) -> str:
        """
        Sanitize content based on security check.
        
        For malicious content: return empty or placeholder
        For suspicious content: wrap with warnings
        For benign content: return as-is
        """
        security_level = check.details.get("security_level", "benign")
        
        if security_level == SecurityLevel.MALICIOUS.value:
            return "[CONTENT BLOCKED: Potential injection detected]"
        
        elif security_level == SecurityLevel.SUSPICIOUS.value:
            return f"""[UNTRUSTED CONTENT - PROCEED WITH CAUTION]
---
{text}
---
[END UNTRUSTED CONTENT]"""
        
        return text
