"""LLM-as-judge detector interface for SentinelAgent."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class LLMJudgeResult:
    """Normalized result from an LLM-as-judge detector."""

    label: str = "abstain"
    risk_score: float = 0.0
    confidence: float = 0.0
    rationale: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class LLMJudge:
    """Interface for pluggable LLM-as-judge implementations."""

    def judge(self, text: str, context: Optional[Dict[str, Any]] = None) -> LLMJudgeResult:
        """Return a normalized injection-risk judgment."""
        raise NotImplementedError


class StubLLMJudge(LLMJudge):
    """
    Non-blocking fallback used until a real judge provider is configured.

    It reports an abstention instead of pretending to have called a model.
    """

    def judge(self, text: str, context: Optional[Dict[str, Any]] = None) -> LLMJudgeResult:
        return LLMJudgeResult(
            label="abstain",
            risk_score=0.0,
            confidence=0.0,
            rationale="LLM judge is not configured; stub abstained.",
            metadata={
                "stub": True,
                "provider": None,
                "profile_name": (context or {}).get("profile_name"),
            },
        )
