"""Security module for SentinelAgent."""

from .injection_detector import InjectionDetector
from .tool_risk_classifier import ToolRiskClassifier
from .exfiltration_detector import ExfiltrationDetector
from .middleware import SecurityMiddleware, SecurityDecision
from .defense_profiles import (
    ABLATION_DEFENSE_CONFIGS,
    ABLATION_CONFIGS,
    ALL_DEFENSE_CONFIGS,
    CORE_DEFENSE_CONFIGS,
    PROTOTYPE_DEFENSE_CONFIGS,
    RESEARCH_DEFENSE_CONFIGS,
    DefenseProfile,
    get_defense_profile_catalog,
    get_defense_profile,
    get_profile_catalog,
    resolve_defense_profile,
)
from .embedding_similarity_detector import EmbeddingSimilarityDetector
from .llm_judge import LLMJudge, LLMJudgeResult, StubLLMJudge
from .permissions import (
    classify_permission_risk,
    explain_tool_permissions,
    get_tool_permissions,
    get_tool_risk,
    has_permission,
)
from .policy_engine import PolicyDecision, RiskAdaptivePolicyEngine

__all__ = [
    "ABLATION_DEFENSE_CONFIGS",
    "ALL_DEFENSE_CONFIGS",
    "CORE_DEFENSE_CONFIGS",
    "EmbeddingSimilarityDetector",
    "InjectionDetector",
    "LLMJudge",
    "LLMJudgeResult",
    "PolicyDecision",
    "RiskAdaptivePolicyEngine",
    "ToolRiskClassifier",
    "ExfiltrationDetector",
    "SecurityMiddleware",
    "SecurityDecision",
    "StubLLMJudge",
    "DefenseProfile",
    "get_defense_profile_catalog",
    "get_defense_profile",
    "get_profile_catalog",
    "resolve_defense_profile",
    "PROTOTYPE_DEFENSE_CONFIGS",
    "RESEARCH_DEFENSE_CONFIGS",
    "ABLATION_CONFIGS",
    "classify_permission_risk",
    "explain_tool_permissions",
    "get_tool_permissions",
    "get_tool_risk",
    "has_permission",
]
