"""Named defense profiles and ablation switches for SentinelAgent."""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class DefenseProfile:
    """Resolved defense behavior for a benchmark or runtime mode."""

    name: str
    description: str
    runs_detection: bool = True
    enforce: bool = True
    injection_enabled: bool = True
    use_ml_classifier: bool = True
    use_rule_guardrails: bool = True
    use_embedding_similarity: bool = False
    use_llm_judge: bool = False
    tool_risk_enabled: bool = True
    exfiltration_enabled: bool = True
    prompt_only: bool = False
    ablation: bool = False

    @property
    def label(self) -> str:
        """Human-readable label used by legacy report/API call sites."""
        return self.name.replace("-", " ").title()

    @property
    def enable_detection(self) -> bool:
        """Compatibility alias for older profile wiring."""
        return self.runs_detection

    @property
    def enforce_input(self) -> bool:
        """Whether malicious user input should block execution."""
        return self.enforce and self.injection_enabled

    @property
    def enforce_retrieval(self) -> bool:
        """Whether malicious retrieved content should be filtered."""
        return self.enforce and self.injection_enabled

    @property
    def enforce_tools(self) -> bool:
        """Whether risky proposed tool calls should block execution."""
        return self.enforce

    @property
    def enforce_response(self) -> bool:
        """Whether response exfiltration findings should sanitize or block."""
        return self.enforce and self.exfiltration_enabled

    @property
    def use_tool_risk_classifier(self) -> bool:
        """Compatibility alias for tool-risk ablation wiring."""
        return self.tool_risk_enabled

    @property
    def use_exfiltration_detector(self) -> bool:
        """Compatibility alias for exfiltration ablation wiring."""
        return self.exfiltration_enabled

    @property
    def middleware_enforced(self) -> bool:
        """Whether this profile can block, filter, or sanitize anything."""
        return self.enforce

    @property
    def detector_mode(self) -> str:
        """Return the closest detector mode label for legacy call sites."""
        if self.use_embedding_similarity and not self.use_ml_classifier and not self.use_rule_guardrails:
            return "embedding-similarity"
        if self.use_llm_judge and not self.use_ml_classifier and not self.use_rule_guardrails:
            return "llm-as-judge"
        if not self.use_ml_classifier and self.use_rule_guardrails:
            return "rule-based"
        if self.use_ml_classifier and not self.use_rule_guardrails:
            return "ml-only"
        if self.use_embedding_similarity or self.use_llm_judge:
            return "hybrid"
        return "ml-assisted"

    def to_detection_context(self, **extra: Any) -> Dict[str, Any]:
        """Build detector context flags without coupling detectors to profiles."""
        context = {
            "defense_config": self.name,
            "detector_mode": self.detector_mode,
            "profile_name": self.name,
            "enforcement_enabled": self.enforce,
            "use_ml_classifier": self.use_ml_classifier,
            "use_rule_guardrails": self.use_rule_guardrails,
            "use_embedding_similarity": self.use_embedding_similarity,
            "use_llm_judge": self.use_llm_judge,
        }
        context.update(extra)
        return context


CORE_DEFENSE_CONFIGS: List[str] = [
    "no-defense",
    "prompt-only",
    "rule-based",
    "ml-assisted",
    "embedding-similarity",
    "llm-as-judge",
    "hybrid",
]

ABLATION_DEFENSE_CONFIGS: List[str] = [
    "full-sentinelagent",
    "no-ml-classifier",
    "no-rule-guardrails",
    "no-exfiltration-detector",
    "no-tool-risk-classifier",
    "detection-only",
]

ALL_DEFENSE_CONFIGS: List[str] = CORE_DEFENSE_CONFIGS + ABLATION_DEFENSE_CONFIGS


_PROFILES: Dict[str, DefenseProfile] = {
    "no-defense": DefenseProfile(
        name="no-defense",
        description="No middleware detection or enforcement.",
        runs_detection=False,
        enforce=False,
        injection_enabled=False,
        use_ml_classifier=False,
        use_rule_guardrails=False,
        tool_risk_enabled=False,
        exfiltration_enabled=False,
    ),
    "prompt-only": DefenseProfile(
        name="prompt-only",
        description="Relies on the system prompt only; middleware does not run.",
        runs_detection=False,
        enforce=False,
        injection_enabled=False,
        use_ml_classifier=False,
        use_rule_guardrails=False,
        tool_risk_enabled=False,
        exfiltration_enabled=False,
        prompt_only=True,
    ),
    "rule-based": DefenseProfile(
        name="rule-based",
        description="Rule/statistical injection guardrails with tool-risk and exfiltration detectors.",
        use_ml_classifier=False,
    ),
    "ml-assisted": DefenseProfile(
        name="ml-assisted",
        description="Default SentinelAgent profile with ML injection detection plus deterministic guardrails.",
    ),
    "embedding-similarity": DefenseProfile(
        name="embedding-similarity",
        description="Embedding-prototype injection detector with tool-risk and exfiltration detectors.",
        use_ml_classifier=False,
        use_rule_guardrails=False,
        use_embedding_similarity=True,
    ),
    "llm-as-judge": DefenseProfile(
        name="llm-as-judge",
        description="LLM-as-judge detector interface; current backend uses a non-blocking stub.",
        use_ml_classifier=False,
        use_rule_guardrails=False,
        use_llm_judge=True,
    ),
    "hybrid": DefenseProfile(
        name="hybrid",
        description="Combines ML, rule guardrails, embedding similarity, LLM judge stub, tool-risk, and exfiltration checks.",
        use_embedding_similarity=True,
        use_llm_judge=True,
    ),
    "full-sentinelagent": DefenseProfile(
        name="full-sentinelagent",
        description="Full SentinelAgent ablation baseline; equivalent to hybrid in this implementation.",
        use_embedding_similarity=True,
        use_llm_judge=True,
        ablation=True,
    ),
    "no-ml-classifier": DefenseProfile(
        name="no-ml-classifier",
        description="Ablation that disables the supervised injection classifier.",
        use_ml_classifier=False,
        ablation=True,
    ),
    "no-rule-guardrails": DefenseProfile(
        name="no-rule-guardrails",
        description="Ablation that keeps ML scoring but disables deterministic injection rules.",
        use_rule_guardrails=False,
        ablation=True,
    ),
    "no-exfiltration-detector": DefenseProfile(
        name="no-exfiltration-detector",
        description="Ablation that disables response and tool-argument exfiltration scans.",
        exfiltration_enabled=False,
        ablation=True,
    ),
    "no-tool-risk-classifier": DefenseProfile(
        name="no-tool-risk-classifier",
        description="Ablation that disables tool-risk scoring while leaving exfiltration checks available.",
        tool_risk_enabled=False,
        ablation=True,
    ),
    "detection-only": DefenseProfile(
        name="detection-only",
        description="Runs all detectors and records findings without blocking, filtering, or sanitizing.",
        enforce=False,
        use_embedding_similarity=True,
        use_llm_judge=True,
        ablation=True,
    ),
}

_ALIASES = {
    "none": "no-defense",
    "off": "no-defense",
    "rules-only": "rule-based",
    "embedding": "embedding-similarity",
    "llm-judge": "llm-as-judge",
    "judge": "llm-as-judge",
    "full": "full-sentinelagent",
    "full-sentinel-agent": "full-sentinelagent",
    "sentinelagent": "full-sentinelagent",
    "sentinel-agent": "full-sentinelagent",
    "no-rules": "no-rule-guardrails",
    "no-rule-guards": "no-rule-guardrails",
    "no-exfil": "no-exfiltration-detector",
    "no-tool-risk": "no-tool-risk-classifier",
    "detect-only": "detection-only",
    "no-enforcement": "detection-only",
}


def normalize_defense_config(defense_config: str) -> str:
    """Normalize a user-facing defense mode name."""
    normalized = (defense_config or "ml-assisted").strip().lower().replace("_", "-")
    return _ALIASES.get(normalized, normalized)


def resolve_defense_profile(defense_config: str, enable_defense: bool = True) -> DefenseProfile:
    """
    Resolve a defense configuration to component flags.

    ``enable_defense=False`` remains an explicit runtime override for no-defense.
    Unknown names fall back to the default profile to preserve previous API behavior.
    """
    if not enable_defense:
        return _PROFILES["no-defense"]

    normalized = normalize_defense_config(defense_config)
    return _PROFILES.get(normalized, _PROFILES["ml-assisted"])


def get_defense_profile_catalog() -> Dict[str, Dict[str, Any]]:
    """Return profile metadata for API responses and reports."""
    return {
        name: {
            "description": profile.description,
            "runs_detection": profile.runs_detection,
            "enforce": profile.enforce,
            "injection_enabled": profile.injection_enabled,
            "use_ml_classifier": profile.use_ml_classifier,
            "use_rule_guardrails": profile.use_rule_guardrails,
            "use_embedding_similarity": profile.use_embedding_similarity,
            "use_llm_judge": profile.use_llm_judge,
            "tool_risk_enabled": profile.tool_risk_enabled,
            "exfiltration_enabled": profile.exfiltration_enabled,
            "prompt_only": profile.prompt_only,
            "ablation": profile.ablation,
        }
        for name, profile in _PROFILES.items()
    }


# Backward-compatible aliases for concurrent call sites.
PROTOTYPE_DEFENSE_CONFIGS = CORE_DEFENSE_CONFIGS
RESEARCH_DEFENSE_CONFIGS = ALL_DEFENSE_CONFIGS
ABLATION_CONFIGS = ABLATION_DEFENSE_CONFIGS
get_defense_profile = resolve_defense_profile
get_profile_catalog = get_defense_profile_catalog
