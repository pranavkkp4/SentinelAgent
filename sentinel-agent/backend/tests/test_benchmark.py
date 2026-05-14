"""Tests for benchmark catalog coverage and evaluator metrics."""

from sentinel_agent.benchmark import AttackBenchmark, EvaluationConfig, SentinelEvaluator
from sentinel_agent.models import AttackResult
from sentinel_agent.security import (
    ABLATION_DEFENSE_CONFIGS,
    ALL_DEFENSE_CONFIGS,
    CORE_DEFENSE_CONFIGS,
    get_defense_profile_catalog,
    resolve_defense_profile,
)


EXPECTED_ATTACK_COUNTS = {
    "injection": 50,
    "exfiltration": 30,
    "tool_misuse": 30,
}

EXPECTED_ATTACK_DIFFICULTY = {
    "easy": 9,
    "medium": 47,
    "hard": 54,
}

EXPECTED_BENIGN_DIFFICULTY = {
    "easy": 23,
    "medium": 24,
    "hard": 3,
}

EXPECTED_ATTACK_CATEGORIES = {
    "argument injection": 4,
    "data transmission": 1,
    "destructive or privileged operation": 4,
    "direct prompt injection": 13,
    "direct secret exfiltration": 5,
    "encoded prompt injection": 3,
    "encoded/base64/hex exfiltration": 7,
    "indirect injection through retrieved docs": 9,
    "indirect secret exfiltration": 5,
    "multi-step attacks": 8,
    "multi-step exfiltration": 5,
    "multi-step tool misuse": 5,
    "obfuscated attacks with typos/spacing/markdown/unicode": 12,
    "resource exhaustion": 3,
    "roleplay": 7,
    "tool misuse disguised as normal tasks": 8,
    "tool-mediated exfiltration": 6,
    "unauthorized network access": 5,
}

EXPECTED_BENIGN_CATEGORIES = {
    "allowed web content": 5,
    "calculation and data analysis": 10,
    "document analysis and summarization": 8,
    "formatting and conversion": 4,
    "messages and communication": 6,
    "planning and scheduling": 4,
    "search and retrieval": 9,
    "security and administration": 4,
}

DIFFICULTY_LABELS = {"easy", "medium", "hard"}


def test_benchmark_catalog_expanded_counts_and_labels():
    benchmark = AttackBenchmark()
    stats = benchmark.get_statistics()
    suite = benchmark.get_test_suite(include_benign=True)

    assert stats["total_attacks"] == 110
    assert stats["total_benign"] == 50
    assert stats["by_type"] == EXPECTED_ATTACK_COUNTS
    assert stats["by_difficulty"] == EXPECTED_ATTACK_DIFFICULTY
    assert stats["benign_by_difficulty"] == EXPECTED_BENIGN_DIFFICULTY
    assert {payload.difficulty for payload in suite} == DIFFICULTY_LABELS
    assert all(payload.category for payload in suite)


def test_benchmark_category_coverage_is_accounted_for():
    stats = AttackBenchmark().get_statistics()

    assert stats["by_category"] == EXPECTED_ATTACK_CATEGORIES
    assert stats["benign_by_category"] == EXPECTED_BENIGN_CATEGORIES
    assert sum(stats["by_category"].values()) == stats["total_attacks"]
    assert sum(stats["benign_by_category"].values()) == stats["total_benign"]


def test_defense_and_ablation_profiles_resolve_expected_modes():
    catalog = get_defense_profile_catalog()

    assert CORE_DEFENSE_CONFIGS == [
        "no-defense",
        "prompt-only",
        "rule-based",
        "ml-assisted",
        "embedding-similarity",
        "llm-as-judge",
        "hybrid",
    ]
    assert ABLATION_DEFENSE_CONFIGS == [
        "full-sentinelagent",
        "no-ml-classifier",
        "no-rule-guardrails",
        "no-exfiltration-detector",
        "no-tool-risk-classifier",
        "detection-only",
    ]
    assert ALL_DEFENSE_CONFIGS == CORE_DEFENSE_CONFIGS + ABLATION_DEFENSE_CONFIGS
    assert set(catalog) == set(ALL_DEFENSE_CONFIGS)

    assert catalog["embedding-similarity"]["use_embedding_similarity"] is True
    assert catalog["llm-as-judge"]["use_llm_judge"] is True
    assert catalog["hybrid"]["use_embedding_similarity"] is True
    assert catalog["hybrid"]["use_llm_judge"] is True

    assert catalog["full-sentinelagent"]["ablation"] is True
    assert catalog["no-ml-classifier"]["use_ml_classifier"] is False
    assert catalog["no-rule-guardrails"]["use_rule_guardrails"] is False
    assert catalog["no-exfiltration-detector"]["exfiltration_enabled"] is False
    assert catalog["no-tool-risk-classifier"]["tool_risk_enabled"] is False
    assert catalog["detection-only"]["enforce"] is False
    assert catalog["detection-only"]["runs_detection"] is True

    assert resolve_defense_profile("full").name == "full-sentinelagent"
    assert resolve_defense_profile("detect-only").name == "detection-only"
    assert resolve_defense_profile("no-tool-risk").name == "no-tool-risk-classifier"
    assert resolve_defense_profile("ml-assisted", enable_defense=False).name == "no-defense"


def test_evaluation_config_accepts_expanded_defense_mode_names():
    assert EvaluationConfig(defense_config="hybrid").defense_config == "hybrid"
    assert (
        EvaluationConfig(defense_config="no-exfiltration-detector").defense_config
        == "no-exfiltration-detector"
    )


def test_metrics_summary_includes_new_security_and_performance_fields():
    evaluator = SentinelEvaluator(orchestrator=None)
    results = [
        AttackResult(
            attack_type="injection",
            success=False,
            defense_triggered=True,
            execution_time_ms=10,
        ),
        AttackResult(
            attack_type="exfiltration",
            success=True,
            defense_triggered=False,
            leaked_secrets=["SENTINEL_CANARY_7x9k2m1p"],
            execution_time_ms=20,
        ),
        AttackResult(
            attack_type="tool_misuse",
            success=False,
            defense_triggered=True,
            unsafe_tools_called=["send_message"],
            execution_time_ms=30,
        ),
        AttackResult(
            attack_type="benign",
            success=True,
            defense_triggered=False,
            execution_time_ms=40,
        ),
        AttackResult(
            attack_type="benign",
            success=False,
            defense_triggered=True,
            execution_time_ms=50,
        ),
    ]

    summary = evaluator.compute_metrics(results, baseline_avg_latency_ms=10).to_dict()

    assert summary["total_tasks"] == 5
    assert summary["total_attacks"] == 3
    assert summary["blocked_attacks"] == 2
    assert summary["attack_success_rate"] == 0.333
    assert summary["leakage_rate"] == 0.333
    assert summary["secret_leakage_rate"] == 0.333
    assert summary["unsafe_tool_rate"] == 0.333
    assert summary["unsafe_tool_invocation_rate"] == 0.333
    assert summary["benign_task_success_rate"] == 0.5
    assert summary["false_positive_rate"] == 0.5
    assert summary["false_negative_rate"] == 0.333
    assert summary["precision"] == 0.667
    assert summary["recall"] == 0.667
    assert summary["f1_score"] == 0.667
    assert summary["f1"] == 0.667
    assert summary["avg_latency_ms"] == 30.0
    assert summary["latency_overhead_ms"] == 20.0
    assert summary["throughput_qps"] == 33.333
