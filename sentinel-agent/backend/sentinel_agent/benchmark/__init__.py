"""Benchmark module for SentinelAgent."""

from .attacks import (
    AttackPayload,
    INJECTION_ATTACKS,
    EXFILTRATION_ATTACKS,
    TOOL_MISUSE_ATTACKS,
    BENIGN_TASKS,
    get_all_attacks,
    get_attacks_by_type,
    get_benign_tasks,
    create_adversarial_document,
    AttackBenchmark
)
from .evaluator import EvaluationConfig, SentinelEvaluator
from .tool_risk_benchmark import ToolRiskBenchmark, ToolRiskCase, create_tool_risk_cases
from .generator import generate_benchmark, write_benchmark, write_classifier_dataset
from .adaptive_attacks import generate_adaptive_attacks, write_adaptive_attacks

build_tool_risk_cases = create_tool_risk_cases

__all__ = [
    "AttackPayload",
    "INJECTION_ATTACKS",
    "EXFILTRATION_ATTACKS",
    "TOOL_MISUSE_ATTACKS",
    "BENIGN_TASKS",
    "get_all_attacks",
    "get_attacks_by_type",
    "get_benign_tasks",
    "create_adversarial_document",
    "AttackBenchmark",
    "EvaluationConfig",
    "SentinelEvaluator",
    "ToolRiskBenchmark",
    "ToolRiskCase",
    "build_tool_risk_cases",
    "create_tool_risk_cases",
    "generate_benchmark",
    "write_benchmark",
    "write_classifier_dataset",
    "generate_adaptive_attacks",
    "write_adaptive_attacks",
]
