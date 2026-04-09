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
    "SentinelEvaluator"
]
