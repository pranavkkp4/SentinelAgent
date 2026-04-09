"""
SentinelAgent: ML-Based Defense Against Prompt Injection and Data Exfiltration
in Tool-Using LLM Agents

A defense-in-depth architecture that treats the LLM as an untrusted reasoning component
and introduces ML-based security middleware across three enforcement boundaries:
1. Retrieval-time injection detection
2. Tool-call risk classification with deterministic policy gating
3. Response-level exfiltration detection
"""

__version__ = "1.0.0"
__author__ = "SentinelAgent Team"
