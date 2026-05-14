from sentinel_agent.policy import (
    AttackSource,
    AttackType,
    EnforcementAction,
    PolicyContext,
    PolicyEngine,
    TargetTool,
)


def test_low_risk_suspicious_tool_asks_confirmation():
    decision = PolicyEngine().evaluate(
        PolicyContext(
            detector_score=0.45,
            detector_label="suspicious",
            attack_type=AttackType.PROMPT_INJECTION,
            attack_source=AttackSource.USER_PROMPT,
            target_tool=TargetTool.CALCULATOR,
        )
    )
    assert decision.action == EnforcementAction.ASK_USER_CONFIRMATION
    assert decision.risk_level.value == "low"


def test_private_data_exfiltration_blocks_session_or_tool():
    decision = PolicyEngine().evaluate(
        PolicyContext(
            detector_score=0.9,
            detector_label="malicious",
            attack_type=AttackType.DATA_EXFILTRATION,
            attack_source=AttackSource.RETRIEVED_DOCUMENT,
            target_tool=TargetTool.FILE_READER,
            private_data_involved=True,
        )
    )
    assert decision.action in {EnforcementAction.BLOCK_TOOL_CALL, EnforcementAction.BLOCK_SESSION}
    assert decision.allowed is False


def test_execute_code_malicious_signal_blocks_session():
    decision = PolicyEngine().evaluate(
        PolicyContext(
            detector_score=0.92,
            detector_label="malicious",
            attack_type=AttackType.TOOL_MISUSE,
            attack_source=AttackSource.TOOL_OUTPUT,
            target_tool=TargetTool.SHELL_EXECUTOR,
        )
    )
    assert decision.action == EnforcementAction.BLOCK_SESSION


def test_benign_low_risk_allows():
    decision = PolicyEngine().evaluate(
        PolicyContext(
            detector_score=0.03,
            detector_label="benign",
            attack_type=AttackType.PROMPT_INJECTION,
            attack_source=AttackSource.USER_PROMPT,
            target_tool=TargetTool.CALCULATOR,
        )
    )
    assert decision.action == EnforcementAction.ALLOW
