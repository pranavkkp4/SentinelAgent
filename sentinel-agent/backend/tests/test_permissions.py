from sentinel_agent.policy import Permission, RiskLevel, TargetTool
from sentinel_agent.policy.permissions import compute_tool_risk, get_permission_risk, get_tool_permissions


def test_tool_permission_mapping_core_contexts():
    assert get_tool_permissions("calculator") == [Permission.READ_PUBLIC]
    assert get_tool_permissions("web_fetch") == [Permission.READ_PUBLIC]
    assert get_tool_permissions("document_search", document_class="confidential") == [Permission.READ_PRIVATE]
    assert set(get_tool_permissions("send_message")) == {Permission.SEND_MESSAGE, Permission.WRITE_EXTERNAL}
    assert set(get_tool_permissions(TargetTool.SHELL_EXECUTOR)) == {Permission.EXECUTE_CODE, Permission.WRITE_EXTERNAL}


def test_permission_risk_levels():
    assert get_permission_risk(Permission.READ_PUBLIC) == RiskLevel.LOW
    assert get_permission_risk(Permission.READ_PRIVATE) == RiskLevel.HIGH
    assert get_permission_risk(Permission.EXECUTE_CODE) == RiskLevel.CRITICAL


def test_compute_tool_risk_uses_highest_permission():
    assert compute_tool_risk("calculator") == RiskLevel.LOW
    assert compute_tool_risk("send_message") == RiskLevel.HIGH
    assert compute_tool_risk("shell_executor") == RiskLevel.CRITICAL
