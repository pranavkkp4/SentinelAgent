from sentinel_agent.benchmark.tool_risk_benchmark import ToolRiskBenchmark
from sentinel_agent.policy.taxonomy import canonical_mappings


def test_canonical_taxonomy_mappings_have_required_fields():
    mappings = canonical_mappings()
    assert mappings
    for mapping in mappings:
        data = mapping.to_dict()
        assert data["attack_type"]
        assert data["attack_source"]
        assert data["target_tool"]
        assert data["tool_permissions"]
        assert data["risk_level"] in {"low", "medium", "high", "critical"}
        assert data["enforcement_action"]


def test_tool_risk_benchmark_runs_without_api_keys():
    payload = ToolRiskBenchmark().run()
    assert payload["results"]
    assert payload["metrics"]["total_cases"] == len(payload["results"])
    risk_levels = {row["risk_level"] for row in payload["results"]}
    assert {"low", "high", "critical"}.issubset(risk_levels)
    assert "policy_decision_distribution" in payload["metrics"]
