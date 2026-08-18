from __future__ import annotations

from fastapi.testclient import TestClient

from threat_intel_agent.api import app, trace_payload
from threat_intel_agent.demo_data import CASES, DATASETS, PAYLOAD_SHA256
from threat_intel_agent.services import ThreatRepository, get_settings

EXPECTED_CASE_OUTCOMES = {
    "case-001": {"route": "exact_signature", "verdict": "malicious"},
    "case-002": {"route": "related_indicator", "verdict": "suspicious"},
    "case-003": {"route": "novel_analysis", "verdict": "review"},
    "case-004": {"route": "semantic_case", "verdict": "benign"},
}


def test_case_matrix_keeps_evaluation_labels_out_of_runtime_data() -> None:
    assert len(CASES) == 4
    assert {item["route"] for item in EXPECTED_CASE_OUTCOMES.values()} == {
        "exact_signature",
        "related_indicator",
        "semantic_case",
        "novel_analysis",
    }
    assert {item["verdict"] for item in EXPECTED_CASE_OUTCOMES.values()} == {
        "malicious",
        "suspicious",
        "benign",
        "review",
    }
    assert {case["case_id"] for case in CASES} == set(EXPECTED_CASE_OUTCOMES)
    assert all("expected_route" not in case for case in CASES)
    assert all("expected_verdict" not in case for case in CASES)


def test_repository_returns_grounded_case_bundle() -> None:
    repository = ThreatRepository(get_settings())
    repository.redis = None
    bundle = repository.case_bundle("case-001")
    assert bundle["ok"] is True
    assert bundle["case"]["primary_indicator"] == PAYLOAD_SHA256
    assert {item["observation_id"] for item in bundle["observations"]} == {
        "obs-001",
        "obs-002",
        "obs-003",
    }
    assert repository.exact_signature(PAYLOAD_SHA256)["matched"] is True


def test_cases_have_traceable_and_conflicting_evidence() -> None:
    required_fields = {
        "sensor_id",
        "event_type",
        "observed_at",
        "collected_at",
        "event_count",
        "observation_window_seconds",
        "direction",
        "evidence_reference",
    }
    assert all(required_fields <= observation.keys() for observation in DATASETS["observations"])
    assert len({item["evidence_reference"] for item in DATASETS["observations"]}) == len(
        DATASETS["observations"]
    )

    directions_by_case = {
        case["case_id"]: {
            observation["direction"]
            for observation in DATASETS["observations"]
            if observation["case_id"] == case["case_id"]
        }
        for case in CASES
    }
    assert directions_by_case["case-001"] == {"supports_malicious"}
    assert {"supports_malicious", "supports_benign"} <= directions_by_case["case-002"]
    assert {"supports_malicious", "supports_benign"} <= directions_by_case["case-003"]
    assert "supports_benign" in directions_by_case["case-004"]


def test_evidence_references_resolve_within_each_case() -> None:
    case_ids = {case["case_id"] for case in CASES}
    indicators = {indicator["indicator_id"]: indicator for indicator in DATASETS["indicators"]}

    assert all(indicator["case_id"] in case_ids for indicator in indicators.values())
    assert all(
        observation["case_id"] in case_ids
        and indicators[observation["indicator_id"]]["case_id"] == observation["case_id"]
        for observation in DATASETS["observations"]
    )
    assert all(
        indicators[record["indicator_id"]]["case_id"] == record["case_id"]
        for record in DATASETS["reputation_records"]
    )
    assert all(
        indicators[relationship["source_indicator_id"]]["case_id"]
        == relationship["case_id"]
        == indicators[relationship["target_indicator_id"]]["case_id"]
        for relationship in DATASETS["relationships"]
    )


def test_unknown_case_is_rejected() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/investigate/stream",
            json={
                "case_id": "missing",
                "session_id": "test-session",
                "model": "gemini-3.1-flash-lite",
            },
        )
    assert response.status_code == 404


def test_case_queue_and_ui_use_product_name() -> None:
    with TestClient(app) as client:
        cases = client.get("/api/cases")
        index = client.get("/")
        icon = client.get("/icon.png")
    assert cases.status_code == 200
    assert len(cases.json()["cases"]) == 4
    assert "Redis Threat Intelligence Agent" in index.text
    assert "sessionId=crypto.randomUUID()" not in index.text
    assert "sessionId=createSessionId()" in index.text
    assert "View request and response" in index.text
    assert '>Context Retriever tools</button>' in index.text
    assert '<dialog id="toolsDialog"' in index.text
    assert "fetch('/api/context/tools')" in index.text
    assert "payload.entities" in index.text
    assert "tool-group" in index.text
    assert '<link rel="icon" type="image/png" href="/icon.png">' in index.text
    assert '<div class="mark" role="img"' in index.text
    assert icon.status_code == 200
    assert icon.headers["content-type"] == "image/png"


def test_context_tool_catalog_returns_live_definitions(monkeypatch) -> None:
    async def tool_definitions(force: bool = False):
        assert force is True
        return [
            {
                "name": "get_indicator_by_id",
                "description": "Get Indicator by ID.",
            },
            {"name": "count_threatcase", "description": "Count ThreatCase records."},
        ]

    monkeypatch.setattr("threat_intel_agent.api.services.context.list_tools", tool_definitions)
    with TestClient(app) as client:
        response = client.get("/api/context/tools")

    assert response.status_code == 200
    assert response.json() == {
        "entities": [
            {
                "name": "Threat Case",
                "tools": [
                    {
                        "name": "count_threatcase",
                        "description": "Count ThreatCase records.",
                    }
                ],
            },
            {
                "name": "Indicator",
                "tools": [
                    {
                        "name": "get_indicator_by_id",
                        "description": "Get Indicator by ID.",
                    }
                ],
            }
        ]
    }


def test_trace_payload_is_bounded_and_redacts_credentials() -> None:
    payload = trace_payload(
        {
            "case_id": "case-001",
            "authorization": "Bearer private",
            "nested": {"api_key": "private", "records": ["evidence"]},
            "long_text": "x" * 4_001,
        }
    )
    assert payload["case_id"] == "case-001"
    assert payload["authorization"] == "[redacted]"
    assert payload["nested"]["api_key"] == "[redacted]"
    assert payload["nested"]["records"] == ["evidence"]
    assert payload["long_text"].endswith("[truncated]")


def test_health_disables_adk_memory(monkeypatch) -> None:
    monkeypatch.setattr("threat_intel_agent.api.services.repository.ping", lambda: False)

    async def no_tools(force: bool = False):
        return []

    async def unavailable():
        return False

    monkeypatch.setattr("threat_intel_agent.api.services.context.list_tools", no_tools)
    monkeypatch.setattr("threat_intel_agent.api.services.langcache.ping", unavailable)
    monkeypatch.setattr("threat_intel_agent.api.services.memory.ping", unavailable)
    with TestClient(app) as client:
        payload = client.get("/api/health").json()
    assert payload["ok"] is True
    assert payload["port"] == 8082
    assert payload["models"] == [
        "gemini-3.1-flash-lite",
        "gemini-3.1-pro-preview",
    ]
    assert payload["services"]["adk_memory"] is False
