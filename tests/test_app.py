from __future__ import annotations

from fastapi.testclient import TestClient

from threat_intel_agent.api import app, trace_payload
from threat_intel_agent.demo_data import CASES
from threat_intel_agent.services import ThreatRepository, get_settings


def test_case_matrix_has_four_distinct_paths() -> None:
    assert len(CASES) == 4
    assert {case["expected_route"] for case in CASES} == {
        "exact_signature",
        "related_indicator",
        "semantic_case",
        "novel_analysis",
    }
    assert {case["expected_verdict"] for case in CASES} == {
        "malicious",
        "suspicious",
        "benign",
        "review",
    }


def test_repository_returns_grounded_case_bundle() -> None:
    repository = ThreatRepository(get_settings())
    repository.redis = None
    bundle = repository.case_bundle("case-001")
    assert bundle["ok"] is True
    assert bundle["case"]["primary_indicator"] == "payload-update.example"
    assert {item["observation_id"] for item in bundle["observations"]} == {
        "obs-001",
        "obs-002",
    }
    assert repository.exact_signature("payload-update.example")["matched"] is True


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
    assert '<link rel="icon" type="image/png" href="/icon.png">' in index.text
    assert '<div class="mark" role="img"' in index.text
    assert icon.status_code == 200
    assert icon.headers["content-type"] == "image/png"


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
