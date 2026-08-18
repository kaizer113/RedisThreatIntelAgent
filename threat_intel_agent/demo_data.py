from __future__ import annotations

from typing import Any

ANALYST = {"analyst_id": "security-analyst", "name": "Security Analyst"}

CASES: list[dict[str, Any]] = [
    {
        "case_id": "case-001",
        "title": "Known payload delivery domain",
        "primary_indicator": "payload-update.example",
        "indicator_type": "domain",
        "first_observed": "2026-08-17T17:10:00Z",
        "last_observed": "2026-08-17T19:42:00Z",
        "source_scope": "synthetic-west-edge",
        "summary": "Repeated downloads match a known synthetic signature and prior case.",
        "expected_verdict": "malicious",
        "expected_route": "exact_signature",
    },
    {
        "case_id": "case-002",
        "title": "Infrastructure related to prior campaign",
        "primary_indicator": "198.51.100.77",
        "indicator_type": "ip",
        "first_observed": "2026-08-17T12:20:00Z",
        "last_observed": "2026-08-17T20:05:00Z",
        "source_scope": "synthetic-network-sensors",
        "summary": (
            "New infrastructure shares certificate and hosting relationships with a prior case."
        ),
        "expected_verdict": "suspicious",
        "expected_route": "related_indicator",
    },
    {
        "case_id": "case-003",
        "title": "Conflicting authentication telemetry",
        "primary_indicator": "cdn-auth.example",
        "indicator_type": "domain",
        "first_observed": "2026-08-17T18:00:00Z",
        "last_observed": "2026-08-17T20:16:00Z",
        "source_scope": "synthetic-web-and-endpoint",
        "summary": (
            "Sparse endpoint behavior conflicts with neutral reputation and recent registration."
        ),
        "expected_verdict": "review",
        "expected_route": "novel_analysis",
    },
    {
        "case_id": "case-004",
        "title": "Benign service false-positive pattern",
        "primary_indicator": "telemetry-service.example",
        "indicator_type": "domain",
        "first_observed": "2026-08-17T09:15:00Z",
        "last_observed": "2026-08-17T20:25:00Z",
        "source_scope": "synthetic-email-and-web",
        "summary": (
            "High-volume traffic resembles beaconing but matches an approved synthetic service."
        ),
        "expected_verdict": "benign",
        "expected_route": "semantic_case",
    },
]

INDICATORS = [
    {
        "indicator_id": "ind-001",
        "case_id": "case-001",
        "type": "domain",
        "value": "payload-update.example",
    },
    {"indicator_id": "ind-002", "case_id": "case-001", "type": "sha256", "value": "a" * 64},
    {"indicator_id": "ind-003", "case_id": "case-002", "type": "ip", "value": "198.51.100.77"},
    {
        "indicator_id": "ind-004",
        "case_id": "case-002",
        "type": "domain",
        "value": "relay-node.example",
    },
    {
        "indicator_id": "ind-005",
        "case_id": "case-003",
        "type": "domain",
        "value": "cdn-auth.example",
    },
    {
        "indicator_id": "ind-006",
        "case_id": "case-004",
        "type": "domain",
        "value": "telemetry-service.example",
    },
]

OBSERVATIONS = [
    {
        "observation_id": "obs-001",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "channel": "web",
        "observed_at": "2026-08-17T19:42:00Z",
        "detail": "Six synthetic clients downloaded the same executable path.",
    },
    {
        "observation_id": "obs-002",
        "case_id": "case-001",
        "indicator_id": "ind-002",
        "channel": "sandbox",
        "observed_at": "2026-08-17T19:44:00Z",
        "detail": "Process injection and persistence behavior observed in the synthetic sandbox.",
    },
    {
        "observation_id": "obs-003",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "channel": "dns",
        "observed_at": "2026-08-17T20:05:00Z",
        "detail": "Two related domains resolved to the same infrastructure.",
    },
    {
        "observation_id": "obs-004",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "channel": "certificate",
        "observed_at": "2026-08-17T20:01:00Z",
        "detail": "Certificate fingerprint overlaps with a previously reviewed cluster.",
    },
    {
        "observation_id": "obs-005",
        "case_id": "case-003",
        "indicator_id": "ind-005",
        "channel": "endpoint",
        "observed_at": "2026-08-17T20:16:00Z",
        "detail": "One encoded command was observed; no persistence or payload followed.",
    },
    {
        "observation_id": "obs-006",
        "case_id": "case-003",
        "indicator_id": "ind-005",
        "channel": "dns",
        "observed_at": "2026-08-17T20:10:00Z",
        "detail": "Low-volume DNS activity with insufficient history.",
    },
    {
        "observation_id": "obs-007",
        "case_id": "case-004",
        "indicator_id": "ind-006",
        "channel": "web",
        "observed_at": "2026-08-17T20:25:00Z",
        "detail": "Periodic requests align with the approved service health interval.",
    },
    {
        "observation_id": "obs-008",
        "case_id": "case-004",
        "indicator_id": "ind-006",
        "channel": "email",
        "observed_at": "2026-08-17T18:02:00Z",
        "detail": "Links appear only in expected synthetic service notifications.",
    },
]

REPUTATION_RECORDS = [
    {
        "reputation_id": "rep-001",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "assessment": "known-bad",
        "confidence": 0.99,
        "updated_at": "2026-08-17T19:50:00Z",
        "source": "synthetic-reputation",
    },
    {
        "reputation_id": "rep-002",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "assessment": "unknown",
        "confidence": 0.40,
        "updated_at": "2026-08-17T20:06:00Z",
        "source": "synthetic-reputation",
    },
    {
        "reputation_id": "rep-003",
        "case_id": "case-003",
        "indicator_id": "ind-005",
        "assessment": "neutral",
        "confidence": 0.52,
        "updated_at": "2026-08-17T20:18:00Z",
        "source": "synthetic-reputation",
    },
    {
        "reputation_id": "rep-004",
        "case_id": "case-004",
        "indicator_id": "ind-006",
        "assessment": "approved-service",
        "confidence": 0.97,
        "updated_at": "2026-08-17T20:26:00Z",
        "source": "synthetic-reputation",
    },
]

SIGNATURE_RECORDS = [
    {
        "signature_id": "sig-001",
        "case_id": "case-001",
        "indicator_value": "payload-update.example",
        "signature_type": "exact-domain",
        "verdict": "malicious",
        "confidence": 0.99,
        "evidence_reference": "hist-001",
        "updated_at": "2026-08-16T14:00:00Z",
    },
]

RELATIONSHIPS = [
    {
        "relationship_id": "rel-001",
        "case_id": "case-002",
        "source_indicator_id": "ind-003",
        "target_indicator_id": "ind-004",
        "relationship_type": "shared-certificate",
        "confidence": 0.88,
    },
    {
        "relationship_id": "rel-002",
        "case_id": "case-002",
        "source_indicator_id": "ind-003",
        "target_indicator_id": "ind-001",
        "relationship_type": "hosting-overlap",
        "confidence": 0.71,
    },
]

HISTORICAL_CASES = [
    {
        "history_id": "hist-001",
        "title": "Synthetic downloader infrastructure",
        "verdict": "malicious",
        "campaign": "synthetic-downloader-cluster",
        "indicator_value": "payload-update.example",
        "closed_at": "2026-08-16T14:00:00Z",
        "notes": (
            "Exact domain and payload behavior were confirmed in controlled synthetic evidence."
        ),
    },
    {
        "history_id": "hist-002",
        "title": "Shared certificate infrastructure",
        "verdict": "suspicious",
        "campaign": "synthetic-relay-cluster",
        "indicator_value": "relay-node.example",
        "closed_at": "2026-08-10T10:30:00Z",
        "notes": "Infrastructure sharing alone supported monitoring and escalation, not blocking.",
    },
    {
        "history_id": "hist-003",
        "title": "Approved telemetry false positive",
        "verdict": "benign",
        "campaign": "",
        "indicator_value": "telemetry-service.example",
        "closed_at": "2026-08-12T16:45:00Z",
        "notes": "Regular beacon-like traffic matched an approved service cadence and certificate.",
    },
]

DATASETS = {
    "cases": CASES,
    "indicators": INDICATORS,
    "observations": OBSERVATIONS,
    "reputation_records": REPUTATION_RECORDS,
    "signature_records": SIGNATURE_RECORDS,
    "relationships": RELATIONSHIPS,
    "historical_cases": HISTORICAL_CASES,
}
