from __future__ import annotations

from typing import Any

ANALYST = {"analyst_id": "security-analyst", "name": "Security Analyst"}

PAYLOAD_SHA256 = "b" * 64
CERTIFICATE_SHA256 = "c" * 64
APPROVED_CERTIFICATE_SHA256 = "d" * 64

CASES: list[dict[str, Any]] = [
    {
        "case_id": "case-001",
        "title": "Known malicious payload recurrence",
        "primary_indicator": PAYLOAD_SHA256,
        "indicator_type": "sha256",
        "first_observed": "2026-08-17T17:10:00Z",
        "last_observed": "2026-08-17T19:48:00Z",
        "source_scope": "synthetic-west-edge",
        "summary": (
            "A previously reviewed payload hash reappeared in web downloads and endpoint "
            "execution telemetry with consistent sandbox behavior."
        ),
    },
    {
        "case_id": "case-002",
        "title": "Infrastructure related to a reviewed campaign",
        "primary_indicator": "198.51.100.77",
        "indicator_type": "ip",
        "first_observed": "2026-08-17T12:20:00Z",
        "last_observed": "2026-08-17T20:05:00Z",
        "source_scope": "synthetic-network-sensors",
        "summary": (
            "New infrastructure shares a certificate and short-lived DNS relationships with a "
            "reviewed cluster, but has no direct malicious payload observation."
        ),
    },
    {
        "case_id": "case-003",
        "title": "Conflicting authentication telemetry",
        "primary_indicator": "cdn-auth.example",
        "indicator_type": "domain",
        "first_observed": "2026-08-17T18:00:00Z",
        "last_observed": "2026-08-17T20:22:00Z",
        "source_scope": "synthetic-web-and-endpoint",
        "summary": (
            "A newly observed domain was associated with one encoded interpreter command, while "
            "repeat sandbox runs and DNS telemetry produced no corroborating malicious behavior."
        ),
    },
    {
        "case_id": "case-004",
        "title": "Approved service false-positive pattern",
        "primary_indicator": "telemetry-service.example",
        "indicator_type": "domain",
        "first_observed": "2026-08-17T09:15:00Z",
        "last_observed": "2026-08-17T20:25:00Z",
        "source_scope": "synthetic-email-and-web",
        "summary": (
            "Regular outbound requests resemble beaconing but match a registered internal service, "
            "its expected certificate, and an approved notification workflow."
        ),
    },
]

INDICATORS = [
    {
        "indicator_id": "ind-001",
        "case_id": "case-001",
        "type": "sha256",
        "value": PAYLOAD_SHA256,
    },
    {
        "indicator_id": "ind-002",
        "case_id": "case-001",
        "type": "domain",
        "value": "payload-update.example",
    },
    {
        "indicator_id": "ind-003",
        "case_id": "case-002",
        "type": "ip",
        "value": "198.51.100.77",
    },
    {
        "indicator_id": "ind-004",
        "case_id": "case-002",
        "type": "domain",
        "value": "relay-node.example",
    },
    {
        "indicator_id": "ind-005",
        "case_id": "case-002",
        "type": "x509_sha256",
        "value": CERTIFICATE_SHA256,
    },
    {
        "indicator_id": "ind-006",
        "case_id": "case-003",
        "type": "domain",
        "value": "cdn-auth.example",
    },
    {
        "indicator_id": "ind-007",
        "case_id": "case-004",
        "type": "domain",
        "value": "telemetry-service.example",
    },
    {
        "indicator_id": "ind-008",
        "case_id": "case-004",
        "type": "x509_sha256",
        "value": APPROVED_CERTIFICATE_SHA256,
    },
]

OBSERVATIONS = [
    {
        "observation_id": "obs-001",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "channel": "web_gateway",
        "sensor_id": "sensor-web-west-02",
        "event_type": "file_download",
        "observed_at": "2026-08-17T19:42:00Z",
        "collected_at": "2026-08-17T19:42:08Z",
        "event_count": 6,
        "observation_window_seconds": 9120,
        "direction": "supports_malicious",
        "evidence_reference": "web-batch-20260817-044",
        "detail": (
            "Six clients downloaded /client/update/v3/update.bin; all responses produced the "
            "case SHA256."
        ),
    },
    {
        "observation_id": "obs-002",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "channel": "sandbox",
        "sensor_id": "sandbox-pool-01",
        "event_type": "behavior_report",
        "observed_at": "2026-08-17T19:44:00Z",
        "collected_at": "2026-08-17T19:46:31Z",
        "event_count": 2,
        "observation_window_seconds": 300,
        "direction": "supports_malicious",
        "evidence_reference": "sandbox-report-7712",
        "detail": (
            "Two isolated executions produced the same interpreter child process, process "
            "injection behavior, and user-logon persistence change."
        ),
    },
    {
        "observation_id": "obs-003",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "channel": "endpoint",
        "sensor_id": "endpoint-fleet-west",
        "event_type": "execution_sequence",
        "observed_at": "2026-08-17T19:48:00Z",
        "collected_at": "2026-08-17T19:48:12Z",
        "event_count": 4,
        "observation_window_seconds": 180,
        "direction": "supports_malicious",
        "evidence_reference": "endpoint-hunt-219",
        "detail": (
            "Four of six download clients executed the file and created the same persistence entry."
        ),
    },
    {
        "observation_id": "obs-004",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "channel": "passive_dns",
        "sensor_id": "dns-sensor-west-03",
        "event_type": "resolution_cluster",
        "observed_at": "2026-08-17T20:05:00Z",
        "collected_at": "2026-08-17T20:05:19Z",
        "event_count": 7,
        "observation_window_seconds": 1800,
        "direction": "context_only",
        "evidence_reference": "dns-window-8821",
        "detail": (
            "Two synthetic domains, including relay-node.example, resolved to the IP during a "
            "30-minute window; neither delivered a captured payload."
        ),
    },
    {
        "observation_id": "obs-005",
        "case_id": "case-002",
        "indicator_id": "ind-005",
        "channel": "tls",
        "sensor_id": "tls-sensor-west-01",
        "event_type": "certificate_reuse",
        "observed_at": "2026-08-17T20:01:00Z",
        "collected_at": "2026-08-17T20:01:07Z",
        "event_count": 3,
        "observation_window_seconds": 86400,
        "direction": "supports_malicious",
        "evidence_reference": "tls-cluster-114",
        "detail": (
            "The certificate fingerprint appeared on the case IP and two hosts from a previously "
            "reviewed infrastructure cluster."
        ),
    },
    {
        "observation_id": "obs-006",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "channel": "network",
        "sensor_id": "flow-sensor-west-04",
        "event_type": "payload_check",
        "observed_at": "2026-08-17T20:04:00Z",
        "collected_at": "2026-08-17T20:04:21Z",
        "event_count": 0,
        "observation_window_seconds": 27900,
        "direction": "supports_benign",
        "evidence_reference": "flow-review-552",
        "detail": (
            "No file transfer, exploit pattern, or callback was observed in the available "
            "flow window."
        ),
    },
    {
        "observation_id": "obs-007",
        "case_id": "case-003",
        "indicator_id": "ind-006",
        "channel": "endpoint",
        "sensor_id": "endpoint-fleet-west",
        "event_type": "encoded_command",
        "observed_at": "2026-08-17T20:16:00Z",
        "collected_at": "2026-08-17T20:16:09Z",
        "event_count": 1,
        "observation_window_seconds": 60,
        "direction": "supports_malicious",
        "evidence_reference": "endpoint-event-9918",
        "detail": (
            "One client launched an encoded interpreter command after connecting to the domain; "
            "the command produced no child payload or persistence event."
        ),
    },
    {
        "observation_id": "obs-008",
        "case_id": "case-003",
        "indicator_id": "ind-006",
        "channel": "domain_inventory",
        "sensor_id": "domain-catalog-01",
        "event_type": "first_seen",
        "observed_at": "2026-08-17T20:10:00Z",
        "collected_at": "2026-08-17T20:12:00Z",
        "event_count": 1,
        "observation_window_seconds": 129600,
        "direction": "context_only",
        "evidence_reference": "domain-record-337",
        "detail": (
            "The domain was first observed 36 hours earlier and has insufficient history for "
            "prevalence scoring."
        ),
    },
    {
        "observation_id": "obs-009",
        "case_id": "case-003",
        "indicator_id": "ind-006",
        "channel": "sandbox",
        "sensor_id": "sandbox-pool-01",
        "event_type": "behavior_report",
        "observed_at": "2026-08-17T20:20:00Z",
        "collected_at": "2026-08-17T20:22:00Z",
        "event_count": 2,
        "observation_window_seconds": 600,
        "direction": "supports_benign",
        "evidence_reference": "sandbox-report-7799",
        "detail": (
            "Two controlled visits produced no download, redirect, credential form, callback, or "
            "persistence."
        ),
    },
    {
        "observation_id": "obs-010",
        "case_id": "case-003",
        "indicator_id": "ind-006",
        "channel": "passive_dns",
        "sensor_id": "dns-sensor-west-03",
        "event_type": "low_prevalence",
        "observed_at": "2026-08-17T20:10:00Z",
        "collected_at": "2026-08-17T20:10:11Z",
        "event_count": 3,
        "observation_window_seconds": 7200,
        "direction": "context_only",
        "evidence_reference": "dns-window-8840",
        "detail": (
            "Three clients queried the domain with no periodic cadence and no related suspicious "
            "resolutions."
        ),
    },
    {
        "observation_id": "obs-011",
        "case_id": "case-004",
        "indicator_id": "ind-007",
        "channel": "network",
        "sensor_id": "flow-sensor-west-02",
        "event_type": "periodic_https",
        "observed_at": "2026-08-17T20:25:00Z",
        "collected_at": "2026-08-17T20:25:05Z",
        "event_count": 288,
        "observation_window_seconds": 86400,
        "direction": "context_only",
        "evidence_reference": "flow-window-881",
        "detail": (
            "HTTPS health requests occurred every 300 seconds with stable size and no payload."
        ),
    },
    {
        "observation_id": "obs-012",
        "case_id": "case-004",
        "indicator_id": "ind-008",
        "channel": "asset_inventory",
        "sensor_id": "service-catalog-01",
        "event_type": "ownership_verification",
        "observed_at": "2026-08-17T20:23:00Z",
        "collected_at": "2026-08-17T20:23:02Z",
        "event_count": 1,
        "observation_window_seconds": 2592000,
        "direction": "supports_benign",
        "evidence_reference": "service-registration-042",
        "detail": (
            "The domain, certificate fingerprint, five-minute cadence, and destination owner match "
            "an active synthetic service registration reviewed within 30 days."
        ),
    },
    {
        "observation_id": "obs-013",
        "case_id": "case-004",
        "indicator_id": "ind-007",
        "channel": "email",
        "sensor_id": "mail-sensor-west-01",
        "event_type": "notification_link",
        "observed_at": "2026-08-17T18:02:00Z",
        "collected_at": "2026-08-17T18:02:14Z",
        "event_count": 42,
        "observation_window_seconds": 43200,
        "direction": "supports_benign",
        "evidence_reference": "mail-campaign-118",
        "detail": (
            "All observed links were confined to the approved service notification template and "
            "tenant list."
        ),
    },
]

REPUTATION_RECORDS = [
    {
        "reputation_id": "rep-001",
        "case_id": "case-001",
        "indicator_id": "ind-001",
        "assessment": "malicious",
        "confidence": 0.99,
        "first_seen": "2026-08-16T12:11:00Z",
        "last_seen": "2026-08-17T19:48:00Z",
        "updated_at": "2026-08-17T19:50:00Z",
        "review_after": "2026-09-17T19:50:00Z",
        "source": "synthetic-file-reputation",
        "basis": "Reviewed hash match plus repeat sandbox and endpoint behavior.",
    },
    {
        "reputation_id": "rep-002",
        "case_id": "case-001",
        "indicator_id": "ind-002",
        "assessment": "malicious",
        "confidence": 0.91,
        "first_seen": "2026-08-16T12:05:00Z",
        "last_seen": "2026-08-17T19:42:00Z",
        "updated_at": "2026-08-17T19:50:00Z",
        "review_after": "2026-08-24T19:50:00Z",
        "source": "synthetic-web-reputation",
        "basis": "Repeated delivery of the reviewed malicious payload hash.",
    },
    {
        "reputation_id": "rep-003",
        "case_id": "case-002",
        "indicator_id": "ind-003",
        "assessment": "unknown",
        "confidence": 0.40,
        "first_seen": "2026-08-17T12:20:00Z",
        "last_seen": "2026-08-17T20:05:00Z",
        "updated_at": "2026-08-17T20:06:00Z",
        "review_after": "2026-08-18T20:06:00Z",
        "source": "synthetic-network-reputation",
        "basis": "Insufficient direct behavior; related infrastructure is evaluated separately.",
    },
    {
        "reputation_id": "rep-004",
        "case_id": "case-003",
        "indicator_id": "ind-006",
        "assessment": "unknown",
        "confidence": 0.52,
        "first_seen": "2026-08-16T08:10:00Z",
        "last_seen": "2026-08-17T20:22:00Z",
        "updated_at": "2026-08-17T20:23:00Z",
        "review_after": "2026-08-18T20:23:00Z",
        "source": "synthetic-domain-reputation",
        "basis": "Low prevalence with one concerning endpoint event and two clean sandbox runs.",
    },
    {
        "reputation_id": "rep-005",
        "case_id": "case-004",
        "indicator_id": "ind-007",
        "assessment": "verified-approved-service",
        "confidence": 0.97,
        "first_seen": "2026-06-01T00:00:00Z",
        "last_seen": "2026-08-17T20:25:00Z",
        "updated_at": "2026-08-17T20:26:00Z",
        "review_after": "2026-09-16T20:26:00Z",
        "source": "synthetic-service-catalog",
        "basis": "Current ownership, certificate, cadence, and notification-template match.",
    },
]

SIGNATURE_RECORDS = [
    {
        "signature_id": "sig-001",
        "case_id": "case-001",
        "indicator_value": PAYLOAD_SHA256,
        "signature_type": "sha256_exact_match",
        "artifact_format": "vendor-neutral-file-hash",
        "target": "downloaded_file",
        "revision": 2,
        "verdict": "malicious",
        "confidence": 0.99,
        "false_positive_risk": "low",
        "evidence_reference": "hist-001",
        "updated_at": "2026-08-16T14:00:00Z",
        "valid_until": "2026-09-17T14:00:00Z",
    },
]

RELATIONSHIPS = [
    {
        "relationship_id": "rel-001",
        "case_id": "case-002",
        "source_indicator_id": "ind-003",
        "target_indicator_id": "ind-005",
        "relationship_type": "presented-certificate",
        "confidence": 0.99,
        "first_seen": "2026-08-17T20:01:00Z",
        "last_seen": "2026-08-17T20:01:00Z",
        "evidence_reference": "tls-cluster-114",
        "basis": "The case IP presented the synthetic certificate fingerprint during collection.",
    },
    {
        "relationship_id": "rel-002",
        "case_id": "case-002",
        "source_indicator_id": "ind-005",
        "target_indicator_id": "ind-004",
        "relationship_type": "certificate-reuse",
        "confidence": 0.88,
        "first_seen": "2026-08-10T09:12:00Z",
        "last_seen": "2026-08-17T20:01:00Z",
        "evidence_reference": "tls-cluster-114",
        "basis": "The same fingerprint appeared on the reviewed relay domain and the case IP.",
    },
    {
        "relationship_id": "rel-003",
        "case_id": "case-002",
        "source_indicator_id": "ind-003",
        "target_indicator_id": "ind-004",
        "relationship_type": "resolved-to",
        "confidence": 0.93,
        "first_seen": "2026-08-17T19:35:00Z",
        "last_seen": "2026-08-17T20:05:00Z",
        "evidence_reference": "dns-window-8821",
        "basis": "Seven passive DNS observations linked the domain and IP in 30 minutes.",
    },
]

HISTORICAL_CASES = [
    {
        "history_id": "hist-001",
        "title": "Synthetic downloader payload",
        "verdict": "malicious",
        "campaign": "synthetic-downloader-cluster",
        "indicator_value": PAYLOAD_SHA256,
        "closed_at": "2026-08-16T14:00:00Z",
        "reviewer_role": "malware-analyst",
        "artifact_type": "file_signature",
        "artifact_reference": "sig-001",
        "false_positive_notes": "Exact hash scope; no collisions observed in the synthetic corpus.",
        "notes": "The hash was confirmed by two sandbox runs and three endpoint execution traces.",
    },
    {
        "history_id": "hist-002",
        "title": "Shared certificate infrastructure",
        "verdict": "suspicious",
        "campaign": "synthetic-relay-cluster",
        "indicator_value": "relay-node.example",
        "closed_at": "2026-08-10T10:30:00Z",
        "reviewer_role": "infrastructure-analyst",
        "artifact_type": "indicator",
        "artifact_reference": "historical-reputation-204",
        "false_positive_notes": "Certificate reuse alone is insufficient for blocking.",
        "notes": (
            "Certificate reuse plus short-lived DNS supported monitoring and review, not blocking."
        ),
    },
    {
        "history_id": "hist-003",
        "title": "Approved telemetry false positive",
        "verdict": "benign",
        "campaign": "",
        "indicator_value": "telemetry-service.example",
        "closed_at": "2026-08-12T16:45:00Z",
        "reviewer_role": "service-owner-reviewer",
        "artifact_type": "allow_exception",
        "artifact_reference": "service-registration-042",
        "false_positive_notes": (
            "Revalidate ownership and certificate before renewing the exception."
        ),
        "notes": (
            "Five-minute HTTPS cadence matched the registered service and expected certificate."
        ),
    },
    {
        "history_id": "hist-004",
        "title": "Uncorroborated encoded command",
        "verdict": "review",
        "campaign": "",
        "indicator_value": "auth-edge.example",
        "closed_at": "2026-08-11T11:20:00Z",
        "reviewer_role": "endpoint-analyst",
        "artifact_type": "none",
        "artifact_reference": "",
        "false_positive_notes": "Encoded commands require process and payload corroboration.",
        "notes": (
            "A single endpoint event with clean sandbox results remained unresolved pending "
            "telemetry."
        ),
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
