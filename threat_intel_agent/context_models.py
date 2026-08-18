"""Governed synthetic evidence model for Redis Context Retriever."""

from __future__ import annotations

from typing import Any

from context_surfaces.context_model import ContextField, ContextModel, ContextRelationship

PREFIX = "threatintel:context"


class ThreatCase(ContextModel):
    __redis_key_template__ = f"{PREFIX}:case:{{case_id}}"

    case_id: str = ContextField(description="Synthetic investigation ID", is_key_component=True)
    title: str = ContextField(description="Investigation title", index="text", weight=2.0)
    primary_indicator: str = ContextField(description="Primary indicator", index="tag")
    indicator_type: str = ContextField(description="Primary indicator type", index="tag")
    first_observed: str = ContextField(description="First observed timestamp", index="tag")
    last_observed: str = ContextField(description="Most recent observation timestamp", index="tag")
    source_scope: str = ContextField(description="Synthetic source scope", index="tag")
    summary: str = ContextField(description="Investigation summary", index="text")
    indicators: Any = ContextRelationship(
        description="Indicators in this case", target="Indicator", source_field="case_id"
    )
    observations: Any = ContextRelationship(
        description="Observations in this case", target="Observation", source_field="case_id"
    )
    reputation: Any = ContextRelationship(
        description="Reputation evidence", target="ReputationRecord", source_field="case_id"
    )
    relationships: Any = ContextRelationship(
        description="Indicator relationships", target="Relationship", source_field="case_id"
    )


class Indicator(ContextModel):
    __redis_key_template__ = f"{PREFIX}:indicator:{{indicator_id}}"

    indicator_id: str = ContextField(description="Indicator ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    type: str = ContextField(description="Indicator type", index="tag")
    value: str = ContextField(description="Indicator value", index="tag")


class Observation(ContextModel):
    __redis_key_template__ = f"{PREFIX}:observation:{{observation_id}}"

    observation_id: str = ContextField(description="Observation ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    indicator_id: str = ContextField(description="Observed indicator ID", index="tag")
    channel: str = ContextField(description="Evidence channel", index="tag")
    sensor_id: str = ContextField(description="Synthetic collection sensor", index="tag")
    event_type: str = ContextField(description="Observed event type", index="tag")
    observed_at: str = ContextField(description="Observation timestamp", index="tag")
    collected_at: str = ContextField(description="Evidence collection timestamp", index="tag")
    event_count: int = ContextField(description="Events represented", index="numeric")
    observation_window_seconds: int = ContextField(
        description="Observation window in seconds", index="numeric"
    )
    direction: str = ContextField(description="How the evidence bears on risk", index="tag")
    evidence_reference: str = ContextField(description="Source evidence reference", index="tag")
    detail: str = ContextField(description="Synthetic observation detail", index="text")


class ReputationRecord(ContextModel):
    __redis_key_template__ = f"{PREFIX}:reputation:{{reputation_id}}"

    reputation_id: str = ContextField(description="Reputation record ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    indicator_id: str = ContextField(description="Indicator ID", index="tag")
    assessment: str = ContextField(description="Source assessment", index="tag")
    confidence: float = ContextField(
        description="Source confidence", index="numeric", sortable=True
    )
    first_seen: str = ContextField(description="First source sighting", index="tag")
    last_seen: str = ContextField(description="Most recent source sighting", index="tag")
    updated_at: str = ContextField(description="Assessment update timestamp", index="tag")
    review_after: str = ContextField(description="Assessment review deadline", index="tag")
    source: str = ContextField(description="Synthetic provenance", index="tag")
    basis: str = ContextField(description="Assessment basis", index="text")


class SignatureRecord(ContextModel):
    __redis_key_template__ = f"{PREFIX}:signature:{{signature_id}}"

    signature_id: str = ContextField(description="Signature ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    indicator_value: str = ContextField(description="Exact indicator value", index="tag")
    signature_type: str = ContextField(description="Signature type", index="tag")
    artifact_format: str = ContextField(description="Vendor-neutral artifact format", index="tag")
    target: str = ContextField(description="Detection target", index="tag")
    revision: int = ContextField(description="Artifact revision", index="numeric")
    verdict: str = ContextField(description="Prior reviewed verdict", index="tag")
    confidence: float = ContextField(description="Reviewed confidence", index="numeric")
    false_positive_risk: str = ContextField(description="False-positive risk", index="tag")
    evidence_reference: str = ContextField(description="Historical evidence ID", index="tag")
    updated_at: str = ContextField(description="Signature update timestamp", index="tag")
    valid_until: str = ContextField(description="Artifact validity deadline", index="tag")


class Relationship(ContextModel):
    __redis_key_template__ = f"{PREFIX}:relationship:{{relationship_id}}"

    relationship_id: str = ContextField(description="Relationship ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    source_indicator_id: str = ContextField(description="Source indicator ID", index="tag")
    target_indicator_id: str = ContextField(description="Target indicator ID", index="tag")
    relationship_type: str = ContextField(description="Relationship type", index="tag")
    confidence: float = ContextField(description="Relationship confidence", index="numeric")
    first_seen: str = ContextField(description="First relationship sighting", index="tag")
    last_seen: str = ContextField(description="Most recent relationship sighting", index="tag")
    evidence_reference: str = ContextField(description="Source evidence reference", index="tag")
    basis: str = ContextField(description="Relationship basis", index="text")


class HistoricalCase(ContextModel):
    __redis_key_template__ = f"{PREFIX}:history:{{history_id}}"

    history_id: str = ContextField(description="Reviewed case ID", is_key_component=True)
    title: str = ContextField(description="Reviewed case title", index="text", weight=2.0)
    verdict: str = ContextField(description="Reviewed verdict", index="tag")
    campaign: str = ContextField(description="Optional synthetic cluster", index="tag")
    indicator_value: str = ContextField(description="Reviewed indicator", index="tag")
    closed_at: str = ContextField(description="Review completion timestamp", index="tag")
    reviewer_role: str = ContextField(description="Synthetic reviewer role", index="tag")
    artifact_type: str = ContextField(description="Resulting artifact type", index="tag")
    artifact_reference: str = ContextField(description="Resulting artifact reference", index="tag")
    false_positive_notes: str = ContextField(description="False-positive guidance", index="text")
    notes: str = ContextField(description="Reviewed analyst notes", index="text")
