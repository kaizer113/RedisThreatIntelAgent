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
    expected_verdict: str = ContextField(description="Demo evaluation label", index="tag")
    expected_route: str = ContextField(description="Demo evaluation route", index="tag")

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
    observed_at: str = ContextField(description="Observation timestamp", index="tag")
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
    updated_at: str = ContextField(description="Evidence update timestamp", index="tag")
    source: str = ContextField(description="Synthetic provenance", index="tag")


class SignatureRecord(ContextModel):
    __redis_key_template__ = f"{PREFIX}:signature:{{signature_id}}"

    signature_id: str = ContextField(description="Signature ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    indicator_value: str = ContextField(description="Exact indicator value", index="tag")
    signature_type: str = ContextField(description="Signature type", index="tag")
    verdict: str = ContextField(description="Prior reviewed verdict", index="tag")
    confidence: float = ContextField(description="Reviewed confidence", index="numeric")
    evidence_reference: str = ContextField(description="Historical evidence ID", index="tag")
    updated_at: str = ContextField(description="Signature update timestamp", index="tag")


class Relationship(ContextModel):
    __redis_key_template__ = f"{PREFIX}:relationship:{{relationship_id}}"

    relationship_id: str = ContextField(description="Relationship ID", is_key_component=True)
    case_id: str = ContextField(description="Investigation ID", index="tag")
    source_indicator_id: str = ContextField(description="Source indicator ID", index="tag")
    target_indicator_id: str = ContextField(description="Target indicator ID", index="tag")
    relationship_type: str = ContextField(description="Relationship type", index="tag")
    confidence: float = ContextField(description="Relationship confidence", index="numeric")


class HistoricalCase(ContextModel):
    __redis_key_template__ = f"{PREFIX}:history:{{history_id}}"

    history_id: str = ContextField(description="Reviewed case ID", is_key_component=True)
    title: str = ContextField(description="Reviewed case title", index="text", weight=2.0)
    verdict: str = ContextField(description="Reviewed verdict", index="tag")
    campaign: str = ContextField(description="Optional synthetic cluster", index="tag")
    indicator_value: str = ContextField(description="Reviewed indicator", index="tag")
    closed_at: str = ContextField(description="Review completion timestamp", index="tag")
    notes: str = ContextField(description="Reviewed analyst notes", index="text")
