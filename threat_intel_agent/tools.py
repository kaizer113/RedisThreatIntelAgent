from __future__ import annotations

from typing import Any

from google.adk.tools import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.genai import types

from threat_intel_agent.services import services


def get_case_evidence(case_id: str) -> dict[str, Any]:
    """Get the complete synthetic evidence bundle for an investigation.

    Args:
        case_id: Exact investigation ID shown in the case queue.
    """
    return services.repository.case_bundle(case_id)


def lookup_exact_signature(indicator_value: str) -> dict[str, Any]:
    """Check for an exact reviewed signature match.

    Args:
        indicator_value: Exact domain, IP, hash, or other indicator value.
    """
    return services.repository.exact_signature(indicator_value)


def search_historical_cases(query: str, limit: int = 3) -> dict[str, Any]:
    """Search reviewed synthetic investigations and analyst notes.

    Args:
        query: Evidence summary or indicator to compare with reviewed cases.
        limit: Maximum reviewed cases to return, from 1 to 5.
    """
    return {"cases": services.repository.historical_cases(query, limit)}


async def list_governed_evidence_tools() -> dict[str, Any]:
    """List governed evidence tools exposed by Redis Context Retriever."""
    return {"tools": await services.context.list_tools()}


class GovernedEvidenceTool(BaseTool):
    def __init__(self, definition: dict[str, Any]) -> None:
        self.definition = definition
        super().__init__(
            name=str(definition["name"]),
            description=str(definition.get("description") or "Query governed synthetic evidence."),
        )

    def _get_declaration(self) -> types.FunctionDeclaration:
        schema = self.definition.get("inputSchema") or self.definition.get("input_schema")
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        return types.FunctionDeclaration(
            name=self.name,
            description=self.description,
            parameters_json_schema=schema,
        )

    async def run_async(
        self,
        *,
        args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any]:
        return await services.context.call(self.name, args)


class GovernedEvidenceToolset(BaseToolset):
    async def get_tools(self, readonly_context: Any | None = None) -> list[BaseTool]:
        definitions = await services.context.list_tools()
        reserved = {tool.__name__ for tool in STATIC_TOOLS}
        return [
            GovernedEvidenceTool(definition)
            for definition in definitions
            if definition.get("name") and str(definition["name"]) not in reserved
        ]


STATIC_TOOLS = [
    get_case_evidence,
    lookup_exact_signature,
    search_historical_cases,
    list_governed_evidence_tools,
]
GOVERNED_EVIDENCE_TOOLSET = GovernedEvidenceToolset()
