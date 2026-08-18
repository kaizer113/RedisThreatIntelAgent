from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from google.adk import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel, Field, field_validator

from threat_intel_agent.agent import build_agent
from threat_intel_agent.config import get_settings
from threat_intel_agent.demo_data import ANALYST, CASES
from threat_intel_agent.services import safe_id, services

settings = get_settings()
log = logging.getLogger(__name__)
logging.basicConfig(level=settings.log_level)
STATIC_PATH = Path(__file__).with_name("static") / "index.html"
ICON_PATH = Path(__file__).parent.parent / "icon2.png"

session_service = InMemorySessionService()
runners = {
    model: Runner(
        app_name=settings.app_name,
        agent=build_agent(model),
        session_service=session_service,
        memory_service=None,
        auto_create_session=True,
    )
    for model in settings.available_google_models
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await asyncio.gather(
        *(runner.close() for runner in runners.values()),
        services.close(),
        return_exceptions=True,
    )


app = FastAPI(title="Redis Threat Intelligence Agent", lifespan=lifespan)


class InvestigationRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    model: str = settings.google_model

    @field_validator("model")
    @classmethod
    def enabled_model(cls, model: str) -> str:
        if model not in runners:
            raise ValueError("model is not enabled")
        return model


def event_text(event: Any) -> str:
    parts = getattr(getattr(event, "content", None), "parts", None) or []
    return "".join(str(part.text) for part in parts if getattr(part, "text", None)).strip()


def snippets(records: list[dict[str, Any]], limit: int = 5) -> list[str]:
    output = []
    for record in records[:limit]:
        text = record.get("text") or record.get("content") or record
        output.append(json.dumps(text, sort_keys=True, default=str)[:500])
    return output


TRACE_SECRET_FIELDS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "redis_url",
    "secret",
    "token",
)


def trace_payload(value: Any, depth: int = 0) -> Any:
    """Return a bounded JSON-safe trace value with credential fields removed."""
    if depth >= 8:
        return "[maximum depth reached]"
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {
            str(key): (
                "[redacted]"
                if any(marker in str(key).lower() for marker in TRACE_SECRET_FIELDS)
                else trace_payload(item, depth + 1)
            )
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        items = [trace_payload(item, depth + 1) for item in value[:100]]
        if len(value) > 100:
            items.append(f"[{len(value) - 100} additional item(s) omitted]")
        return items
    if isinstance(value, str):
        return value if len(value) <= 4_000 else f"{value[:4_000]}… [truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


async def investigation_events(request: InvestigationRequest) -> AsyncIterator[dict[str, Any]]:
    case = next((item for item in CASES if item["case_id"] == request.case_id), None)
    if case is None:
        yield {"type": "error", "message": "Investigation not found"}
        return

    session_id = safe_id(request.session_id, "investigation-session")
    total_started = time.perf_counter()
    yield {"type": "start", "case_id": request.case_id, "session_id": session_id}

    route = await asyncio.to_thread(
        services.router.route,
        f"{case['title']} {case['summary']}",
    )
    yield {
        "type": "trace",
        "id": "routing",
        "label": "RedisVL decision routing",
        "duration_ms": route["duration_ms"],
        "summary": f"{route['route']} · {route['source']}",
        "request": trace_payload(
            {
                "text": f"{case['title']} {case['summary']}",
            }
        ),
        "response": trace_payload(route),
    }

    governed_calls = {
        "observations": (
            "filter_observation",
            {"conditions": [{"field": "case_id", "value": request.case_id}], "limit": 20},
        ),
        "reputation": (
            "filter_reputationrecord",
            {"conditions": [{"field": "case_id", "value": request.case_id}], "limit": 20},
        ),
        "signatures": (
            "filter_signaturerecord",
            {"conditions": [{"field": "case_id", "value": request.case_id}], "limit": 20},
        ),
        "relationships": (
            "filter_relationship",
            {"conditions": [{"field": "case_id", "value": request.case_id}], "limit": 20},
        ),
        "reviewed_history": (
            "search_historicalcase_by_text",
            {"query": case["summary"], "limit": 5},
        ),
    }

    async def governed_call(
        label: str,
        name: str,
        arguments: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any], float]:
        started = time.perf_counter()
        result = await services.context.call(name, arguments)
        return label, name, result, round((time.perf_counter() - started) * 1000, 2)

    governed_results: dict[str, Any] = {}
    tasks = [
        asyncio.create_task(governed_call(label, name, arguments))
        for label, (name, arguments) in governed_calls.items()
    ]
    for task in asyncio.as_completed(tasks):
        label, name, result, duration = await task
        governed_results[label] = result
        count = result.get("count", len(result.get("results", [])))
        yield {
            "type": "trace",
            "id": f"context-{label}",
            "label": f"Context Retriever · {name}",
            "duration_ms": duration,
            "summary": f"{count} governed record(s)",
            "request": trace_payload({"tool": name, "arguments": governed_calls[label][1]}),
            "response": trace_payload(result),
        }

    memory_started = time.perf_counter()
    recent_task = asyncio.to_thread(services.memory.recent, session_id)
    recall_task = asyncio.to_thread(
        services.memory.recall,
        f"analyst review preferences for {case['indicator_type']} evidence",
    )
    recent, recalled = await asyncio.gather(recent_task, recall_task)
    yield {
        "type": "trace",
        "id": "memory",
        "label": "Redis Agent Memory",
        "duration_ms": round((time.perf_counter() - memory_started) * 1000, 2),
        "summary": f"{len(recent)} session events · {len(recalled)} durable memories",
        "request": trace_payload(
            {
                "session": {"session_id": session_id, "limit": 8},
                "long_term_memory": {
                    "query": (
                        f"analyst review preferences for {case['indicator_type']} evidence"
                    ),
                    "limit": 4,
                },
            }
        ),
        "response": trace_payload(
            {"session_events": recent, "durable_memories": recalled}
        ),
    }

    await asyncio.to_thread(
        services.memory.add_event,
        session_id,
        "USER",
        f"Analyze {request.case_id}: {case['title']}",
    )

    state_delta = {
        "case_id": request.case_id,
        "route": route["route"],
        "session_context": "\n".join(snippets(recent)) or "No prior session context.",
        "analyst_context": "\n".join(snippets(recalled)) or "No durable analyst context.",
        "governed_context": json.dumps(governed_results, sort_keys=True, default=str),
    }
    runner_started = time.perf_counter()
    final_answer = ""
    llm_calls = 0
    tool_starts: dict[str, tuple[float, str, dict[str, Any]]] = {}
    try:
        async with asyncio.timeout(settings.agent_timeout_seconds):
            async for event in runners[request.model].run_async(
                user_id=settings.analyst_id,
                session_id=session_id,
                new_message=types.Content(
                    role="user",
                    parts=[types.Part(text=f"Analyze synthetic investigation {request.case_id}.")],
                ),
                state_delta=state_delta,
            ):
                if (
                    getattr(event, "content", None)
                    and getattr(event.content, "role", "") == "model"
                ):
                    llm_calls += 1
                for call in event.get_function_calls():
                    call_id = str(call.id or call.name or "tool")
                    name = str(call.name or "tool")
                    arguments = trace_payload(getattr(call, "args", {}) or {})
                    tool_starts[call_id] = (time.perf_counter(), name, arguments)
                    yield {
                        "type": "trace",
                        "id": f"tool-{call_id}",
                        "label": name,
                        "status": "running",
                        "summary": "Calling governed evidence source",
                        "request": {"tool": name, "arguments": arguments},
                    }
                for response in event.get_function_responses():
                    call_id = str(response.id or response.name or "tool")
                    started, name, arguments = tool_starts.pop(
                        call_id,
                        (time.perf_counter(), str(response.name or "tool"), {}),
                    )
                    yield {
                        "type": "trace",
                        "id": f"tool-{call_id}",
                        "label": name,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                        "summary": "Evidence returned",
                        "request": {"tool": name, "arguments": arguments},
                        "response": trace_payload(getattr(response, "response", {}) or {}),
                    }
                if event.is_final_response():
                    final_answer = event_text(event)
    except TimeoutError:
        yield {"type": "error", "message": "Analysis timed out; retry the investigation."}
        return
    except Exception as exc:
        log.exception("Investigation failed")
        yield {"type": "error", "message": f"Analysis failed: {exc}"}
        return

    if not final_answer:
        yield {"type": "error", "message": "The agent returned no proposed assessment."}
        return

    await asyncio.to_thread(
        services.memory.add_event,
        session_id,
        "ASSISTANT",
        final_answer,
    )
    yield {
        "type": "trace",
        "id": "generation",
        "label": "Agent Loop + LLM",
        "duration_ms": round((time.perf_counter() - runner_started) * 1000, 2),
        "summary": f"{llm_calls} model event(s)",
        "request": {"model": request.model, "case_id": request.case_id},
        "response": {"assessment_status": "proposed"},
    }
    yield {"type": "answer", "answer": final_answer, "status": "proposed"}
    yield {
        "type": "trace",
        "id": "total",
        "label": "Total investigation",
        "duration_ms": round((time.perf_counter() - total_started) * 1000, 2),
        "summary": "Proposed assessment ready for human review",
    }


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse(STATIC_PATH.read_text(encoding="utf-8"))


@app.get("/icon.png", include_in_schema=False)
async def icon() -> FileResponse:
    return FileResponse(ICON_PATH, media_type="image/png")


@app.get("/api/cases")
async def cases() -> dict[str, Any]:
    return {"analyst": ANALYST, "cases": services.repository.cases()}


@app.get("/api/health")
async def health() -> dict[str, Any]:
    async def probe(operation: Any) -> bool:
        try:
            return bool(await operation)
        except Exception:
            return False

    redis_ok, context_ok, langcache_ok, memory_ok = await asyncio.gather(
        asyncio.to_thread(services.repository.ping),
        probe(services.context.list_tools()),
        probe(services.langcache.ping()),
        probe(services.memory.ping()),
    )
    return {
        "ok": True,
        "app": settings.app_name,
        "port": settings.port,
        "redis_endpoint": settings.redis_endpoint,
        "models": list(settings.available_google_models),
        "services": {
            "redis_database": redis_ok,
            "context_retriever": bool(context_ok),
            "redisvl": services.router.configured,
            "langcache": langcache_ok,
            "redis_agent_memory": memory_ok,
            "adk_memory": False,
        },
    }


@app.get("/api/context/tools")
async def context_tools() -> dict[str, Any]:
    tools = await services.context.list_tools(force=True)
    entities = [
        ("threatcase", "Threat Case"),
        ("indicator", "Indicator"),
        ("observation", "Observation"),
        ("reputationrecord", "Reputation Record"),
        ("signaturerecord", "Signature Record"),
        ("relationship", "Relationship"),
        ("historicalcase", "Historical Case"),
    ]
    grouped = {key: [] for key, _ in entities}
    grouped["other"] = []
    for tool in tools:
        name = str(tool.get("name") or "").lower()
        key = next((key for key, _ in entities if f"_{key}" in name), "other")
        grouped[key].append(tool)
    return {
        "entities": [
            {"name": label, "tools": sorted(grouped[key], key=lambda tool: tool.get("name", ""))}
            for key, label in [*entities, ("other", "Other")]
            if grouped[key]
        ]
    }


@app.post("/api/investigate/stream")
async def investigate(request: InvestigationRequest) -> StreamingResponse:
    if request.case_id not in {item["case_id"] for item in CASES}:
        raise HTTPException(status_code=404, detail="Investigation not found")

    async def stream() -> AsyncIterator[str]:
        async for event in investigation_events(request):
            yield json.dumps(event, default=str) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")
