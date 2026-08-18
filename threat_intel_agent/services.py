from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import redis
from redisvl.extensions.cache.embeddings import EmbeddingsCache
from redisvl.utils.vectorize import HFTextVectorizer

from threat_intel_agent.config import Settings, get_settings
from threat_intel_agent.demo_data import CASES, DATASETS, HISTORICAL_CASES, SIGNATURE_RECORDS

log = logging.getLogger(__name__)


def safe_id(value: str, fallback: str) -> str:
    normalized = "".join(char if char.isalnum() or char in "-_" else "-" for char in value)
    return normalized.strip("-")[:128] or fallback


class ThreatRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.redis: redis.Redis | None = None
        if settings.redis_url:
            try:
                self.redis = redis.Redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    health_check_interval=30,
                )
            except Exception as exc:
                log.warning("Redis initialization failed: %s", exc)

    def ping(self) -> bool:
        return bool(self.redis and self.redis.ping())

    def seed(self) -> int:
        if self.redis is None:
            raise RuntimeError("REDIS_URL is required")
        pipeline = self.redis.pipeline(transaction=False)
        count = 0
        id_fields = {
            "cases": "case_id",
            "indicators": "indicator_id",
            "observations": "observation_id",
            "reputation_records": "reputation_id",
            "signature_records": "signature_id",
            "relationships": "relationship_id",
            "historical_cases": "history_id",
        }
        for dataset_name, rows in DATASETS.items():
            entity = dataset_name.removesuffix("s").replace("_records", "")
            id_field = id_fields[dataset_name]
            for row in rows:
                key = f"{self.settings.redis_key_prefix}:{entity}:{row[id_field]}"
                pipeline.hset(
                    key,
                    mapping={
                        name: json.dumps(value) if isinstance(value, (dict, list)) else value
                        for name, value in row.items()
                    },
                )
                count += 1
        pipeline.execute()
        return count

    def cases(self) -> list[dict[str, Any]]:
        if self.redis is None:
            return CASES
        rows = []
        for case in CASES:
            value = self.redis.hgetall(f"{self.settings.redis_key_prefix}:case:{case['case_id']}")
            rows.append(value or case)
        return rows

    def case_bundle(self, case_id: str) -> dict[str, Any]:
        case = next((item for item in CASES if item["case_id"] == case_id), None)
        if case is None:
            return {"ok": False, "error": "case_not_found"}
        return {
            "ok": True,
            "case": case,
            "indicators": [row for row in DATASETS["indicators"] if row["case_id"] == case_id],
            "observations": [row for row in DATASETS["observations"] if row["case_id"] == case_id],
            "reputation_records": [
                row for row in DATASETS["reputation_records"] if row["case_id"] == case_id
            ],
            "relationships": [
                row for row in DATASETS["relationships"] if row["case_id"] == case_id
            ],
        }

    def exact_signature(self, indicator_value: str) -> dict[str, Any]:
        match = next(
            (
                record
                for record in SIGNATURE_RECORDS
                if record["indicator_value"].lower() == indicator_value.lower()
            ),
            None,
        )
        return {"matched": bool(match), "signature": match}

    def historical_cases(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        terms = {term.lower() for term in query.split() if len(term) > 3}
        ranked = sorted(
            HISTORICAL_CASES,
            key=lambda item: sum(
                term in f"{item['title']} {item['notes']} {item['indicator_value']}".lower()
                for term in terms
            ),
            reverse=True,
        )
        return ranked[: max(1, min(limit, 5))]


class EmbeddingService:
    def __init__(self, settings: Settings, redis_client: redis.Redis | None) -> None:
        self.settings = settings
        self.redis = redis_client
        self._vectorizer: HFTextVectorizer | None = None
        self._lock = threading.Lock()

    def vectorizer(self) -> HFTextVectorizer:
        if self._vectorizer is not None:
            return self._vectorizer
        with self._lock:
            if self._vectorizer is None:
                cache = None
                if self.redis is not None:
                    cache = EmbeddingsCache(
                        name=f"{self.settings.redis_key_prefix}-embeddings-v1",
                        redis_client=self.redis,
                        ttl=self.settings.embedding_cache_ttl_seconds,
                    )
                self._vectorizer = HFTextVectorizer(
                    model=self.settings.embedding_model,
                    cache=cache,
                )
        return self._vectorizer


class SemanticRouterService:
    ROUTES = {
        "exact_signature": [
            "exact signature match for a known indicator",
            "known payload hash or domain",
        ],
        "related_indicator": [
            "indicator connected to known infrastructure",
            "shared certificate hosting or campaign relationship",
        ],
        "semantic_case": [
            "similar to a previously reviewed investigation",
            "historical analyst case notes match this behavior",
        ],
        "novel_analysis": [
            "new conflicting or incomplete evidence requires review",
            "unknown indicator with sparse observations",
        ],
    }

    def __init__(
        self, settings: Settings, redis_client: redis.Redis | None, embeddings: EmbeddingService
    ) -> None:
        self.settings = settings
        self.redis = redis_client
        self.embeddings = embeddings
        self._router: Any | None = None
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return self.redis is not None

    def _get_router(self) -> Any:
        if self._router is not None:
            return self._router
        with self._lock:
            if self._router is None:
                from redisvl.extensions.router import Route, SemanticRouter

                self._router = SemanticRouter(
                    name=self.settings.semantic_router_index,
                    routes=[
                        Route(
                            name=name,
                            references=references,
                            distance_threshold=self.settings.semantic_router_threshold,
                        )
                        for name, references in self.ROUTES.items()
                    ],
                    vectorizer=self.embeddings.vectorizer(),
                    redis_client=self.redis,
                    overwrite=False,
                )
        return self._router

    def route(self, text: str, deterministic_route: str = "") -> dict[str, Any]:
        if deterministic_route in self.ROUTES:
            return {
                "route": deterministic_route,
                "source": "evidence-priority",
                "distance": None,
                "duration_ms": 0,
            }
        if not self.configured:
            return {
                "route": "novel_analysis",
                "source": "fallback",
                "distance": None,
                "duration_ms": 0,
            }
        started = time.perf_counter()
        try:
            vector = self.embeddings.vectorizer().embed(text)
            match = self._get_router()(vector=vector)
            return {
                "route": getattr(match, "name", None) or "novel_analysis",
                "source": "redisvl",
                "distance": getattr(match, "distance", None),
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        except Exception as exc:
            log.warning("RedisVL routing failed open: %s", exc)
            return {
                "route": "novel_analysis",
                "source": "fallback",
                "distance": None,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            }


class LangCacheService:
    """LangCache plumbing for future stable analyst guidance; verdicts never use it."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base_url = (
            f"{settings.langcache_host.rstrip('/')}/v1/caches/{settings.langcache_cache_id}"
            if settings.langcache_configured
            else ""
        )
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self.settings.langcache_api_key}"},
                timeout=10,
                follow_redirects=True,
            )
        return self._client

    async def ping(self) -> bool:
        if not self.base_url:
            return False
        client = await self._get_client()
        response = await client.post(
            f"{self.base_url}/entries/search",
            json={
                "prompt": "scope:analyst-help-v1\nHow should evidence provenance be reviewed?",
                "similarityThreshold": self.settings.langcache_similarity_threshold,
                "searchStrategies": ["semantic"],
            },
        )
        response.raise_for_status()
        return True

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()


class AgentMemoryService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client: Any | None = None
        self.models: Any | None = None
        if settings.memory_configured:
            try:
                from redis_agent_memory import AgentMemory, models

                self.client = AgentMemory(
                    settings.agent_memory_base_url,
                    store_id=settings.agent_memory_store_id,
                    api_key=settings.agent_memory_api_key,
                    timeout_ms=10_000,
                )
                self.models = models
            except Exception as exc:
                log.warning("Agent Memory initialization failed: %s", exc)

    async def ping(self) -> bool:
        if self.client is None:
            return False
        await self.client.health_async(timeout_ms=5_000)
        return True

    def add_event(self, session_id: str, role: str, text: str) -> bool:
        if self.client is None or self.models is None:
            return False
        try:
            self.client.add_session_event(
                session_id=safe_id(session_id, "investigation-session"),
                actor_id=(
                    self.settings.analyst_id
                    if role == "USER"
                    else f"{self.settings.redis_key_prefix}-agent"
                ),
                role=getattr(self.models.MessageRole, role),
                content=[{"text": text}],
                created_at=datetime.now(UTC),
                metadata={"app": self.settings.app_name, "channel": "web"},
            )
            return True
        except Exception as exc:
            log.warning("Agent Memory event write failed open: %s", exc)
            return False

    def recent(self, session_id: str, limit: int = 8) -> list[dict[str, Any]]:
        if self.client is None:
            return []
        try:
            response = self.client.get_session_memory(
                session_id=safe_id(session_id, "investigation-session"),
                include_summarised_events=True,
            )
            events = list(getattr(response, "events", []) or [])[-limit:]
            return [event.model_dump(mode="json") for event in events]
        except Exception as exc:
            if "404" not in str(exc):
                log.warning("Agent Memory session read failed open: %s", exc)
            return []

    def recall(self, query: str, limit: int = 4) -> list[dict[str, Any]]:
        if self.client is None or self.models is None:
            return []
        try:
            response = self.client.search_long_term_memory(
                request={
                    "text": query,
                    "similarity_threshold": self.settings.agent_memory_similarity_threshold,
                    "filter_op": self.models.FilterConjunction.ALL,
                    "filter_": {
                        "owner_id": {"eq": self.settings.analyst_id},
                        "namespace": {"eq": self.settings.agent_memory_namespace},
                    },
                    "limit": limit,
                }
            )
            return [item.model_dump(mode="json") for item in response.items]
        except Exception as exc:
            log.warning("Agent Memory recall failed open: %s", exc)
            return []

    async def close(self) -> None:
        client, self.client = self.client, None
        close = getattr(client, "close", None)
        if callable(close):
            await asyncio.to_thread(close)


class ContextRetrieverService:
    def __init__(self, settings: Settings) -> None:
        self.agent_key = settings.mcp_agent_key
        self._client: Any | None = None
        self._tools: list[dict[str, Any]] | None = None
        self._lock = asyncio.Lock()

    async def _get_client(self) -> Any:
        if self._client is None:
            from context_surfaces import UnifiedClient

            self._client = UnifiedClient()
            await self._client.__aenter__()
        return self._client

    async def list_tools(self, force: bool = False) -> list[dict[str, Any]]:
        if not self.agent_key:
            return []
        if self._tools is not None and not force:
            return self._tools
        async with self._lock:
            client = await self._get_client()
            tools = await client.list_tools(self.agent_key)
            self._tools = [tool if isinstance(tool, dict) else tool.model_dump() for tool in tools]
        return self._tools

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.agent_key:
            return {"ok": False, "error": "context_retriever_not_configured"}
        started = time.perf_counter()
        try:
            raw = await (await self._get_client()).query_tool(
                agent_key=self.agent_key,
                tool_name=name,
                arguments=arguments,
            )
            if isinstance(raw, dict) and raw.get("content"):
                text = raw["content"][0].get("text", "{}")
                result = json.loads(text)
            else:
                result = raw if isinstance(raw, dict) else {"result": str(raw)}
            return {
                **result,
                "operation_duration_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        except Exception as exc:
            log.warning("Context Retriever call failed open: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.__aexit__(None, None, None)


class Services:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.repository = ThreatRepository(self.settings)
        self.embeddings = EmbeddingService(self.settings, self.repository.redis)
        self.router = SemanticRouterService(
            self.settings,
            self.repository.redis,
            self.embeddings,
        )
        self.langcache = LangCacheService(self.settings)
        self.memory = AgentMemoryService(self.settings)
        self.context = ContextRetrieverService(self.settings)

    async def close(self) -> None:
        await asyncio.gather(
            self.langcache.close(),
            self.memory.close(),
            self.context.close(),
            return_exceptions=True,
        )


services = Services()
