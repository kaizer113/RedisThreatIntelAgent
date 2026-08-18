from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "redis-threat-intelligence-agent"
    redis_key_prefix: str = "threatintel"
    redis_url: str = ""
    vm_redis_url: str = ""

    google_genai_use_vertexai: bool = True
    google_cloud_project: str = ""
    google_cloud_location: str = "global"
    google_model: str = "gemini-3.1-flash-lite"
    google_models: str = "gemini-3.1-flash-lite gemini-3.1-pro-preview"

    embedding_model: str = "redis/langcache-embed-v3-small"
    embedding_device: str = "cpu"
    embedding_cache_ttl_seconds: int = Field(default=86_400, ge=60)
    semantic_router_threshold: float = Field(default=0.48, gt=0, le=2)
    semantic_router_index: str = "threatintel-router-v2"

    ctx_admin_key: str = ""
    ctx_mcp_url: str = "https://gcp-us-east4.context-surfaces.redis.io/mcp"
    ctx_surface_id: str = ""
    mcp_agent_key: str = ""
    context_surface_name: str = "Redis Threat Intelligence"
    context_agent_name: str = "redis-threat-intelligence-agent"

    langcache_host: str = "https://gcp-us-east4.langcache.redis.io"
    langcache_cache_id: str = ""
    langcache_api_key: str = ""
    langcache_similarity_threshold: float = Field(default=0.80, ge=0, le=1)

    agent_memory_base_url: str = "https://gcp-us-east4.memory.redis.io"
    agent_memory_store_id: str = ""
    agent_memory_api_key: str = ""
    agent_memory_namespace: str = "redis-threat-intelligence"
    agent_memory_similarity_threshold: float = Field(default=0.30, ge=0, le=1)

    analyst_id: str = "security-analyst"
    agent_timeout_seconds: float = Field(default=90, ge=5, le=120)
    port: int = 8082
    log_level: str = "INFO"

    @property
    def available_google_models(self) -> tuple[str, ...]:
        models = tuple(item for item in self.google_models.split() if item)
        return models or (self.google_model,)

    @property
    def redis_endpoint(self) -> str:
        parsed = urlparse(self.redis_url)
        if not parsed.hostname:
            return ""
        return f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname

    @property
    def langcache_configured(self) -> bool:
        return bool(self.langcache_host and self.langcache_cache_id and self.langcache_api_key)

    @property
    def memory_configured(self) -> bool:
        return bool(
            self.agent_memory_base_url and self.agent_memory_store_id and self.agent_memory_api_key
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
