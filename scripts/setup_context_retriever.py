from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from context_surfaces import UnifiedClient
from dotenv import dotenv_values

from threat_intel_agent.config import Settings, get_settings
from threat_intel_agent.context_models import (
    HistoricalCase,
    Indicator,
    Observation,
    Relationship,
    ReputationRecord,
    SignatureRecord,
    ThreatCase,
)
from threat_intel_agent.demo_data import DATASETS

ROOT = Path(__file__).resolve().parents[1]
MODELS_PATH = ROOT / "threat_intel_agent" / "context_models.py"


def upsert_env(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    output: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            output.append(line)
            continue
        key = line.split("=", 1)[0]
        if key in updates:
            output.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in updates.items() if key not in seen)
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def ctxctl(*args: str, admin_key: str) -> Any:
    command = [
        "uv",
        "run",
        "ctxctl",
        "--no-color",
        "-o",
        "json",
        *args,
        "--admin-key",
        admin_key,
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "ctxctl command failed")
    return json.loads(result.stdout) if result.stdout.strip() else None


def redis_connection(redis_url: str) -> tuple[str, str, str, bool]:
    parsed = urlparse(redis_url)
    if not parsed.hostname or not parsed.port:
        raise ValueError("REDIS_URL must include a hostname and port")
    return (
        f"{parsed.hostname}:{parsed.port}",
        unquote(parsed.username or "default"),
        unquote(parsed.password or ""),
        parsed.scheme == "rediss",
    )


def ensure_surface(
    env: dict[str, str],
    settings: Settings,
    env_path: Path,
) -> tuple[str, str]:
    admin_key = env.get("CTX_ADMIN_KEY", "")
    if not admin_key:
        raise SystemExit("CTX_ADMIN_KEY is required")
    address, username, password, tls = redis_connection(env.get("REDIS_URL", ""))
    surface_id = ""
    for surface in ctxctl("surface", "list", admin_key=admin_key) or []:
        if surface.get("name") == settings.context_surface_name:
            surface_id = str(surface["id"])
            break
    if not surface_id:
        args = [
            "surface",
            "create",
            "--name",
            settings.context_surface_name,
            "--description",
            "Governed synthetic evidence for Redis Threat Intelligence Agent",
            "--models",
            str(MODELS_PATH),
            "--redis-addr",
            address,
            "--redis-username",
            username,
            "--redis-password",
            password,
        ]
        if tls:
            args.append("--redis-tls")
        surface_id = str(ctxctl(*args, admin_key=admin_key)["id"])
        print(f"Created Context Surface {surface_id}")
    else:
        ctxctl(
            "surface",
            "update",
            surface_id,
            "--name",
            settings.context_surface_name,
            "--description",
            "Governed synthetic evidence for Redis Threat Intelligence Agent",
            "--models",
            str(MODELS_PATH),
            admin_key=admin_key,
        )
        print(f"Updated Context Surface {surface_id}")

    agent_payload = ctxctl(
        "agent",
        "create",
        "--surface-id",
        surface_id,
        "--name",
        settings.context_agent_name,
        "--description",
        "Read-only synthetic evidence analyst",
        admin_key=admin_key,
    )
    agent_key = str(agent_payload["key"])
    upsert_env(env_path, {"CTX_SURFACE_ID": surface_id, "MCP_AGENT_KEY": agent_key})
    print("Created a dedicated Context Retriever agent key")
    return surface_id, agent_key


async def import_records(surface_id: str, admin_key: str) -> None:
    entities = {
        ThreatCase: DATASETS["cases"],
        Indicator: DATASETS["indicators"],
        Observation: DATASETS["observations"],
        ReputationRecord: DATASETS["reputation_records"],
        SignatureRecord: DATASETS["signature_records"],
        Relationship: DATASETS["relationships"],
        HistoricalCase: DATASETS["historical_cases"],
    }
    async with UnifiedClient() as client:
        for model, rows in entities.items():
            result = await client.import_data(
                admin_key=admin_key,
                context_surface_id=surface_id,
                records=[model(**row) for row in rows],
                on_conflict="overwrite",
                on_error="fail_fast",
            )
            print(f"{model.__name__}: imported={result.imported}, failed={result.failed}")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    args = parser.parse_args()
    env_path = args.env_file.resolve()
    env = {key: str(value or "") for key, value in dotenv_values(env_path).items()}
    os.environ.update(env)
    get_settings.cache_clear()
    settings = Settings(_env_file=env_path)
    surface_id, agent_key = ensure_surface(env, settings, env_path)
    await import_records(surface_id, env["CTX_ADMIN_KEY"])
    async with UnifiedClient() as client:
        tools = await client.list_tools(agent_key)
    print(f"Context Retriever ready with {len(tools)} generated tools")


if __name__ == "__main__":
    asyncio.run(main())
