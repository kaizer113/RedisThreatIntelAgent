# Local development workflow

Verified on 2026-08-17 with `uv 0.11.7`, CPython 3.12.10, and port `8082`.

## Setup

```bash
uv sync --all-extras
make seed
make setup-context
make dev
```

`.env` is gitignored and contains the laptop-accessible Redis endpoint plus managed service
credentials. `VM_REDIS_URL` contains the private endpoint intended for deployment. Never print,
commit, or copy those values into tracked files.

`make setup-context` creates or updates the `Redis Threat Intelligence` Context Retriever surface,
imports the synthetic entities, and writes a dedicated agent key to `.env`.

## Validation

```bash
make lint
make test
curl -fsS http://127.0.0.1:8082/api/health
```

Verified baseline:

- Ruff passes for the current application and setup scripts.
- Pytest: 6 passed, with upstream deprecation warnings only.
- Health reports Redis, Context Retriever, RedisVL, LangCache, and Redis Agent Memory available.
- Health reports ADK persistent memory disabled.
- Case 002 completed end to end with five governed Context Retriever reads and a structured
  `status=proposed` assessment.
- Investigation traces expose bounded, credential-redacted request and response payloads for
  routing, retrieval, memory, and agent tool calls.

## Architecture constraints

- Google ADK uses an in-memory Runner session only; do not add Agent Platform Sessions or Memory
  Bank.
- Redis Agent Memory owns bounded analyst session context and durable analyst preferences.
- Never store or serve final assessments through LangCache.
- All demo data is synthetic.
- External approval, publication, and enforcement remain outside the application.
- The shared-VM target port is `8082`.

Do not run deployment commands unless the user explicitly requests deployment.
