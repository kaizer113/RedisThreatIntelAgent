# Redis Threat Intelligence Agent repository guidance

## Mission

This repository is being migrated from RedisXADK into **Redis Threat Intelligence Agent**, a
synthetic threat-intelligence analyst demo. It must use only synthetic or explicitly approved data.

Use **Redis Threat Intelligence Agent** as the exact product display name. Keep repository content
vendor-neutral: do not include third-party security-company or threat-research-organization brand
names in code, configuration, datasets, fixtures, prompts, UI copy, documentation, tests, assets, or
generated files unless the user explicitly changes this rule.

The Python package is `threat_intel_agent`. No compatibility package or inherited commerce API is
supported.

## Read before changing code

Read, in order:

1. this file;
2. `local_agent.md` for the verified development workflow and current baseline;
3. `MIGRATION_PLAN.md` for component disposition, target structure, checkpoints, and validation;
4. the files directly involved in the requested change.

If these documents disagree, stop and resolve the discrepancy explicitly before modifying runtime
code.

## Current phase boundary

The repository now contains the first synthetic vertical slice. Continue implementing only the
approved synthetic contract:

- do not deploy or create additional cloud resources unless explicitly requested;
- do not invent or assume external APIs, schemas, verdict taxonomies, feeds, credentials, or
  publishing mechanisms;
- keep all assessments proposed-only and require external human review;
- do not add approval, publishing, distribution, or enforcement actions.

When domain work is authorized, require an approved synthetic contract or a verified primary source
for each external API. State uncertainty instead of filling gaps.

## Preserve these infrastructure capabilities

Preserve behavior, then separate it from the commerce domain:

- FastAPI lifecycle, health checks, newline-delimited JSON streaming, and static UI hosting;
- Google ADK agent construction, in-process Runner sessions, dynamic tools, and tool callbacks;
- Redis connectivity and health probing;
- Redis Context Retriever discovery and governed dynamic-tool invocation;
- RedisVL embeddings, vector search, semantic routing, and embedding-cache plumbing;
- Redis LangCache cache-aside plumbing;
- Redis Agent Memory session-event and long-term-memory plumbing;
- request/tool/service tracing, latency attribution, warmup, keepalive, and graceful shutdown;
- Docker, Compute Engine, Cloud Run, Secret Manager, and build/deployment foundations.

Preservation means retaining the reusable capability, not retaining commerce names, schemas, routes,
fixtures, prompts, or compatibility aliases. Follow the extraction order in `MIGRATION_PLAN.md`.

## No compatibility shims

No backward compatibility is required. Do not restore the inherited package, deprecated routes,
duplicate environment-variable names, fixtures, or import aliases. Tests cover only the current
synthetic threat-intelligence application.

## Development rules

- Keep changes scoped to the active migration checkpoint.
- Prefer small modules with explicit domain/infrastructure boundaries.
- Keep configuration environment-driven and never commit credentials or live customer data.
- Use lowercase, colon-separated Redis keys. Give cache keys a TTL. Preserve connection pooling and
  bounded timeouts. Define index fields only after query requirements are approved.
- Keep volatile or analyst-specific content out of shared semantic-cache scopes.
- Do not add Agent Platform Sessions or ADK Memory Bank; Redis Agent Memory owns analyst context.
- Never cache final assessments in LangCache.
- Keep health checks free of secrets and destructive side effects.
- Add or update tests for current behavior only; do not test retired code or compatibility paths.
- Run the validation commands for the active checkpoint and report any failure accurately.
- Do not deploy unless the user explicitly asks. For any future resource that supports labels or
  tags, set `owner=lionel_giavelli` and `skip_deletion=yes`.

## Documentation standard

Use precise language: distinguish implemented behavior, inherited behavior, proposed design, and
unknown external contracts. Do not present a proposal as if it already exists. Update the inventory
and checkpoint status when migration work changes a component's disposition.
