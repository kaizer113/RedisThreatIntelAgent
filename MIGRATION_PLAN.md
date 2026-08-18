# Redis Threat Intelligence Agent delivery plan

## Current status

The inherited commerce application has been replaced by the first runnable synthetic
threat-intelligence vertical slice. No backward-compatibility package or route is retained.

Completed on 2026-08-17:

- `threat_intel_agent` package and product naming;
- FastAPI case queue, live NDJSON trace, and port `8082` UI;
- Google ADK orchestration without persistent ADK session or long-term memory services;
- four synthetic cases covering exact, related, semantic-history, and novel-analysis paths;
- structured proposed assessment contract and human-review boundary;
- Redis database seeding with 38 synthetic records;
- RedisVL decision routing and embedding-cache plumbing;
- Redis Agent Memory session and durable-memory plumbing;
- LangCache health/plumbing with verdict caching prohibited;
- a new Context Retriever surface with 38 imported entities and 34 generated governed tools;
- concurrent governed retrieval of observations, reputation, signatures, relationships, and
  reviewed history;
- expandable, redacted request/response drill-downs for routing, retrieval, memory, and agent tools;
- six passing tests and successful live case analysis.

Improved on 2026-08-18:

- removed evaluation verdicts and routes from runtime evidence and routing inputs;
- enriched observations with sensor, collection time, event count, observation window, evidence
  direction, and traceable source references;
- added concrete certificate, DNS, file-hash, ownership, freshness, validity, and false-positive
  evidence;
- separated vendor-neutral proposed artifact types from internal semantic-routing decisions;
- expanded current-behavior validation to eight passing tests and 38 model-valid records.

## Current data contract

Synthetic entities:

- `ThreatCase`
- `Indicator`
- `Observation`
- `ReputationRecord`
- `SignatureRecord`
- `Relationship`
- `HistoricalCase`

Every result is `status=proposed` and contains a bounded verdict vocabulary, confidence, evidence
references, related indicators, optional synthetic cluster, decision path, proposed artifact type,
artifact validity, scope, recommended action, conflicting evidence, evidence gaps, false-positive
risk, provenance, and explanation.

## Remaining checkpoints

### Checkpoint A — hardening

- Validate the structured model response before streaming it as an assessment.
- Add explicit freshness and conflicting-evidence evaluation tests.
- Add exact Redis Query Engine and RedisVL historical-case retrieval rather than fixture ranking.
- Add session-scoped tool-result caching with TTL and trace attribution.
- Bound and redact error details returned to the browser.

Validation:

```bash
make lint
make test
make seed
curl -fsS http://127.0.0.1:8082/api/health
```

### Checkpoint B — shared VM deployment readiness

- Retarget the inherited VM deployment script to the existing VM and a dedicated container.
- Map `VM_REDIS_URL` to runtime `REDIS_URL` without logging credentials.
- Publish host port `8082` and preserve other running containers.
- Verify labels `owner=lionel_giavelli` and `skip_deletion=yes` on supported resources.
- Add a port-specific health check and rollback instructions.

Validation must build and inspect locally without deploying. Deployment requires a separate explicit
request.

### Checkpoint C — demo polish and evaluation

- Render the assessment as a verdict card instead of raw JSON.
- Add relationship visualization.
- Evaluate all four cases for expected verdict, mandatory citations, decision path, false-positive
  avoidance, and proposed-only status.
- Document an 8–10 minute presenter flow.

## External contract boundary

No external vendor API, production verdict taxonomy, feed, approval system, publishing mechanism,
or enforcement interface is assumed. Adding one requires verified primary documentation and an
explicit design decision.

## Future workflow proposal

[BACKGROUND_ANALYSIS_SPEC.md](BACKGROUND_ANALYSIS_SPEC.md) defines a proposed submission-triggered
background workflow, immutable decision checkpoints, an analyst review queue, and optional
checkpoint-grounded conversation. It is not part of the current implementation or active migration
checkpoints.
