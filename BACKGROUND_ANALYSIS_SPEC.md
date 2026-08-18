# Background Analysis and Decision Review Specification

Status: proposed future design; not implemented

## Objective

Redis Threat Intelligence Agent should analyze each new threat submission in the background and
place a proposed assessment in an analyst review queue. The analyst reviews the completed output;
the analyst does not need to start, prompt, or supervise the agent.

A later phase may let an analyst open a saved decision and ask how the agent reached it. That
conversation must be grounded in the original decision checkpoint and must not change the saved
assessment.

All data remains synthetic or explicitly approved. Every assessment remains `status=proposed`.
Approval, publication, distribution, blocking, and enforcement remain outside the application.

## Current and target behavior

| Concern | Current implementation | Proposed future behavior |
|---|---|---|
| Trigger | Analyst starts a selected case in the UI | A new submission creates a background job |
| Execution | Analysis runs in the HTTP streaming request | A worker runs independently of the analyst UI |
| Result storage | Final output is written as an Agent Memory event | An immutable, versioned decision checkpoint is the system of record |
| Review | Analyst watches execution and reads the result | Analyst opens an already completed proposed assessment |
| Conversation | No dedicated decision-review conversation | Optional chat is anchored to one saved decision version |
| Reanalysis | Starting the case runs it again | Explicit reanalysis creates a new version and preserves the prior version |

The current Start Investigation interaction may continue to simulate a submission during the demo
until the background workflow replaces it. It should be described as a demo trigger, not as the
future analyst workflow.

## Target workflow

1. A trusted submission adapter accepts a synthetic threat submission under an approved internal
   contract. No external vendor API is assumed by this specification.
2. The application validates and normalizes the submission, assigns a `submission_id`, and applies
   an idempotency key.
3. The application creates an analysis job and appends it to a Redis Stream.
4. A background consumer claims the job and executes the existing governed investigation flow.
5. The worker validates the structured assessment and writes an immutable decision checkpoint.
6. The review queue displays the completed proposed assessment and its evidence summary.
7. Opening a decision records UI review activity separately without changing `status=proposed`.
8. If enabled, the analyst may start a conversation grounded in that exact checkpoint.
9. If new evidence requires another analysis, the system creates a new decision version rather
   than modifying the prior checkpoint.

## Proposed components

### Submission service

Responsibilities:

- validate the approved synthetic submission contract;
- reject malformed, oversized, or duplicate submissions;
- generate stable submission and job identifiers;
- persist normalized submission metadata;
- enqueue work without waiting for model execution.

The initial submission contract should contain only fields required by the existing synthetic
domain. Any external schema mapping requires a separately approved contract or verified primary
documentation.

### Background analysis worker

The worker should reuse one shared investigation service extracted from the current streaming
request handler. HTTP presentation and background execution must not contain separate analysis
implementations.

Responsibilities:

- claim jobs through a Redis Stream consumer group;
- retrieve governed observations, reputation, signatures, relationships, and reviewed history;
- perform semantic routing and agent orchestration;
- validate the assessment against the structured output schema;
- persist bounded, redacted trace events;
- create a decision checkpoint only after successful validation;
- retry transient failures with a bounded policy;
- record a redacted terminal failure after retries are exhausted.

Consumer claims and decision creation must be idempotent. Reprocessing the same job must not create
duplicate decision versions.

### Decision checkpoint store

A decision checkpoint is an immutable record of what the agent proposed and the context used to
produce it. It is not a resumable model process or a mutable chat transcript.

Minimum checkpoint fields:

```json
{
  "decision_id": "decision-...",
  "decision_version": 1,
  "submission_id": "submission-...",
  "job_id": "job-...",
  "created_at": "timestamp",
  "completed_at": "timestamp",
  "status": "proposed",
  "assessment": {
    "verdict": "malicious | suspicious | benign | review",
    "confidence": 0.0,
    "evidence_references": [],
    "related_indicators": [],
    "decision_path": "exact_signature | related_indicator | semantic_case | novel_analysis",
    "recommended_artifact": "indicator | network_rule | file_signature | allow_exception | none",
    "artifact_validity_seconds": 0,
    "scope": "",
    "action": "block | monitor | allow | escalate",
    "conflicting_evidence": [],
    "evidence_gaps": [],
    "false_positive_risk": "low | medium | high",
    "provenance": [],
    "explanation": ""
  },
  "evidence_snapshot": {
    "record_ids": [],
    "record_digests": [],
    "retrieved_at": "timestamp"
  },
  "execution": {
    "trace_id": "trace-...",
    "model": "configured model identifier",
    "prompt_version": "version",
    "output_schema_version": "version",
    "router_version": "version",
    "tool_versions": {}
  }
}
```

The exact storage representation remains an implementation decision. Candidate Redis keys should
remain lowercase and colon-separated, for example:

- `threatintel:submission:{submission_id}`
- `threatintel:job:{job_id}`
- `threatintel:decision:{decision_id}:version:{version}`
- `threatintel:decision:{decision_id}:trace`
- `threatintel:analysis:jobs`

Final assessments must never be stored in LangCache. Retention for submissions, checkpoints, and
traces must be decided explicitly before implementation; it must not be confused with a cache TTL.

### Analyst review queue

The queue is a read-oriented view over completed checkpoints. It should show:

- proposed verdict and confidence;
- primary indicator and submission time;
- evidence freshness and provenance;
- conflicts, gaps, and false-positive risk;
- proposed artifact and validity;
- analysis completion and failure state;
- whether the assessment has been opened.

An `unseen` or `opened` UI state may be recorded separately. It must not alter the assessment,
represent approval, or imply that an external action occurred.

### Checkpoint-grounded conversation

Conversation is optional and begins only after the analyst opens a decision. Each conversation is
bound to one `decision_id` and `decision_version`.

For every turn, the review agent receives:

- the immutable checkpoint;
- the bounded evidence snapshot referenced by that checkpoint;
- the original redacted execution trace where relevant;
- recent conversation turns from Redis Agent Memory;
- durable analyst preferences that are appropriate for review.

The review agent may explain, compare, summarize, and identify what additional evidence could
change the assessment. It must cite checkpoint evidence IDs and distinguish original reasoning
from later interpretation.

The review agent must not:

- modify the checkpoint;
- claim that a new verdict has been issued;
- approve, publish, distribute, block, or enforce anything;
- silently retrieve newer evidence and present it as part of the original decision;
- use LangCache for decision-specific responses.

If the analyst explicitly requests evaluation with newer evidence, the system creates a new
background job and a new decision version. The UI should compare versions rather than overwrite the
original.

## Proposed internal API surface

These are application-owned contracts, not external vendor contracts:

- `POST /api/submissions` — validate, persist, and enqueue a synthetic submission;
- `GET /api/decisions` — list proposed assessments for review;
- `GET /api/decisions/{decision_id}/versions/{version}` — retrieve one checkpoint;
- `GET /api/decisions/{decision_id}/versions/{version}/trace` — retrieve its redacted trace;
- `POST /api/decisions/{decision_id}/versions/{version}/conversations` — start a grounded review
  conversation;
- `POST /api/conversations/{conversation_id}/turns` — ask about the checkpoint;
- `POST /api/decisions/{decision_id}/reanalyze` — enqueue a new version using explicitly selected
  evidence scope.

There must be no approval, publishing, distribution, or enforcement endpoint.

## Reliability and observability

Required operational behavior:

- at-least-once job delivery with idempotent decision creation;
- bounded retry count and reclaimable worker leases;
- graceful shutdown without losing claimed jobs;
- job, retrieval, model, checkpoint, and conversation latency attribution;
- redacted failure records safe for the UI;
- correlation across submission, job, decision, trace, and conversation identifiers;
- health checks for queue lag and worker availability without exposing submission content;
- metrics for queued, running, completed, retried, and terminally failed jobs.

## Security and governance

- Continue using read-only governed evidence tools.
- Keep credentials and raw sensitive payloads out of checkpoints and traces.
- Bound all stored evidence snapshots and conversation context.
- Authorize access to decision and conversation records before supporting multiple analysts.
- Treat decision checkpoints as the source of record; Agent Memory is conversational context, not
  the decision store.
- Preserve the synthetic-only data boundary until an external contract is explicitly approved.

## Delivery phases

### Phase 1 — reusable analysis and checkpoints

- Extract investigation execution from the HTTP stream into a shared service.
- Add strict assessment validation.
- Define versioned submission, job, checkpoint, and trace models.
- Persist immutable decision checkpoints.

### Phase 2 — background execution

- Add Redis Stream enqueueing and a consumer-group worker.
- Add idempotency, retries, leases, failure handling, and queue observability.
- Replace the interactive investigation trigger with synthetic submission processing.

### Phase 3 — analyst review experience

- Replace the case queue with a proposed-decision review queue.
- Render verdict, evidence, conflicts, gaps, artifact scope, and trace from the checkpoint.
- Record only separate `unseen` and `opened` UI state.

### Phase 4 — checkpoint-grounded conversation

- Add decision-bound conversation sessions.
- Ground every response in checkpoint evidence and require evidence citations.
- Add explicit reanalysis that creates a new version.
- Add version comparison in the review experience.

## Acceptance criteria

1. A valid submission returns promptly without waiting for analysis completion.
2. A background worker produces exactly one decision version for a job despite redelivery.
3. A validated proposed checkpoint survives application and worker restarts.
4. The analyst can review the complete result without starting or chatting with the agent.
5. The checkpoint records evidence identity, freshness, execution versions, conflicts, and gaps.
6. A conversation answer cites only evidence available to its bound checkpoint unless it clearly
   initiates a new analysis.
7. Conversation cannot mutate an existing checkpoint or assessment.
8. Reanalysis creates a new version and preserves the prior version.
9. No final assessment or decision-specific conversation is read from or written to LangCache.
10. No application path approves, publishes, distributes, or enforces an artifact.

## Open decisions before implementation

- the approved synthetic submission schema and trusted trigger mechanism;
- checkpoint and trace retention periods;
- whether evidence snapshots store bounded copies, immutable digests, or both;
- worker concurrency, retry limits, and terminal-failure policy;
- authentication and authorization requirements for multiple analysts;
- whether opening a decision should be recorded locally or delegated to an external review system;
- how a reviewer explicitly selects evidence scope for reanalysis.
