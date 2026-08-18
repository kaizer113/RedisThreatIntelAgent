# Redis Threat Intelligence Agent architecture

## Request path

1. The analyst selects a synthetic investigation.
2. RedisVL records the evidence-priority decision path.
3. Redis Agent Memory retrieves bounded session and analyst context.
4. Google ADK invokes exact application tools and dynamically discovered Context Retriever tools.
5. Current observations, reputation, signatures, relationships, and reviewed history are returned
   with evidence identifiers and synthetic provenance.
6. Gemini produces a structured proposed assessment.
7. The UI renders the verdict and execution trace for human review.

The application intentionally does not configure Google ADK persistent sessions or Memory Bank.
The Runner uses an in-process session service only for the current ADK invocation. Redis Agent
Memory owns conversational continuity.

## Component responsibilities

| Component | Responsibility |
|---|---|
| FastAPI | Case queue, streaming API, health checks, lifecycle, and UI |
| Google ADK | Agent loop, model invocation, and governed tool selection |
| Redis database | Synthetic records, exact lookup, router vectors, and embedding cache |
| RedisVL | Semantic decision routing |
| Context Retriever | Governed access to structured synthetic evidence and relationships |
| Redis Agent Memory | Analyst session events and durable workflow preferences |
| LangCache | Stable analyst guidance only; verdict caching is prohibited |

## Human-review boundary

Every assessment has `status=proposed`. Approval, publication, distribution, blocking, and other
external actions are outside this application. The UI makes that boundary explicit.

## Deployment

The target is the same Compute Engine VM as the two inherited demos, using a separate container
and host port `8082`. Runtime Redis traffic uses the private endpoint. Any supported cloud resource
must carry `owner=lionel_giavelli` and `skip_deletion=yes`.
