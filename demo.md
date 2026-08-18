# Redis Threat Intelligence Agent — Short Demo

Target time: 4 minutes

## Opening — 30 seconds

“The operating model for Redis Threat Intelligence Agent is background analysis whenever a new
threat is submitted. It collects governed evidence, correlates it with prior investigations, and
places a proposed assessment in the analyst’s review queue. The analyst reviews the output—the
analyst does not need to operate or supervise the agent.”

Explain that clicking **Start Investigation** simulates the arrival of a new submission in the
current demo. The live trace makes the normally background execution visible for presentation
purposes. All data is synthetic, and every result remains subject to external human review.

## Use case 1: Known malicious payload recurrence — 90 seconds

Open **Known malicious payload recurrence** and trigger the simulated submission.

“A previously reviewed file hash has reappeared. In the background, the agent confirms the exact
match and retrieves six web downloads, two consistent sandbox executions, and endpoint evidence
showing execution and persistence.”

Expand the signature, observations, and historical-case trace entries while the assessment runs.

“In the target workflow, this completed output appears in the analyst’s queue as a high-confidence
proposed malicious assessment with a narrowly scoped file-signature recommendation. The evidence
agrees across independent sources, but the agent still does not publish or enforce anything.”

## Use case 2: Related infrastructure — 90 seconds

Open **Infrastructure related to a reviewed campaign** and trigger the simulated submission.

“This IP has no exact malicious signature and no captured payload. The background investigation
finds a reused certificate and a short-lived passive-DNS relationship to reviewed infrastructure.”

Expand the relationship, DNS, and historical-case trace entries.

“The agent also preserves evidence against overclassification: no file transfer, exploit pattern,
or callback was observed. In the target workflow, the analyst therefore receives a proposed
suspicious assessment and a monitoring recommendation—not an automatic malicious verdict or
block.”

## Close — 30 seconds

“The primary experience is asynchronous decision review. Redis supports submission processing,
evidence retrieval, relationship analysis, semantic routing, and analyst context. A future version
could checkpoint each decision so an analyst can reopen it and ask why the agent reached that
conclusion, without changing the original assessment.”
