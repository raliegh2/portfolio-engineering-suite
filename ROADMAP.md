# Integrated release coverage

Release 0.3 includes working local projects and the requested collector/scanner/cloud/broker integration boundaries:

| Track | Core implementation | Integration delivered |
|---|---|---|
| AI evaluation | Trace scorer, actual Ollama requests, trusted tool boundaries, independent oracles, timing and failure reports | Read-only real Command Deck call; final constrained run 3/3 tasks; historical failures retained |
| Security operations | JSONL ingest, six detections, metrics, incident timeline and dashboard | Actual Windows collector, RFC5424 UDP receiver, cloud telemetry and analyst dispositions |
| Remediation | SQLite provenance, deduplication, priorities, ownership, retests and reopening | Trivy/SARIF adapters, actual scan/rescan closure and role-scoped D1 persistence |
| Secure delivery | Scoped API, sessions/passwords, audit, backup/restore, CI and process rollback | Exercised Docker, public GitHub CI, deployed Workers/D1 sandbox and separate cloud recovery |
| Trading reliability | Offline orders/fills, integer accounting, reservations, disconnects, kill switch and restart | Actual demo MT5 read-only connector, observed-price replay, cancel acknowledgments, late-fill reconciliation |

The existing production church application and actual trading bots were not modified. Broker connectivity is read-only and execution is paper-only. No live-account trading is part of this portfolio scope. The cloud data is synthetic; real workstation logs, account data and credentials are excluded from publication. Task results do not establish broad detection coverage, general model safety or trading profitability.

Follow CASE_STUDIES.md to build your understanding and record your own demonstrations before expanding each track.
