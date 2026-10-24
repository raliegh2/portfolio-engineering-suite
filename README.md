# Portfolio Engineering Suite — five integrated projects

[![Verification](https://github.com/raliegh2/portfolio-engineering-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/raliegh2/portfolio-engineering-suite/actions/workflows/ci.yml)

Version 0.3 adds actual Windows collection, loopback syslog transport, Trivy/SARIF imports, deployed Cloudflare Workers/D1 APIs and recovery, read-only MT5 history, and broker cancellation/reconciliation. See [integration verification](docs/INTEGRATIONS.md) and [public evidence](evidence/real-integrations.json). The [cloud sandbox health endpoint](https://portfolio-engineering-sandbox.church-care-hub.workers.dev/health) is public; data APIs require private role tokens.

A standard-library Node.js learning suite combining AI agent evaluation, security detection, vulnerability management, secure software delivery and trading infrastructure. The source is managed under the existing Command Deck project `portfolio-engineering-foundations`.

Requires Node.js **22.16 or newer** with `node:sqlite`. This session used Node 22.23.1. No `npm install`, hosted model key, subscription purchase or cloud account is needed for the deterministic suite. Live AI evaluation requires local Ollama with `deepseek-r1:1.5b`; its optional Deck connector reads only this project's README from loopback Command Deck using the existing private token file.

## Quick start

Run in the registered project directory:

```powershell
npm run ci
npm run fixtures
npm run agent:live
npm run release:demo
```

`ci` runs regression tests, source syntax/dependency-policy checks, the original trace fixtures and the four-project integration demo. It writes `evidence/ci-report.json`, `evidence/suite-report.json` and `evidence/dashboard.html`. `agent:live` is separate so CI stays reproducible and model availability cannot make offline tests flaky. `release:demo` starts real packaged child processes in the order v1, v2, v1 and saves `evidence/release-report.json`.

The dashboard is a generated evidence report; regenerate it with `npm run demo` after a live benchmark. It is not a production monitoring feed.

## 1. AI evaluation and local-model adapter

`src/evaluator.js` grades traces. `src/agent.js` calls the fixed loopback Ollama API, enforces tool/field allowlists in host code and records actual executor results. It runs frozen owner/status tasks against a synthetic fixture and a project-name task against Command Deck. The synthetic document includes an adversarial instruction. Denied tools are never invoked; unavailable models, tool failures, timeouts, malformed JSON and exhausted output budgets are explicit outcomes.

The default benchmark supplies task-specific JSON schemas because these are preauthorized narrow workflows. The schema fixes which tool and field the workflow permits. Task success is independently checked against known values; policy compliance is reported separately. This tests constrained dispatch, not general autonomous planning, a large prompt-injection benchmark or a proof of security. No model-authored assertion counts as verification.

The local model may use a significant part of its token budget for reasoning. Only the parsed final action, actual result, token count and timing are retained; hidden reasoning is not saved. A token-budget failure remains a failure. `evidence/agent-baseline.json` retains the earlier unrestricted-JSON baseline from this session; do not compare the runs as a controlled statistical study.

## 2. Security monitoring and incident response

```powershell
node src/cli.js soc examples/security.jsonl evidence/soc
```

The JSONL ingester validates UTC timestamps, platform/type fields and event identity, rejects malformed records, detects conflicting duplicate IDs, deduplicates identical records and orders out-of-order input. Six deterministic rules cover failed-login bursts, encoded PowerShell, privileged-role grants, certificate-tool downloads, registry startup writes and rundll32 script execution. Alerts include stable IDs, supporting event IDs and timestamps; `incident.md` provides an investigation timeline.

The labeled fixture includes benign controls and eight valid events. Fixture precision and recall measure that small dataset only. `collect-windows` reads actual Windows Event Logs with per-channel checkpoints, pseudonymization and backlog-gap detection. `syslog` accepts RFC5424 frames over loopback UDP. Cloud telemetry and incident APIs persist counts and analyst dispositions. These rules do not cover every technique and the collectors do not contain endpoints automatically.

```powershell
node src/cli.js collect-windows work/collector Application 100
node src/cli.js soc work/collector/windows.jsonl evidence/actual-windows
node src/cli.js syslog work/syslog/events.jsonl 5514
```

## 3. Vulnerability remediation tracker

```powershell
node src/cli.js vuln asset work/findings.sqlite lab-web-1 platform-team 3 2
node src/cli.js vuln import work/findings.sqlite examples/scan.json
node src/cli.js vuln report work/findings.sqlite evidence/findings.json
```

Copy a finding ID from the report and replace `FINDING_ID` below:

```powershell
node src/cli.js vuln assign work/findings.sqlite FINDING_ID analyst
node src/cli.js vuln retest work/findings.sqlite FINDING_ID fixed fixture://retest-1 2026-10-24T12:00:00Z
node src/cli.js vuln close work/findings.sqlite FINDING_ID 2026-10-24T12:01:00Z
```

SQLite stores assets, ownership, scan provenance, deduplicated findings, append-only observations, retests and closure transitions. Import validation is atomic. A scan ID cannot be reused with altered content. Finding identity is asset+scanner+rule; new scan evidence preserves history. Closing requires assignment and a current successful retest. Later vulnerability evidence reopens the finding; delayed pre-fix observations cannot undo a more recent fix. Prioritization is a documented severity × asset importance × exposure heuristic, not CVSS or exploit probability. The demo exports technical JSON and a management summary. Real Trivy JSON and SARIF 2.1.0 adapters import scanner findings; the deployed D1 API provides authenticated role-scoped finding access, assignments and retests.

```powershell
node src/cli.js scan-import trivy image-scan.json work/findings.sqlite portfolio-container
node src/cli.js scan-import sarif results.sarif work/findings.sqlite source-project
```

## 4. Synthetic church-data API and secure delivery

```powershell
npm run serve
```

This starts `http://127.0.0.1:8894`. Runtime files are in `work/church-runtime/`. On first start, the application generates private random credentials in `bootstrap.json` and a session key in `session.key`. They are local runtime material: do not commit or publish that directory. Login IDs are `admin`, `staff`, `volunteer`; there are no fixed default passwords.

| Method | Path | Behavior |
|---|---|---|
| GET | /health | Local health, active release and executable build |
| POST | /login | JSON `id,password`; returns a signed bearer session |
| GET | /members | Admin sees all; staff sees own group; volunteer sees own group without private notes |
| POST | /members | Admin writes all groups; staff writes own group; volunteer denied |
| GET | /audit | Admin-only audit records |

Send subsequent requests with `Authorization: Bearer SESSION`. Roles and scopes are reloaded from SQLite on each request, so changing a role invalidates previous privileges even while the token remains signed. Passwords use salted scrypt hashes. Sessions expire, malformed/tampered tokens are denied, login attempts are throttled, input sizes are bounded and audit logs include timestamps without copying private notes.

```powershell
node src/cli.js backup work/church-runtime/church.sqlite work/church-backup.sqlite
node src/cli.js restore work/church-backup.sqlite work/church-restored.sqlite
```

Backups use the SQLite backup API. Restore verifies SQLite integrity, requires an unused destination and checks the restored logical data hash in the demo. Release packages have source-hash manifests; startup rejects changed artifacts. The local deployment exercise launches actual v1/v2 processes and verifies rollback to the v1 executable over HTTP. This is compatible-version rollback, not automatic recovery across destructive schema migrations.

`deploy/compose.yml` defines loopback publishing, a persistent data volume, non-root execution, a read-only root filesystem, dropped capabilities, health checks and resource limits. When Docker is available:

```powershell
docker compose -f deploy/compose.yml up --build
```

The Docker path is now built and exercised. The standard-library runtime omits unused npm/Yarn tooling and upgrades SSL libraries; Trivy rescans provide the dated vulnerability evidence. The GitHub workflow verifies Windows/Linux tests, container startup, image scanning and actual cloud health. A separate Workers/D1 sandbox provides role-scoped members, findings, collector telemetry, analyst incident dispositions and export/restore. Recovery is verified against a second independent D1 database by comparing snapshot hashes. This remains synthetic training data, separate from the user's production church database.

## 5. Trading replay reliability

```powershell
node src/cli.js replay examples/trading.json evidence/replay.json
```

This deterministic paper exchange supports limit orders, partial fills, per-unit fees, adverse slippage, cash/position reservations, duplicate-event idempotency, disconnections, cancellation, a kill switch and checkpoint restart. All money is represented in integer cents and guarded against invalid or unsafe integer values. The event ledger is replayed to verify checkpoint state rather than trusting serialized balances.

Already-submitted orders may fill while disconnected; new orders are blocked. `PaperExchange` retains its immediate-cancellation simulation. The additional `BrokerLifecycle` tracks pending cancellation until venue acknowledgment, accepts late fill observations, preserves real exposure and halts submissions on reconciliation discrepancies. The read-only Windows MT5 adapter reads an existing demo session's bars/history/positions, then an offline historical-price adapter exercises deterministic execution without claiming strategy performance. No external order submission code is included.

```powershell
python -m pip install -r requirements-broker.txt
python scripts/mt5-readonly.py --output work/mt5-snapshot.json
node scripts/market-history-replay.js work/mt5-snapshot.json
```

## Learning and portfolio evidence

See `ARCHITECTURE.md` for boundaries and data flow, `CASE_STUDIES.md` for reproducible demonstrations and `ORCHESTRATION.md` for the two-model development process. Save source hashes and actual reports with a short demo, explain a deliberate failure in your own words, and distinguish measured fixture performance from real-world coverage.
