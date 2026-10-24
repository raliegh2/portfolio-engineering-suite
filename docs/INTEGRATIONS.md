# Operational integrations

This release extends the five projects beyond the original synthetic local MVPs. Verification records distinguish actual integrations from controlled contract tests.

| Boundary | Implemented and exercised | Evidence |
|---|---|---|
| Windows Event Log | Read 100 actual Application records, normalized timestamps and pseudonymized host/user fields; uploaded counters to D1 | `evidence/real-integrations.json` |
| Linux syslog | RFC5424 parser and actual loopback UDP receiver; transport exercised using explicitly labeled synthetic SSH frames | Integration tests; remote Linux-host collection is not claimed |
| Scanner | Actual Trivy source/image scans, SARIF adapter, local and cloud finding imports, assignments and retests | 51 original image findings; hardened rescan 0; closure artifacts retained privately |
| Cloud | Separate deployed Workers/D1 API with member/finding/telemetry/incident role scopes | `evidence/cloud-verification.json` |
| Cloud recovery | Exported primary snapshot and restored into an independent empty D1 database | Matching snapshot hash in `evidence/real-integrations.json` |
| Container | Real image build, non-root process, read-only filesystem, dropped capabilities, loopback HTTP health | `evidence/docker-verification.json` |
| Broker | Official Python MT5 SDK connected to existing demo terminal; read 500 bars, history and positions | Sanitized receipt and historical replay report; no account identifiers or raw snapshots published |
| Execution | Cancellation acknowledgment, late-fill exposure and reconciliation tested in `BrokerLifecycle`; actual historical prices replayed offline | No broker order submission code or profitability claim |

## Collector operation

`node src/cli.js collect-windows work/collector Application 100` samples the chosen channel. Security and PowerShell channels require suitable local Windows permissions. Checkpoints advance after normalized output is appended. A crash between append and checkpoint may replay a record; stable event IDs allow downstream deduplication. Backlog gaps and reset record IDs stop collection for review rather than silently skipping data. Raw command lines, if enabled, remain private local telemetry.

`node src/cli.js syslog work/syslog/events.jsonl 5514` binds only loopback UDP. Use a trusted local rsyslog/syslog-ng relay when integrating a remote Linux machine. UDP can drop messages; this receiver is not an authenticated internet-facing collector. RFC5424 metadata/time is required. Received records are normalized through the same SOC contract.

## Scanner operation

Run Trivy with JSON output, then use `scan-import trivy REPORT DB ASSET`; use `scan-import sarif` for SARIF 2.1.0. Package identity includes scanner target type/package location/CVE, so artifact filenames and installed-version changes do not create arbitrary identities. Scan provenance and individual evidence are retained. `UNKNOWN` maps to a low-priority review item, not a statement of known exploit severity.

The verified image uses a pinned Node base, upgrades SSL libraries, and removes npm/Yarn because the runtime requires no external packages. The before/after finding counts are dated scanner observations. They do not establish that software has no possible vulnerabilities.

## Cloud deployment and recovery

Copy `cloud/wrangler.example.json` to a private `cloud/wrangler.json`, create separate primary/recovery D1 databases and fill their binding IDs. Apply both SQL migrations. Deploy with the Wrangler CLI. Generate three independent random role tokens, at least 32 characters each, and load them with `wrangler secret bulk PRIVATE_FILE --config cloud/wrangler.json`. Never place that private file in the repository.

The deployed primary is [portfolio-engineering-sandbox](https://portfolio-engineering-sandbox.church-care-hub.workers.dev/health). All stored members, assets and incidents are training data. Roles use separately generated machine tokens bound to fixed training scopes. They are service identities, not a public user-signup/OIDC product.

`CloudClient.fromSecrets` attaches a selected private role token inside host code. The Worker exposes `/api/members`, `/api/assets`, `/api/scans`, `/api/findings`, `/api/telemetry`, `/api/incidents`, `/api/audit`, `/api/export` and `/api/restore`. Finding actions use `/api/findings/ID/assign|retest|close`. Incident dispositions require an analyst owner and evidence. Restores require `RESTORE_TO_EMPTY`, a matching digest and empty target tables. D1 batches commit each mutation atomically.

`scripts/cloud-smoke.js ORIGIN PRIVATE_FILE REPORT PRIVATE_BACKUP` exercises roles and retests with synthetic records. Backups and role credentials remain private. The public recovery receipt contains counts/hashes only.

## Broker operation

Install `requirements-broker.txt` in an isolated Windows virtual environment and connect the existing MT5 terminal to a demo account before running `scripts/mt5-readonly.py`. The connector fails closed for funded/live sessions and has no `order_send` operation. It does not read account credentials from environment files or copy account balances/login IDs into reports.

`scripts/market-history-replay.js` consumes the private SDK snapshot and publishes a summary-only execution replay receipt. It uses normalized quote units and logical simulation clocks; it does not infer broker timezone, choose a trading strategy or calculate actual account-currency profit.

`BrokerLifecycle` models pending cancellation until acknowledgment and reconciles late observed fills even after an acknowledgment. Actual exposure is recorded before risk response; discrepancies halt submissions rather than discarding inconvenient broker observations.

## Public publishing boundary

The repository contains source, generated synthetic examples, templates, case studies and sanitized evidence summaries. It excludes private logs, MT5 snapshots, SQLite databases, Cloudflare role tokens, runtime bootstrap files, session keys, actual D1 binding configurations and local build/test directories. No existing private repository was converted to public.
