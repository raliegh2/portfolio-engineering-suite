# Reproducible portfolio demonstrations

## Agent evaluation

Run `npm run agent:live`. Compare task success against policy compliance, inspect an actual tool result and explain why a blocked request can comply with policy while failing the requested task. The first unrestricted-JSON run completed 1/3 tasks, blocked an adversarial action and produced one malformed response. A schema-constrained run at the same small output budget completed 2/3. With the larger response budget, the final complete run succeeded on 3/3, including the real Deck read. These runs changed more than one generation setting, so improvement cannot be attributed to one intervention. The tasks are three small frozen workflows, not a general benchmark. Never merge the best outcome from multiple trials into a single claimed run.

## Security operations

Run the SOC CLI on `examples/security.jsonl`. The fixture contains eight valid Windows/Linux events, one duplicate and one invalid JSON line. Expect three labeled detections and no false positives on those controls. Explain which source records support the login burst and which benign processes were excluded. Change the failed-login timestamps to exceed 60 seconds and rerun. A malicious command pattern alone does not establish a real compromise; write your disposition and next evidence request.

## Remediation workflow

Import `examples/scan.json` twice. The second import must be marked duplicate and leave one finding/observation. Attempt closure before assigning and retesting; it must fail. Complete a successful retest and close, then import a new later scan showing the issue again. Demonstrate that it reopens while a delayed observation from before the fix does not. Explain fingerprint identity, atomic import and the limits of the priority score.

## Secure delivery and recovery

Run the actual HTTP tests via `npm test`: volunteer private-field projection, cross-group writes, session tampering/expiry, immediate role changes, login throttling and concurrent writes. Run `npm run release:demo` to see verified executable build identities v1, v2, v1. Run `npm run demo` for the SQLite backup/restore hash and measured restore time. Explain why API success is not proof of restored data and why schema rollback needs compatibility planning. Container definitions are not evidence of a successful Docker deployment.

## Trading infrastructure

Replay `examples/trading.json` twice. Both ledgers/hashes must match. The fixed example ends with 99,281 cents cash and one unit held after fees, slippage and partial fills. Replay a duplicate fill and show the balance stays unchanged. Try a second order exceeding pending exposure, then restart from the checkpoint and complete remaining events. Explain why existing orders can fill during a disconnect and why immediate cancellation is a simulation assumption.

## CV statements after verification

- Built a local-model evaluation adapter with host-enforced tool policies, independent task oracles, trace grading and explicit failure outcomes.
- Implemented three security detections with JSONL validation, incident timelines and labeled fixture evaluation.
- Built a persistent SQLite remediation tracker with idempotent imports, scan provenance and retest-gated closure.
- Implemented a role-scoped synthetic API, signed sessions, audited actions, verified backup recovery and executable release rollback.
- Built a deterministic paper exchange with integer-money accounting, partial fills, exposure reservations and ledger-verified restart.

Report only test counts and measurements from the current evidence files. Add your own implementation decisions and explanations; these projects support a portfolio, not a claim of professional production experience you have not had.
