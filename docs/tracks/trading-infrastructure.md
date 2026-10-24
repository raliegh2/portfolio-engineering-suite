# Trading replay, broker history and reconciliation

The paper exchange implements integer-money accounting, fees/slippage, partial fills, resource reservations, idempotent messages, disconnections and ledger-verified checkpoint recovery. The venue lifecycle model separates cancellation requests from acknowledgments and records late fills instead of dropping real exposure.

The official MT5 SDK read an existing demo session's history/positions and 500 historical bars. Observed prices were passed through a deterministic offline execution replay. Zero orders were submitted to an external broker. Quote-unit simulation does not measure actual account-currency profit or strategy performance.

Reproduce the offline fixture with `replay`; use the read-only Python connector on Windows for an existing demo terminal. Study `src/replay.js`, `src/broker-lifecycle.js`, `src/market-history.js` and their recovery/risk tests.
