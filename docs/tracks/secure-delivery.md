# Secure delivery, cloud persistence and recovery

The local synthetic church API uses salted password hashes, signed expiring sessions, stored role scopes, private-field projection, audit records and bounded/throttled requests. A separate Workers/D1 implementation provides machine-role scoped members, findings, telemetry and incidents.

Verification includes actual HTTP role denials, compatible executable upgrade/rollback v1-v2-v1, a real non-root hardened Docker process, image scanning, and cloud snapshot restoration into a second independent D1 database with an identical hash. The sandbox is separate from production church data.

Reproduce with `npm run ci`, `release:demo`, Docker Compose and the cloud smoke tool. GitHub Actions runs Windows/Linux regression checks, Docker startup/scanning and actual sandbox health. Deployment tokens and data exports remain private; the public repository contains configuration templates rather than account binding files.
