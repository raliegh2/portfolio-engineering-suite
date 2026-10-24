# Two-model development through Command Deck

The ChatGPT/Codex session designs, implements and verifies the code. Local DeepSeek-R1 1.5B is consulted through the DeepSeek MCP harness for independent advisory input. Command Deck stores project identity, queued briefs, guarded source proposals and APPLY receipts. The user explicitly authorized this session to perform APPLY; that permission carries forward to these requested implementations. No new paid-provider or cloud-execution setting is enabled.

## Advisory review in this implementation

DeepSeek MCP consult completed locally in 48.092 seconds. Its final suggestions included missing timestamps, concurrent API requests and startup/recovery checks. Some suggestions conflated Ollama with the database or proposed reporting vulnerabilities without evidence; those were rejected. Codex selected and implemented concrete tests for timestamp validation, atomic imports, concurrent HTTP writes, actual release startup and rollback, then verified behavior. No hidden reasoning was saved.

The earlier consultation and unrestricted-JSON benchmark are historical evidence. The live adapter also calls the same local model through Ollama with output schemas, while its host implementation limits actual tools. This is a tested integration, not an always-running autonomous two-model development team.

## Workflow for future changes

1. Read project handoff and source. Define behavior and failure conditions.
2. Give local DeepSeek a small synthetic plan or patch to critique. Attribute advice and identify what was rejected.
3. Implement in a separate candidate and run `npm run ci`. Run `agent:live` separately when model behavior changes.
4. Stage source through Command Deck with the current baseHash. Apply via its guarded API only within the user's authorization.
5. Verify applied source hashes, rerun CI in the registered workspace and retain dated reports.
6. Update the handoff and distinguish local verified functionality, untested packaging and production deployment.

The integrated 0.3 release now includes collectors, scanner adapters, real container/cloud deployment and demo broker history. The current Deck API has no supported work-item completion endpoint; do not edit its live runtime state to fabricate a transition. Applied changes and the project STATUS.json establish implementation evidence even if original queue entries still display queued.

The integration review again consulted local DeepSeek. Its advice was general and incorrectly conflated operating-system compatibility, including suggesting Linux for the official MT5 Python connector. That recommendation was rejected against official documentation and the actual Windows runtime. Implementation decisions were validated by actual Windows collection, Docker/Trivy, Workers/D1 requests, independent recovery and demo-terminal reads. Model agreement was never used as verification.
