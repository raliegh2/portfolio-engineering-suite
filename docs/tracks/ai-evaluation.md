# AI reliability and tool-policy evaluation

The system grades observed agent traces rather than accepting model claims as proof. A local Ollama adapter, constrained workflow schemas and host allowlists connect real DeepSeek requests to synthetic reads and a fixed read-only Command Deck summary.

The final three-task constrained run completed all tasks, with zero false completions. Earlier unrestricted/low-budget runs are retained privately and summarized in the case study; they exposed blocked prompt injection and response truncation. This small workflow test is not a general autonomous-planning or model-safety benchmark.

Reproduce with `npm run ci` and `npm run agent:live` when local Ollama is available. Study `src/agent.js`, `src/evaluator.js`, and the policy/failure tests. The host owns credentials, permitted capabilities and task oracles. The model never receives a shell or the private Deck token.
