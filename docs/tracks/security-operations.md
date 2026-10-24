# Security collection, detection and incident response

An actual Windows Event Log adapter and an RFC5424 loopback UDP receiver produce a validated, deduplicated JSONL stream. Six rules detect authentication bursts, privileged membership changes and selected suspicious process patterns. Stable evidence IDs support an incident timeline.

The real integration read 100 Windows Application records and stored privacy-preserving counters in the cloud. Those records are not represented as attacks. Synthetic labeled events separately exercise detections, benign controls and analyst dispositions. Remote Linux collection requires a trusted relay; the verified UDP test is explicitly synthetic transport traffic.

Reproduce using `collect-windows`, `syslog` and `soc` CLI commands. Study `src/collectors.js`, `src/soc.js`, the collector contract tests and cloud telemetry/incident endpoints. Explain backlog-gap detection, privilege boundaries, clock normalization and UDP delivery limits.
