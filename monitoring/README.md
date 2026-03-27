# Monitoring — Runtime Observability

This directory contains tools for monitoring the vault at runtime. These answer: **"what is happening inside the moat right now?"**

## Tools

| Tool | Status | Purpose |
|------|--------|---------|
| `network-log-parser.py` | Stub | Analyze proxy logs for anomalies (unexpected domains, large payloads, request frequency) |
| `session-report.sh` | Stub | Generate human-readable post-session summary (duration, API calls, security events) |

See `docs/roadmap.md` Phase 2 for implementation plans.

## Skill Scanning Does NOT Belong Here

Skill scanning is a **supply chain concern**, not a runtime concern. It lives in **clawhub-forge** (`tools/skill-scan.sh`), which has a complete 87-pattern scanner with MITRE ATT&CK mapping, zero-trust verification, and SARIF output.

See `docs/trifecta.md` in the lobster-trapp root for the full ownership matrix.
