# OpenClaw-Vault — TODO

Tracked gaps from the 2026-03-03 audit. See `docs/vision-and-status.md` in lobster-trapp for the high-level roadmap.

---

## Monitoring Stubs

The following scripts exist but are placeholder implementations (~15 lines each, print a message and exit):

- [ ] `monitoring/network-log-parser.py` — Should parse mitmproxy JSON logs into structured security events
- [ ] `monitoring/session-report.sh` — Should generate per-session summaries (API calls made, domains contacted, tool executions)
- [ ] `monitoring/skill-scanner.sh` — Should scan loaded skills against forge's pattern database

These are visible in the GUI under the "monitoring" command group once wired.

---

## Phase 2 VM Isolation Stubs

These scripts exist for future Hyper-V and WSL isolation (beyond containers). Config files are real; scripts are placeholder:

- [ ] `hyperv/create-vm.ps1` — Placeholder, prints "not yet implemented"
- [ ] `hyperv/provision.ps1` — Placeholder, prints "not yet implemented"
- [ ] `wsl/wsl-setup.ps1` — Placeholder, prints "not yet implemented"
- [ ] `wsl/wsl-teardown.ps1` — Placeholder, prints "not yet implemented"

Not blocking anything — these are Phase 2 aspirational.

---

## Test Bug

- [ ] `tests/test-network-isolation.sh` tests 1-2 use `wget` to verify blocked domains, but `wget` was intentionally stripped from the container image for security. `verify.sh` already works around this by using Node.js `http.get()`. Fix: replace `wget` with a Node.js equivalent or `curl` (if available).

---

## Minor

- [ ] README screenshot placeholder: `<!-- TODO: capture terminal screenshot -->` — capture and embed actual terminal output of `verify.sh` running
