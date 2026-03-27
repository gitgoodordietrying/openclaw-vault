# OpenClaw-Vault — TODO

Tracked gaps. See `docs/roadmap.md` for the phased development plan, and `docs/trifecta.md` in lobster-trapp root for cross-module strategy.

---

## Monitoring Stubs (Roadmap Phase 2)

The following scripts exist but are placeholder implementations (~15 lines each, print a message and exit):

- [ ] `monitoring/network-log-parser.py` — Should parse mitmproxy JSON logs into structured security events
- [ ] `monitoring/session-report.sh` — Should generate per-session summaries (API calls made, domains contacted, tool executions)

Skill scanning was removed from this module — it belongs in clawhub-forge (`tools/skill-scan.sh`). See `monitoring/README.md`.

---

## Phase 2 VM Isolation Stubs

These scripts exist for future Hyper-V and WSL isolation (beyond containers). Config files are real; scripts are placeholder:

- [ ] `hyperv/create-vm.ps1` — Placeholder, prints "not yet implemented"
- [ ] `hyperv/provision.ps1` — Placeholder, prints "not yet implemented"
- [ ] `wsl/wsl-setup.ps1` — Placeholder, prints "not yet implemented"
- [ ] `wsl/wsl-teardown.ps1` — Placeholder, prints "not yet implemented"

Not blocking anything — these are aspirational.

---

## Resolved

- [x] `monitoring/skill-scanner.sh` — Removed (2026-03-27). Skill scanning lives in clawhub-forge.
- [x] Gear → Shell terminology — Migrated across all docs and configs (2026-03-27).
- [x] `component.yml` config paths — Fixed: `allowlist.txt` → `proxy/allowlist.txt`, `openclaw-hardening.yml` → `config/openclaw-hardening.json5` (2026-03-27).
- [x] `CLAUDE.md` profile claim — Updated from `minimal` to `coding` for Split Shell state (2026-03-27).
- [x] `tests/test-network-isolation.sh` — replaced `wget` with Node.js `http` module (2026-03-23)
- [x] `component.yml` proxy-logs command — fixed container name `openclaw-proxy` → `vault-proxy` (2026-03-23)
- [x] `CLAUDE.md` command table — same proxy container name fix (2026-03-23)
- [x] `proxy/vault-proxy.py` anthropic-version header — made configurable via `ANTHROPIC_API_VERSION` env var (2026-03-23)
- [x] `compose.yml` — passes `ANTHROPIC_API_VERSION` to proxy container with default (2026-03-23)

---

## Minor

- [ ] README screenshot placeholder: `<!-- TODO: capture terminal screenshot -->` — capture and embed actual terminal output of `verify.sh` running
