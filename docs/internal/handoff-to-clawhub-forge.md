# Handoff Document: openclaw-vault → clawhub-forge

**Date:** 2026-04-01
**From:** openclaw-vault (certified, all 8 phases complete)
**To:** clawhub-forge (next module to polish)

> **NOTE (2026-04-02):** The authoritative design document for clawhub-forge is now
> `clawhub-forge/docs/forge-identity-and-design.md`. It defines the forge's identity
> (Shield/Anvil/Stamp), the CDR innovation, the 5-phase roadmap, and all resolved
> design decisions. The roadmap below is superseded by that document's Phase 2-3.

---

## What Was Done in openclaw-vault

### Summary
Built a complete zero-trust security harness for the OpenClaw AI agent with three shell levels (Hard/Split/Soft), per-tool whitelisting/blacklisting, 24-point security verification, and comprehensive monitoring. The module is certified and shippable.

### Key Deliverables
- **Three shell levels:** Hard Shell (cage, 0.0), Split Shell (arena, 0.18), Soft Shell (safari, 0.34)
- **Tool control system:** Per-tool whitelisting/blacklisting from a YAML manifest (26 tools documented with injection vectors)
- **24-point security verification:** Exoskeleton (14) + shell-specific (4) + per-tool security (6)
- **Monitoring:** Network log parser, session report generator, log rotation, vault audit, read-chat
- **Config integrity protection:** Entrypoint chmod 444 + SHA-256 hash tamper detection
- **Hardened container image:** rm/rmdir/chown/chgrp stripped, no interpreters, no curl/wget
- **13 test scripts (81 total assertions):** Tool control (47), attack surfaces (21), plus 13 individual test scripts
- **Air-gap architecture:** Agent is constructive only. All destructive ops are user-side (Claude as prison guard).

### Architecture Decisions to Know
- Agent config locked read-only by entrypoint (OpenClaw's atomic write bypasses chmod 444, but integrity hash detects tampering)
- `bash` tool explicitly denied (distinct from `exec` in OpenClaw's `group:runtime`)
- `askFallback` documented in OpenClaw docs but rejected by Zod schema in v2026.2.26 — omitted from generated configs
- Telegram bot token stays in the container (accepted exception — URL path injection, not header)
- Feed scanning integration deferred until Moltbook domains added to allowlist

---

## What clawhub-forge Needs to Do

### Per the Forge Roadmap (`components/clawhub-forge/docs/roadmap.md`)

**Phase 1: Housekeeping**
- Remove duplicate `docs/security-report.md` (keep `docs/research/` version)
- Create `.devcontainer/setup.sh` (referenced in devcontainer.json but missing)
- Complete Gear → Shell terminology migration
- Fix `coding-agent` skill exclusion

**Phase 2: Trust File Generation**
- Generate `.trust` files (SHA-256 hashes) for all 25 skills
- Document `.trust` file lifecycle
- Add `make trust-all` target

**Phase 3: Vault Integration — Skill Installation Path (HIGHEST PRIORITY)**
- Design the clearance report JSON format (scan + verify results)
- Build `make export SKILL=<name>` that packages a vetted skill with its clearance report
- The vault's `scripts/install-skill.sh` already validates clearance reports — format defined in `docs/specs/2026-03-30-skill-installation-path.md`

**Phase 4: Scanner Improvements**
- Verify scanner against real ClawHub skills
- Pattern sharing investigation with moltbook-pioneer

**Phase 5: CI/CD Pipeline**
- Uncomment and configure auto-publish CI
- GitHub Actions workflow for PR testing

### The Clearance Report Format (Vault Expects This)

The vault's `install-skill.sh` validates this JSON structure:

```json
{
  "skill": "<name>",
  "version": "1.0.0",
  "exported_at": "2026-03-30T12:00:00Z",
  "scan": {
    "status": "PASS",
    "critical": 0,
    "high": 0,
    "medium": 0,
    "pattern_count": 87
  },
  "verify": {
    "verdict": "VERIFIED",
    "safe_lines_pct": 98.5,
    "suspicious_lines": 0,
    "malicious_lines": 0
  },
  "checksum": "sha256:<hash-of-SKILL.md>"
}
```

---

## What NOT to Do in clawhub-forge

- Do not add runtime isolation logic (that's vault's job)
- Do not add network proxying or container orchestration (vault's job)
- Do not add API key management (vault's job)
- Do not duplicate the attack surface test patterns (vault handles runtime probing)

---

## Cross-Module References

| Document | Location | What It Contains |
|---|---|---|
| Trifecta overview | `lobster-trapp/docs/trifecta.md` | How all three modules work together |
| Vault roadmap | `openclaw-vault/docs/roadmap.md` | All 8 phases (complete) |
| Forge roadmap | `clawhub-forge/docs/roadmap.md` | 5 phases (created 2026-03-27) |
| Pioneer roadmap | `moltbook-pioneer/docs/roadmap.md` | 5 phases (created 2026-03-27) |
| Skill installation spec | `openclaw-vault/docs/specs/2026-03-30-skill-installation-path.md` | Clearance report format |
| Tool manifest | `openclaw-vault/config/tool-manifest.yml` | All 26 tools with injection vectors |
| GLOSSARY | `lobster-trapp/GLOSSARY.md` | Official terminology (Shell levels, safari analogy) |

---

## Development Principles (Carry Forward)

These were established during vault development and apply to all modules:

1. **Security first.** This is a public security promise. Every line must uphold it.
2. **Spec before code.** Every new feature requires a written spec before implementation.
3. **One task at a time.** Always validate before moving to the next.
4. **Research first.** Always consult official documentation before assuming.
5. **No trust jumps.** Complete and test each level before the next.
6. **Each tool is an injection vector.** Evaluate accordingly.
7. **Agent is constructive only.** Destructive ops are user-side.
8. **Test with live data.** Synthetic tests pass; real data reveals truth.

---

## Current System State

- **openclaw-vault:** Soft Shell active, Hum alive on Telegram, 24/24 verify PASS
- **clawhub-forge:** 25 published skills, 87-pattern scanner, untouched since 2026-03-27
- **moltbook-pioneer:** 3 tools (feed scanner, census, identity checklist), untouched since 2026-03-27
- **lobster-trapp:** GUI framework exists, submodule references updated

---

*The vault is the moat. The forge is the gatekeeper. The pioneer is the scout. Together they form the trifecta.*
