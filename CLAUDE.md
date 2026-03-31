# OpenClaw-Vault — Hardened Security Harness for OpenClaw

## What This Is

OpenClaw-Vault is a **hardened security harness** that safely runs the OpenClaw autonomous agent runtime inside a containerized, proxy-gated environment. Its core innovations:

1. **API keys never enter the agent container** — a mitmproxy sidecar injects credentials at the network layer
2. **All network traffic is logged and filtered** — domain allowlist enforced by the proxy
3. **Tool policy works with container isolation** — OpenClaw's own tool filtering prevents the LLM from seeing denied tools, while container hardening limits blast radius if any software layer has a bug

**Role in ecosystem**: `runtime` — the innermost execution environment where AI agents actually run.

**For detailed source code analysis:** See `docs/openclaw-internals.md`

## This Repo Is a Lobster-TrApp Component

This repo is integrated into [lobster-trapp](https://github.com/gitgoodordietrying/lobster-trapp) as a git submodule under `components/openclaw-vault/`. The file `component.yml` in this repo's root is the **manifest contract** that tells the Lobster-TrApp GUI how to discover, display, and control this component.

### Manifest Contract Rules
- `component.yml` must always parse as valid YAML
- `identity.id` must be `openclaw-vault` (the GUI uses this as a stable key)
- `identity.role` must be `runtime`
- All `available_when` values must reference states declared in `status.states`
- All `restart_command` values in configs must reference command IDs in `commands`
- Command IDs must be unique
- Health probe IDs must be unique

### Validating the Manifest
From the lobster-trapp root:
```bash
bash tests/orchestrator-check.sh    # Validates all manifests including this one
cargo test -p lobster-trapp          # Rust tests parse this manifest specifically
```

## Architecture

```
Two-container stack (compose.yml):

┌─────────────────────────────────────────────┐
│  vault-proxy (mitmproxy sidecar)            │
│  - Holds real API keys (in env vars)        │
│  - Enforces domain allowlist                │
│  - Injects API key into request headers     │
│  - Logs every request as structured JSON    │
│  - Has internet access (vault-external net) │
│  - SETUID/SETGID caps for gosu entrypoint   │
└──────────────┬──────────────────────────────┘
               │ HTTP proxy (vault-internal network)
┌──────────────┴──────────────────────────────┐
│  openclaw-vault (agent container)           │
│  - OpenClaw gateway running with Haiku      │
│  - Read-only root filesystem                │
│  - All Linux capabilities dropped           │
│  - Custom seccomp (deny-by-default)         │
│  - noexec on all tmpfs mounts               │
│  - no-new-privileges flag set               │
│  - tini PID 1 (signal forwarding)           │
│  - Non-root user (vault, uid 1000)          │
│  - PID limit, 4GB RAM, 2 CPUs              │
│  - NO internet (vault-internal only)        │
│  - NO real API keys (placeholder only)      │
│  - sandbox.mode="off" (container IS sandbox)│
│  - Tool profile: coding (see tool-manifest)  │
│  - Telegram bot for user interaction        │
└─────────────────────────────────────────────┘
```

### How Our Vault Synergizes With OpenClaw

| OpenClaw Layer | What It Does | Our Vault Layer | What It Adds |
|---------------|-------------|-----------------|-------------|
| Tool policy (deny/allow) | Filters tools before LLM sees them | Container isolation | Limits blast radius if tool policy has a bug |
| Exec security (deny/allowlist) | Blocks or gates shell commands | Read-only root + noexec tmpfs | Even if exec runs, can't write/execute files |
| Auth profiles (API keys) | Stores and sends credentials | Proxy key injection | Real key never enters the container |
| Sandbox mode (Docker) | Isolates tool execution | Not used — container IS the sandbox | Our container is stronger than OpenClaw's Docker sandbox |
| DM policy (pairing) | Controls who can message the agent | Network proxy + allowlist | Controls what the agent can reach |

## Directory Structure

```
openclaw-vault/
├── Containerfile                   Hardened multi-stage image (Node 22-alpine)
├── compose.yml                     Container + proxy orchestration
├── .env.example                    API key + bot token template (gitignored)
├── component.yml                   MANIFEST — Lobster-TrApp contract
├── config/
│   ├── tool-manifest.yml           Source of truth — all tools, risk, injection vectors
│   ├── openclaw-hardening.json5    Agent config (JSON5, baked into image)
│   ├── hard-shell.json5            Hard Shell preset config
│   ├── split-shell.json5           Split Shell preset config
│   ├── hard-shell-allowlist.txt    Hard Shell domain template
│   ├── vault-seccomp.json          Syscall filter (vault container)
│   └── vault-proxy-seccomp.json    Syscall filter (proxy container)
├── patches/
│   └── fix-telegram-proxy.sh       Source patch: Telegram proxy bypass fix
├── proxy/
│   ├── vault-proxy.py              mitmproxy addon (key injection + allowlist)
│   └── allowlist.txt               Active domain allowlist
├── scripts/
│   ├── entrypoint.sh               Container startup (config + CA cert + auth)
│   ├── proxy-bootstrap.mjs         Global undici proxy dispatcher
│   ├── tool-control.sh              Per-tool whitelisting/blacklisting (replaces switch-shell.sh)
│   ├── tool-control-core.py        Config generator core (python3, called by tool-control.sh)
│   ├── setup.sh / setup.ps1        One-command setup
│   ├── kill.sh / kill.ps1          Three-level kill switch
│   ├── switch-shell.sh             DEPRECATED — use tool-control.sh instead
│   └── verify.sh                   23-point security verification
├── monitoring/                     [Stubs] Skill scanner, log parser
├── tests/                          Isolation verification tests
└── docs/
    ├── openclaw-internals.md       Source code analysis (verified knowledge)
    ├── phase1-findings.md          Phase 1 compatibility test results
    ├── openclaw-reference.md       How OpenClaw works (tools, config, Telegram, sessions)
    ├── roadmap.md                  Phased development plan
    └── setup-guide.md              Non-technical user setup guide
```

## OpenClaw Configuration

**Format:** JSON5 (NOT YAML). File: `~/.openclaw/openclaw.json` inside the container.
**Validation:** Zod schema at startup — unknown keys cause Gateway to refuse to start.
**Config placed by:** `scripts/entrypoint.sh` copies `config/openclaw-hardening.json5` to the correct path.

### Key Config Decisions

| Setting | Value | Why |
|---------|-------|-----|
| `agents.defaults.model.primary` | `"anthropic/claude-haiku-4-5"` | Cheapest model, $5 test key |
| `agents.defaults.sandbox.mode` | `"off"` | Container IS the sandbox; no Docker socket available |
| `tools.profile` | `"coding"` | Split Shell: includes exec, read, write, grep, find, ls |
| `tools.deny` | `[browser, web_search, web_fetch, group:automation, group:sessions, ...]` | Split Shell: no web, no cron, no sub-agents |
| `tools.exec.security` | `"allowlist"` | Only safeBins-approved commands, with Telegram approval |
| `tools.elevated.enabled` | `false` | Permanently disabled in all shell levels |
| `gateway.mode` | `"local"` | Required for containerized operation |
| `channels.telegram.dmPolicy` | `"pairing"` | Each sender must be approved |

## Commands

| Command ID | Shell | Danger | Description |
|-----------|-------|--------|-------------|
| `setup` | `make setup` | caution | Build container environment |
| `start` | `make start` | safe | Start vault + proxy |
| `soft-stop` | `make stop` | safe | Graceful container stop |
| `hard-kill` | `make kill` | destructive | Force stop, remove containers + volumes |
| `nuclear-kill` | `make nuclear` | destructive | Remove everything |
| `verify` | `make verify` | safe | 23-point security check |
| `test` | `make test` | safe | Run all test scripts |
| `tools-status` | `make tools-status` | safe | Show per-tool enabled/disabled status |
| `hard-shell` | `make hard-shell` | caution | Switch to Hard Shell preset |
| `split-shell` | `make split-shell` | caution | Switch to Split Shell preset |
| `network-report` | `make network-report` | safe | Analyze proxy logs for anomalies |
| `session-report` | `make session-report` | safe | Post-session activity summary |
| `log-rotate` | `make log-rotate` | safe | Rotate proxy logs, check transcript size |
| `logs` | `podman logs -f openclaw-vault` | safe | Stream vault logs |
| `proxy-logs` | `podman logs -f vault-proxy` | safe | Stream proxy logs |

## Editable Configs (via GUI)

| Path | Format | Danger | Notes |
|------|--------|--------|-------|
| `.env` | env | caution | API keys + bot tokens. Restart required. |
| `proxy/allowlist.txt` | line-list | safe | Domain allowlist. Hot-reloadable (SIGHUP). |
| `config/openclaw-hardening.json5` | json5 | destructive | Agent security policy. Rebuild required. |

## Security Patches Applied

| Patch | Target | Purpose | Removable When |
|-------|--------|---------|----------------|
| `patches/fix-telegram-proxy.sh` | `dist/send-DslMV0Oj.js` | Preserves ProxyAgent in Telegram global dispatcher | OpenClaw ships upstream fix (PR #30367) |

## Security Model

### Six Defense Layers
1. **Container isolation** — read-only root, caps dropped, seccomp, noexec, non-root, PID/mem limits
2. **Network proxy** — domain allowlist, API key injection, request logging, payload size limits
3. **Tool policy** — deny list filters tools BEFORE LLM sees them (verified in source code)
4. **Application restrictions** — sandbox.mode, workspaceOnly, elevated disabled
5. **Exec controls** — security: allowlist, ask: always, safeBins whitelist (Split Shell)
6. **Hardening config** — DM pairing, no persistence, telemetry disabled

### 23-Point Verification (verify.sh)
- **Checks 1-14:** Universal exoskeleton — proxy DNS, TCP, read-only root, caps dropped, no host mounts, no interop, API key isolation, no Docker socket, no sudo, non-root, seccomp, noexec, no-new-privileges, PID limit
- **Checks 15-18:** Shell-specific config — adapts to detected shell level (Hard: profile=minimal, exec=deny; Split: profile=coding, exec=allowlist+always, safeBins match profiles)
- **Checks 19-23:** Per-tool security — NEVER-enable tools denied, rm not in safeBins, no interpreters in safeBins, proxy allowlist verified, risk score within expected range

## Development Principles

**This is a zero-trust security project.** Our public claim is that anybody can use a clawbot securely on their private machine without ever risking leaks of private or sensitive data. Every line of code must uphold this promise.

### Process
- Work slowly and methodically — one task at a time
- Always validate a change before moving to the next task
- Read and understand existing code before modifying it
- No batching or rushing — security-critical work deserves patience
- When in doubt, stop and verify rather than assume

### Research First
- **Always consult OpenClaw's official documentation** before making assumptions about how OpenClaw works. We are wrapping their system — we must understand it accurately.
- Do not guess at OpenClaw config syntax, tool behavior, or API formats — look it up or verify from source code
- When official docs are insufficient, verify from the actual dist/ source bundles inside the container (see `docs/openclaw-internals.md` for methodology)

### Security Model
- **Each tool use is a potential injection attack vector.** Every tool added to the agent's capabilities expands the attack surface. Evaluate accordingly.
- **No trust jumps.** Complete and test the current shell level fully before designing the next one. Each new capability must be individually verified.
- **Shell levels are completed in order.** Hard Shell → Split Shell → Soft Shell. Never skip levels, never bundle multiple capability expansions.

### Spec-Driven Development
- **Every new feature requires a written spec before implementation.** No exceptions.
- Specs live in `docs/specs/` and must cover: purpose, security implications, implementation approach, and verification plan
- The spec must be reviewed and approved before code is written
- This applies to all changes that affect the security boundary: tool policy, safeBins, allowlist, container config, exec controls

## What NOT to Do

- Do not change `identity.id` or `identity.role` in component.yml without coordinating with lobster-trapp
- Do not remove or rename command IDs that the GUI depends on — add new ones instead
- Do not put real API keys anywhere except `.env` (which is gitignored) — they belong in the proxy only
- Do not disable seccomp profiles or add capabilities — the security model is defense-in-depth
- Do not modify allowlist.txt to include ClawHub domains (11.9% malware rate)
- Do not set `tools.elevated.enabled: true` — permanently disabled
- Do not add interpreters (node, sh, python) to `tools.exec.safeBins`
- Do not add destructive commands (rm, rmdir) to `tools.exec.safeBins` — deletion is user-side only
- Do not add permission tools (chmod, chown) to `tools.exec.safeBins`
- Do not change `sandbox.mode` from `"off"` — the container IS the sandbox
- Do not give the agent any destructive capabilities — the agent is constructive only (read, write, create, search); all destructive operations are handled by the user or Claude from the host side

---
*Last updated: 2026-03-30 — Tool control system, per-tool whitelisting*
