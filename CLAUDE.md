# OpenClaw-Vault — Hardened Container Sandbox

## What This Is

OpenClaw-Vault is a **hardened container sandbox** that safely runs the OpenClaw autonomous agent runtime. Its core security innovation: API keys never enter the container. A mitmproxy sidecar injects credentials at the network layer, so even full container compromise reveals nothing.

**Role in ecosystem**: `runtime` — the innermost execution environment where AI agents actually run.

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
┌─────────────────────────────────────────┐
│  vault-proxy (mitmproxy sidecar)        │
│  - Holds API keys                       │
│  - Enforces domain allowlist            │
│  - Logs all requests as JSON            │
│  - Has internet access                  │
└──────────────┬──────────────────────────┘
               │ HTTP proxy
┌──────────────┴──────────────────────────┐
│  openclaw-vault (agent container)       │
│  - Read-only root filesystem            │
│  - All capabilities dropped             │
│  - tmpfs mounts (noexec)                │
│  - 256 PID limit, 4GB RAM, 2 CPUs      │
│  - NO internet (routes through proxy)   │
│  - NO API keys in environment           │
└─────────────────────────────────────────┘
```

## Directory Structure

```
openclaw-vault/
├── Containerfile                 Hardened multi-stage image (node 20-alpine)
├── compose.yml                   Container + proxy orchestration
├── .env.example                  API key template (proxy-side only)
├── component.yml                 MANIFEST — Lobster-TrApp contract
├── config/
│   ├── openclaw-hardening.yml    Agent lockdown (approval mode, no persistence)
│   ├── vault-seccomp.json        Syscall filter (vault)
│   └── vault-proxy-seccomp.json  Syscall filter (proxy)
├── proxy/
│   ├── vault-proxy.py            mitmproxy script (key injection + allowlist)
│   └── allowlist.txt             Domain allowlist (one per line)
├── scripts/
│   ├── setup.sh / setup.ps1      One-command setup
│   ├── kill.sh / kill.ps1        Three-level kill switch
│   └── verify.sh                 15-point security verification
├── monitoring/                   [Stubs] Skill scanner, log parser
├── tests/                        Isolation verification tests
└── docs/                         Architecture diagrams, threat definitions
```

## Commands

The component.yml declares these commands for the GUI. They map to shell scripts:

| Command ID | Shell | Danger | Description |
|-----------|-------|--------|-------------|
| `setup` | `make setup` | caution | Build container environment |
| `start` | `make start` | safe | Start vault + proxy |
| `soft-stop` | `make stop` | safe | Graceful container stop |
| `hard-kill` | `make kill` | caution | Force stop immediately |
| `nuclear-kill` | `make nuclear` | destructive | Remove everything |
| `verify` | `make verify` | safe | 15-point security check |
| `logs` | `podman logs -f openclaw-vault` | safe | Stream vault logs |
| `proxy-logs` | `podman logs -f vault-proxy` | safe | Stream proxy logs |
## Editable Configs (via GUI)

| Path | Format | Danger | Notes |
|------|--------|--------|-------|
| `.env` | env | caution | API keys (proxy-side). Restart required. |
| `proxy/allowlist.txt` | line-list | safe | Domain allowlist. Hot-reloadable. |
| `config/openclaw-hardening.yml` | yaml | destructive | Agent security policy. Restart required. |

## Security Model

1. **Proxy-injected credentials** — API keys exist only in the proxy container's environment
2. **Domain allowlist** — Only explicitly listed domains are reachable
3. **Read-only filesystem** — Container root is immutable at runtime
4. **Approval mode** — Every agent tool execution requires explicit approval
5. **No persistence** — Container state doesn't survive restarts
6. **Custom seccomp** — Minimal syscall surface for both containers

### 15-Point Verification (verify.sh)
Validates: proxy reachable, blocked domains return 403, read-only root, capabilities dropped, no host mounts, API keys absent from env, no docker socket, no sudo, non-root user, seccomp loaded, noexec /tmp, no-new-privileges, PID limit, config approval mode.

## Dual-Copy Sync

This repo may exist in two places on your machine:
- **Standalone**: `B:\REPOS\local-llm\openclaw-vault\`
- **Submodule**: `B:\REPOS\local-llm\lobster-trapp\components\openclaw-vault\`

After pushing changes from either location, sync the other:
```bash
# In the other copy:
git pull
# If submodule copy, also update parent:
cd ../.. && git add components/openclaw-vault && git commit -m "Update openclaw-vault ref"
```

## What NOT to Do

- Do not change `identity.id` or `identity.role` in component.yml without coordinating with lobster-trapp
- Do not remove or rename command IDs that the GUI depends on — add new ones instead
- Do not put API keys anywhere except `.env` (which is gitignored) — they belong in the proxy only
- Do not disable seccomp profiles or add capabilities — the security model is defense-in-depth
- Do not modify allowlist.txt to include ClawHub domains without understanding the 11.9% malware rate
