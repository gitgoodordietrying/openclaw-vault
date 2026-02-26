# openclaw-VAULT

You've decided to run [OpenClaw](https://github.com/anthropics/openclaw). This makes that decision less likely to ruin your day.

**The headline feature:** your API key never enters the container. A proxy sidecar injects it into outbound requests at the network layer. Even with full container compromise, `env | grep API` returns nothing. No other hardening guide does this.

```
HOST (your machine)
│
│   no shared credentials ── no host mounts ── no Docker socket
│
├── Hardened Container (Podman or Docker)
│     read-only root · ALL caps dropped · custom seccomp
│     no-new-privileges · 4GB RAM · 256 PIDs · non-root user
│     ↓ (internal network only — no default gateway)
│
├── Network Proxy (mitmproxy sidecar)
│     API key injection · domain allowlist · exfiltration alerts
│     request/response logging (JSON on host)
│
└── Kill Switch
      --soft (stop, preserve)  --hard (nuke containers)  --nuclear (destroy VM)
```

---

## Why This Exists

This isn't theoretical. All of this happened in one week (Jan 28 – Feb 3, 2026):

| Incident | Impact |
|----------|--------|
| **CVE-2026-25253** | One-click RCE — stolen tokens disable the sandbox via OpenClaw's own API |
| **ClawHavoc** | 341 of 2,857 ClawHub skills were malware (11.9%), delivering Atomic Stealer |
| **Database breach** | 1.5M API tokens, 35K emails exposed — Supabase RLS was disabled entirely |
| **21,639 instances exposed** | On the public internet, most with no authentication |

Every other hardening guide puts the API key inside the container as an environment variable. A compromised process reads it from `/proc/self/environ`. The openclaw-VAULT solves this with proxy-side injection: the container talks to `http://vault-proxy:8080`, the proxy checks the domain allowlist, injects the auth header, and forwards. The container never sees the key.

For a deep dive into the threat landscape, see the [Security Analysis Compilation](https://github.com/gitgoodordietrying/openclaw-research/blob/main/docs/security-report.md) in the companion research repository.

---

## Who This Is For (and Not For)

**For you if:** you know what OpenClaw is, have Docker or Podman installed, want to experiment with Moltbook or agentic workflows, and don't want to hand an unvetted process your API keys and unrestricted network access on your primary machine.

**Not for you if:** you've never used a terminal, don't know what a container is, or expect this to make OpenClaw safe for casual use. OpenClaw's own maintainer said "if you can't understand how to run a command line, this is far too dangerous for you." The openclaw-VAULT doesn't change that — it makes the dangerous thing safer for people who were going to do it anyway.

---

## What This Is (and What It Is Not)

**The openclaw-VAULT is a safe exploration tool.** It lets you run a Moltbook agent, interact with it via Telegram, observe the agent ecosystem, experiment with system prompts and personas, and prototype agentic workflows — all inside a hardened container that can't access your files, your accounts, or unauthorized network destinations.

**The openclaw-VAULT is not an agentic workstation.** The features that make OpenClaw a "personal AI assistant" — managing your email, reading your files, controlling your browser, sending WhatsApp messages on your behalf — are deliberately disabled. Those features require host-level access, which is exactly what the openclaw-VAULT prevents. If you want OpenClaw to manage your life, you accept the full risk surface. The openclaw-VAULT is deliberately not that.

**In concrete terms, you can:**
- Run a Moltbook agent that reads, posts, comments, and votes via the allowlisted API
- Message your agent via Telegram and approve or reject its actions
- Test system prompts, personas, and agent behavior in a safe-to-fail environment
- Write and test custom skills without touching ClawHub's supply chain
- Prototype scheduling, memory, and tool-use workflows before trusting them on real infrastructure
- Monitor every outbound request your agent makes via structured proxy logs

**You cannot:**
- Access host email, calendar, files, or browser from inside the container
- Use WhatsApp, iMessage, or Signal integration (requires host-level access)
- Install skills from ClawHub (registry domains blocked by default — 11.9% malicious rate)
- Persist data across container restarts without explicit volume configuration
- Run Docker-in-Docker (socket not mounted)

---

## Choose Your Isolation Level

The openclaw-VAULT is the best container-level isolation available for OpenClaw. But containers are not virtual machines, and virtual machines are not air-gapped hardware. Be honest with yourself about your threat model before choosing.

### Tier 1: Disposable Cloud VM — strongest, recommended

Run the openclaw-VAULT on a $6/month DigitalOcean, Hetzner, or Linode droplet. Separate kernel, separate network, zero relationship to your personal infrastructure. If compromised, the attacker is on a disposable VM with nothing on it. They can't reach your home network, your other machines, or anything real. Destroy and rebuild in minutes.

**Choose this if:** you take the threat landscape seriously, plan to run agents unattended, or want true infrastructure isolation.

### Tier 2: Local VM — strong

Run the openclaw-VAULT inside VirtualBox, Hyper-V, or UTM on your local machine. Separate kernel, snapshot/destroy capability similar to a cloud droplet. But the VM shares your physical hardware and local network. A VM escape (rare, state-actor level) puts the attacker on your machine. DNS rebinding could potentially reach LAN devices.

**Choose this if:** you don't want to pay for cloud hosting but want stronger isolation than a container. Phase 2 of the openclaw-VAULT (WSL2/Hyper-V layer) targets this tier.

### Tier 3: Container on your local machine — good, default

This is what the openclaw-VAULT provides out of the box. The container can't see your files (no host mounts), can't reach unauthorized domains (proxy allowlist), and can't escalate privileges (capabilities dropped, seccomp enforced, non-root user). When you kill the stack, the agent's session data is destroyed.

**However:** the container shares your host kernel. A kernel exploit — unlikely but not impossible — would put the attacker on your actual machine. The container runtime stores metadata and layer caches on the host that survive container destruction. And during a live session, a compromised agent could exfiltrate data through allowed domains before you hit the kill switch.

**Choose this if:** you're experimenting, accept the residual risk of sharing a kernel with untrusted software, and use a dedicated API key with a hard spending cap.

### What about dedicating an empty drive?

No. An empty drive doesn't give you kernel isolation, which is the actual security gap. The container already can't access your other drives because there are no host volume mounts. Moving the Docker data directory to a separate drive just relocates the container layer cache — it doesn't change the security boundary. If you want more isolation than Tier 3, use a VM (Tier 2) or a cloud droplet (Tier 1), not a different disk.

---

## Quick Start

**Requirements:** Podman or Docker. An Anthropic or OpenAI API key.

### Path A: Podman/Docker + mitmproxy (recommended)

```bash
git clone https://github.com/gitgoodordietrying/openclaw-vault.git
cd openclaw-vault
bash scripts/setup.sh        # Linux / macOS
.\scripts\setup.ps1          # Windows PowerShell
```

Detects your runtime, prompts for your API key, builds the hardened image, starts the stack, runs 10 security checks. Five minutes.

### Path B: Docker Desktop Sandbox Plugin (simpler, weaker)

```bash
bash scripts/docker-sandbox-setup.sh
```

Fewer moving parts if you're on Docker Desktop 4.49+. Trade-off: the API key lives inside the container as an env var. Documented as weaker than Path A.

---

## How You Actually Use This

The openclaw-VAULT runs the OpenClaw gateway headlessly inside a container. You don't sit inside a terminal typing commands at it. Here's a typical session:

### Control: Telegram

OpenClaw is controlled through a messaging app — that's the UI. After the stack is running, attach to the container (`podman exec -it openclaw-vault sh`) and run OpenClaw's own Telegram pairing flow. It will give you a code to enter in a Telegram bot. Use a **dedicated Telegram account** for this — not your personal one (see residual risks below).

From then on, you message your agent, it responds, you approve or reject actions. All from your phone or Telegram desktop, not from a shell.

The hardened config defaults to **approval mode**: every action requires your explicit OK via Telegram. Loosen this once you trust your system prompt. Start strict.

### Monitor: proxy logs on the host

```bash
# Every request the agent makes — allowed, blocked, flagged
podman exec vault-proxy cat /var/log/vault-proxy/requests.jsonl

# Live container logs
podman compose logs -f

# Re-run the 10-point security check
bash scripts/verify.sh
```

### Data in and out

No host filesystem mounts by default. This is intentional — a compromised container can't touch your files.

```bash
# Drop files into the container
podman cp ~/research/prompt-tests.txt openclaw-vault:/home/vault/workspace/

# Pull results out
podman cp openclaw-vault:/home/vault/workspace/results.json ~/research/
```

The agent also sends you results directly via Telegram — that's the normal flow for most interactions.

### Stop

```bash
bash scripts/kill.sh --soft     # stop, preserve workspace for review
bash scripts/kill.sh --hard     # remove containers, volumes, networks
bash scripts/kill.sh --nuclear  # terminate WSL distro / VM (Phase 2)
```

---

## Verification

```bash
bash scripts/verify.sh
```

| # | Check | What it proves |
|---|-------|---------------|
| 1 | Proxy reachable | Network routing through sidecar works |
| 2 | Blocked domains return 403 | Allowlist enforcement active |
| 3 | Root filesystem read-only | Can't persist malware to image |
| 4 | Capabilities dropped | No raw sockets, no privilege escalation |
| 5 | Host mounts not accessible | Container can't read your files |
| 6 | Windows interop disabled | No `cmd.exe` escape from WSL |
| 7 | API keys absent from env | Proxy-side injection confirmed |
| 8 | Docker socket not mounted | Can't spawn sibling containers |
| 9 | sudo unavailable | No privilege escalation path |
| 10 | Running as non-root (uid 1000) | Principle of least privilege |

---

## Domain Allowlist

Edit `proxy/allowlist.txt`. One domain per line. Subdomains included automatically.

```bash
podman compose restart vault-proxy   # reload after editing
```

ClawHub registry domains are **commented out by default**. Uncomment only after manually reviewing a specific skill's source code.

---

## Protection Scope

### Protects against

- API key exfiltration (proxy-side injection — key not in container)
- Network exfiltration to unauthorized domains (allowlist + logging)
- Container escape via filesystem, capabilities, or privilege escalation
- Resource exhaustion (fork bombs, memory, PID limits)
- Host contamination from malicious payloads

### Does not protect against

- Hypervisor escape (state-actor level — not your threat model)
- WSL2/container kernel zero-days (mitigated in Phase 2: VM isolation)
- Social engineering (if you approve a malicious action, the sandbox can't help)
- Compromised base images (mitigate by pinning image digests)
- Side-channel attacks (Spectre/Meltdown class — not practical here)

### Known residual risks you must understand

These are not theoretical concerns — they are architectural realities of the openclaw-VAULT's design. Read them before deploying.

**The proxy sidecar holds the API key.** The mitmproxy container is the one component that has your key. If an attacker compromises the proxy container itself (not the OpenClaw container), they get the key directly. The proxy is hardened with the same restrictions as the main container (read-only root, dropped capabilities, minimal surface), but you should understand that the key exists somewhere in the stack — just not where OpenClaw can reach it.

**Allowed domains can be abused during a live session.** The API provider domains (e.g. `api.anthropic.com`) must be on the allowlist for OpenClaw to function. A compromised agent can make arbitrary API calls using the proxy-injected credentials — it can't see the raw key, but it can use it. This means it could rack up charges, generate content, or encode exfiltrated data into API request payloads. **Your mitigation: set a hard spending cap on your API key. This is not optional. Treat the spending cap as part of the security boundary, not as a billing preference.**

**The Telegram control channel is a trust boundary.** If someone compromises your Telegram account, they control the agent and can approve any action. Use a dedicated Telegram account (not your personal one), enable two-factor authentication, and treat those credentials as security-critical. Do not reuse passwords.

**Container kill does not guarantee complete cleanup.** When you run `kill.sh --hard`, containers, volumes, and networks are destroyed. The agent's session workspace is gone. But the container runtime (Docker/Podman) stores layer caches, image metadata, and runtime logs on the host that survive container destruction. These do not contain your API key (proxy-side injection ensures that), but they may contain conversation logs or agent activity metadata. For thorough cleanup after you're done with the openclaw-VAULT entirely, also remove the cloned repo directory and prune your container runtime: `podman system prune -a` or `docker system prune -a`.

---

## Project Structure

```
openclaw-vault/
├── Containerfile                # Hardened image (multi-stage, stripped)
├── compose.yml                  # Container + proxy orchestration
├── vault-seccomp.json           # Custom syscall filter
├── proxy/
│   ├── vault-proxy.py           # Key injection + allowlist + logging
│   └── allowlist.txt            # Editable domain allowlist
├── config/
│   └── openclaw-hardening.yml   # Locked-down OpenClaw gateway config
├── scripts/
│   ├── setup.sh / setup.ps1     # One-command setup
│   ├── kill.sh / kill.ps1       # Three-level kill switch
│   ├── verify.sh                # 10-point security verification
│   └── docker-sandbox-setup.sh  # Path B alternative
├── phase2-vm-isolation/         # [Planned] WSL2/Hyper-V layer
├── monitoring/                  # [Planned] Skill scanner, log parser
└── tests/                       # Isolation verification tests
```

---

## Background

This started as security research, not a container project. Understanding OpenClaw's architecture, mapping its threat landscape, and documenting the incidents that make it dangerous to run uncontained — the research informed the design.

The companion research repository documents the full journey:

- [openclaw-research](https://github.com/gitgoodordietrying/openclaw-research) — security analysis, threat modeling, ecosystem exploration, and 24 published ClawHub skills

The openclaw-VAULT is the infrastructure that emerged from understanding the problem space first.

---

## Disclaimer

> This software is provided "as is", without warranty of any kind. By using any part of this repository, you accept full responsibility for what happens on your machine, your network, your accounts, and your API bills. This is a containment tool for inherently dangerous software. It reduces risk — it does not eliminate it.
>
> We are not responsible for financial losses from API key abuse, data loss or corruption, security breaches from misconfiguration or unpatched vulnerabilities, malicious skills or payloads, or anything that happens after you type `./setup.sh`.
>
> **You are the operator. You own the risk.** If your threat model requires guaranteed isolation, run this on a disposable VM with a disposable API key and a hard spending cap. If you don't understand that sentence, this tool is not for you.

## License

MIT. Security tool, not a security guarantee.
