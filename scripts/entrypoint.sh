#!/bin/sh
# OpenClaw-Vault entrypoint wrapper
#
# Handles both volatile (tmpfs/Hard Shell) and persistent (volume/Split Shell) modes.
# 1. Install or preserve OpenClaw config
# 2. Wait for mitmproxy CA cert
# 3. Install or preserve auth profile
# 4. Lock config read-only (prevent agent self-modification)
# 5. Exec into OpenClaw

CONFIG_SRC="/opt/openclaw-hardening.json5"
CONFIG_DST="/home/vault/.openclaw/openclaw.json"
AUTH_DIR="/home/vault/.openclaw/agents/main/agent"
AUTH_FILE="$AUTH_DIR/auth-profiles.json"
CERT="/opt/proxy-ca/mitmproxy-ca-cert.pem"

# --- 1. Config installation ---
# On tmpfs (Hard Shell): always copy — tmpfs is empty on start.
# On persistent volume (Split Shell): only copy on first run.
# The switch-shell.sh script writes config directly to the volume when switching.
mkdir -p "$(dirname "$CONFIG_DST")"

if [ -f "$CONFIG_DST" ]; then
    echo "[vault] Existing config preserved (persistent volume)"
else
    if [ -f "$CONFIG_SRC" ]; then
        cp "$CONFIG_SRC" "$CONFIG_DST"
        echo "[vault] Config installed from image (first run)"
    else
        echo "[vault] ERROR: No config found at $CONFIG_SRC or $CONFIG_DST" >&2
        exit 1
    fi
fi

# --- 2. Wait for mitmproxy CA cert ---
echo "[vault] Waiting for proxy CA certificate..."
for i in $(seq 1 60); do
    if [ -f "$CERT" ] && grep -q "END CERTIFICATE" "$CERT" 2>/dev/null; then
        echo "[vault] CA certificate found."
        break
    fi
    sleep 1
done
if [ ! -f "$CERT" ] || ! grep -q "END CERTIFICATE" "$CERT" 2>/dev/null; then
    echo "[vault] ERROR: Proxy CA cert not found or incomplete after 60s. Aborting." >&2
    exit 1
fi

# --- 3. Auth profile ---
# Placeholder API key — the real key is injected by the proxy sidecar.
# Only create if it doesn't exist (preserves across restarts on persistent volume).
if [ ! -f "$AUTH_FILE" ]; then
    mkdir -p "$AUTH_DIR"
    cat > "$AUTH_FILE" << 'AUTHEOF'
{
  "profiles": {
    "anthropic:api": {
      "provider": "anthropic",
      "type": "api_key",
      "key": "sk-ant-api03-placeholder-vault-proxy-will-inject-real-key-placeholder"
    }
  },
  "order": {
    "anthropic": ["anthropic:api"]
  }
}
AUTHEOF
    echo "[vault] Auth profile installed (placeholder key — real key injected by proxy)"
else
    echo "[vault] Auth profile preserved (persistent volume)"
fi

# --- 4. Lock config read-only ---
# Prevent the agent from modifying its own security policy.
# OpenClaw reads the config fine with 444 permissions (tested 2026-03-31).
# The config is only writable during this entrypoint setup phase and via
# tool-control.sh --apply (which restarts the container).
#
# Why this matters: if an attacker gains code execution inside the container
# (bypassing tool policy), they could modify openclaw.json to disable deny
# lists, enable elevated access, or set exec to "full". OpenClaw hot-reloads
# config changes, so the escalation would take effect immediately.
# chmod 444 prevents this — the vault user (uid 1000) cannot write to files
# they don't have write permission on, and no-new-privileges + dropped
# capabilities prevent escalation to root.
chmod 444 "$CONFIG_DST" 2>/dev/null && \
    echo "[vault] Config locked read-only (self-modification prevented)" || \
    echo "[vault] WARNING: Could not lock config read-only"

# --- 5. Install container constraints documentation ---
# Tells the agent its ACTUAL capabilities inside this hardened container.
# Without this, the LLM hallucinates about having full system access.
CONSTRAINTS_FILE="/home/vault/.openclaw/workspace/CONSTRAINTS.md"
if [ ! -f "$CONSTRAINTS_FILE" ]; then
    mkdir -p "$(dirname "$CONSTRAINTS_FILE")"
    cat > "$CONSTRAINTS_FILE" << 'CONSTRAINTSEOF'
# CONSTRAINTS.md — Your Actual Capabilities in This Container

**READ THIS FIRST.** You are running inside a hardened container managed by Lobster-TrApp. Your capabilities are restricted for the user's safety. Do NOT claim capabilities you don't have.

## What You CAN Do
- Read, write, and edit files in `/home/vault/.openclaw/workspace/` ONLY
- Run a limited set of safe commands (see safeBins below)
- Search your memory files
- Communicate via Telegram
- Analyze images with vision

## What You CANNOT Do (These Are Hard Restrictions)
- Access files outside the workspace (the filesystem is read-only)
- Run curl, wget, python, node, bash, or any interpreter (stripped from image)
- Delete files (rm is stripped from the image)
- Access the internet directly (all traffic goes through a proxy gateway)
- Access the user's personal files, SSH keys, passwords, or keyrings
- Modify your own security configuration
- Spawn sub-agents or background sessions
- Browse websites (no browser tool)
- Send emails (no email integration)
- Post to social media (no integration)

## Safe Commands (safeBins)
These are the ONLY shell commands you can run:
cat, echo, mkdir, cp, mv, touch, date, head, tail, wc, sort, uniq, tr, cut, jq, tee

In Soft Shell, additional commands are available:
grep, sed, awk, diff, xargs, basename, dirname, env, test, printf

Everything else requires explicit user approval via Telegram.

## Network Access
You can only reach domains on the proxy allowlist (currently: Anthropic API, Telegram). All other domains are blocked. You cannot reach internal networks or the user's LAN.

## Why These Restrictions Exist
The user trusts you to work safely. These restrictions ensure that even if something goes wrong — a bug in your code, a prompt injection attack, or a malicious skill — you cannot harm the user's system, steal their data, or run up their API bill beyond what the spending cap allows.

**When reporting your capabilities to the user, be accurate. Refer to this file.**
CONSTRAINTSEOF
    echo "[vault] Constraints documentation installed"
else
    echo "[vault] Constraints documentation preserved"
fi

# --- 6. Start OpenClaw ---
echo "[vault] Starting OpenClaw..."
exec "$@"
