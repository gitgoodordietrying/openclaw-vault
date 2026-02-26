#!/usr/bin/env bash
# openclaw-VAULT: Path B — Docker Desktop Sandbox Plugin Setup
#
# Uses Docker Desktop's built-in sandbox feature (4.49+).
# Simpler than Path A but the API key IS passed as an env var
# (Docker sandbox doesn't support proxy-side injection).
#
# Usage: bash scripts/docker-sandbox-setup.sh

set -euo pipefail

VAULT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$VAULT_DIR/.env"
SANDBOX_NAME="openclaw-vault"

echo "╔══════════════════════════════════════════════════════╗"
echo "║    openclaw-VAULT — Docker Sandbox Plugin Path       ║"
echo "║    (Path B: simpler but weaker key isolation)        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# --- Check Docker sandbox plugin ---
if ! docker sandbox --help &>/dev/null 2>&1; then
    echo "[!] ERROR: Docker sandbox plugin not available."
    echo "    Requires Docker Desktop 4.49+"
    echo "    Enable: Docker Desktop → Settings → Features in development → Sandbox"
    exit 1
fi

# --- Load or prompt for API key ---
if [ -f "$ENV_FILE" ]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
else
    echo "Enter your Anthropic API key (required):"
    read -rsp "  ANTHROPIC_API_KEY: " ANTHROPIC_API_KEY
    echo ""
    export ANTHROPIC_API_KEY
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[!] ERROR: ANTHROPIC_API_KEY is required."
    exit 1
fi

# --- Build image ---
echo "[*] Building openclaw-vault image..."
docker build -t openclaw-vault -f "$VAULT_DIR/Containerfile" "$VAULT_DIR"

# --- Remove existing sandbox if present ---
if docker sandbox ls 2>/dev/null | grep -q "$SANDBOX_NAME"; then
    echo "[*] Removing existing sandbox..."
    docker sandbox rm "$SANDBOX_NAME" 2>/dev/null || true
fi

# --- Create sandbox ---
echo "[*] Creating Docker sandbox..."
docker sandbox create "$SANDBOX_NAME" \
    --image openclaw-vault:latest

# --- Network policy: deny all, then allowlist ---
echo "[*] Configuring network proxy (deny-by-default)..."
docker sandbox network proxy "$SANDBOX_NAME" --policy deny

# Allow only LLM APIs and package registry
for domain in api.anthropic.com api.openai.com registry.npmjs.org github.com raw.githubusercontent.com; do
    docker sandbox network proxy "$SANDBOX_NAME" --allow-host "$domain"
    echo "    Allowed: $domain"
done

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              DOCKER SANDBOX READY                    ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  ⚠  API key is in container env (Path B trade-off)  ║"
echo "║  For stronger isolation, use Path A (mitmproxy).    ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Run:   docker sandbox exec $SANDBOX_NAME sh        ║"
echo "║  Stop:  docker sandbox stop $SANDBOX_NAME           ║"
echo "║  Remove: docker sandbox rm $SANDBOX_NAME            ║"
echo "╚══════════════════════════════════════════════════════╝"
