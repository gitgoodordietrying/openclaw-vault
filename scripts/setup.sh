#!/usr/bin/env bash
# openclaw-VAULT: One-command setup (Linux/macOS)
# Usage: bash scripts/setup.sh

set -euo pipefail

VAULT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$VAULT_DIR/.env"

echo "╔══════════════════════════════════════════════════════╗"
echo "║         openclaw-VAULT — Secure Containment          ║"
echo "║    Defense-in-depth sandbox for OpenClaw research    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# --- Detect container runtime ---
RUNTIME=""
if command -v podman &>/dev/null; then
    RUNTIME="podman"
    echo "[+] Detected: Podman (rootless — recommended)"
elif command -v docker &>/dev/null; then
    RUNTIME="docker"
    echo "[+] Detected: Docker"
    echo "    Note: Podman is preferred for rootless operation."
    echo "    Install: https://podman.io/docs/installation"
else
    echo "[!] ERROR: Neither podman nor docker found."
    echo "    Install Podman: https://podman.io/docs/installation"
    echo "    Or Docker:      https://docs.docker.com/get-docker/"
    exit 1
fi

# Check for compose
COMPOSE=""
if command -v "${RUNTIME}-compose" &>/dev/null; then
    COMPOSE="${RUNTIME}-compose"
elif $RUNTIME compose version &>/dev/null 2>&1; then
    COMPOSE="$RUNTIME compose"
else
    echo "[!] ERROR: ${RUNTIME} compose not found."
    echo "    Install: https://docs.docker.com/compose/install/"
    exit 1
fi
echo "[+] Compose: $COMPOSE"

# --- Prompt for API keys ---
echo ""
echo "API keys are stored in $ENV_FILE (gitignored)."
echo "Keys are injected by the proxy sidecar — they NEVER enter the OpenClaw container."
echo ""

if [ -f "$ENV_FILE" ]; then
    echo "[+] Existing .env file found. Using existing keys."
    echo "    Edit $ENV_FILE to change keys."
else
    echo "Enter your Anthropic API key (required):"
    read -rsp "  ANTHROPIC_API_KEY: " ANTHROPIC_KEY
    echo ""

    echo "Enter your OpenAI API key (optional, press Enter to skip):"
    read -rsp "  OPENAI_API_KEY: " OPENAI_KEY
    echo ""

    cat > "$ENV_FILE" <<ENVEOF
# openclaw-VAULT API keys — NEVER committed to git
# These are injected by the mitmproxy sidecar, not the OpenClaw container.
#
# Best practices:
#   - Create scoped/restricted API keys for sandbox use only
#   - Set hard spending limits on your API provider dashboard
#   - Rotate keys regularly
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
OPENAI_API_KEY=${OPENAI_KEY}
ENVEOF
    chmod 600 "$ENV_FILE"
    echo "[+] API keys saved to $ENV_FILE (mode 600)"
fi

# --- Build the image ---
echo ""
echo "[*] Building openclaw-vault container image..."
$RUNTIME build -t openclaw-vault -f "$VAULT_DIR/Containerfile" "$VAULT_DIR"

# --- Start the stack ---
echo ""
echo "[*] Starting vault stack..."
cd "$VAULT_DIR"
$COMPOSE up -d

echo ""
echo "[+] Vault stack is running."
echo "    Container: openclaw-vault"
echo "    Proxy:     vault-proxy (mitmproxy on internal network)"
echo ""

# --- Run verification ---
echo "[*] Running security verification..."
bash "$VAULT_DIR/scripts/verify.sh"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                    VAULT IS READY                    ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Attach: $RUNTIME exec -it openclaw-vault sh        ║"
echo "║  Logs:   $COMPOSE logs -f                           ║"
echo "║  Stop:   bash scripts/kill.sh --soft                 ║"
echo "║  Nuke:   bash scripts/kill.sh --hard                ║"
echo "╚══════════════════════════════════════════════════════╝"
