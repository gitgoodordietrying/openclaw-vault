#!/usr/bin/env bash
# openclaw-VAULT: Kill Switch
#
# Three escalation levels:
#   --soft    Graceful stop (preserves workspace for forensics)
#   --hard    Kill + remove containers + prune network
#   --nuclear Terminate WSL distro or Hyper-V VM (Phase 2)
#
# Usage: bash scripts/kill.sh --soft|--hard|--nuclear

set -euo pipefail

VAULT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Detect runtime
RUNTIME="podman"
command -v podman &>/dev/null || RUNTIME="docker"

COMPOSE="$RUNTIME compose"

usage() {
    echo "Usage: $0 --soft | --hard | --nuclear"
    echo ""
    echo "  --soft     Graceful stop (preserves state for forensics)"
    echo "  --hard     Kill containers, remove volumes, prune networks"
    echo "  --nuclear  Terminate VM/WSL distro (Phase 2 only)"
    exit 1
}

[ $# -lt 1 ] && usage

case "$1" in
    --soft)
        echo "[SOFT KILL] Graceful shutdown..."
        cd "$VAULT_DIR"
        $COMPOSE stop
        echo "[+] Containers stopped. Workspace preserved for forensic review."
        echo "    Inspect: $RUNTIME logs openclaw-vault"
        echo "    Inspect: $RUNTIME logs vault-proxy"
        echo "    Proxy logs: $RUNTIME exec vault-proxy cat /var/log/vault-proxy/requests.jsonl"
        ;;

    --hard)
        echo "[HARD KILL] Force removing all vault resources..."
        cd "$VAULT_DIR"
        $COMPOSE kill 2>/dev/null || true
        $COMPOSE down --volumes --remove-orphans 2>/dev/null || true

        # Also clean up Docker sandbox if it exists
        if command -v docker &>/dev/null; then
            docker sandbox rm openclaw-vault 2>/dev/null || true
        fi

        # Remove the image
        $RUNTIME rmi openclaw-vault 2>/dev/null || true

        # Prune dangling resources
        $RUNTIME network prune -f 2>/dev/null || true
        $RUNTIME volume prune -f 2>/dev/null || true

        echo "[+] All vault containers, volumes, networks, and images removed."
        ;;

    --nuclear)
        echo "[NUCLEAR KILL] Destroying isolation boundary..."
        echo ""

        # Phase 2: WSL distro
        if command -v wsl.exe &>/dev/null; then
            echo "  Terminating WSL distro 'openclaw-vault'..."
            wsl.exe --terminate openclaw-vault 2>/dev/null || true
            echo "  To fully unregister: wsl.exe --unregister openclaw-vault"
        fi

        # Phase 2: Hyper-V VM
        if command -v powershell.exe &>/dev/null; then
            echo "  Stopping Hyper-V VM 'openclaw-vault'..."
            powershell.exe -Command "Stop-VM -Name 'openclaw-vault' -TurnOff -Force" 2>/dev/null || true
            echo "  To fully remove: powershell.exe -Command \"Remove-VM -Name 'openclaw-vault' -Force\""
        fi

        # Also do a hard kill of containers
        "$0" --hard

        echo ""
        echo "[+] NUCLEAR KILL complete. All vault infrastructure destroyed."
        ;;

    *)
        usage
        ;;
esac
