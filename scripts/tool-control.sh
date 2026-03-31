#!/usr/bin/env bash
# OpenClaw-Vault: Tool Control — Per-Tool Whitelisting/Blacklisting
#
# Manages which tools the OpenClaw agent can use.
# Shell levels (Hard/Split/Soft) are presets on a sliding zero-trust scale.
# The user can also enable/disable individual tools.
#
# Usage:
#   bash scripts/tool-control.sh --preset hard --dry-run      # Preview Hard Shell config
#   bash scripts/tool-control.sh --preset split --dry-run     # Preview Split Shell config
#   bash scripts/tool-control.sh --preset split --enable web_search --dry-run
#   bash scripts/tool-control.sh --status                     # Show current tool status
#   bash scripts/tool-control.sh --preset split --apply       # Apply (Step 3)
#
# Security: All logic runs on the HOST. The container is untrusted.

set -uo pipefail

VAULT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$VAULT_DIR/scripts/tool-control-core.py"
MANIFEST="$VAULT_DIR/config/tool-manifest.yml"

RUNTIME="podman"
command -v podman &>/dev/null || RUNTIME="docker"
CONTAINER="openclaw-vault"

# Colors
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Prerequisite checks ---
check_prerequisites() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}ERROR: python3 not found. Required for config generation.${NC}" >&2
        exit 1
    fi
    if ! python3 -c "import yaml" 2>/dev/null; then
        echo -e "${RED}ERROR: pyyaml not installed. Run: pip3 install pyyaml${NC}" >&2
        exit 1
    fi
    if [ ! -f "$CORE" ]; then
        echo -e "${RED}ERROR: Core script not found: $CORE${NC}" >&2
        exit 1
    fi
    if [ ! -f "$MANIFEST" ]; then
        echo -e "${RED}ERROR: Tool manifest not found: $MANIFEST${NC}" >&2
        exit 1
    fi
}

# --- Status: show current tool status from running container ---
show_status() {
    echo ""
    echo -e "${BOLD}OpenClaw-Vault: Tool Status${NC}"
    echo "==========================="
    echo ""

    # Check container
    if ! $RUNTIME inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        echo -e "${RED}Container not running. Start it first: make start${NC}"
        exit 1
    fi

    # Read current config from container
    local config_json
    config_json=$($RUNTIME exec "$CONTAINER" sh -c "cat /home/vault/.openclaw/openclaw.json 2>/dev/null") || {
        echo -e "${RED}Cannot read config from container.${NC}"
        exit 1
    }

    # Parse with core script
    local status_json
    status_json=$(python3 "$CORE" --manifest "$MANIFEST" --output status --status-json "$config_json" 2>&1) || {
        echo -e "${RED}Failed to parse config: $status_json${NC}"
        exit 1
    }

    # Pretty-print the status
    echo "$status_json" | python3 -c "
import sys, json

s = json.loads(sys.stdin.read())
print(f'  Profile:        {s[\"profile\"]}')
print(f'  Exec security:  {s[\"exec_security\"]}')
print(f'  SafeBins:       {s[\"safeBins_count\"]}')
print(f'  Risk score:     {s[\"risk_score\"]}')
print(f'  Enabled tools:  {s[\"enabled_count\"]} of {len(s[\"tools\"])}')
print()

# Risk colors
colors = {'critical': '\033[1;31m', 'high': '\033[0;31m', 'medium': '\033[0;33m', 'low': '\033[0;36m'}
nc = '\033[0m'
green = '\033[0;32m'
red = '\033[0;31m'

print(f'  {\"Tool\":<22} {\"Risk\":<10} {\"Status\":<10} Description')
print(f'  {\"-\"*22} {\"-\"*10} {\"-\"*10} {\"-\"*40}')

for name, t in s['tools'].items():
    risk_color = colors.get(t['risk'], '')
    if t['status'] == 'ENABLED':
        status_str = f'{green}ENABLED{nc}'
    elif t['status'] == 'NEVER':
        status_str = f'{red}NEVER{nc}  '
    else:
        status_str = f'DENIED '
    print(f'  {name:<22} {risk_color}{t[\"risk\"]:<10}{nc} {status_str}  {t[\"description\"]}')
"
    echo ""
    echo "==========================="
    echo ""
}

# --- Dry-run: generate and display config ---
do_dry_run() {
    local preset="$1"
    shift
    local extra_args=("$@")

    echo ""
    echo -e "${BOLD}OpenClaw-Vault: Tool Control — Dry Run${NC}"
    echo "======================================="
    echo ""

    # Generate config
    local config_json
    config_json=$(python3 "$CORE" --manifest "$MANIFEST" --preset "$preset" "${extra_args[@]}" --output config 2>&1) || {
        echo -e "${RED}$config_json${NC}"
        exit 1
    }

    # Generate risk assessment
    local risk_json
    risk_json=$(python3 "$CORE" --manifest "$MANIFEST" --preset "$preset" "${extra_args[@]}" --output risk 2>&1) || {
        echo -e "${RED}$risk_json${NC}"
        exit 1
    }

    # Generate allowlist
    local allowlist
    allowlist=$(python3 "$CORE" --manifest "$MANIFEST" --preset "$preset" "${extra_args[@]}" --output allowlist 2>&1) || {
        echo -e "${RED}$allowlist${NC}"
        exit 1
    }

    # Display risk assessment
    echo -e "${BOLD}Risk Assessment${NC}"
    echo "$risk_json" | python3 -c "
import sys, json

r = json.loads(sys.stdin.read())
colors = {'critical': '\033[1;31m', 'high': '\033[0;31m', 'medium': '\033[0;33m', 'low': '\033[0;36m'}
nc = '\033[0m'
green = '\033[0;32m'

print(f'  Risk score: {r[\"risk_score\"]}  ({r[\"enabled_count\"]}/{r[\"total_tools\"]} tools enabled)')
print()

enabled = [(n, t) for n, t in r['tools'].items() if t['status'] == 'ENABLED']
if enabled:
    print(f'  Enabled tools:')
    for name, t in enabled:
        c = colors.get(t['risk'], '')
        print(f'    {c}{t[\"risk\"]:<10}{nc} {name:<22} {t[\"description\"]}')
        for iv in t['injection_vectors']:
            print(f'             \033[0;33m⚠ {iv}{nc}')
    print()
"
    echo ""

    # Display allowlist
    echo -e "${BOLD}Proxy Allowlist${NC}"
    echo "$allowlist" | grep -v "^#" | grep -v "^$" | while read -r domain; do
        echo "    $domain"
    done
    echo ""

    # Display generated config
    echo -e "${BOLD}Generated Config (openclaw.json)${NC}"
    echo "$config_json" | python3 -m json.tool | head -60
    local total_lines
    total_lines=$(echo "$config_json" | python3 -m json.tool | wc -l)
    if [ "$total_lines" -gt 60 ]; then
        echo "    ... ($((total_lines - 60)) more lines)"
    fi

    echo ""
    echo "======================================="
    echo -e "  ${YELLOW}This is a dry run — no changes applied.${NC}"
    echo "  To apply: add --apply instead of --dry-run"
    echo ""
}

# --- Parse arguments ---
MODE=""
PRESET=""
EXTRA_ARGS=()
FROM_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --status)
            MODE="status"
            shift
            ;;
        --preset)
            PRESET="$2"
            shift 2
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --apply)
            MODE="apply"
            shift
            ;;
        --enable)
            EXTRA_ARGS+=("--enable" "$2")
            shift 2
            ;;
        --disable)
            EXTRA_ARGS+=("--disable" "$2")
            shift 2
            ;;
        --from-file)
            FROM_FILE="$2"
            EXTRA_ARGS+=("--from-file" "$2")
            shift 2
            ;;
        --help|-h)
            echo "OpenClaw-Vault: Tool Control"
            echo ""
            echo "Usage:"
            echo "  $0 --status                              Show current tool status"
            echo "  $0 --preset <name> --dry-run             Preview a preset config"
            echo "  $0 --preset <name> --apply               Apply a preset config"
            echo "  $0 --preset <name> --enable <tool> --dry-run"
            echo "  $0 --preset <name> --disable <tool> --dry-run"
            echo ""
            echo "Presets: hard, split"
            echo ""
            echo "Examples:"
            echo "  $0 --preset hard --dry-run               Preview Hard Shell"
            echo "  $0 --preset split --dry-run              Preview Split Shell"
            echo "  $0 --preset split --enable web_search --dry-run"
            echo "  $0 --status                              What's currently enabled?"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1. Use --help for usage." >&2
            exit 1
            ;;
    esac
done

# --- Execute ---
check_prerequisites

case "$MODE" in
    status)
        show_status
        ;;
    dry-run)
        if [ -z "$PRESET" ] && [ -z "$FROM_FILE" ]; then
            echo "ERROR: --preset or --from-file required for dry-run." >&2
            exit 1
        fi
        if [ -n "$PRESET" ]; then
            do_dry_run "$PRESET" "${EXTRA_ARGS[@]}"
        else
            do_dry_run "" "${EXTRA_ARGS[@]}"
        fi
        ;;
    apply)
        echo -e "${YELLOW}--apply not yet implemented (Step 3 of the plan).${NC}"
        echo "Use --dry-run to preview the config."
        exit 1
        ;;
    *)
        echo "ERROR: Specify --status, --dry-run, or --apply. Use --help for usage." >&2
        exit 1
        ;;
esac
