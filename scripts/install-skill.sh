#!/usr/bin/env bash
# OpenClaw-Vault: Skill Installation — Forge-Vetted Skills into Vault Workspace
#
# Copies a skill SKILL.md into the vault agent's workspace after validation.
# Skills are reference material (markdown) — they instruct the agent but do not
# execute code directly. Even so, a malicious skill can social-engineer the agent.
#
# Usage:
#   bash scripts/install-skill.sh <skill-dir>                     # warns if no clearance
#   bash scripts/install-skill.sh <skill-dir> --clearance <report.json>  # validates report
#   bash scripts/install-skill.sh --list                           # list installed skills
#   bash scripts/install-skill.sh --remove <name>                  # remove a skill (user-side destructive op)
#
# Security:
#   - All logic runs on the HOST (never inside the container)
#   - Skills are never downloaded from ClawHub (domains blocked)
#   - Agent cannot install skills autonomously
#   - Clearance report checksum verified if provided

set -uo pipefail

VAULT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="podman"
command -v podman &>/dev/null || RUNTIME="docker"
CONTAINER="openclaw-vault"
WORKSPACE_SKILLS="/home/vault/.openclaw/workspace/skills"

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- List installed skills ---
list_skills() {
    echo ""
    echo -e "${BOLD}Installed Skills${NC}"
    echo "================"
    echo ""

    if ! $RUNTIME inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        echo -e "${RED}Container not running. Start it first: make start${NC}"
        exit 1
    fi

    local skills
    skills=$($RUNTIME exec "$CONTAINER" sh -c "find $WORKSPACE_SKILLS -name 'SKILL.md' -type f 2>/dev/null" 2>&1) || skills=""

    if [ -z "$skills" ]; then
        echo "  No skills installed."
    else
        echo "$skills" | while read -r skill_path; do
            local name
            name=$(echo "$skill_path" | sed "s|$WORKSPACE_SKILLS/||;s|/SKILL.md||")
            local size
            size=$($RUNTIME exec "$CONTAINER" sh -c "wc -c < '$skill_path' 2>/dev/null" 2>&1)
            echo "  $name ($size bytes)"
        done
    fi
    echo ""
}

# --- Remove a skill ---
remove_skill() {
    local name="$1"
    echo ""
    echo -e "${BOLD}Remove Skill: $name${NC}"
    echo ""

    if ! $RUNTIME inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        echo -e "${RED}Container not running. Start it first: make start${NC}"
        exit 1
    fi

    local skill_path="$WORKSPACE_SKILLS/$name/SKILL.md"
    if ! $RUNTIME exec "$CONTAINER" sh -c "test -f '$skill_path'" 2>/dev/null; then
        echo -e "${RED}Skill not found: $name${NC}"
        exit 1
    fi

    read -rp "Remove skill '$name'? [y/N] " confirm
    if [ "${confirm,,}" != "y" ]; then
        echo "Cancelled."
        exit 0
    fi

    $RUNTIME exec "$CONTAINER" sh -c "rm -rf '$WORKSPACE_SKILLS/$name'" 2>/dev/null && {
        echo -e "${GREEN}Skill '$name' removed.${NC}"
    } || {
        echo -e "${RED}Failed to remove skill.${NC}"
        exit 1
    }
    echo ""
}

# --- Install a skill ---
install_skill() {
    local skill_dir="$1"
    local clearance_file="${2:-}"

    echo ""
    echo -e "${BOLD}OpenClaw-Vault: Install Skill${NC}"
    echo "============================="
    echo ""

    # Validate skill directory
    if [ ! -d "$skill_dir" ]; then
        echo -e "${RED}ERROR: Not a directory: $skill_dir${NC}"
        exit 1
    fi

    local skill_md="$skill_dir/SKILL.md"
    if [ ! -f "$skill_md" ]; then
        echo -e "${RED}ERROR: No SKILL.md found in $skill_dir${NC}"
        exit 1
    fi

    # Extract skill name from frontmatter
    local skill_name
    skill_name=$(python3 -c "
import yaml, sys
with open('$skill_md') as f:
    content = f.read()
# Extract YAML frontmatter between --- delimiters
parts = content.split('---', 2)
if len(parts) >= 3:
    fm = yaml.safe_load(parts[1])
    print(fm.get('name', ''))
else:
    print('')
" 2>/dev/null) || skill_name=""

    if [ -z "$skill_name" ]; then
        echo -e "${RED}ERROR: Cannot extract skill name from SKILL.md frontmatter${NC}"
        exit 1
    fi

    local skill_size
    skill_size=$(wc -c < "$skill_md")
    echo "  Skill:    $skill_name"
    echo "  File:     $skill_md ($skill_size bytes)"

    # Validate clearance report if provided
    if [ -n "$clearance_file" ]; then
        if [ ! -f "$clearance_file" ]; then
            echo -e "${RED}ERROR: Clearance report not found: $clearance_file${NC}"
            exit 1
        fi

        echo "  Report:   $clearance_file"

        local report_valid
        report_valid=$(python3 -c "
import json, hashlib, sys

with open('$clearance_file') as f:
    report = json.loads(f.read())

# Check scan status
scan = report.get('scan', {})
if scan.get('status') != 'PASS':
    print(f'FAIL: scan status is {scan.get(\"status\")}')
    sys.exit(1)
if scan.get('critical', 1) > 0:
    print(f'FAIL: {scan[\"critical\"]} critical findings')
    sys.exit(1)

# Check verify verdict
verify = report.get('verify', {})
if verify.get('verdict') != 'VERIFIED':
    print(f'FAIL: verify verdict is {verify.get(\"verdict\")}')
    sys.exit(1)

# Check checksum if present
checksum = report.get('checksum', '')
if checksum.startswith('sha256:'):
    expected = checksum[7:]
    with open('$skill_md', 'rb') as sf:
        actual = hashlib.sha256(sf.read()).hexdigest()
    if actual != expected:
        print(f'FAIL: checksum mismatch (expected {expected[:16]}..., got {actual[:16]}...)')
        sys.exit(1)
    print('PASS (scan clean, verified, checksum valid)')
else:
    print('PASS (scan clean, verified, no checksum)')
" 2>&1) || {
            echo -e "${RED}  Clearance: $report_valid${NC}"
            exit 1
        }
        echo -e "  Clearance: ${GREEN}$report_valid${NC}"
    else
        echo ""
        echo -e "${YELLOW}  WARNING: No clearance report provided.${NC}"
        echo "  This skill has NOT been scanned by clawhub-forge."
        echo "  You should run: cd components/clawhub-forge && make scan-one SKILL=$skill_name"
        echo ""
        read -rp "  Install without clearance? [y/N] " confirm
        if [ "${confirm,,}" != "y" ]; then
            echo "  Cancelled."
            exit 0
        fi
    fi

    # Check container is running
    if ! $RUNTIME inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        echo -e "${RED}Container not running. Start it first: make start${NC}"
        exit 1
    fi

    # Create skills directory if needed
    $RUNTIME exec "$CONTAINER" sh -c "mkdir -p '$WORKSPACE_SKILLS/$skill_name'" 2>/dev/null

    # Copy skill into workspace
    echo ""
    echo "  Installing..."
    if $RUNTIME cp "$skill_md" "$CONTAINER:$WORKSPACE_SKILLS/$skill_name/SKILL.md" 2>/dev/null; then
        echo -e "  ${GREEN}Skill '$skill_name' installed to workspace/skills/$skill_name/${NC}"
    else
        echo -e "${RED}  Failed to copy skill into container.${NC}"
        exit 1
    fi

    # Verify installation
    local installed_size
    installed_size=$($RUNTIME exec "$CONTAINER" sh -c "wc -c < '$WORKSPACE_SKILLS/$skill_name/SKILL.md' 2>/dev/null" 2>&1)
    if [ "$installed_size" = "$skill_size" ]; then
        echo -e "  ${GREEN}Verified: $installed_size bytes (matches source)${NC}"
    else
        echo -e "${YELLOW}  WARNING: size mismatch — source=$skill_size, installed=$installed_size${NC}"
    fi

    echo ""
    echo "  The agent can now reference this skill from its workspace."
    echo ""
}

# --- Parse arguments ---
case "${1:-}" in
    --list)
        list_skills
        ;;
    --remove)
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 --remove <skill-name>"
            exit 1
        fi
        remove_skill "$2"
        ;;
    --help|-h)
        echo "OpenClaw-Vault: Skill Installation"
        echo ""
        echo "Usage:"
        echo "  $0 <skill-dir>                            Install a skill (warns without clearance)"
        echo "  $0 <skill-dir> --clearance <report.json>  Install with forge clearance report"
        echo "  $0 --list                                 List installed skills"
        echo "  $0 --remove <name>                        Remove an installed skill"
        echo ""
        echo "Skills must be vetted by clawhub-forge before installation."
        echo "Run: cd components/clawhub-forge && make scan-one SKILL=<name>"
        exit 0
        ;;
    "")
        echo "Usage: $0 <skill-dir> [--clearance <report.json>]"
        echo "Use --help for more options."
        exit 1
        ;;
    *)
        skill_dir="$1"
        clearance=""
        if [ "${2:-}" = "--clearance" ] && [ -n "${3:-}" ]; then
            clearance="$3"
        fi
        install_skill "$skill_dir" "$clearance"
        ;;
esac
