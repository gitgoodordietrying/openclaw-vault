#!/usr/bin/env bash
# Test: Hardened config integrity — verify security-critical settings
set -euo pipefail

RUNTIME="${RUNTIME:-podman}"
CONTAINER="openclaw-vault"
CONFIG_PATH="/home/vault/.config/openclaw/config.yml"

echo "=== Config Integrity Tests ==="

# Helper: check a config value
check_config() {
    local desc="$1" key="$2" expected="$3"
    printf "  %-45s " "$desc:"
    value=$($RUNTIME exec "$CONTAINER" sh -c "grep -E '^\s*${key}:' $CONFIG_PATH 2>/dev/null | head -1" 2>&1) || true
    if echo "$value" | grep -q "$expected"; then
        echo "PASS"
    else
        echo "FAIL — expected '$expected', got '$value'"
        return 1
    fi
}

# Test 1: Config file exists and is readable
echo -n "  Config file present: "
if $RUNTIME exec "$CONTAINER" sh -c "test -f $CONFIG_PATH" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL — config not found at $CONFIG_PATH"
    exit 1
fi

# Test 2: Approval mode is "always"
check_config "Approval mode = always" "mode" '"always"'

# Test 3: Persistence is false
check_config "Persistence disabled" "persistence" "false"

# Test 4: Telemetry is disabled
check_config "Telemetry disabled" "enabled" "false"

# Test 5: Sandbox scope is session
check_config "Sandbox scope = session" "scope" '"session"'

# Test 6: No elevated tool privileges
echo -n "  No elevated tool privileges:                "
elevated=$($RUNTIME exec "$CONTAINER" sh -c "grep 'elevated:' $CONFIG_PATH 2>/dev/null | head -1" 2>&1) || true
if echo "$elevated" | grep -q '\[\]'; then
    echo "PASS"
else
    echo "FAIL — elevated tools configured: $elevated"
    exit 1
fi

# Test 7: Persistent memory is disabled
check_config "Persistent memory disabled" "persistent" "false"

# Test 8: mDNS disabled
echo -n "  mDNS discovery disabled:                    "
mdns=$($RUNTIME exec "$CONTAINER" sh -c "grep -A1 'mdns:' $CONFIG_PATH 2>/dev/null" 2>&1) || true
if echo "$mdns" | grep -q "false"; then
    echo "PASS"
else
    echo "FAIL — mDNS may be enabled: $mdns"
    exit 1
fi

echo "=== All config integrity tests passed ==="
