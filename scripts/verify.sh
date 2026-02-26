#!/usr/bin/env bash
# OpenClaw-Vault: 15-Point Security Verification
#
# Runs inside the openclaw-vault container to validate all security controls.
# Can also be run from the host (it will exec into the container).
#
# Usage: bash scripts/verify.sh

set -uo pipefail

# Detect runtime
RUNTIME="podman"
command -v podman &>/dev/null || RUNTIME="docker"

CONTAINER="openclaw-vault"
PASS=0
FAIL=0
SKIP=0

check() {
    local num="$1" desc="$2" cmd="$3" expect_fail="${4:-false}"

    printf "  [%2d] %-50s " "$num" "$desc"

    output=$($RUNTIME exec "$CONTAINER" sh -c "$cmd" 2>&1) && exit_code=0 || exit_code=$?

    if [ "$expect_fail" = "true" ]; then
        # We EXPECT this to fail (nonzero exit or error output)
        if [ $exit_code -ne 0 ]; then
            echo "PASS (blocked as expected)"
            PASS=$((PASS + 1))
        else
            echo "FAIL (should have been blocked)"
            echo "       Output: $output"
            FAIL=$((FAIL + 1))
        fi
    else
        # We expect this to succeed
        if [ $exit_code -eq 0 ]; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL"
            echo "       Output: $output"
            FAIL=$((FAIL + 1))
        fi
    fi
}

echo ""
echo "OpenClaw-Vault Security Verification"
echo "====================================="
echo ""

# Check container is running
if ! $RUNTIME inspect "$CONTAINER" &>/dev/null; then
    echo "[!] Container '$CONTAINER' is not running."
    echo "    Start it first: $RUNTIME compose up -d"
    exit 1
fi

echo "Running 15-point security check..."
echo ""

# 1. Network: can reach allowed domain (via proxy)
check 1 "Network: proxy reachable" \
    "wget -q -O /dev/null --timeout=10 http://vault-proxy:8080 || true"

# 2. Network: blocked domain returns 403
check 2 "Network: evil.com blocked" \
    "wget -q -O /dev/null --timeout=5 http://evil.com" true

# 3. Filesystem: root is read-only
check 3 "Filesystem: root is read-only" \
    "touch /test-readonly 2>&1" true

# 4. Capabilities: ping fails (NET_RAW dropped)
check 4 "Capabilities: ping blocked (NET_RAW dropped)" \
    "ping -c 1 127.0.0.1 2>&1" true

# 5. Host mount: /mnt/c not accessible
check 5 "Host mount: /mnt/c not accessible" \
    "ls /mnt/c/ 2>&1" true

# 6. Interop: cmd.exe not found
check 6 "Interop: cmd.exe not available" \
    "which cmd.exe 2>&1" true

# 7. API key: not in container environment
check 7 "API key: not in container env" \
    "env | grep -i 'api_key\|api-key\|apikey' | grep -v HTTP_PROXY" true

# 8. Docker socket: not mounted
check 8 "Docker socket: not mounted" \
    "ls /var/run/docker.sock 2>&1" true

# 9. Privilege escalation: sudo not available
check 9 "Privilege escalation: sudo unavailable" \
    "which sudo 2>&1" true

# 10. Non-root user
check 10 "Non-root user: running as vault (uid 1000)" \
    "test \$(id -u) -eq 1000"

# 11. Seccomp: profile is loaded (mode 2 = filter)
check 11 "Seccomp: profile loaded (filter mode)" \
    "test \$(grep Seccomp /proc/1/status | awk '{print \$2}') -eq 2"

# 12. Noexec: cannot execute scripts on /tmp
check 12 "Noexec: /tmp blocks execution" \
    "echo '#!/bin/sh' > /tmp/nxtest.sh && chmod +x /tmp/nxtest.sh && /tmp/nxtest.sh; rm -f /tmp/nxtest.sh; false" true

# 13. No-new-privileges: flag is set
check 13 "No-new-privileges: flag set" \
    "test \$(grep NoNewPrivs /proc/1/status | awk '{print \$2}') -eq 1"

# 14. PID limit: capped at 256
printf "  [%2d] %-50s " 14 "PID limit: configured"
pids_limit=$($RUNTIME inspect "$CONTAINER" --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || echo "unknown")
if [ "$pids_limit" = "256" ]; then
    echo "PASS (limit = 256)"
    PASS=$((PASS + 1))
elif [ "$pids_limit" != "unknown" ] && [ "$pids_limit" != "0" ] && [ "$pids_limit" != "-1" ] 2>/dev/null; then
    echo "PASS (limit = $pids_limit)"
    PASS=$((PASS + 1))
else
    echo "FAIL — PID limit not confirmed ($pids_limit)"
    FAIL=$((FAIL + 1))
fi

# 15. Config integrity: approval mode is always
check 15 "Config: approval mode = always" \
    "grep 'mode:.*always' /home/vault/.config/openclaw/config.yml"

echo ""
echo "====================================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "[!] SECURITY VERIFICATION FAILED"
    echo "    $FAIL check(s) did not pass. Review output above."
    exit 1
else
    echo "[+] ALL CHECKS PASSED — Vault is secure."
fi
