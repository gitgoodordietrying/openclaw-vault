#!/usr/bin/env bash
# Test: Seccomp profile enforcement — blocked syscalls actually fail
set -euo pipefail

RUNTIME="${RUNTIME:-podman}"
CONTAINER="openclaw-vault"

echo "=== Seccomp Enforcement Tests ==="

# Test 1: Verify seccomp profile is loaded
echo -n "  Seccomp profile loaded: "
seccomp_mode=$($RUNTIME exec "$CONTAINER" sh -c 'grep Seccomp /proc/1/status 2>/dev/null | awk "{print \$2}"' 2>&1) || true
if [ "$seccomp_mode" = "2" ]; then
    echo "PASS (mode 2 = filter active)"
else
    echo "FAIL — Seccomp mode is '$seccomp_mode' (expected 2)"
    exit 1
fi

# Test 2: mount syscall is blocked
echo -n "  mount() blocked: "
if $RUNTIME exec "$CONTAINER" sh -c 'mount -t tmpfs none /tmp 2>&1' &>/dev/null; then
    echo "FAIL — mount succeeded (should be blocked)"
    exit 1
else
    echo "PASS"
fi

# Test 3: ptrace syscall is blocked (attempt via Python if available, else via /proc)
echo -n "  ptrace() blocked: "
ptrace_result=$($RUNTIME exec "$CONTAINER" sh -c '
    if command -v python3 &>/dev/null; then
        python3 -c "import ctypes; libc=ctypes.CDLL(None); r=libc.ptrace(0,1,0,0); print(r)" 2>&1
    else
        # Fallback: try to read another process memory via /proc (requires ptrace)
        cat /proc/1/mem 2>&1
    fi
' 2>&1) && ptrace_exit=0 || ptrace_exit=$?
if [ $ptrace_exit -ne 0 ] || echo "$ptrace_result" | grep -qiE "denied|not permitted|operation not|error|-1"; then
    echo "PASS"
else
    echo "FAIL — ptrace may not be blocked: $ptrace_result"
    exit 1
fi

# Test 4: unshare syscall is blocked (namespace creation)
echo -n "  unshare() blocked: "
if $RUNTIME exec "$CONTAINER" sh -c 'unshare --mount /bin/true 2>&1' &>/dev/null; then
    echo "FAIL — unshare succeeded (should be blocked)"
    exit 1
else
    echo "PASS"
fi

# Test 5: reboot syscall is blocked
echo -n "  reboot() blocked: "
if $RUNTIME exec "$CONTAINER" sh -c 'reboot 2>&1' &>/dev/null; then
    echo "FAIL — reboot succeeded (should be blocked)"
    exit 1
else
    echo "PASS"
fi

echo "=== All seccomp enforcement tests passed ==="
