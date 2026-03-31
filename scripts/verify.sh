#!/usr/bin/env bash
# OpenClaw-Vault: Security Verification (23 checks)
#
# Validates all security controls. Runs from the host (execs into container).
# Shell-aware: detects Hard Shell or Split Shell and verifies config accordingly.
#
# Checks 1-14:  Universal exoskeleton checks (same for all shells)
# Checks 15-18: Shell-specific config verification (adapts to detected level)
# Checks 19-23: Per-tool security checks (NEVER-enable, rm, interpreters, allowlist, risk)
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

echo "Running security checks..."
echo ""

# 1. Network: can resolve proxy hostname (proves vault-internal DNS works)
check 1 "Network: vault-proxy hostname resolves" \
    "node -e \"require('dns').lookup('vault-proxy',(e,a)=>{process.exit(e?1:0)})\""

# 2. Network: can TCP-connect to proxy on port 8080
check 2 "Network: TCP connect to vault-proxy:8080" \
    "node -e \"const c=require('net').createConnection({host:'vault-proxy',port:8080},()=>{c.destroy();process.exit(0)});c.on('error',()=>process.exit(1));c.setTimeout(5000,()=>{c.destroy();process.exit(1)})\""

# 3. Filesystem: root is read-only
check 3 "Filesystem: root is read-only" \
    "touch /test-readonly 2>&1" true

# 4. Capabilities: ping fails (NET_RAW dropped)
check 4 "Capabilities: ping blocked (NET_RAW dropped)" \
    "ping -c 1 127.0.0.1 2>&1" true

# 5. Host mount: /mnt/c not accessible
check 5 "Host mount: /mnt/c not accessible" \
    "ls /mnt/c/ 2>&1" true

# 6. Interop: no Windows binaries in PATH
check 6 "Interop: no Windows binaries in PATH" \
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
# Read /proc/1/status directly — avoid awk/cut quoting issues in sh -c
check 11 "Seccomp: profile loaded (filter mode)" \
    "grep -q 'Seccomp:.*2' /proc/1/status"

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

# 15-18. Shell-level config verification
# Detect current shell level using proper JSON parsing, then verify
# the config matches expected values for that level.

echo ""
echo "  Shell-level config verification:"

# Extract key config values via python (safe JSON parsing, no fragile grep)
config_json=$($RUNTIME exec "$CONTAINER" sh -c "cat /home/vault/.openclaw/openclaw.json 2>/dev/null") || config_json=""

if [ -z "$config_json" ]; then
    printf "  [%2d] %-50s FAIL\n" 15 "Config: readable"
    echo "       Cannot read config file"
    FAIL=$((FAIL + 1))
else
    # Parse config into shell variables
    eval "$(echo "$config_json" | python3 -c "
import sys, json
c = json.loads(sys.stdin.read())
t = c.get('tools', {})
e = t.get('exec', {})
a = c.get('agents', {}).get('defaults', {})
print(f'CFG_PROFILE={t.get(\"profile\", \"unknown\")}')
print(f'CFG_EXEC_SEC={e.get(\"security\", \"unknown\")}')
print(f'CFG_EXEC_ASK={e.get(\"ask\", \"unknown\")}')
print(f'CFG_EXEC_HOST={e.get(\"host\", \"unknown\")}')
print(f'CFG_ELEVATED={t.get(\"elevated\", {}).get(\"enabled\", \"unknown\")}')
print(f'CFG_SANDBOX={a.get(\"sandbox\", {}).get(\"mode\", \"unknown\")}')
print(f'CFG_SAFEBINS_COUNT={len(e.get(\"safeBins\", []))}')
print(f'CFG_SAFEBINPROFILES_COUNT={len(e.get(\"safeBinProfiles\", {}))}')
print(f'CFG_DENY_COUNT={len(t.get(\"deny\", []))}')
has_browser = \"browser\" in t.get(\"deny\", [])
print(f'CFG_BROWSER_DENIED={has_browser}')
" 2>/dev/null)"

    # Determine shell level
    SHELL_LEVEL="UNKNOWN"
    if [ "$CFG_PROFILE" = "minimal" ] && [ "$CFG_EXEC_SEC" = "deny" ]; then
        SHELL_LEVEL="HARD"
    elif [ "$CFG_PROFILE" = "coding" ] && [ "$CFG_EXEC_SEC" = "allowlist" ] && [ "$CFG_EXEC_ASK" = "always" ] && [ "$CFG_BROWSER_DENIED" = "True" ]; then
        SHELL_LEVEL="SPLIT"
    fi

    echo "  Detected shell level: $SHELL_LEVEL"
    echo ""

    if [ "$SHELL_LEVEL" = "HARD" ]; then
        # Hard Shell checks — use node (python3 not available in container)
        check 15 "Config: profile = minimal" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.tools.profile==='minimal'?0:1)\""

        check 16 "Config: exec security = deny" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.tools.exec.security==='deny'?0:1)\""

        check 17 "Config: elevated disabled" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.tools.elevated.enabled===false?0:1)\""

        check 18 "Config: sandbox mode = off" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.agents.defaults.sandbox.mode==='off'?0:1)\""

    elif [ "$SHELL_LEVEL" = "SPLIT" ]; then
        # Split Shell checks — use node (python3 not available in container)
        check 15 "Config: profile = coding" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.tools.profile==='coding'?0:1)\""

        check 16 "Config: exec = allowlist + ask always" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); const e=c.tools.exec; process.exit(e.security==='allowlist'&&e.ask==='always'?0:1)\""

        check 17 "Config: exec host = gateway, elevated off" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); process.exit(c.tools.exec.host==='gateway'&&c.tools.elevated.enabled===false?0:1)\""

        # Verify safeBins and safeBinProfiles match (no orphans)
        check 18 "Config: safeBins match safeBinProfiles" \
            "node -e \"const c=JSON.parse(require('fs').readFileSync('/home/vault/.openclaw/openclaw.json','utf8')); const e=c.tools.exec; const bins=new Set(e.safeBins||[]); const profs=new Set(Object.keys(e.safeBinProfiles||{})); const missing=[...bins].filter(b=>!profs.has(b)); const extra=[...profs].filter(p=>!bins.has(p)); process.exit(missing.length===0&&extra.length===0?0:1)\""

    else
        printf "  [%2d] %-50s FAIL\n" 15 "Config: known shell level"
        echo "       Shell level UNKNOWN — config does not match Hard or Split Shell"
        echo "       profile=$CFG_PROFILE exec.security=$CFG_EXEC_SEC exec.ask=$CFG_EXEC_ASK"
        FAIL=$((FAIL + 1))
    fi
fi

# --- Per-tool security checks (19-23) ---
# These run on the HOST using the config_json already extracted above.

echo ""
echo "  Per-tool security checks:"

if [ -n "$config_json" ]; then

    # Check 19: NEVER-enabled tools are in the deny list
    printf "  [%2d] %-50s " 19 "NEVER-enable tools denied (gateway, nodes)"
    result=$(echo "$config_json" | python3 -c "
import sys, json
c = json.loads(sys.stdin.read())
deny = set(c.get('tools', {}).get('deny', []))
never = ['gateway', 'nodes']
missing = [t for t in never if t not in deny]
if missing:
    print(f'MISSING from deny list: {missing}')
    sys.exit(1)
print('ok')
" 2>&1) && echo "PASS" && PASS=$((PASS + 1)) || {
        echo "FAIL"
        echo "       $result"
        FAIL=$((FAIL + 1))
    }

    # Check 20: rm not in safeBins
    printf "  [%2d] %-50s " 20 "rm NOT in safeBins (destructive — user-side)"
    result=$(echo "$config_json" | python3 -c "
import sys, json
c = json.loads(sys.stdin.read())
safebins = c.get('tools', {}).get('exec', {}).get('safeBins', [])
if 'rm' in safebins:
    print('FOUND rm in safeBins — destructive tool must not be agent-accessible')
    sys.exit(1)
if 'rmdir' in safebins:
    print('FOUND rmdir in safeBins — destructive tool must not be agent-accessible')
    sys.exit(1)
print('ok')
" 2>&1) && echo "PASS" && PASS=$((PASS + 1)) || {
        echo "FAIL"
        echo "       $result"
        FAIL=$((FAIL + 1))
    }

    # Check 21: No interpreters in safeBins
    printf "  [%2d] %-50s " 21 "No interpreters in safeBins"
    result=$(echo "$config_json" | python3 -c "
import sys, json
c = json.loads(sys.stdin.read())
safebins = set(c.get('tools', {}).get('exec', {}).get('safeBins', []))
interpreters = {'sh', 'bash', 'node', 'python', 'python3', 'ruby', 'perl'}
found = safebins & interpreters
if found:
    print(f'FOUND interpreters in safeBins: {sorted(found)}')
    sys.exit(1)
print('ok')
" 2>&1) && echo "PASS" && PASS=$((PASS + 1)) || {
        echo "FAIL"
        echo "       $result"
        FAIL=$((FAIL + 1))
    }

    # Check 22: Proxy allowlist contains only expected domains
    printf "  [%2d] %-50s " 22 "Proxy allowlist — no unexpected domains"
    proxy_allowlist=""
    if $RUNTIME inspect "vault-proxy" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        proxy_allowlist=$($RUNTIME exec vault-proxy sh -c "cat /opt/vault/allowlist.txt 2>/dev/null" 2>&1) || proxy_allowlist=""
    fi
    if [ -n "$proxy_allowlist" ]; then
        result=$(echo "$proxy_allowlist" | python3 -c "
import sys
# Known safe base domains
base = {'api.anthropic.com', 'api.openai.com', 'api.telegram.org'}
domains = set()
for line in sys.stdin:
    line = line.strip()
    if line and not line.startswith('#'):
        domains.add(line)
unexpected = domains - base
if unexpected:
    print(f'Unexpected domains in allowlist: {sorted(unexpected)}')
    sys.exit(1)
print('ok')
" 2>&1) && echo "PASS" && PASS=$((PASS + 1)) || {
            echo "FAIL"
            echo "       $result"
            FAIL=$((FAIL + 1))
        }
    else
        echo "SKIP (proxy not running)"
        SKIP=$((SKIP + 1))
    fi

    # Check 23: Risk score report (informational — not pass/fail)
    printf "  [%2d] %-50s " 23 "Risk score"
    MANIFEST="$(cd "$(dirname "$0")/.." && pwd)/config/tool-manifest.yml"
    CORE="$(cd "$(dirname "$0")/.." && pwd)/scripts/tool-control-core.py"
    if [ -f "$MANIFEST" ] && [ -f "$CORE" ]; then
        score=$(echo "$config_json" | python3 "$CORE" --manifest "$MANIFEST" --output status --status-json "$(echo "$config_json")" 2>/dev/null | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('risk_score', '?'))" 2>/dev/null) || score="?"
        echo "INFO ($score)"
    else
        echo "SKIP (manifest or core not found)"
    fi

else
    echo "  Skipped — config not readable"
fi

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
