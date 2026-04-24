"""
OpenClaw-Vault: mitmproxy Addon — API Key Injection + Domain Allowlist

This is the core security component. It runs as a mitmproxy addon in the
vault-proxy sidecar container, intercepting all outbound traffic from the
OpenClaw container.

Key behaviors:
  1. Block requests to domains not on the allowlist → 403
  2. Block raw IP addresses (allowlist is domain-only) → 403
  3. Block large outbound payloads (potential exfiltration) → 413
  4. Inject API keys into LLM provider requests (key never enters OpenClaw container)
  5. Redact API keys if reflected in responses
  6. Log all requests/responses as structured JSON for forensic review
  7. Block oversized responses (>10 MB)

Usage:
  mitmdump --listen-port 8080 --scripts vault-proxy.py
"""

import ipaddress
import json
import logging
import os
import re
import signal
import time
from pathlib import Path

from mitmproxy import ctx, http

LOG_DIR = Path("/var/log/vault-proxy")
ALLOWLIST_PATH = Path("/opt/vault/allowlist.txt")
EXFIL_THRESHOLD_BYTES = 1 * 1024 * 1024  # 1 MB — block large outbound payloads
EXFIL_RESPONSE_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB — block large responses
ANTHROPIC_API_VERSION = os.environ.get("ANTHROPIC_API_VERSION", "2023-06-01")

# Telegram Bot API embeds the token in the URL path: https://api.telegram.org/bot<id>:<hash>/<method>
# Redact before logging so tokens never hit stdout or the requests.jsonl file.
BOT_TOKEN_PATH_RE = re.compile(r"(/bot)\d+:[A-Za-z0-9_-]{20,}")


class VaultProxy:
    def __init__(self):
        self.allowlist: set[str] = set()
        self.logger = self._setup_logger()
        self._load_allowlist()
        self.logger.info("VaultProxy initialized with %d allowed domains", len(self.allowlist))
        signal.signal(signal.SIGHUP, lambda s, f: self._reload_allowlist())

    def _setup_logger(self) -> logging.Logger:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("vault-proxy")
        logger.setLevel(logging.INFO)

        # Structured JSON log
        handler = logging.FileHandler(LOG_DIR / "requests.jsonl")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

        # Also log to stdout for `podman compose logs`
        stdout = logging.StreamHandler()
        stdout.setFormatter(logging.Formatter("[vault-proxy] %(message)s"))
        logger.addHandler(stdout)

        return logger

    def _load_allowlist(self):
        """Load allowed domains from allowlist.txt, one domain per line."""
        if not ALLOWLIST_PATH.exists():
            ctx.log.warn(f"Allowlist not found at {ALLOWLIST_PATH} — blocking ALL requests")
            return
        with open(ALLOWLIST_PATH) as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    self.allowlist.add(domain.lower())

    def _reload_allowlist(self):
        """Reload allowlist from disk (triggered by SIGHUP). Atomic swap to avoid empty-set window."""
        old_count = len(self.allowlist)
        new_allowlist: set[str] = set()
        if ALLOWLIST_PATH.exists():
            with open(ALLOWLIST_PATH) as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith("#"):
                        new_allowlist.add(domain.lower())
        self.allowlist = new_allowlist
        self.logger.info("Allowlist reloaded: %d → %d domains", old_count, len(self.allowlist))

    def _is_allowed(self, host: str) -> bool:
        """Check if host matches any allowed domain (exact or subdomain)."""
        host = host.lower()
        # Reject raw IP addresses — allowlist is domain-only
        # Strip brackets for IPv6 (mitmproxy returns [::1] form)
        host_for_ip_check = host.strip("[]")
        try:
            ipaddress.ip_address(host_for_ip_check)
            return False
        except ValueError:
            pass
        for allowed in self.allowlist:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False

    def _log_event(self, event: dict):
        """Write structured JSON log entry."""
        event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.logger.info(json.dumps(event, default=str))

    @staticmethod
    def _redact_url(url: str) -> str:
        # Bot-token-in-URL pattern is specific to Telegram; add others here if needed.
        return BOT_TOKEN_PATH_RE.sub(r"\1<REDACTED_BOT_TOKEN>", url)

    def running(self):
        # Silence mitmproxy's built-in per-flow summary prints, which also contain the
        # Telegram token in the URL and bypass our _log_event redaction path.
        ctx.options.flow_detail = 0

    def request(self, flow: http.HTTPFlow):
        """Intercept outbound requests: allowlist check, size check, API key injection."""
        host = flow.request.pretty_host
        method = flow.request.method
        url = flow.request.pretty_url

        # --- 1. Domain allowlist enforcement ---
        if not self._is_allowed(host):
            self._log_event({
                "action": "BLOCKED",
                "method": method,
                "url": self._redact_url(url),
                "host": host,
                "reason": "domain not in allowlist",
            })
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "blocked_by_vault",
                    "message": f"Domain '{host}' is not in the VAULT allowlist. "
                               f"Add it to proxy/allowlist.txt if this is intentional.",
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return

        # --- 2. Block large outbound payloads (potential exfiltration) ---
        # MUST happen BEFORE API key injection so keys are never attached to blocked requests
        request_size = len(flow.request.content) if flow.request.content else 0
        if request_size > EXFIL_THRESHOLD_BYTES:
            self._log_event({
                "action": "EXFIL_BLOCKED",
                "method": method,
                "url": self._redact_url(url),
                "request_bytes": request_size,
                "reason": f"outbound payload exceeds {EXFIL_THRESHOLD_BYTES} bytes",
            })
            flow.response = http.Response.make(
                413,
                json.dumps({
                    "error": "exfiltration_blocked",
                    "message": f"Outbound payload ({request_size} bytes) exceeds "
                               f"exfiltration threshold ({EXFIL_THRESHOLD_BYTES} bytes).",
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return

        # --- 3. API key injection (the headline feature) ---
        # Keys come from environment variables in the PROXY container only.
        # The OpenClaw container never sees these values.

        if host == "api.anthropic.com" or host.endswith(".api.anthropic.com"):
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                flow.request.headers["x-api-key"] = api_key
                flow.request.headers["anthropic-version"] = ANTHROPIC_API_VERSION
            else:
                ctx.log.warn("ANTHROPIC_API_KEY not set — request will fail auth")

        elif host == "api.openai.com" or host.endswith(".api.openai.com"):
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if api_key:
                flow.request.headers["Authorization"] = f"Bearer {api_key}"
            else:
                ctx.log.warn("OPENAI_API_KEY not set — request will fail auth")

        self._log_event({
            "action": "ALLOWED",
            "method": method,
            "url": self._redact_url(url),
            "host": host,
            "request_bytes": request_size,
        })

    def response(self, flow: http.HTTPFlow):
        """Block oversized responses, redact reflected API keys, log metadata."""
        if flow.response:
            response_size = len(flow.response.content) if flow.response.content else 0

            # --- 1. Block oversized responses FIRST (before logging misleading 200) ---
            if response_size > EXFIL_RESPONSE_THRESHOLD_BYTES:
                self._log_event({
                    "action": "LARGE_RESPONSE_BLOCKED",
                    "url": self._redact_url(flow.request.pretty_url),
                    "response_bytes": response_size,
                    "reason": "response exceeds 10 MB threshold",
                })
                flow.response = http.Response.make(
                    413, b"Response too large", {"Content-Type": "text/plain"}
                )
                return

            # --- 2. Redact API keys if reflected in response (headers + body) ---
            for env_var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
                key = os.environ.get(env_var, "")
                if not key:
                    continue
                key_bytes = key.encode()
                redacted = False
                # Scan ALL response headers (handles duplicate header names)
                # headers.fields is a tuple of (name, value) byte pairs
                new_fields = []
                for hname, hval in flow.response.headers.fields:
                    if key_bytes in hval:
                        hval = hval.replace(key_bytes, b"[REDACTED_BY_VAULT]")
                        redacted = True
                    new_fields.append((hname, hval))
                if redacted:
                    flow.response.headers.fields = tuple(new_fields)
                # Scan response body
                if flow.response.content and key_bytes in flow.response.content:
                    flow.response.content = flow.response.content.replace(
                        key_bytes, b"[REDACTED_BY_VAULT]"
                    )
                    redacted = True
                if redacted:
                    self._log_event({
                        "action": "KEY_REFLECTED",
                        "url": self._redact_url(flow.request.pretty_url),
                        "env_var": env_var,
                        "reason": "API key found in response — redacted",
                    })

            # --- 3. Log response metadata ---
            self._log_event({
                "action": "RESPONSE",
                "url": self._redact_url(flow.request.pretty_url),
                "status": flow.response.status_code,
                "response_bytes": response_size,
            })


addons = [VaultProxy()]
