"""
openclaw-VAULT: mitmproxy Addon — API Key Injection + Domain Allowlist

This is the core security component. It runs as a mitmproxy addon in the
vault-proxy sidecar container, intercepting all outbound traffic from the
OpenClaw container.

Key behaviors:
  1. Block requests to domains not on the allowlist → 403
  2. Inject API keys into LLM provider requests (key never enters OpenClaw container)
  3. Log all requests/responses as structured JSON for forensic review
  4. Flag suspiciously large responses (potential data exfiltration)

Usage:
  mitmdump --listen-port 8080 --scripts vault-proxy.py
"""

import json
import logging
import os
import time
from pathlib import Path

from mitmproxy import ctx, http

LOG_DIR = Path("/var/log/vault-proxy")
ALLOWLIST_PATH = Path("/opt/vault/allowlist.txt")
EXFIL_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB — flag large outbound payloads


class VaultProxy:
    def __init__(self):
        self.allowlist: set[str] = set()
        self.logger = self._setup_logger()
        self._load_allowlist()
        self.logger.info("VaultProxy initialized with %d allowed domains", len(self.allowlist))

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
                    self.allowlist.add(domain)

    def _is_allowed(self, host: str) -> bool:
        """Check if host matches any allowed domain (exact or subdomain)."""
        for allowed in self.allowlist:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False

    def _log_event(self, event: dict):
        """Write structured JSON log entry."""
        event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.logger.info(json.dumps(event, default=str))

    def request(self, flow: http.HTTPFlow):
        """Intercept outbound requests: allowlist check + API key injection."""
        host = flow.request.pretty_host
        method = flow.request.method
        url = flow.request.pretty_url

        # --- Domain allowlist enforcement ---
        if not self._is_allowed(host):
            self._log_event({
                "action": "BLOCKED",
                "method": method,
                "url": url,
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

        # --- API key injection (the headline feature) ---
        # Keys come from environment variables in the PROXY container only.
        # The OpenClaw container never sees these values.

        if "api.anthropic.com" in host:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                flow.request.headers["x-api-key"] = api_key
                flow.request.headers["anthropic-version"] = "2023-06-01"
            else:
                ctx.log.warn("ANTHROPIC_API_KEY not set — request will fail auth")

        elif "api.openai.com" in host:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if api_key:
                flow.request.headers["Authorization"] = f"Bearer {api_key}"
            else:
                ctx.log.warn("OPENAI_API_KEY not set — request will fail auth")

        # --- Flag large outbound payloads (potential exfiltration) ---
        request_size = len(flow.request.content) if flow.request.content else 0
        if request_size > EXFIL_THRESHOLD_BYTES:
            self._log_event({
                "action": "EXFIL_WARNING",
                "method": method,
                "url": url,
                "request_bytes": request_size,
                "reason": f"outbound payload exceeds {EXFIL_THRESHOLD_BYTES} bytes",
            })

        self._log_event({
            "action": "ALLOWED",
            "method": method,
            "url": url,
            "host": host,
            "request_bytes": request_size,
        })

    def response(self, flow: http.HTTPFlow):
        """Log response metadata for forensic review."""
        if flow.response:
            response_size = len(flow.response.content) if flow.response.content else 0
            self._log_event({
                "action": "RESPONSE",
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "response_bytes": response_size,
            })

            if response_size > EXFIL_THRESHOLD_BYTES:
                self._log_event({
                    "action": "LARGE_RESPONSE",
                    "url": flow.request.pretty_url,
                    "response_bytes": response_size,
                    "reason": "unusually large response — review for data exfiltration",
                })


addons = [VaultProxy()]
