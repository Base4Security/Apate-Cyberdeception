#!/usr/bin/env python3
"""
Phase 5: Port Scanning
Scans discovered hosts for open ports using nmap via command injection.

MITRE ATT&CK: T1046 — Network Service Scanning
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class PortScanning(BaseAttacker):
    """Performs nmap-based port scanning on hosts discovered during reconnaissance."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def scan_ports(self, discovered_hosts: list) -> dict:
        """Phase 5: Port Scanning using nmap on discovered hosts."""
        logger.info("\n[PORT SCANNING] Using nmap for comprehensive port scanning...")

        filtered_hosts = []
        for host in discovered_hosts:
            if host.endswith(".1"):
                logger.info("[SKIP] Skipping gateway: %s", host)
                continue

            if "." in host and any(c.isdigit() for c in host) and len(host.split(".")) == 4:
                filtered_hosts.append(host)
                continue

            try:
                response = self.session.post(
                    f"{self.frontend_url}/execute",
                    json={"command": f"nslookup {host}"},
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        resolved_ip = None
                        for line in result.get("output", "").split("\n"):
                            if "Address:" in line and "#" not in line:
                                ip = line.split("Address:")[1].strip()
                                if "." in ip and not ip.startswith("127.") and not ip.startswith("::1"):
                                    resolved_ip = ip
                                    break
                        if resolved_ip:
                            filtered_hosts.append(resolved_ip)
                        else:
                            logger.warning("   ❌ Could not resolve %s to valid IP", host)
                    else:
                        logger.warning("❌ Resolution failed for %s", host)
                else:
                    logger.warning("❌ Resolution failed for %s (HTTP %s)", host, response.status_code)
            except Exception as e:
                logger.error("❌ Resolution failed for %s: %s", host, e)

        logger.info("[PORT SCAN] Will scan %d IP addresses (excluding gateways)", len(filtered_hosts))

        open_ports: dict = {}

        for host in filtered_hosts:
            open_ports[host] = []
            logger.info("[NMAP PORT SCAN] Scanning %s...", host)

            try:
                cmd = f"nmap -Pn -T4 --top-ports 100 {host}"
                logger.info("Executing port scan '%s' → Target host: %s", cmd, host)
                response = self.session.post(
                    f"{self.frontend_url}/execute",
                    json={"command": cmd},
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        output = result.get("output", "")
                        logger.info("✅ Port scan completed for %s", host)
                        for line in output.split("\n"):
                            if "/tcp" in line and "open" in line:
                                parts = line.split()
                                if len(parts) >= 3:
                                    port_info = parts[0]
                                    service = parts[2] if len(parts) > 2 else "unknown"
                                    port = port_info.split("/")[0]
                                    open_ports[host].append(
                                        {"port": port, "protocol": "tcp", "service": service}
                                    )
                                    logger.info("   ✅ %s:%s - OPEN (%s)", host, port, service)
                    else:
                        logger.warning("❌ Port scan failed for %s: %s", host, result.get("error", "Unknown error"))
                else:
                    logger.warning("❌ Port scan failed for %s - HTTP %s", host, response.status_code)
            except Exception as e:
                logger.error("❌ Port scan failed for %s: %s", host, e)

        total_ports = sum(len(ports) for ports in open_ports.values())
        logger.info("[PORT SCAN SUMMARY] Total open ports found: %d", total_ports)

        if total_ports > 0:
            logger.info("\n[OPEN PORTS DISCOVERED]:")
            for host, ports in open_ports.items():
                if ports:
                    port_list = [f"{p['port']}({p['service']})" for p in ports]
                    logger.info("   %s: %s", host, ", ".join(port_list))

        return open_ports
