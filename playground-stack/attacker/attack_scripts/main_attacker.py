#!/usr/bin/env python3
"""
Main Attacker Script for Cyber Deception Playground
Orchestrates all attack phases in a modular, MITRE ATT&CK-annotated sequence.
"""

import logging
import sys

from components.base_attacker import BaseAttacker, print_mitre_header
from components.web_application_discovery import WebApplicationDiscovery
from components.command_injection import CommandInjection
from components.sql_injection import SQLInjection
from components.reconnaissance import Reconnaissance
from components.port_scanning import PortScanning
from components.ssh_bruteforce import SSHBruteForce
from components.lateral_movement import LateralMovement
from components.data_exfiltration import DataExfiltration


def configure_logging() -> None:
    """Configure root logger with timestamp and level formatting."""
    fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


class MainAttacker(BaseAttacker):
    """Orchestrates the full 7-phase attack kill-chain against the Deception Playground."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)
        self.web_application_discovery = WebApplicationDiscovery(frontend_url)
        self.command_injection = CommandInjection(frontend_url)
        self.sql_injection = SQLInjection(frontend_url)
        self.reconnaissance = Reconnaissance(frontend_url)
        self.port_scanning = PortScanning(frontend_url)
        self.ssh_bruteforce = SSHBruteForce(frontend_url)
        self.lateral_movement = LateralMovement(frontend_url)
        self.data_exfiltration = DataExfiltration(frontend_url)

    def run_full_attack(self) -> None:
        """Execute the complete MITRE ATT&CK-mapped attack sequence."""
        self.logger.info("[ATTACK SEQUENCE] Starting comprehensive attack...")
        self.logger.info("=" * 60)

        self.logger.info("\n[ATTACK PHASES SUMMARY]")
        self.logger.info("The following phases will be executed:")
        self.logger.info("  Phase 1  [T1595.003]  Web Application Discovery")
        self.logger.info("  Phase 2  [T1059.004]  Command Injection Attack")
        self.logger.info("  Phase 3  [T1190]      SQL Injection Attack")
        self.logger.info("  Phase 4  [T1018]      Network Reconnaissance")
        self.logger.info("  Phase 5  [T1046]      Port Scanning")
        self.logger.info("  Phase 6  [T1110.001]  SSH Brute Force Attack")
        self.logger.info("  Phase 6.5[T1021.004]  Lateral Movement via SSH")
        self.logger.info("  Phase 7  [T1041]      Data Exfiltration")
        self.logger.info("\nYou can continue, skip, or quit at each phase.")
        self.logger.info("=" * 60)

        # Phase 1: Web Application Discovery
        print_mitre_header("web_application_discovery")
        choice = self.ask_continue("Phase 1: Web Application Discovery")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping web application discovery phase")
        else:
            self.web_application_discovery.discover_endpoints()

        # Phase 2: Command Injection
        print_mitre_header("command_injection")
        choice = self.ask_continue("Phase 2: Command Injection Attack")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping command injection phase")
        else:
            self.command_injection.execute_commands()

        # Phase 3: SQL Injection
        print_mitre_header("sql_injection")
        choice = self.ask_continue("Phase 3: SQL Injection Attack")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping SQL injection phase")
        else:
            self.sql_injection.attempt_bypass()

        # Phase 4: Network Reconnaissance
        print_mitre_header("reconnaissance")
        choice = self.ask_continue("Phase 4: Network Reconnaissance")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping reconnaissance phase")
            discovered_hosts = []
        else:
            discovered_hosts = self.reconnaissance.discover_network()

        # Phase 5: Port Scanning
        print_mitre_header("port_scanning")
        choice = self.ask_continue("Phase 5: Port Scanning")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping port scanning phase")
            open_ports = {}
        else:
            open_ports = self.port_scanning.scan_ports(discovered_hosts)

        # Phase 6: SSH Brute Force Attack
        print_mitre_header("ssh_bruteforce")
        choice = self.ask_continue("Phase 6: SSH Brute Force Attack")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping SSH brute force phase")
            successful_ssh_logins = []
        else:
            ssh_hosts = list({
                host
                for host, ports in open_ports.items()
                for port_info in ports
                if port_info["port"] == 22 or port_info["service"] == "ssh"
            })

            if ssh_hosts:
                self.logger.info(
                    "[SSH TARGETS] Found %d host(s) with SSH open: %s",
                    len(ssh_hosts),
                    ", ".join(ssh_hosts),
                )
                successful_ssh_logins = self.ssh_bruteforce.run_ssh_attack(ssh_hosts)
            else:
                self.logger.warning(
                    "[SSH TARGETS] No hosts with SSH port open found. Skipping SSH brute force."
                )
                successful_ssh_logins = []

        # Phase 6.5: Lateral Movement
        print_mitre_header("lateral_movement")
        choice = self.ask_continue("Phase 6.5: Lateral Movement via SSH")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping lateral movement phase")
        else:
            self.lateral_movement.attempt_lateral_movement(
                discovered_hosts, successful_ssh_logins
            )

        # Phase 7: Data Exfiltration
        print_mitre_header("data_exfiltration")
        choice = self.ask_continue("Phase 7: Data Exfiltration")
        if choice == "quit":
            self.logger.info("Attack cancelled by user")
            return
        elif choice == "skip":
            self.logger.info("Skipping data exfiltration phase")
        else:
            self.data_exfiltration.extract_data()

        self.logger.info("\n" + "=" * 60)
        self.logger.info("[ATTACK COMPLETE] Attack sequence finished!")
        self.logger.info("[SUMMARY] Discovered %d internal hosts", len(discovered_hosts))
        if discovered_hosts:
            self.logger.info("[TARGETS] Hosts found: %s", ", ".join(discovered_hosts))

        if open_ports:
            self.logger.info("\n[PORT SCAN RESULTS]:")
            for host, ports in open_ports.items():
                if ports:
                    port_list = [f"{p['port']}({p['service']})" for p in ports]
                    self.logger.info("   %s: %s", host, ", ".join(port_list))
                else:
                    self.logger.info("   %s: No open ports found", host)


if __name__ == "__main__":
    configure_logging()
    attacker = MainAttacker()
    attacker.run_full_attack()
