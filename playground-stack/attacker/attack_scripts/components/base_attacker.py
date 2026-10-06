#!/usr/bin/env python3
"""
Base Attacker Class for Cyber Deception Playground
Provides common functionality, logging, and MITRE ATT&CK annotations for all attack phases.
"""

import logging
import requests

# MITRE ATT&CK TTP mapping for each attack phase
MITRE_TTPS = {
    "web_application_discovery": {
        "id": "T1595.003",
        "tactic": "Reconnaissance",
        "technique": "Active Scanning: Vulnerability Scanning",
    },
    "command_injection": {
        "id": "T1059.004",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter: Unix Shell",
    },
    "sql_injection": {
        "id": "T1190",
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
    },
    "reconnaissance": {
        "id": "T1018",
        "tactic": "Discovery",
        "technique": "Remote System Discovery",
    },
    "port_scanning": {
        "id": "T1046",
        "tactic": "Discovery",
        "technique": "Network Service Scanning",
    },
    "ssh_bruteforce": {
        "id": "T1110.001",
        "tactic": "Credential Access",
        "technique": "Brute Force: Password Guessing",
    },
    "lateral_movement": {
        "id": "T1021.004",
        "tactic": "Lateral Movement",
        "technique": "Remote Services: SSH",
    },
    "data_exfiltration": {
        "id": "T1041",
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over C2 Channel",
    },
}


def print_mitre_header(phase_key: str) -> None:
    """Print a MITRE ATT&CK banner for the given phase key."""
    ttp = MITRE_TTPS.get(phase_key)
    if not ttp:
        return
    logger = logging.getLogger(__name__)
    banner = (
        f"\n{'=' * 60}\n"
        f"  MITRE ATT&CK  |  {ttp['id']}\n"
        f"  Tactic        |  {ttp['tactic']}\n"
        f"  Technique     |  {ttp['technique']}\n"
        f"{'=' * 60}"
    )
    logger.info(banner)


class BaseAttacker:
    """Base class for all attack modules."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        self.frontend_url = frontend_url
        self.session = requests.Session()
        self.logger = logging.getLogger(self.__class__.__name__)

    def ask_continue(self, step_name: str) -> str:
        """Ask the user whether to continue, skip, or quit the given step."""
        self.logger.info("\n[CONFIRMATION] %s", step_name)
        print("  [c] Continue to next step")
        print("  [s] Skip this step")
        print("  [q] Quit attack")

        while True:
            try:
                choice = input("Enter your choice [c/s/q]: ").lower().strip()
                if choice in ["c", "continue"]:
                    return "continue"
                elif choice in ["s", "skip"]:
                    return "skip"
                elif choice in ["q", "quit", "exit"]:
                    return "quit"
                else:
                    print("Invalid choice. Please enter 'c', 's', or 'q'")
            except KeyboardInterrupt:
                self.logger.warning("Attack cancelled by user (KeyboardInterrupt)")
                return "quit"
