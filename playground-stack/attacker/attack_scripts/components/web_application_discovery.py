#!/usr/bin/env python3
"""
Phase 1: Web Application Discovery and Vulnerability Assessment
Discovers vulnerable endpoints in the web application.

MITRE ATT&CK: T1595.003 — Active Scanning: Vulnerability Scanning
"""

import logging
import re

from .base_attacker import BaseAttacker

logger = logging.getLogger(__name__)


class WebApplicationDiscovery(BaseAttacker):
    """Enumerates endpoints and identifies vulnerable elements in the target web app."""

    def __init__(self, frontend_url: str = "http://frontend:3000") -> None:
        super().__init__(frontend_url)

    def discover_endpoints(self) -> dict:
        """Phase 1: Web Application Discovery and Vulnerability Assessment."""
        logger.info("\n[WEB APPLICATION DISCOVERY] Analyzing web application for vulnerable endpoints...")

        common_endpoints = [
            "/", "/login", "/admin", "/api", "/api/login", "/api/users", "/api/execute",
            "/api/query", "/api/system", "/api/network", "/health", "/status",
            "/admin/login", "/dashboard", "/panel", "/control", "/manage",
            "/upload", "/files", "/download", "/backup", "/config",
            "/test", "/debug", "/info", "/version", "/help",
        ]

        discovered_endpoints = []
        vulnerable_elements = []

        for endpoint in common_endpoints:
            try:
                response = self.session.get(f"{self.frontend_url}{endpoint}")
                logger.info("   %s: %s", endpoint, response.status_code)

                if response.status_code == 200:
                    discovered_endpoints.append({"endpoint": endpoint, "status": response.status_code, "type": "GET"})
                    logger.info("   ✅ Endpoint found: %s", endpoint)
                    page_analysis = self.analyze_page_content(response.text, endpoint)
                    if page_analysis:
                        vulnerable_elements.extend(page_analysis)

                elif response.status_code == 405:
                    try:
                        post_response = self.session.post(
                            f"{self.frontend_url}{endpoint}",
                            json={},
                            headers={"Content-Type": "application/json"},
                        )
                        if post_response.status_code in [200, 400, 422]:
                            discovered_endpoints.append(
                                {"endpoint": endpoint, "status": post_response.status_code, "type": "POST"}
                            )
                            logger.info("   ✅ POST endpoint found: %s", endpoint)
                    except Exception:
                        pass

            except Exception as e:
                logger.error("   ❌ Error testing %s: %s", endpoint, e)

        logger.info(
            "\n[WEB APPLICATION SUMMARY] Total endpoints discovered: %d", len(discovered_endpoints)
        )
        for ep in discovered_endpoints:
            logger.info("   - %s (%s) - Status: %s", ep["endpoint"], ep["type"], ep["status"])

        if vulnerable_elements:
            logger.info(
                "\n[VULNERABLE ELEMENTS] Found %d potentially vulnerable elements:", len(vulnerable_elements)
            )
            for element in vulnerable_elements:
                logger.info(
                    "   - %s: %s at %s", element["type"], element["description"], element["endpoint"]
                )

        return {"endpoints": discovered_endpoints, "vulnerable_elements": vulnerable_elements}

    def analyze_page_content(self, html_content: str, endpoint: str) -> list:
        """Analyze HTML content for potentially vulnerable elements."""
        vulnerable_elements = []

        try:
            if "<form" in html_content.lower():
                vulnerable_elements.extend(self.extract_forms(html_content, endpoint))
            if "<input" in html_content.lower():
                vulnerable_elements.extend(self.extract_inputs(html_content, endpoint))
            if "<script" in html_content.lower():
                vulnerable_elements.extend(self.extract_scripts(html_content, endpoint))
            if 'type="file"' in html_content.lower() or 'enctype="multipart/form-data"' in html_content.lower():
                vulnerable_elements.append(
                    {"type": "FILE_UPLOAD", "description": "File upload functionality detected", "endpoint": endpoint}
                )
            admin_keywords = ["admin", "manage", "control", "dashboard", "panel"]
            if any(k in html_content.lower() for k in admin_keywords):
                vulnerable_elements.append(
                    {"type": "ADMIN_INTERFACE", "description": "Admin/management interface detected", "endpoint": endpoint}
                )
            if "fetch(" in html_content or "XMLHttpRequest" in html_content or "$.ajax" in html_content:
                vulnerable_elements.append(
                    {"type": "AJAX_ENDPOINTS", "description": "AJAX/API calls detected in JavaScript", "endpoint": endpoint}
                )
            sql_keywords = ["select", "insert", "update", "delete", "drop", "create", "alter"]
            if any(k in html_content.lower() for k in sql_keywords):
                vulnerable_elements.append(
                    {"type": "SQL_REFERENCES", "description": "SQL-related content detected", "endpoint": endpoint}
                )
            self.extract_ids_from_elements(html_content, vulnerable_elements, endpoint)
        except Exception as e:
            logger.error("   ❌ Error analyzing content for %s: %s", endpoint, e)

        return vulnerable_elements

    def extract_forms(self, html_content: str, endpoint: str) -> list:
        """Extract form information from HTML."""
        forms = []
        form_pattern = r"<form[^>]*>(.*?)</form>"
        for i, form_content in enumerate(re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)):
            form_info = {"type": "FORM", "description": f"Form #{i+1} found", "endpoint": endpoint}
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            if action_match:
                form_info["action"] = action_match.group(1)
                form_info["description"] += f' with action="{action_match.group(1)}"'
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            if method_match:
                form_info["method"] = method_match.group(1).upper()
                form_info["description"] += f" (method: {method_match.group(1).upper()})"
            forms.append(form_info)
        return forms

    def extract_inputs(self, html_content: str, endpoint: str) -> list:
        """Extract input field information from HTML."""
        inputs = []
        for i, input_tag in enumerate(re.findall(r"<input[^>]*>", html_content, re.IGNORECASE)):
            input_info = {"type": "INPUT_FIELD", "description": f"Input field #{i+1}", "endpoint": endpoint}
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            if type_match:
                input_type = type_match.group(1)
                input_info["input_type"] = input_type
                input_info["description"] += f" (type: {input_type})"
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            if name_match:
                input_info["name"] = name_match.group(1)
                input_info["description"] += f" (name: {name_match.group(1)})"
            if type_match and type_match.group(1).lower() in ["password", "email", "file", "hidden"]:
                input_info["sensitive"] = True
                input_info["description"] += " [SENSITIVE]"
            inputs.append(input_info)
        return inputs

    def extract_scripts(self, html_content: str, endpoint: str) -> list:
        """Extract script information from HTML."""
        scripts = []
        for i, script_content in enumerate(
            re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)
        ):
            script_info = {"type": "SCRIPT", "description": f"JavaScript code block #{i+1}", "endpoint": endpoint}
            for pattern in ["document.write", "innerHTML", "eval(", "setTimeout", "setInterval"]:
                if pattern in script_content:
                    script_info["description"] += f" (contains {pattern})"
                    break
            scripts.append(script_info)
        return scripts

    def extract_ids_from_elements(self, html_content: str, vulnerable_elements: list, endpoint: str) -> None:
        """Annotate vulnerable elements with HTML id attributes where available."""
        id_pattern = r'<(\w+)[^>]*id=["\']([^"\']*)["\'][^>]*>'
        id_mapping = {}
        for tag_name, element_id in re.findall(id_pattern, html_content, re.IGNORECASE):
            element_pattern = rf'<{tag_name}[^>]*id=["\']?{re.escape(element_id)}["\']?[^>]*>'
            element_match = re.search(element_pattern, html_content, re.IGNORECASE)
            if element_match:
                id_mapping[element_match.group(0)] = element_id

        for element in vulnerable_elements:
            if element["type"] not in ["FORM", "INPUT_FIELD", "SCRIPT"]:
                continue
            for element_content, element_id in id_mapping.items():
                tag = element["type"].lower().replace("_field", "").replace("input", "input")
                if f"<{tag}" in element_content.lower():
                    element["id"] = element_id
                    element["description"] += f" (id: {element_id})"
