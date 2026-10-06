# MITRE ATT&CK Coverage

This document maps the **Cyber Deception Playground** attack simulation and detection capabilities to the [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/).

---

## Attack Simulation — Kill Chain Coverage

| Phase | ATT&CK Tactic | Technique ID | Technique Name | Component |
|-------|--------------|-------------|----------------|-----------|
| 1 | Reconnaissance | T1595.003 | Active Scanning: Vulnerability Scanning | `web_application_discovery.py` |
| 2 | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | `command_injection.py` |
| 3 | Initial Access | T1190 | Exploit Public-Facing Application (SQLi) | `sql_injection.py` |
| 4 | Discovery | T1018 | Remote System Discovery | `reconnaissance.py` |
| 5 | Discovery | T1046 | Network Service Scanning | `port_scanning.py` |
| 4+5 | Discovery | T1087.001 | Account Discovery: Local Account | `reconnaissance.py` (`/users` endpoint) |
| 6 | Credential Access | T1110.001 | Brute Force: Password Guessing | `ssh_bruteforce.py` |
| 6 | Credential Access | T1555 | Credentials from Password Stores (DB) | `sql_injection.py` (UNION SELECT users) |
| 6.5 | Lateral Movement | T1021.004 | Remote Services: SSH | `lateral_movement.py` |
| 7 | Exfiltration | T1041 | Exfiltration Over C2 Channel | `data_exfiltration.py` |
| 7 | Collection | T1005 | Data from Local System | `data_exfiltration.py` |

---

## Deception Capabilities by Level

| Capability | none | basic | complete | impossible |
|-----------|:----:|:-----:|:--------:|:----------:|
| SSH Honeypot (T1110.001 detection) | ❌ | ✅ | ✅ | ✅ |
| Fake Credentials (T1555 misdirection) | ❌ | ✅ | ✅ | ✅ |
| Decoy Database Columns (T1005 misdirection) | ❌ | ❌ | ✅ | ✅ |
| Fake Activity Generator (T1036 — Masquerading) | ❌ | ❌ | ✅ | ✅ |
| Decoy API Endpoints / Honeytokens (T1190 detection) | ❌ | ❌ | ✅ | ✅ |
| Modified Service Banners (T1592 misdirection) | ❌ | ❌ | ❌ | ✅ |
| Anti-Forensics Measures (T1070 detection) | ❌ | ❌ | ❌ | ✅ |
| Tampered Executables (T1036.005 misdirection) | ❌ | ❌ | ❌ | ✅ |

---

## Detection Coverage — Elastic Stack Indicators

The following security indicators are extracted from logs and indexed in Elasticsearch:

| Indicator Type | ATT&CK Technique | Kibana Field |
|---------------|-----------------|-------------|
| SQL injection pattern | T1190 | `security.attack_type: SQL_INJECTION` |
| Command injection | T1059.004 | `security.attack_type: COMMAND_INJECTION` |
| Path traversal | T1083 | `security.attack_type: PATH_TRAVERSAL` |
| SSH brute force attempt | T1110.001 | `security.attack_type: SSH_BRUTE_FORCE` |
| Suspicious SSH username | T1110.001 | `security.attack_type: CREDENTIAL_PROBING` |
| Honeytoken / decoy endpoint access | T1190 | `security.attack_type: HONEYTOKEN_ACCESS` |
| Credential extraction via SQL | T1555 | `security.attack_type: SQL_INJECTION` + `mitre.technique_id: T1190` |
| Fake activity masquerading as legitimate user | T1036 | `fake_activity: true` (SSH honeypot logs) |
| Data exfiltration via exposed query endpoint | T1005 | `security.attack_type: SQL_INJECTION` on `/query` |

---

## Roadmap

| ATT&CK Technique | Tactic | Notes |
|-----------------|--------|-------|
| T1068 | Privilege Escalation | Container escape / privilege escalation |
| T1070.004 | Defense Evasion | Log deletion / tampering |
| T1055 | Defense Evasion | Process injection |
