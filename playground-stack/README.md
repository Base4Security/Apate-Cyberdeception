<h3 align="center">Cyber Deception Playground</h3>
<h4 align="center"><i>Lab for cyber deception research</i></h4>

<hr>

<div align="center">

[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![docs](https://img.shields.io/badge/docs-read%20the%20docs-blue)](https://cyberdeception-playground.readthedocs.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](/LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.13140%2FRG.2.2.21196.68481-blue)](https://doi.org/10.13140/RG.2.2.21196.68481)

</div>

<div align="center">

[![release](https://img.shields.io/github/v/release/Base4Security/cyberdeception-playground)](https://github.com/Base4Security/cyberdeception-playground/releases)
[![issues](https://img.shields.io/github/issues/Base4Security/cyberdeception-playground)](https://github.com/Base4Security/cyberdeception-playground/issues)
[![pull requests](https://img.shields.io/github/issues-pr/Base4Security/cyberdeception-playground)](https://github.com/Base4Security/cyberdeception-playground/pulls)

</div>

> ⚠️ **Authorized use only.** This lab contains intentional security vulnerabilities for research and training purposes. Run it exclusively in an isolated environment. Never expose it to the public internet. See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

**Open-source lab for adversary and defender perspectives on cyber deception.** Deploy a fictitious financial environment (Andesfinance) with configurable deception levels, monitoring (Elastic Stack), and built-in attacker simulation—all via Docker Compose.

**Cite this work:** [https://doi.org/10.13140/RG.2.2.21196.68481](https://doi.org/10.13140/RG.2.2.21196.68481)

---

## Description

This project disseminates both adversary and defender perspectives on cyber deception. It deploys a fictitious production environment with monitoring, multiple deception levels, and an attacker container. The environment simulates a financial organization (**Andesfinance**) with intentionally vulnerable web services, SSH honeypots, decoy APIs, fake activity generators, and optional high-fidelity deception (banners, tampered executables).

### Features

- **Configurable deception levels**: None, Basic, Complete, Impossible (progressive honeypots, decoys, and anti-forensics).
- **Full stack**: Node.js frontend/backend, MySQL, custom SSH honeypot, fake activity generator, Elastic Stack (Filebeat, Elasticsearch, Kibana).
- **Attacker container**: Preloaded with recon and attack scripts covering 8 phases: web discovery, command injection, SQL injection, network reconnaissance, port scanning, SSH brute force, lateral movement, and data exfiltration.
- **Observability**: Centralized logs and Kibana dashboards for events, source IPs, and executed commands.
- **Cross-platform**: Docker Compose; startup scripts for Linux (`startup.sh`) and Windows (`startup.bat`).

### License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

### Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and notable changes.

---

## Why this tool?

Most security labs teach attacks or defenses in isolation. **Cyber Deception Playground** puts both sides in the same environment: an attacker container runs a full kill-chain while a defender monitors every step in Kibana — and the environment fights back with increasing layers of deception.

Concrete use cases:
- **Measure deception effectiveness** — compare attacker dwell-time and detection latency across the four levels.
- **Red team training** — practice a realistic 7-phase kill-chain (T1595 → T1190 → T1046 → T1110 → T1021 → T1041) against a live target.
- **Blue team training** — learn to distinguish real attacks from fake activity, triage honeypot alerts, and correlate MITRE ATT&CK techniques in Kibana.
- **Research** — extend the deception taxonomy by adding new levels, honeytokens, or detection rules.

## Objective

Show how an environment looks with:
- ✅ Multiple deployed deception activities
- ✅ Activity monitoring
- ✅ An adversary facing increasing decision-making difficulty

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                            "EXTERNAL" NETWORK                                    │
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        Attacker Container                               │   │
│  │                                                                         │   │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐  │   │
│  │  │  Scripting      │    │   Manual        │    │   Recon Tools       │  │   │
│  │  │  Attacks        │    │   Testing       │    │                     │  │   │
│  │  │                 │    │   (SSH/Web)     │    │   (nmap, etc.)      │  │   │
│  │  │   Port 5000     │    │                 │    │                     │  │   │
│  │  │                 │    │                 │    │                     │  │   │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                DMZ NETWORK                                      │
│                                                                                 │
│                   ┌───────────────────────────────────┐                         │
│                   │             Frontend              │                         │
│                   │                                   │                         │
│                   │          Employee Portal          │                         │
│                   │             Port 3000             │                         │
│                   └─────────────────────┬─────────────┘                         │
│                                         │                                       │
│                                         │ Backend Communication                 │
│                                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                           SERVER NETWORK                                │    │
│  │                                                                         │    │
│  │  ┌───────────────┐    ┌──────────────┐    ┌─────────────────────────┐   │    │
│  │  │    Backend    │    │ SSH Honeypot │    │   Fake Activity         │   │    │
│  │  │               │    │              │    │   Generator             │   │    │
│  │  │ Financial API │    │  Port 22     │◄───│                         │   │    │
│  │  │   Port 3001   │    │              │    │                         │   │    │
│  │  └───────┬───────┘    └──────────────┘    └─────────────────────────┘   │    │
│  │          │                                                              │    │
│  │          │ Database Access                                              │    │
│  │          ▼                                                              │    │
│  │  ┌─────────────────────────────────────────────────────────────────┐    │    │
│  │  │                     DATABASE NETWORK                            │    │    │
│  │  │                                                                 │    │    │
│  │  │  ┌─────────────────────────────────────────────────────────┐    │    │    │
│  │  │  │                    MySQL Database                       │    │    │    │
│  │  │  │                                                         │    │    │    │
│  │  │  │              Financial Database                         │    │    │    │
│  │  │  │                Port 3306                                │    │    │    │
│  │  │  │                                                         │    │    │    │
│  │  │  └─────────────────────────────────────────────────────────┘    │    │    │
│  │  └─────────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                        MONITOR NETWORK                                  │    │
│  │                                                                         │    │
│  │  ┌──────────────┐    ┌──────────────┐    ┌─────────────────────────┐    │    │
│  │  │   Filebeat   │────│Elasticsearch │────│       Kibana            │    │    │
│  │  │ (Log Shipper)│    │  (Storage)   │    │  (Visualization)        │    │    │
│  │  │              │    │  Port 9200   │    │   Port 5601             │    │    │
│  │  └──────────────┘    └──────────────┘    └─────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

- **Frontend**: Andesfinance employee portal (Node.js/Express)
- **Backend**: Andesfinance financial API
- **MySQL**: Financial database with sensitive data
- **SSH Honeypot**: Custom SSH honeypot
- **Fake Activity**: Fake activity generator
- **Elastic Stack**: Filebeat + Elasticsearch + Kibana
- **Docker Compose**: Container orchestration

## Security Architecture

- **Frontend**: Accessible from localhost (port 3000) - controlled entry point
- **Backend**: Only internally accessible - protected from external access
- **MySQL**: Only internally accessible - isolated database
- **SSH Honeypot**: Only accessible internally from server network
- **Elastic Stack**: Accessible from localhost (Port 5601) - monitoring entry point

## Project Structure

```
/cyberdeception-playground/
├── docker-compose.yml          # Service orchestration
├── frontend/                   # Vulnerable web application
│   ├── Dockerfile             # Frontend image
│   ├── package.json           # Node.js dependencies
│   ├── server.js              # Vulnerable web server
│   ├── start-with-monitor.sh  # Startup script with monitoring
│   ├── apk-monitor.sh         # APK package monitor
│   ├── wait-for-backend.js    # Backend wait script
│   ├── wait-for-mysql.js      # MySQL wait script
│   ├── public/                # Static files
│   │   └── index.html         # Main page
│   └── config/                # Configuration files
│       ├── access.txt         # Access control
│       ├── aws-credentials.json # Fake AWS credentials
│       ├── database.conf      # Database configuration
│       ├── environment.env    # Environment variables
│       ├── export-test-customer-data.csv # Test data
│       └── export2-employee-database.xlsx # Employee database
├── backend/                   # Vulnerable backend API
│   ├── Dockerfile             # Backend image
│   ├── package.json           # Node.js dependencies
│   ├── server.js              # Vulnerable API server
│   ├── deception-endpoints.js # Deception endpoints
│   └── wait-for-mysql.js      # MySQL wait script
├── mysql/                     # MySQL database
│   ├── Dockerfile             # MySQL image
│   ├── init.sql               # Basic initialization script
│   ├── init-basic.sql         # Basic level initialization
│   ├── init-complete.sql      # Complete level initialization
│   ├── init-impossible.sql    # Impossible level initialization
│   └── select-init.sh         # Initialization selection script
├── ssh-honeypot/              # SSH Honeypot
│   ├── Dockerfile             # Honeypot image
│   ├── ssh_honeypot.py        # Custom SSH honeypot
│   ├── startup.sh             # Startup script
│   ├── config/
│   │   └── userdb.txt         # Users and passwords
│   └── logs/                  # Honeypot logs
│       ├── ssh_connections.json # Registered SSH connections
│       └── ssh_honeypot.log   # Honeypot log
├── fake-activity/             # Fake activity generator
│   ├── Dockerfile             # Generator image
│   ├── requirements.txt       # Python dependencies
│   └── app.py                 # Generator application
├── attacker/                  # Attacker container
│   ├── Dockerfile             # Image with attack tools
│   ├── requirements.txt       # Python dependencies
│   └── attack_scripts/        # Automated attack scripts
│       ├── main_attacker.py   # Main attack script
│       └── components/        # Attack components
│           ├── base_attacker.py # Base attacker class
│           ├── command_injection.py # Command injection
│           ├── data_exfiltration.py # Data exfiltration
│           ├── port_scanning.py # Port scanning
│           ├── reconnaissance.py # Reconnaissance
│           ├── sql_injection.py # SQL injection
│           ├── ssh_bruteforce.py # SSH brute force
│           └── web_application_discovery.py # Web application discovery
├── filebeat/                  # Log collection agent
│   ├── Dockerfile             # Filebeat image
│   └── filebeat.yml           # Filebeat configuration
├── dashboards/                # Kibana dashboards
│   └── setup-kibana.sh        # Kibana configuration script
├── logs/                      # System logs
│   ├── backend/               # Backend logs
│   ├── frontend/              # Frontend logs
│   └── mysql/                 # MySQL logs
├── scripts/                   # Utility scripts
│   ├── startup.bat            # Startup script (Windows)
│   └── shutdown.bat            # Shutdown script (Windows)
├── LICENSE                    # Project license
├── README.md                  # This file
└── README_ES.md               # Spanish documentation
```

## Installation

### Requirements

- **Docker** (engine and Compose v2)
- **Resources**: At least 4 GB RAM; recommended 8 GB for full stack + Elasticsearch
- **Ports**: 3000 (frontend), 22 (SSH honeypot), 5601 (Kibana), 9200 (Elasticsearch) — backend and MySQL are internal only
- **Disk**: Sufficient space for Docker images and Elasticsearch data

### Supported Platforms

- **Linux**: Use `./scripts/startup.sh <level>` (bash).
- **Windows**: Use `.\scripts\startup.bat <level>` (PowerShell or cmd).

### Supported Languages / Stack

- **Runtime**: Node.js (frontend, backend), Python (SSH honeypot, fake activity, attacker scripts)
- **Databases**: MySQL
- **Containers**: Docker / Docker Compose (all services containerized)

### Steps

```bash
# 1 — Clone
git clone https://github.com/Base4Security/cyberdeception-playground.git
cd cyberdeception-playground

# 2 — Start (choose a deception level; defaults to 'complete')
./quickstart.sh complete      # Linux / macOS
.\scripts\startup.bat complete  # Windows

# 3 — Verify all services are healthy
./scripts/verify.sh
```

`quickstart.sh` waits for Elasticsearch and Kibana to be ready before printing the access URLs — no manual polling needed. Expected startup time: **2–4 minutes** on a machine with 8 GB RAM.

Available deception levels: `none` · `basic` · `complete` · `impossible`

4. **Alternative manual start** (if you prefer step-by-step):

   ```bash
   # Linux / macOS
   ./scripts/startup.sh <level>

   # Windows
   .\scripts\startup.bat <level>
   ```

3. **Verify services**

   ```bash
   docker compose ps
   curl http://localhost:5601   # Kibana
   curl http://localhost:3000   # Frontend
   docker exec attacker-tools whoami
   ```

---

## Usage

### Parameters

The startup script accepts one argument: the **deception level**.

| Parameter   | Description |
|------------|-------------|
| `none`     | Production baseline — vulnerable but undeceived. |
| `basic`    | SSH honeypot + fake credentials + decoy config files. |
| `complete` | Basic + fake activity generator + decoy API endpoints + hidden HTML links + extra DB columns. |
| `impossible` | Complete + modified banners + anti-forensics + tampered executables + full decoy credential/key database. |

For a full description of what each level deploys and what an attacker observes, see the [Deception Levels documentation](https://cyberdeception-playground.readthedocs.io/en/latest/deception-levels.html).

#### Levels vs deployed capabilities

| Capability | None | Basic | Complete | Impossible |
|------------|:----:|:-----:|:--------:|:----------:|
| SSH Honeypot — T1110.001 detection | ❌ | ✅ | ✅ | ✅ |
| Fake credentials in userdb | ❌ | ✅ | ✅ | ✅ |
| Decoy config files (`/config`) | ❌ | ✅ | ✅ | ✅ |
| Fake Activity Generator (T1036 masquerading) | ❌ | ❌ | ✅ | ✅ |
| Decoy API endpoints / honeytokens | ❌ | ❌ | ✅ | ✅ |
| Hidden HTML links (scanner bait) | ❌ | ❌ | ✅ | ✅ |
| Extra DB columns (`password2`, `password_selector`) | ❌ | ❌ | ✅ | ✅ |
| `system_config` / `file_system` / `network_info` / `sensitive_data` tables † | ✅ | ✅ | ✅ | ✅ |
| `exposed_credentials` view, `api_keys`, `ssh_keys` tables † | ❌ | ✅ | ✅ | ✅ |
| Decoy service accounts in `users` table | 11 | 22 | 22 | 32 |
| Modified service banners (T1592 misdirection) | ❌ | ❌ | ❌ | ✅ |
| Anti-forensics indicators (T1070 detection) | ❌ | ❌ | ❌ | ✅ |
| Tampered executables (T1036.005 misdirection) | ❌ | ❌ | ❌ | ✅ |

> † The MySQL seed (`mysql/init*.sql`) currently creates these honeypot tables at the levels shown, regardless of the README's original "Impossible-only" claim — `system_config`, `file_system`, `network_info`, and `sensitive_data` exist even at `none`. Per-level gating is **not** enforced at the DB schema layer; level differentiation comes from the active services and code-gated features above (SSH honeypot, fake-activity, decoy endpoints, hidden links), the `password2`/`password_selector` columns (complete+), and the number of decoy `users` rows.

### Usage examples

**Example 1 — Start with complete deception**

```bash
./scripts/startup.sh complete
# Wait for services; then open http://localhost:3000 and http://localhost:5601
```

**Example 2 — Access the web portal and Kibana**

- **Andesfinance Portal**: `http://localhost:3000` — credentials `admin` / `admin123`
- **Kibana**: `http://localhost:5601` — use "Discover" for events

**Example 3 — Run automated attacks from the attacker container**

```bash
docker exec -it attacker-tools /bin/bash
cd attack_scripts/
python3 main_attacker.py
```

**Example 4 — Manual command-injection test (from attacker container)**

```bash
docker exec -it attacker-tools /bin/bash
curl -X POST http://frontend:3000/diagnostics -H "Content-Type: application/json" \
  -d '{"system_check": "ping", "target_host": "localhost | hostname"}'
```

**Example 5 — Shut down (Windows)**

```batch
.\scripts\shutdown.bat
```

## Attack Simulation

The **attacker** container includes recon and attack tools (e.g. nmap, curl, Python scripts) to simulate intrusions. See [Usage → Usage examples](#usage-examples) for commands. From inside the container you can run `main_attacker.py` for automated attacks or use manual curl/SSH commands against the frontend and SSH honeypot.

## Kibana Visualization

The dashboard includes:

- **Events by Type**: Distribution of event types
- **Real-time Activity**: Activity timeline
- **Source IPs**: Top IPs attempting access
- **Executed Commands**: Most frequent commands
- **Detailed Logs**: Detailed view of all events


# Level Analysis

## Observing Different Levels

### None Level
- No deception **services** (no SSH honeypot, fake-activity generator, decoy API endpoints, or hidden HTML links)
- Note: the MySQL seed still creates baseline decoy tables (`system_config`, `sensitive_data`, `file_system`, `network_info`) — see the † note under the capability table

### Basic Level

✅ SSH Decoy: Captures SSH connection attempts
✅ Fake credentials in users db
✅ Decoy files: Attractive fake documents

### Complete Level

✅ Basic +
✅ Activity generator on decoy: Daily usage pattern traces
✅ Decoy API endpoints: Decoy API endpoint
✅ Database structure changes: Additional columns in DB especially monitored

### Impossible Level

✅ Complete +
✅ Changes in banners and "installed" services
✅ Forced uninstallation of recent installation
✅ Changes in key executables: Specially modified executables

## Advanced Configuration

### Customize Fake Activity

Edit `fake-activity/app.py`:

```python
# Add new users
USERS = ["alice", "bob", "carol", "new_user"]

# Add new commands
COMMANDS = [
    "ls -la",
    "cat /etc/passwd", 
    "new_interesting_command"
]
```

### Configure More Honeypots

Add to `docker-compose.yml`:

```yaml
services:
  ssh-honeypot-2:
    build: ./ssh-honeypot
    ports:
      - "2224:22"
    # ... rest of configuration
```

### Integrate with External SIEM

Modify `filebeat/filebeat.yml`:

```yaml
output.elasticsearch:
  hosts: ["external-siem:9200"]
  # ... additional configuration
```

## Troubleshooting

### Debug Logs

```bash
# View logs from all services
docker-compose logs -f

# View logs from a specific service
docker-compose logs -f ssh-honeypot
docker-compose logs -f fake-activity
docker-compose logs -f filebeat
```

## Additional Resources

- [A Practical Guide to Adversary Engagement](https://engage.mitre.org/learn-more-practical-guide)
- [Honeypot Best Practices](https://www.sans.org/white-papers/36607/)
- [Design of cyber deception strategies from cyber threat intelligence](https://www.researchgate.net/publication/394808490_Diseno_de_estrategias_de_ciberengano_a_partir_de_inteligencia_de_ciberamenazas)

## Contributions

Contributions are welcome!

1. Fork the project
2. Create a branch for your feature
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

This project is under the MIT License. See [LICENSE](LICENSE) for more details.

## Repository and documentation

- **Source**: [https://github.com/Base4Security/cyberdeception-playground](https://github.com/Base4Security/cyberdeception-playground)
- **Read the Docs**: The ``docs/`` folder contains Sphinx source (RST). To build on Read the Docs, import the repository at [readthedocs.org](https://readthedocs.org/); the root ``.readthedocs.yaml`` and ``docs/conf.py`` are already configured.

## Disclaimer

This tool is for authorized security research and education only. Use only in isolated lab environments. The authors are not responsible for misuse or damage.

---
