#!/usr/bin/env bash
# Cyber Deception Playground — one-command quickstart
# Usage: ./quickstart.sh [none|basic|complete|impossible]
# Default deception level: complete

set -euo pipefail

DECEPTION_LEVEL="${1:-${DECEPTION_LEVEL:-complete}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Prerequisites ──────────────────────────────────────────────────────────────
check_prereqs() {
    local missing=0
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}✗ docker not found. Install Docker Desktop: https://docs.docker.com/get-docker/${NC}"
        missing=1
    fi
    if ! (docker compose version &>/dev/null || docker-compose version &>/dev/null); then
        echo -e "${RED}✗ docker compose not found. Upgrade Docker Desktop or install the compose plugin.${NC}"
        missing=1
    fi
    [[ $missing -eq 0 ]] || exit 1
}

# ── Wait helpers ───────────────────────────────────────────────────────────────
wait_for_url() {
    local url="$1" label="$2" timeout="${3:-120}"
    local elapsed=0
    printf "${YELLOW}  Waiting for %-30s${NC}" "$label..."
    until curl -sf "$url" &>/dev/null; do
        sleep 3; elapsed=$((elapsed + 3))
        if [[ $elapsed -ge $timeout ]]; then
            echo -e " ${RED}TIMEOUT${NC}"
            return 1
        fi
        printf "."
    done
    echo -e " ${GREEN}ready${NC}"
}

# ── Main ───────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       Cyber Deception Playground                 ║${NC}"
echo -e "${BOLD}${CYAN}║       Deception level: ${DECEPTION_LEVEL}$(printf '%*s' $((24 - ${#DECEPTION_LEVEL})) '')║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}\n"

check_prereqs

echo -e "${CYAN}[1/3] Starting lab (deception level: ${DECEPTION_LEVEL})...${NC}"
# Pass DECEPTION_LEVEL as env var; startup.sh reads it
DECEPTION_LEVEL="$DECEPTION_LEVEL" bash "$SCRIPT_DIR/scripts/startup.sh" "$DECEPTION_LEVEL" --non-interactive 2>&1 | grep -v "^$" || true

echo -e "\n${CYAN}[2/3] Waiting for services to be ready...${NC}"
wait_for_url "http://localhost:3000"        "Frontend (Andesfinance)"   120
wait_for_url "http://localhost:9200"        "Elasticsearch"              180
wait_for_url "http://localhost:5601/api/status" "Kibana"                 240

echo -e "\n${CYAN}[3/3] Running health checks...${NC}"
if [[ -f "$SCRIPT_DIR/scripts/verify.sh" ]]; then
    bash "$SCRIPT_DIR/scripts/verify.sh" || true
fi

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  ✅  Lab is ready!                               ║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║  Frontend   →  http://localhost:3000             ║${NC}"
echo -e "${BOLD}${GREEN}║  Kibana     →  http://localhost:5601             ║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║  Run the attack simulation:                      ║${NC}"
echo -e "${BOLD}${GREEN}║  docker exec -it attacker-tools bash             ║${NC}"
echo -e "${BOLD}${GREEN}║  cd attack_scripts && python3 main_attacker.py   ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
