#!/usr/bin/env bash
# Verify that the Cyber Deception Playground stack is healthy.
# Exit code 0 = all checks passed, 1 = one or more failures.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local label="$1"
    shift
    if "$@" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $label"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $label"
        FAIL=$((FAIL + 1))
    fi
}

check_container() {
    local name="$1"
    docker ps --format '{{.Names}}' | grep -q "^${name}$"
}

check_http() {
    local url="$1"
    curl -sf --max-time 5 "$url" >/dev/null
}

check_es_index() {
    curl -sf --max-time 5 "http://localhost:9200/_cat/indices?h=index" 2>/dev/null | grep -q "playground-logs"
}

check_attacker_dns() {
    docker exec attacker-tools ping -c1 -W2 frontend >/dev/null 2>&1
}

echo -e "\n${YELLOW}[Cyber Deception Playground — Health Check]${NC}"
echo "──────────────────────────────────────────"

echo "Containers:"
check "frontend"               check_container "prod-frontend"
check "backend"                check_container "prod-backend"
check "mysql"                  check_container "prod-mysql"
check "elasticsearch"          check_container "monitoring-elasticsearch"
check "kibana"                 check_container "monitoring-kibana"
check "filebeat"               check_container "monitoring-filebeat"
check "attacker-tools"         check_container "attacker-tools"

echo "HTTP Endpoints:"
check "Frontend (localhost:3000)"            check_http "http://localhost:3000"
check "Kibana status (localhost:5601)"       check_http "http://localhost:5601/api/status"
check "Elasticsearch (localhost:9200)"       check_http "http://localhost:9200"

echo "Elasticsearch:"
check "Cluster health (green/yellow)"  bash -c 'curl -sf --max-time 5 "http://localhost:9200/_cluster/health" | grep -qE "\"status\":\"(green|yellow)\""'
check "playground-logs-* index exists"  check_es_index

echo "Network:"
check "Attacker can resolve 'frontend'" check_attacker_dns

echo "──────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${PASS}/${TOTAL} checks passed ✅${NC}\n"
    exit 0
else
    echo -e "${RED}${FAIL}/${TOTAL} checks FAILED ❌${NC}"
    echo -e "Run ${YELLOW}docker compose logs <service>${NC} to investigate.\n"
    exit 1
fi
