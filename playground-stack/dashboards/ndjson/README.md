# Kibana Dashboard Exports

Place Kibana saved-objects exports (`.ndjson` files) in this directory.

`setup-kibana.sh` will automatically import all `.ndjson` files found here via
`POST /api/saved_objects/_import?overwrite=true` when the stack starts.

## Exporting dashboards from a running Kibana

```bash
# Export all saved objects (dashboards, visualizations, data views)
curl -s "http://localhost:5601/api/saved_objects/_export" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{"type": ["dashboard","visualization","lens","index-pattern"], "includeReferencesDeep": true}' \
  -o dashboards/ndjson/playground-dashboards.ndjson
```

## Recommended dashboards to create

| Dashboard | Key fields | Purpose |
|-----------|-----------|---------|
| Attack Overview | `mitre.technique_id`, `security.attack_type` | Kill-chain timeline |
| Top Source IPs | `source.ip`, `security.risk_score` | Attacker identification |
| SSH Brute Force | `service_name: ssh_honeypot`, `username` | Credential attacks |
| Command & SQL Injection | `security.attack_type`, `message` | Exploitation attempts |
| Deception Triggers | `security.deception_triggered` | Honeytoken/honeypot hits |
