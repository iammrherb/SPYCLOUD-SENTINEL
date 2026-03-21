# Automation Rule Templates

ARM templates for Microsoft Sentinel automation rules.

These rules automatically trigger playbooks based on incident properties.

| Template | Trigger | Action |
|----------|---------|--------|
| `auto-enrich-template.json` | New incident | Run SpyCloud enrichment playbook |
| `auto-investigate-template.json` | High severity incident | Run investigation playbook |
| `auto-remediate-template.json` | Confirmed compromise | Run remediation playbook |
| `auto-triage-template.json` | New alert | Run initial triage playbook |
