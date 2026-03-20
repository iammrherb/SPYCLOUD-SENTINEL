# SpyCloud Sentinel — Roadmap

## v13.0.0 (Current Release — SCORCH)

The v13.0 release introduces **SCORCH** (SpyCloud Compromised Operations Research & Credential Hunter) — a grumpy, sarcastic, brilliantly overworked SOC analyst personality powering the most comprehensive identity threat intelligence agent in the Security Copilot ecosystem. Massively expanded API coverage, Logic App remediation actions callable from Copilot, and MCP server architecture.

### SCORCH Agent Enhancements
- **SCORCH persona**: Grumpy, sarcastic, comedic overworked SOC analyst personality
- Personality calibration by audience (SOC → full snark, CISO → professional wit, compliance → formal)
- MITRE ATT&CK mapping for all SpyCloud data types (10+ techniques)
- Exhaustive research capabilities for malware families, threat actors, campaigns
- 150+ categorized prompt library across 12 investigation types
- Executive brief and compliance evidence generation GPT skills
- Cross-ecosystem correlation guide with 6 priority patterns
- Password risk model with time-to-crack and sarcastic assessments

### Full API Suite Plugin (NEW)
- **54 API endpoints** across all 8 SpyCloud products (up from 9 — 500% increase)
- Enterprise ATO: email, domain, IP, username, password, watchlist CRUD, catalog
- Compass: devices, applications, records (list + detail)
- SIP: stolen cookies by domain, SIP breach catalog
- CAP: email, username, IP, phone, zero-knowledge check
- Investigations: 15 lookup types (email, domain, IP, phone, username, log ID, machine ID, social handle, credit card, email username, SSN, bank number, drivers license, national ID, passport)
- IdLink: identity graph by email, phone, username
- Exposure Metrics: per-email and per-domain aggregate stats
- NIST Password Check: SHA256 hash verification against breach corpus
- Compromised Credit Cards: BIN lookup, card list
- Data Partnership: email, domain, SSN, phone lookups

### Logic App Plugin (NEW)
- 8 Logic App skills invokable from Security Copilot conversations
- Enrichment: email, domain, IP, catalog context → writes to Sentinel incident
- Response: MDE device isolation, CA password reset + session revocation
- Notification: Teams/Slack SOC channel alert
- Investigation: full multi-API investigation playbook
- Automated incident triage pattern (Sentinel → Logic App → Copilot → remediate)

### MCP Server Architecture (NEW — Design)
- 20 MCP tools covering all SpyCloud APIs + Sentinel KQL + remediation
- 5 MCP resources (severity model, password risk, MITRE mapping, catalog, watchlist)
- 6 MCP prompts (investigate-user, device, org-overview, hunt, compliance, executive)
- Multi-client: Security Copilot, Claude, VS Code, Copilot Studio
- Azure App Service hosting with managed identity + Key Vault

### Previous Capabilities (Carried Forward)
- 6 SpyCloud APIs integrated (Enterprise, Catalog, Compass, SIP, Identity Exposure, Investigations)
- 9 independent REST API pollers via Codeless Connector Framework (CCF)
- 14 custom Log Analytics tables
- 38 analytics rules + 28 hunting queries
- 10 Logic App playbooks + 4 automation rules
- 3 workbooks + 3 Jupyter notebooks + 4 watchlists
- 90 KQL plugin skills + 26 agent sub-agents
- GitHub Actions CI/CD + ARM template + post-deploy automation

---

## v13.1 (Planned)

- [ ] MCP server implementation (Node.js on Azure App Service)
- [ ] Logic App ARM templates for all 8 enrichment + remediation playbooks
- [ ] Additional IdP correlations (CyberArk, OneLogin)
- [ ] ServiceNow ticketing playbook
- [ ] Jira ticketing playbook
- [ ] EU API region support
- [ ] NHI (Non-Human Identity) detection skills for exposed API keys/tokens
- [ ] Promptbook templates for common SCORCH workflows

---

## v14.0 (Future)

- [ ] Security Store publication (Microsoft partner marketplace)
- [ ] A2A agent orchestration for multi-step remediation
- [ ] Real-time streaming ingestion via Azure Event Hubs
- [ ] Custom ML models for credential risk scoring
- [ ] Multi-tenant MSSP support
- [ ] Predictive breach impact analysis
- [ ] PagerDuty / Opsgenie integration
- [ ] Power BI embedded executive dashboards
