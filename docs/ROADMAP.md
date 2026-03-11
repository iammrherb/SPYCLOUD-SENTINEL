# SpyCloud Sentinel -- Roadmap

## v8.0.0 (Current Release)

The v8.0 release represents the most comprehensive SpyCloud Sentinel deployment to date, delivering full-spectrum dark web threat intelligence with autonomous investigation capabilities across the entire Microsoft security ecosystem.

### Data Pipeline
- 6 SpyCloud APIs integrated (Enterprise, Catalog, Compass, SIP, Identity Exposure, Investigations)
- 9 independent REST API pollers via Codeless Connector Framework (CCF)
- 10 custom Log Analytics tables with KQL transform ingestion
- Data Collection Endpoint (DCE) and Data Collection Rule (DCR) architecture

### Detection & Hunting
- 49 analytics rules (38 scheduled, 1 Fusion, 5 NRT, 5 MSIC) -- all enabled by default
- 28 proactive threat hunting queries across 12 categories
- UEBA behavioral analytics correlation with credential exposure
- Fusion ML multistage attack detection integration

### Response & Automation
- 10 Logic App playbooks (identity, device, network, notification, enrichment, orchestration)
- 4 automation rules (auto-trigger, auto-escalate, auto-task, auto-close)
- 3-phase full remediation orchestration chaining all playbooks

### Visualization & Analysis
- 3 workbooks (Executive Dashboard, SOC Operations, Threat Intelligence)
- 3 Jupyter notebooks (Incident Triage, Threat Hunting, Threat Landscape Analysis)
- 4 watchlists (VIP/Executive, IOC Blocklist, Approved Domains, High-Value Assets)

### Security Copilot Integration
- 3 integrated plugins:
  - **KQL Plugin**: 90 promptbook skills across 29 categories
  - **API Plugin**: 20 direct REST API skills across 6 SpyCloud APIs
  - **Investigation Agent**: 17 specialized sub-agents + 6 GPT-4o analysis skills + 35 internal KQL skills = 58 total agent capabilities
- SENTINEL persona with autonomous investigation orchestration
- Cross-platform correlation: Sentinel, Defender XDR, Intune, Entra ID, CASB

### Deployment & Infrastructure
- GitHub Actions CI/CD pipeline for automated deployment
- Terraform modules for infrastructure-as-code provisioning
- ARM template with Azure Portal wizard deployment
- Post-deployment automation script (auto-RBAC, admin consent, connector setup, health verification)

---

## v8.1 (Planned)

- [ ] Additional IdP correlations (CyberArk, OneLogin) for SSO credential exposure tracking
- [ ] ServiceNow ticketing playbook -- auto-create incidents from SpyCloud alerts
- [ ] Jira ticketing playbook -- auto-create issues with SpyCloud context and evidence
- [ ] Power BI integration for embedded executive dashboards and scheduled reporting
- [ ] Additional Security Copilot skills for new detection scenarios
- [ ] EU API region support for SpyCloud data residency compliance
- [ ] Enhanced SOAR runbooks for guided incident response workflows
- [ ] Adaptive Card interactive response buttons in Microsoft Teams

---

## v9.0 (Future)

- [ ] Real-time streaming ingestion via Azure Event Hubs for sub-minute data freshness
- [ ] Custom ML models for credential risk scoring via Azure Machine Learning
- [ ] Multi-tenant support for MSSP deployments with cross-tenant federation
- [ ] Predictive breach impact analysis using historical exposure patterns
- [ ] Automated compliance reporting (SOC 2, PCI DSS, HIPAA) with scheduled generation
- [ ] PagerDuty and Opsgenie integration for on-call alerting
- [ ] Additional firewall vendors (Cisco Meraki, SonicWall, WatchGuard)
- [ ] MCP integrations (Atlassian, Gmail, Slack direct connectors)
- [ ] Custom VIP/executive watchlist with elevated alerting and board-level reporting
