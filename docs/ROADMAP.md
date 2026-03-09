# SpyCloud Sentinel Supreme — Comprehensive Enhancement Roadmap

## Phase 1: Core Pipeline & Cross-Connector (v8.0) ✅ THIS PR

### New Data Sources
- **Compass Data** poller + `SpyCloudCompassData_CL` table (29 cols)
- **Compass Devices** poller + `SpyCloudCompassDevices_CL` table (8 cols)

### New Analytics Rules (10 additional → 38 total)
- SpyCloud × Office 365: Compromised user email forwarding/delegation
- SpyCloud × Email Events: Exposed credentials in email phishing chains
- SpyCloud × Identity Logon: Compromised user lateral movement
- SpyCloud × Threat Intelligence: SpyCloud IOCs matching external TI feeds
- SpyCloud × Behavior Analytics: UEBA anomalies for exposed users
- SpyCloud × Azure Activity: Compromised user cloud resource access
- SpyCloud × Compass: Consumer identity cross-reference with corporate
- SpyCloud × Firewall: Infected IP in CommonSecurityLog (CEF/Syslog)
- SpyCloud × Impossible Travel: Exposed credential used from distant locations
- SpyCloud × Compass Devices: Infected device reappearance in Compass

### Enhanced Connector UI
- Full cross-connector integration guide
- Recommended additional connectors table
- Enhanced verification queries for all 6 tables

### Enhanced Copilot (Plugin + Agent)
- Compass investigation skills
- Cross-connector correlation skills
- Proactive threat hunting prompts
- Risk scoring and prioritization

## Phase 2: Advanced Automation (v8.5) — PLANNED
- Jupyter investigation notebooks
- SOAR runbooks for guided response
- Adaptive Card interactive notifications
- PagerDuty/Opsgenie integration
- Auto-enable high-confidence rules on deploy

## Phase 3: Intelligence Platform (v9.0) — FUTURE
- ML-based credential risk scoring (Azure ML / OpenAI)
- Predictive breach impact analysis
- Automated threat intelligence report generation
- Cross-tenant federation for MSSPs
- Azure DevOps pipeline for rule CI/CD testing
- MCP integrations (Atlassian, Gmail, Slack direct)
- EU API region support
- Custom VIP/executive watchlist with elevated alerting
