# SpyCloud Sentinel Supreme

![SpyCloud](https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-200.png)

**The most comprehensive darknet identity threat intelligence integration for Microsoft Sentinel.**

[![Version](https://img.shields.io/badge/version-13.1-blue.svg)](#) [![Resources](https://img.shields.io/badge/ARM_resources-144-orange.svg)](#) [![Rules](https://img.shields.io/badge/analytics_rules-38-red.svg)](#) [![Playbooks](https://img.shields.io/badge/playbooks-13-purple.svg)](#)

---

## What Is This?

When an employee's device gets infected with infostealer malware, the attacker captures everything — passwords, session cookies, browser autofill, VPN credentials, SSO tokens. SpyCloud recaptures that stolen data from the criminal underground **hours after exposure**. This Sentinel integration transforms that intelligence into automated detection, investigation, and response.

### What Gets Deployed (144 ARM Resources)

| Category | Count | What |
|----------|-------|------|
| Custom Tables | 15 | All SpyCloud data streams + audit logs |
| Content Templates | 57 | 38 analytics rules + 16 hunting queries + 1 workbook + 2 connector |
| Playbooks | 13 | 5 response + 8 enrichment Logic Apps |
| Function App | 7 | Enrichment backend + Key Vault + risk score engine |
| Workbooks | 4 | SOC ops, executive, Defender response, threat intel |
| Hunting Queries | 16 | Proactive threat hunting |
| Automation Rules | 4 | Auto-trigger playbooks on incidents |
| Watchlists | 4 | VIP users, exclusions, severity mapping |
| Copilot Plugin | 1 | 28+ KQL skills + AI agent + 5 promptbooks |
| MCP Server | 1 | Model Context Protocol for AI-native integration |

---

## Architecture

```
CRIMINAL UNDERGROUND                    SpyCloud Recaptures
  Infostealer Malware ──> Stolen Data ──────────────────────┐
  (RedLine, Vidar,                                          │
   Raccoon, LummaC2)                                        ▼
                                               SpyCloud API
                                          (api.spycloud.io)
                                                    │
                              ┌──────────────────────┼───────────────────┐
                              │                      │                   │
                              ▼                      ▼                   ▼
                     CCF Pollers (13)       Function App (17)    Logic Apps (13)
                     Bulk data ingest       API endpoints       Incident-triggered
                     on schedule            + Risk Score        enrichment/response
                              │             + Key Vault                  │
                              │                      │                   │
                              ▼                      ▼                   ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │              Microsoft Sentinel Workspace                 │
                    │                                                          │
                    │  15 Tables ──> 38 Rules ──> Incidents ──> Playbooks     │
                    │                    │                           │         │
                    │              4 Workbooks              MDE Isolate       │
                    │             16 Hunting Queries        CA Password Reset │
                    │              3 Notebooks              Notifications     │
                    │             Copilot Plugin            Risk Score → CA   │
                    └──────────────────────────────────────────────────────────┘
```

### Identity Risk Score — Closed Loop

```
EXPOSURE ──> SCORE (0-100) ──> ENTRA CA POLICY ──> AUTO-RESPONSE ──> SCORE REDUCES
                                                                          │
   SpyCloud     Severity 0-30        Score > 80:         Password reset   │
   detects      Credential 0-25     block access         = -10 points ◄───┘
   stolen       Session 0-25        Score 61-80:         Session revoke
   creds        Device 0-10         hardware MFA         = -5 points
                Temporal 0.2-1.0x   Score 41-60:
                Remediation -20     hourly re-auth
```

| Score | Tier | Automated Response |
|-------|------|-------------------|
| 0-20 | 🟢 LOW | Monitor |
| 21-40 | 🟡 MODERATE | Schedule password reset |
| 41-60 | 🟠 HIGH | Force reset + revoke sessions |
| 61-80 | 🔴 CRITICAL | Immediate reset + isolate device |
| 81-100 | 🟣 EMERGENCY | Disable account + IR team engaged |

---

## Quick Start

### 1. Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

### 2. Connect

Sentinel → Data Connectors → SpyCloud → Enter API key → Connect

### 3. Enable Rules

Sentinel → Analytics → Rule Templates → Filter "SpyCloud" → Enable

### 4. Verify

```kql
SpyCloudBreachWatchlist_CL | take 10
```

---

## Prerequisites

| Required | Details |
|----------|---------|
| **SpyCloud Enterprise API Key** | [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys |
| **Azure Subscription** | With Microsoft Sentinel enabled |
| **Permissions** | Sentinel Contributor + Log Analytics Contributor |
| **Network** | Outbound HTTPS to api.spycloud.io (port 443) |

| Recommended | Enables |
|-------------|---------|
| MDE P2 | Device isolation playbooks |
| Entra ID P1+ | CA password reset playbooks |
| Compass License | Post-infection device forensics |
| SIP License | Stolen cookie MFA bypass detection |

---

## API Key Flow (Enter Once, Works Everywhere)

```
DEPLOYMENT WIZARD          CONNECTOR PAGE (after deploy)
┌──────────────────┐       ┌──────────────────────────┐
│ Enterprise Key   │──KV──>│ Enterprise Key (required) │
│ (1 field only)   │       │ Compass Key (optional)    │
└──────────────────┘       │ SIP Key (optional)        │
                           │ Investigations (optional)  │
                           │ IdLink (optional)          │
                           │ Exposure (optional)        │
                           │ CAP (optional)             │
                           │ Data Partnership (opt)     │
                           │                            │
                           │ Persistent & updatable     │
                           │ without redeploying        │
                           └──────────────────────────┘
```

---

## SpyCloud Products

| Product | What It Detects | Table | License |
|---------|----------------|-------|---------|
| **Enterprise Watchlist** | Stolen credentials + PII + device forensics | BreachWatchlist_CL | Enterprise |
| **Breach Catalog** | Breach source metadata (malware family, confidence) | BreachCatalog_CL | Enterprise |
| **Compass Data** | Application-level stolen credentials | CompassData_CL | Compass |
| **Compass Devices** | Infected device fingerprints (OS, AV, malware) | CompassDevices_CL | Compass |
| **SIP Cookies** | Stolen session cookies (MFA bypass) | SipCookies_CL | SIP |
| **Investigations** | Full database for threat hunting | Investigations_CL | Investigations |
| **IdLink** | Identity correlation across personas | IdLink_CL | IdLink |

---

## Analytics Rules (38 Templates)

| Category | Rules | Key Detections |
|----------|-------|---------------|
| **Core Credential** | 8 | Infostealer, plaintext, PII, cookies, re-infection, reuse |
| **IdP Correlation** | 8 | Okta, Duo, Ping, Entra sign-in + exposed credential |
| **Cross-Platform** | 8 | UEBA anomaly, firewall, DNS C2, VPN, impossible travel |
| **O365/Entra** | 6 | Mailbox rules, OAuth consent, admin role, eDiscovery |
| **Operations** | 4 | Remediation gap, data health, SLA breach, risk score |
| **Advanced** | 4 | Executive/VIP, password reuse, breach enrichment |

---

## Playbooks (13 Logic Apps)

| Playbook | Trigger | Action | Requires |
|----------|---------|--------|----------|
| MDE Device Isolation | Incident (sev 20+) | Isolate device in Defender | MDE P2 |
| CA Password Reset | Incident (credential) | Force password change | Entra P1+ |
| Credential Response | Incident (any) | Teams/Slack/email notification | Webhook URL |
| MDE Blocklist | Scheduled | Submit IOCs to Defender | MDE P2 |
| TI Enrichment | Incident | VirusTotal/AbuseIPDB lookup | VT API key |
| Email Enrichment | Incident + Account | SpyCloud email lookup | Enterprise key |
| Domain Enrichment | Incident + DNS | SpyCloud domain lookup | Enterprise key |
| IP Enrichment | Incident + IP | SpyCloud IP lookup | Enterprise key |
| Username Enrichment | Incident + Account | SpyCloud username lookup | Enterprise key |
| Catalog Enrichment | Incident | Breach source context | Enterprise key |
| Compass Enrichment | Incident + Account | Device forensics | Compass key |
| SIP Cookie Enrichment | Incident + Account | Stolen cookie assessment | SIP key |
| Investigation Enrichment | Incident + Account | Full database deep dive | Investigations key |

---

## Workbooks (4 Dashboards)

| Workbook | Audience | Key Panels |
|----------|----------|-----------|
| **SOC Operations** | Analysts | Exposure tiles, severity trends, top users/devices, remediation tracker |
| **Executive Dashboard** | CISO/Management | Risk score trend, exposure posture, remediation KPIs, compliance |
| **Defender/CA Response** | IR Team | MDE isolation audit, CA action log, device timeline |
| **Threat Intel** | Threat Hunters | Malware families, breach sources, geographic distribution |

---

## Cost Optimization

| Strategy | How | Savings |
|---------|-----|---------|
| Severity filter ≥ 20 | Skip low-severity breach credentials | 50-70% less data |
| Analytics plan tables | Cheaper than Log Analytics plan | 50% per GB |
| 60-min polling | Instead of 30-min default | 50% fewer API calls |
| Conditional pollers | Only enable products you're licensed for | No waste |
| Function App Consumption | First 1M executions free | $0 for most orgs |

| Environment | Daily Ingestion | Est. Monthly Cost |
|-------------|----------------|-------------------|
| Small (<1K users) | 1-10 MB | ~$5-15 |
| Medium (1K-10K) | 10-100 MB | ~$15-75 |
| Large (10K-100K) | 100-500 MB | ~$75-400 |

---

## Cross-Ecosystem Integrations

SpyCloud data correlates with 100+ security products:

| Category | Vendors | Rules/Playbooks |
|----------|---------|----------------|
| **Microsoft Defender** | MDE, MDCA, MDI, Entra, Intune, M365 | 36 correlation rules |
| **Identity Providers** | Okta, Duo, Ping, Google Workspace | 10 correlation rules |
| **Firewalls/VPN** | Palo Alto, Fortinet, Cisco, Zscaler | 16 network rules |
| **EDR/XDR** | CrowdStrike, SentinelOne, Carbon Black, Cortex | 8 rules |
| **ITSM** | ServiceNow, Jira, Azure DevOps | 3 playbooks |
| **Threat Intel** | VirusTotal, AbuseIPDB, GreyNoise, MISP | 3 enrichment playbooks |
| **Other SIEMs** | Splunk, Rapid7, Chronicle, XSOAR | Event Hub forwarding |

See [docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) for the complete integration map.

---

## Marketplace & ISV Readiness

See [docs/ISV-MARKETPLACE-STRATEGY-v12.10.md](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) for the complete publishing guide.

### Publishing Process
1. Submit PR to `Azure/Azure-Sentinel` GitHub repository
2. Microsoft reviews and approves (~2-4 weeks)
3. Create Azure Application offer in Partner Center
4. Certification and go-live

### Update Process
1. Bump `_solutionVersion` in ARM template
2. Submit updated PR
3. Customers see "Update available" in Content Hub
4. One-click update — data and connections preserved

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Technical architecture details |
| [Product Catalog](docs/PRODUCT-CATALOG-v12.md) | All SpyCloud products with use cases |
| [Enrichment Architecture](docs/ENRICHMENT-ARCHITECTURE-v12.md) | Enrichment design and workflows |
| [Cross-Ecosystem Map](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) | 100+ vendor integrations |
| [ISV Strategy](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) | Marketplace publishing guide |
| [Production Readiness](docs/PRODUCTION-READINESS-v12.10.md) | Deployment checklist |
| [Security Copilot](docs/SECURITY-COPILOT-SPEC.md) | Copilot plugin specification |
| [Agents & Plugins](docs/AGENTS-AND-PLUGINS-GUIDE.md) | AI agent configuration |
| [Permissions](docs/PERMISSIONS-AND-PLAYBOOKS.md) | Required roles and permissions |
| [API Setup](docs/API-SETUP-GUIDE.md) | SpyCloud API configuration |
| [Roadmap](docs/ROADMAP.md) | Feature roadmap |

---

## Troubleshooting

| Issue | Likely Cause | Fix |
|-------|-------------|-----|
| No data after connecting | API key invalid or network blocked | Verify key at portal.spycloud.com, check outbound HTTPS |
| Rules don't appear in Analytics | Content Package dependencies | Update to v12.10+ (56 deps declared) |
| Workbook shows no data | Tables not populated yet | Wait 15-30 min after first connect |
| MDE playbook fails | Missing MDE P2 license | Playbook deploys but requires P2 to function |
| Connector page type error | Old version with enable Dropdowns | Update to v12.5+ (Dropdowns removed) |
| "SpyCloudCCF not found" | Wrong connector definition name | Update to v12.7+ (fixed to SpyCloudIdentityIntelligence) |

---

## Support

| Channel | Contact |
|---------|---------|
| SpyCloud Support | [support@spycloud.com](mailto:support@spycloud.com) |
| Integration Help | [integrations@spycloud.com](mailto:integrations@spycloud.com) |
| SpyCloud Portal | [portal.spycloud.com](https://portal.spycloud.com) |
| GitHub Issues | [github.com/iammrherb/SPYCLOUD-SENTINEL/issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues) |

---

**Built with ❤️ by SpyCloud for the Microsoft Sentinel community.**
