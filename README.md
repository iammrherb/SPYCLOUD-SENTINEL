<div align="center">

![SpyCloud](https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-white.png)

# SENTINEL SUPREME

### The Most Powerful Darknet Identity Threat Intelligence Platform for Microsoft Sentinel

[![Version](https://img.shields.io/badge/version-13.12.0-00D4AA?style=for-the-badge)](#) [![ARM Resources](https://img.shields.io/badge/ARM_Resources-144-0097A7?style=for-the-badge)](#) [![Analytics Rules](https://img.shields.io/badge/Analytics_Rules-38+-E91E63?style=for-the-badge)](#) [![Playbooks](https://img.shields.io/badge/Playbooks-32-9C27B0?style=for-the-badge)](#) [![AI Skills](https://img.shields.io/badge/Copilot_Skills-28+-FF9800?style=for-the-badge)](#)

**173 files** · **144 ARM resources** · **57 content templates** · **32 playbooks** · **4 workbooks** · **13 workbook templates** · **3 notebooks** · **16 scripts** · **5 promptbooks** · **MCP server** · **Terraform module** · **13 test data sets**

---

*When infostealers strike, SpyCloud knows what was stolen — and Sentinel Supreme makes sure you act on it before the attackers do.*

</div>

---

## 🔥 Why SpyCloud Sentinel Supreme?

Every 39 seconds, an infostealer malware infection steals an employee's credentials, session cookies, browser autofill, VPN tokens, and SSO sessions. Traditional EDR might catch the malware. **SpyCloud tells you exactly what was stolen and from whom** — hours after exposure, straight from the criminal underground.

**No other Sentinel integration offers this:**

| What Others Do | What SpyCloud Supreme Does |
|:---:|:---:|
| Alert on suspicious sign-ins | Know **which credentials are stolen** before they're used |
| Detect anomalies after the fact | **Quantify identity risk** with a 0-100 composite score |
| Require manual investigation | **Auto-remediate** — isolate devices, reset passwords, revoke sessions |
| Provide generic threat intel | Deliver **device-specific forensics** — exactly which apps, cookies, and tokens were stolen |
| Offer basic playbooks | Deploy **32 playbooks** with autonomous AI agent investigation |
| Static dashboards | **4 workbooks + 13 templates** for SOC, executives, IR, and threat intel |
| Simple API lookups | **17-endpoint Function App** with centralized Key Vault and risk scoring |
| No AI integration | **SCORCH Agent** — autonomous Security Copilot AI that investigates, scores, and recommends |

---

## 🏗️ Architecture

### Data Flow — From Criminal Underground to Automated Response

```
                          ╔══════════════════════════════╗
                          ║    CRIMINAL UNDERGROUND       ║
                          ║                              ║
                          ║  Infostealer Malware →       ║
                          ║  Stolen Creds + Cookies →    ║
                          ║  Dark Web Markets             ║
                          ╚══════════════╤═══════════════╝
                                         │
                              SpyCloud Recaptures
                              (hours, not weeks)
                                         │
                                         ▼
                          ╔══════════════════════════════╗
                          ║      SpyCloud API             ║
                          ║   api.spycloud.io             ║
                          ║                              ║
                          ║  11 API Endpoints:            ║
                          ║  Enterprise · Compass · SIP   ║
                          ║  Investigations · IdLink      ║
                          ║  Exposure · CAP · Partnership ║
                          ╚══╤════════════╤═══════════╤══╝
                             │            │           │
                ┌────────────┘            │           └────────────┐
                │                         │                        │
                ▼                         ▼                        ▼
    ╔═══════════════════╗   ╔══════════════════════╗   ╔════════════════════╗
    ║  CCF POLLERS (13)  ║   ║  FUNCTION APP (17)    ║   ║  LOGIC APPS (32)    ║
    ║                   ║   ║                      ║   ║                    ║
    ║ Bulk scheduled    ║   ║ • Risk Score Engine  ║   ║ Response:          ║
    ║ data ingestion    ║   ║ • 7 Enrichment APIs  ║   ║ • MDE Isolate      ║
    ║ across 15 tables  ║   ║ • Investigation Orch ║   ║ • CA Password Reset║
    ║                   ║   ║ • Reporting APIs     ║   ║ • Session Revoke   ║
    ║ Watchlist (New)   ║   ║ • Health & Audit     ║   ║ • Notify SOC       ║
    ║ Watchlist (Mod)   ║   ║                      ║   ║ • Block/Enforce    ║
    ║ Breach Catalog    ║   ║ Key Vault Integration║   ║                    ║
    ║ Compass ×3        ║   ║ Rate Limiting        ║   ║ Enrichment:        ║
    ║ SIP Cookies       ║   ║ Circuit Breaker      ║   ║ • Email/Domain/IP  ║
    ║ + 6 more          ║   ║ Audit Logging        ║   ║ • Compass/SIP      ║
    ╚════════╤══════════╝   ╚══════════╤═══════════╝   ║ • Catalog/Invest   ║
             │                         │               ║                    ║
             │                         │               ║ ITSM:              ║
             │                         │               ║ • ServiceNow       ║
             │                         │               ║ • Jira             ║
             └─────────────┬───────────┘               ║ • Azure DevOps     ║
                           │                           ╚═════════╤══════════╝
                           ▼                                     │
    ╔═════════════════════════════════════════════════════════════╧═══════════╗
    ║                     MICROSOFT SENTINEL WORKSPACE                       ║
    ║                                                                        ║
    ║  ┌─────────────┐ ┌──────────────┐ ┌────────────┐ ┌─────────────────┐  ║
    ║  │ 15 Custom    │ │ 38 Analytics │ │ 4 Workbooks│ │ SCORCH Agent    │  ║
    ║  │ Tables       │ │ Rule         │ │ + 13       │ │                 │  ║
    ║  │              │ │ Templates    │ │ Templates  │ │ Autonomous AI   │  ║
    ║  │ 600B+        │ │              │ │            │ │ investigation   │  ║
    ║  │ recaptured   │ │ Core         │ │ SOC Ops    │ │ with 28+ skills │  ║
    ║  │ records      │ │ IdP Corr     │ │ Executive  │ │ 5 promptbooks   │  ║
    ║  │              │ │ Network      │ │ Defender   │ │ Risk scoring    │  ║
    ║  │              │ │ UEBA Fusion  │ │ Threat Int │ │ Remediation rec │  ║
    ║  └─────────────┘ │ O365/Entra   │ └────────────┘ └─────────────────┘  ║
    ║                  │ Operations   │                                      ║
    ║  ┌─────────────┐ └──────────────┘ ┌────────────┐ ┌─────────────────┐  ║
    ║  │ 16 Hunting   │                 │ 3 Jupyter   │ │ MCP Server      │  ║
    ║  │ Queries      │ ┌──────────────┐│ Notebooks   │ │                 │  ║
    ║  │              │ │ 4 Automation ││             │ │ Model Context   │  ║
    ║  │ Proactive    │ │ Rules        ││ Triage      │ │ Protocol for    │  ║
    ║  │ threat       │ │              ││ Landscape   │ │ AI-native       │  ║
    ║  │ hunting      │ │ Auto-trigger ││ Hunting     │ │ integration     │  ║
    ║  └─────────────┘ │ playbooks    │└────────────┘ └─────────────────┘  ║
    ║                  └──────────────┘                                      ║
    ╚════════════╤═══════════════╤════════════════╤══════════════════════════╝
                 │               │                │
                 ▼               ▼                ▼
    ╔════════════════╗ ╔═════════════════╗ ╔══════════════════╗
    ║ DEFENDER (MDE)  ║ ║ ENTRA ID        ║ ║ NOTIFICATIONS    ║
    ║                ║ ║                 ║ ║                  ║
    ║ Device Isolate ║ ║ Password Reset  ║ ║ Teams · Slack    ║
    ║ IOC Submit     ║ ║ Session Revoke  ║ ║ Email · Webhooks ║
    ║ Device Tag     ║ ║ CA Group Add    ║ ║ ServiceNow       ║
    ║ Blocklist      ║ ║ Account Disable ║ ║ Jira · AzDO      ║
    ║                ║ ║ Risk Score →    ║ ║                  ║
    ║                ║ ║ Custom Attribute║ ║                  ║
    ║                ║ ║ → CA Policy     ║ ║                  ║
    ╚════════════════╝ ╚═════════════════╝ ╚══════════════════╝
```

### The Identity Risk Score — A Closed Loop No One Else Has

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │                                                                      │
   │  EXPOSURE          SCORE           POLICY          RESPONSE          │
   │  ─────────────────────────────────────────────────────────────       │
   │                                                                      │
   │  SpyCloud       ┌─────────┐    Entra ID CA     Password Reset       │
   │  detects        │  0-100  │    Custom Security  + Session Revoke     │
   │  stolen ───────▶│  Risk   │───▶Attribute ──────▶+ Device Isolate    │
   │  credentials    │  Score  │                     + Notify SOC         │
   │                 └─────────┘                            │             │
   │                      │                                 │             │
   │  5 Components:       │     Score > 80 → Block access   │             │
   │  • Severity  0-30    │     Score 61-80 → Hardware MFA  │             │
   │  • Credential 0-25   │     Score 41-60 → Hourly reauth │             │
   │  • Session   0-25    │     Score 21-40 → Normal MFA    │             │
   │  • Device    0-10    │     Score 0-20  → Passwordless  │             │
   │  • Temporal  ×0.2-1.0│                                 │             │
   │                      │         ┌───────────────────────┘             │
   │  + Remediation       │         │                                     │
   │    Credit: -20       │         ▼                                     │
   │    per action ◀──────┼── SCORE DECREASES ──────────────────────      │
   │                      │   Password reset = -10 points                 │
   │                      │   Session revoke = -5 points                  │
   │                      │   Account disable = -15 points                │
   │                      │                                               │
   │  Score naturally     │   Your remediation actions                    │
   │  decays over time:   │   REDUCE the score automatically.            │
   │  24h=full weight     │   No other vendor offers this                │
   │  365d=20% weight     │   closed-loop integration.                   │
   │                      │                                               │
   └──────────────────────┴───────────────────────────────────────────────┘

   🟢 LOW (0-20)   🟡 MODERATE (21-40)   🟠 HIGH (41-60)   🔴 CRITICAL (61-80)   🟣 EMERGENCY (81-100)
```

---

## 🤖 SCORCH — The Autonomous Security Agent

**SCORCH** (SpyCloud Orchestrated Response and Contextual Hunting) is an AI-powered Security Copilot agent that doesn't just answer questions — it **investigates, scores, correlates, and recommends** autonomously.

### What Makes SCORCH Different

| Traditional SIEM Queries | SCORCH Agent |
|:---:|:---:|
| Write KQL, read results | "Investigate this user" → full cross-table analysis |
| Manual correlation | Automatic correlation across all 15 SpyCloud tables |
| Static dashboards | Dynamic investigation reports with risk scoring |
| One query at a time | Chains multiple queries and enrichments automatically |
| No recommendations | Specific, prioritized remediation recommendations |

### SCORCH Capabilities

```
┌────────────────────────────────────────────────────────────────────┐
│                         SCORCH AGENT                               │
│                                                                    │
│  28+ KQL Skills            5 Promptbooks           AI Engine       │
│  ─────────────             ──────────────           ─────────      │
│  • User Exposures          • Incident Triage       • Risk Scoring  │
│  • Device Forensics        • Threat Hunting        • Prioritization│
│  • Password Analysis       • User Investigation    • Correlation   │
│  • Malware Intelligence    • Org Risk Assessment   • Natural Lang  │
│  • Breach Catalog          • Compliance Audit      • Follow-up Q's │
│  • MDE Correlation                                                 │
│  • CA Action Audit         MCP Server                              │
│  • Geographic Analysis     ──────────                              │
│  • Remediation Stats       • AI-native protocol                    │
│  • Full Investigation      • Real-time data access                 │
│  • AV Coverage Gaps        • Tool-based integration                │
│  • Cross-Table Joins       • Works with any AI platform            │
│                                                                    │
│  "Tell me about user@company.com"                                  │
│  → Checks 15 tables → Scores risk → Correlates with MDE/Entra     │
│  → Identifies stolen cookies → Checks session validity             │
│  → Recommends: "Reset password, revoke sessions, isolate DESKTOP-  │
│    ABC123, investigate Okta SSO access logs from last 72h"         │
│  → Provides follow-up questions for deeper investigation           │
└────────────────────────────────────────────────────────────────────┘
```

### Promptbooks — Guided AI Investigations

| Promptbook | Purpose | Steps |
|-----------|---------|-------|
| **Incident Triage** | Rapid assessment of SpyCloud incidents | Exposure → Risk → Device → Remediation status |
| **Threat Hunt** | Proactive hunting for undetected compromises | High-severity scan → Password analysis → Device correlation |
| **User Investigation** | Deep dive on a specific identity | Full cross-table → Identity graph → Timeline → Recommendations |
| **Org Risk Assessment** | Organization-wide exposure posture | Domain risk → Distribution → Top risks → Trend analysis |
| **Compliance Audit** | Evidence package for auditors/regulators | Detection coverage → Remediation rates → SLA compliance |

---

## 📦 What's In The Box — Complete Inventory

### ARM Template (144 Resources)

| Category | Count | Details |
|----------|:-----:|---------|
| **Custom Tables** | 15 | BreachWatchlist, BreachCatalog, CompassData, CompassDevices, CompassApplications, SipCookies, Investigations, IdLink, Exposure, CAP, DataPartnership, EnrichmentAudit, MDE_Logs, CA_Logs, IdentityExposure |
| **Content Templates** | 57 | 38 analytics rules + 16 hunting queries + 1 workbook + 2 connector templates |
| **Logic App Playbooks** | 13 | 5 response + 8 enrichment (all with SpyCloud Sentinel tags) |
| **Function App Stack** | 7 | Function App + Storage + App Insights + App Service Plan + Key Vault + 4 secrets |
| **Analytics Rules** | 6 | 5 standalone + 1 risk score rule |
| **Automation Rules** | 4 | Auto-trigger playbooks on matching incidents |
| **Watchlists** | 4 | VIP users, exclusions, severity mapping, monitored domains |
| **DCR/DCE** | 3 | 2 data collection rules + 1 endpoint |
| **API Connections** | 3 | Custom SpyCloud connector + Sentinel + SpyCloud API |
| **Sentinel Settings** | 5 | EntityAnalytics, UEBA, Anomalies, EyesOn, onboarding |
| **Workspace** | 2 | Log Analytics + Sentinel solution |
| **Notifications** | 1 | Action group |

### Beyond The ARM Template

| Component | Files | Purpose |
|-----------|:-----:|---------|
| **Standalone Playbooks** | 19 | Full Logic App JSONs ready for individual deployment |
| **Playbook Templates** | 18 | ARM-wrapped playbooks for Content Hub |
| **Workbook Templates** | 13 | Per-table and per-product workbook templates |
| **Workbook JSONs** | 4 | SOC Operations, Executive, Defender/CA, Threat Intel |
| **Analytics YAML** | 8 | Rule definitions by category (core, O365, UEBA, network) |
| **Automation Templates** | 4 | Auto-trigger rule templates |
| **Copilot Plugin** | 6 | Plugin YAML, OpenAPI spec, manifest, MCP plugin |
| **Copilot Agent** | 1 | SCORCH autonomous investigation agent |
| **Promptbooks** | 5 | Guided AI investigation workflows |
| **MCP Server** | 5 | Node.js MCP server for AI-native protocol |
| **Notebooks** | 3 | Incident Triage, Threat Landscape, Threat Hunting |
| **Function App** | 3 | Python enrichment backend + risk score engine |
| **Terraform** | 4 | Alternative IaC deployment |
| **Scripts** | 16 | Deploy, test, audit, grant permissions, generate data |
| **Test Data** | 14 | Realistic sample data for all 13 tables + ingestion script |

---

## 🚀 Quick Start

### Deploy in 3 Minutes

**1. Click Deploy:**

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

**2. Enter your SpyCloud Enterprise API key** (the only key needed during deployment)

**3. Connect the data connector** → Sentinel → Data Connectors → SpyCloud → Add product keys → Connect

**4. Enable analytics rules** → Sentinel → Analytics → Rule Templates → Filter "SpyCloud"

**5. Verify data flow:**
```kql
SpyCloudBreachWatchlist_CL | take 10
```

### API Key Flow — Enter Once, Works Everywhere

```
┌──────────────────────────┐        ┌─────────────────────────────────────┐
│   DEPLOYMENT WIZARD       │        │   CONNECTOR PAGE (after deploy)     │
│                          │        │                                     │
│   Enterprise API Key ────┼── KV ──│── Enterprise Key (required)         │
│   (1 field only)         │        │   Compass Key (optional)            │
│                          │        │   SIP Key (optional)                │
│   That's it.             │        │   Investigations Key (optional)     │
│   One key.               │        │   IdLink Key (optional)             │
│   Done.                  │        │   Exposure Key (optional)           │
│                          │        │   CAP Key (optional)                │
│                          │        │   Data Partnership Key (optional)   │
│                          │        │                                     │
│                          │        │   ✅ Persistent                     │
│                          │        │   ✅ Updatable without redeploying  │
│                          │        │   ✅ Product pollers auto-activate  │
└──────────────────────────┘        └─────────────────────────────────────┘
```

---

## 🎯 SpyCloud Products & Cross-Product Power

### Every API, Every Use Case

| Product | What It Detects | Sentinel Value |
|---------|----------------|----------------|
| **Enterprise Watchlist** | Stolen credentials + PII + device forensics | Core of everything — 38 rules, 13 playbooks, 4 workbooks all depend on this |
| **Breach Catalog** | Breach source metadata (malware family, confidence) | "Where did this come from?" — enriches every incident with attribution |
| **Compass Data** | Application-level stolen credentials | The blast radius — which VPN, SSO, cloud app credentials were stolen |
| **Compass Devices** | Infected device fingerprints | MDE correlation — match infected devices to your fleet |
| **SIP Cookies** | Stolen session cookies | **The MFA killer** — attackers bypass MFA with stolen cookies |
| **Investigations** | Full SpyCloud database access | Threat hunting — search 600B+ records for any indicator |
| **IdLink** | Identity correlation across personas | One person, many accounts — find them all |
| **Exposure Stats** | Domain-level aggregate metrics | Executive dashboards — "how exposed are we?" over time |

### Multi-Product Fusion — Where Real Power Lives

When you combine SpyCloud products, the detections become exponentially more powerful:

| Combination | Detection | Why It's Devastating |
|------------|-----------|---------------------|
| Enterprise + SIP | Credential + Cookie Double Exposure | Attacker has BOTH password AND session cookies = complete MFA bypass |
| Enterprise + Compass | Infection with Application Blast Radius | Not just "password stolen" but "VPN, SSO, AWS console, Okta, and 12 other apps compromised" |
| Compass + SIP | Device Infection with Active Sessions | Infected device had cookies stolen that are STILL VALID right now |
| Enterprise + Exposure | Spike Correlated with New Breach | New breach published that massively impacts your org |
| Enterprise + IdLink | Linked Identity Chain Exposure | One compromised personal email → maps to 5 other accounts → all need remediation |

---

## 🌐 Cross-Ecosystem: 100+ Integrations

SpyCloud data enriches and correlates with your entire security stack:

| Ecosystem | Vendors | Integrations |
|-----------|---------|:------------:|
| **Microsoft Defender** | MDE, MDCA, MDI, Entra ID, Intune, M365 | 45 |
| **Identity Providers** | Okta, Duo, Ping, Google Workspace | 10 |
| **Firewalls/VPN** | Palo Alto, Fortinet, Cisco, Zscaler, Cloudflare | 16 |
| **EDR/XDR** | CrowdStrike, SentinelOne, Carbon Black, Cortex XDR | 8 |
| **ITSM** | ServiceNow, Jira, Azure DevOps | 6 |
| **Threat Intel** | VirusTotal, AbuseIPDB, GreyNoise, MISP, Recorded Future | 5 |
| **Other SIEMs/SOARs** | Splunk, Rapid7, Chronicle, XSOAR | 4 |
| **DNS/NAC** | Infoblox, Cisco ISE, Aruba ClearPass | 4 |
| **RMM/MDM** | ConnectWise, Jamf, Intune | 3 |

See [Cross-Ecosystem Integration Map](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) for the complete matrix with rule names and playbook details.

---

## 💰 Cost Optimization

| Strategy | Savings | How |
|---------|:-------:|-----|
| Severity filter ≥ 20 | **50-70%** | Skip low-severity public breach credentials |
| Analytics plan tables | **50%** | Cheaper per-GB than Log Analytics plan |
| 60-min polling | **50%** | Instead of 30-min default |
| Conditional pollers | **100%** | Only enable products you're licensed for |
| Function App Consumption | **Free** | First 1M executions/month included |
| Retention tiering | **80%** | 90-day hot, archive for compliance |

| Environment | Users | Daily Ingestion | Est. Monthly Cost |
|:------------|------:|:---------------:|:-----------------:|
| POC | < 1K | 1-10 MB | **$5-15** |
| Medium | 1K-10K | 10-100 MB | **$15-75** |
| Large | 10K-100K | 100-500 MB | **$75-400** |
| Enterprise | 100K+ | 500+ MB | Contact SpyCloud |

---

## 🏪 Marketplace & ISV

### Content Hub Ready

All 57 content templates are registered in the Content Package with proper dependencies. Install from Content Hub → everything appears in the Sentinel UI:

- **Analytics** → Rule Templates → 38 SpyCloud rules
- **Hunting** → Queries → 16 SpyCloud queries
- **Workbooks** → SpyCloud dashboards
- **Automation** → Playbook templates
- **Content Hub** → Manage → all items with version tracking

### Update Path

```
Version bump → GitHub PR → Microsoft review → Content Hub "Update available" badge
→ Customer one-click update → Templates updated, data preserved
```

See [ISV & Marketplace Strategy](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) for the complete publishing guide.

---

## 📖 Documentation

| Document | Focus |
|----------|-------|
| [Product Catalog](docs/PRODUCT-CATALOG-v12.md) | All 8 SpyCloud products with pollers, playbooks, rules |
| [Enrichment Architecture](docs/ENRICHMENT-ARCHITECTURE-v12.md) | Enrichment design, cross-platform correlations |
| [Cross-Ecosystem Map](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) | 100+ vendor integrations with rule/playbook details |
| [ISV Strategy](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) | Azure Functions, Key Vault, marketplace publishing |
| [Security Copilot Spec](docs/SECURITY-COPILOT-SPEC.md) | Copilot plugin, SCORCH agent, promptbooks |
| [Agents & Plugins](docs/AGENTS-AND-PLUGINS-GUIDE.md) | AI agent configuration and capabilities |
| [Permissions Guide](docs/PERMISSIONS-AND-PLAYBOOKS.md) | Required roles and API permissions |
| [API Setup](docs/API-SETUP-GUIDE.md) | SpyCloud API configuration |
| [Production Readiness](docs/PRODUCTION-READINESS-v12.10.md) | Deployment checklist and validation |
| [Roadmap](docs/ROADMAP.md) | Release history and future vision |

---

## 🛠️ Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No data after connecting | API key invalid | Verify at portal.spycloud.com |
| Rules not in Analytics blade | Old version without content deps | Update to v12.10+ |
| MDE playbook fails | Missing P2 license | Playbook deploys but needs P2 |
| Domain-based pollers fail | monitoredDomain blank | Enter domain on connector page |
| Workbook shows no data | Tables not populated | Wait 15-30 min after first connect |

---

## 📬 Support

| Channel | Contact |
|---------|---------|
| **SpyCloud Support** | [support@spycloud.com](mailto:support@spycloud.com) |
| **Integration Help** | [integrations@spycloud.com](mailto:integrations@spycloud.com) |
| **SpyCloud Portal** | [portal.spycloud.com](https://portal.spycloud.com) |
| **GitHub Issues** | [Issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues) |

---

<div align="center">

**Built with 💚 by SpyCloud for the Microsoft Sentinel community.**

*Protecting identities. Preventing breaches. Powering SOCs.*

![SpyCloud](https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-200.png)

</div>
