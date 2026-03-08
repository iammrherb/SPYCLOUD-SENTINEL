<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" alt="SpyCloud" width="320" style="background:#0D1B2A;padding:20px;border-radius:8px"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence for Microsoft Sentinel</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-7.1-00B4D8?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/sentinel-ready-0D1B2A?style=for-the-badge&logo=microsoftazure"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft"/>
  <img src="https://img.shields.io/badge/playbooks-4-2D6A4F?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/rules-22-415A77?style=for-the-badge"/>
</p>

---

## Product Features & Capabilities

| Category | Feature | Details |
|----------|---------|---------|
| 🔌 **Data Ingestion** | CCF REST API Connector | 3 pollers (Watchlist New, Watchlist Modified, Breach Catalog) with Bearer token auth, cursor-based pagination, configurable severity/type filters |
| | 4 Custom Tables | SpyCloudBreachWatchlist_CL (73 cols), SpyCloudBreachCatalog_CL (5 cols), Spycloud_MDE_Logs_CL (19 cols), SpyCloud_ConditionalAccessLogs_CL (14 cols) |
| | Data Collection Rule | KQL transforms normalize raw API data before table ingestion |
| | Data Collection Endpoint | HTTPS ingestion endpoint for secure data flow |
| ⚙️ **Automation** | MDE Device Isolation | Searches MDE for infected devices, isolates, tags with SpyCloud identifier |
| | CA Identity Protection | Forces password reset, revokes sessions, adds to CA exclusion group |
| | Credential Response | Checks recent sign-ins, resets password, revokes sessions, sends Teams/Slack alert |
| | MDE Blocklist (Scheduled) | Scans severity 25 records on schedule, auto-isolates matched MDE devices |
| 🎯 **Detection** | 22 Analytics Rules | 12 core detection + 4 IdP correlation + 5 advanced correlation + 1 health monitoring |
| | MITRE ATT&CK Mapping | T1078, T1110, T1530, T1539, T1547, T1550, T1552, T1555, T1562, T1589 |
| | Entity Mapping | Account, Host, IP entity extraction for investigation |
| 📊 **Visualization** | Sentinel Workbook | 12 interactive charts: exposure tiles, severity trends, top users, top devices, password types, domains, geo, remediation, catalog |
| 🤖 **AI Integration** | Security Copilot Plugin | 28 KQL skills across 9 categories |
| | Security Copilot Agent | 30 interactive skills with natural language investigation |
| 🔔 **Notifications** | Teams Webhook | Real-time SOC channel alerts via MessageCard |
| | Slack Webhook | Real-time Slack SOC notifications |
| | Email Notifications | Action Group alerts for health monitoring |
| 🔒 **Security** | Managed Identity | Zero credentials in Logic App workflows |
| | SecureString API Key | Never exposed in logs or outputs |
| | Resource Tags | Default + custom tags on all resources |

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │       SpyCloud Darknet Intelligence    │
                    │    api.spycloud.io (US) / api.eu (EU) │
                    └────────────────┬─────────────────────┘
                                     │ HTTPS / Bearer Token
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     MICROSOFT SENTINEL                                  │
│                                                                        │
│  ┌──────────────┐    ┌──────┐    ┌─────────────────────────────────┐  │
│  │ CCF Connector │───▶│ DCE  │───▶│   DCR (4 KQL Transforms)       │  │
│  │ 3 Pollers     │    │HTTPS │    │                                 │  │
│  │ • Watchlist   │    │Ingest│    │ ┌─ SpyCloudBreachWatchlist_CL  │  │
│  │ • Modified    │    └──────┘    │ │  (73 columns: creds, PII,    │  │
│  │ • Catalog     │               │ │   device forensics, social)   │  │
│  └──────────────┘               │ ├─ SpyCloudBreachCatalog_CL     │  │
│                                  │ │  (5 cols: source metadata)    │  │
│                                  │ ├─ Spycloud_MDE_Logs_CL        │  │
│                                  │ │  (19 cols: MDE audit trail)   │  │
│                                  │ └─ SpyCloud_CA_Logs_CL         │  │
│                                  │    (14 cols: CA audit trail)    │  │
│                                  └──────────────┬──────────────────┘  │
│                                                  │                     │
│  ┌──────────────────────┐  ┌─────────────────────┼───────────────┐    │
│  │ 📊 Workbook Dashboard │  │  22 Analytics Rules  │               │    │
│  │  12 charts            │  │  (all disabled by    ▼               │    │
│  │  Tiles, trends, geo   │  │   default)     Sentinel Incidents   │    │
│  └──────────────────────┘  └───────────────┬─────────────────────┘    │
│                                             │                          │
│         ┌──────────┬──────────┬─────────────┤                          │
│         ▼          ▼          ▼             ▼                          │
│    ┌─────────┐┌────────┐┌──────────┐┌─────────────┐                   │
│    │ PB1 MDE ││PB2 CA  ││ PB3 Cred ││ PB4 MDE     │                   │
│    │ Isolate ││Identity││ Response ││ Blocklist   │                   │
│    │ + Tag   ││Protect ││ +Teams   ││ (Scheduled) │                   │
│    └────┬────┘└───┬────┘└────┬─────┘└──────┬──────┘                   │
│         │         │          │              │                          │
│    MDE API   Graph API  Graph+Teams    MDE API                        │
│                              +Slack                                    │
└────────────────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┴────────────────┐
              │  Microsoft Security Copilot    │
              │  Plugin: 28 KQL skills         │
              │  Agent: 30 interactive skills   │
              └──────────────────────────────┘
```

---

## Deploy

### Step 1: Deploy Infrastructure (ARM Template)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

The portal wizard has 3 steps: **Workspace** (create or select existing + retention) → **Playbooks & Rules** (toggle 4 playbooks, MDE config, 22 rules) → **Security** (dashboard, tags, Teams/Slack/email, IdP correlation).

The ARM template deploys: workspace, Sentinel (auto-enabled via OnboardingStates API), DCE, DCR, 4 tables, 3 pollers, connector definition, 4 Logic Apps, 22 analytics rules, workbook dashboard, managed identity, deployment script.

<details><summary><strong>Azure CLI</strong></summary>

```bash
az login && az group create -n spycloud-sentinel -l eastus
az deployment group create -g spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters workspace=my-sentinel-ws
```
</details>

<details><summary><strong>PowerShell</strong></summary>

```powershell
Connect-AzAccount
New-AzResourceGroupDeployment -Name "SpyCloud" -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "my-sentinel-ws"
```
</details>

### Step 2: Activate the SpyCloud Connector

> **The ARM template deploys the connector framework. You must activate it in Sentinel to start data flow.**

1. Portal → **Microsoft Sentinel** → your workspace → **Data connectors**
2. Search **"SpyCloud"** → click → **Open connector page**
3. **Step 1:** Paste your SpyCloud API key (from portal.spycloud.com → Settings → API Keys)
4. **Step 2:** Select severity levels (recommend: all 4), exposure types, password handling
5. **Step 3:** Click **Connect**
6. Data appears within 5-10 minutes

### Step 3: Verify Deployment

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/verify-deployment.sh | bash -s -- -g YOUR-RG -w YOUR-WS
```

Checks 10 sections: workspace, Sentinel, DCE, DCR, 4 tables, connector status, Logic Apps + permissions, analytics rules, workbook, deployment script.

### Step 4: Enable Analytics Rules

Sentinel → **Analytics** → filter "SpyCloud" → enable rules individually. Recommended first: #1 (Infostealer Exposure), #2 (Plaintext Password), #4 (Session Cookies), #9 (Remediation Gap), #12 (Data Health).

### Step 5: Grant API Permissions (if needed)

The deployment script attempts to grant MDE + Graph API permissions. If it shows "needs admin consent":
1. Entra ID → Enterprise Applications → filter **Managed Identities**
2. Find each SpyCloud Logic App → Permissions → **Grant admin consent**

### Step 6: Upload Security Copilot Files

| File | Destination |
|------|------------|
| `copilot/SpyCloud_Plugin.yaml` | securitycopilot.microsoft.com → Sources → Custom → Upload Plugin |
| `copilot/SpyCloud_Agent.yaml` | securitycopilot.microsoft.com → Build → Upload YAML → Publish |

---

## 22 Analytics Rules

| # | Rule | Sev | Use Case |
|---|------|-----|----------|
| 1 | Infostealer Exposure | 🔴 High | Severity 20+ malware-stolen credentials |
| 2 | Plaintext Password | 🔴 High | Cleartext passwords available to attackers |
| 3 | Sensitive PII | 🔴 High | SSN, bank, tax, health data exposed |
| 4 | Session Cookie Theft | 🔴 High | Stolen cookies/tokens bypass MFA |
| 5 | Device Re-Infection | 🔴 High | Same device compromised again |
| 6 | Multi-Domain Exposure | 🟠 Med | Credentials for 5+ domains |
| 7 | Geographic Anomaly | 🟠 Med | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 Med | Same creds in 3+ sources |
| 9 | Remediation Gap | 🔴 High | No auto-response after 2+ hours |
| 10 | AV Bypass | 🟢 Info | AV present but failed |
| 11 | New Malware Family | 🟢 Info | New breach source detected |
| 12 | Data Ingestion Health | 🟠 Med | No data for 3+ hours |
| 13-16 | IdP Correlation (×4) | 🔴 High | Okta, Duo, Ping, Entra cross-reference |
| 17 | Credential + Sign-In | 🔴 High | Compromised user signed in within 24h |
| 18 | Breach Enrichment | 🟠 Med | Joins catalog for breach context |
| 19 | Executive/VIP | 🔴 High | CEO/CFO/CISO accounts exposed |
| 20 | Password Reuse | 🔴 High | Same password for 3+ domains |
| 21 | Stale Exposure | 🟠 Med | Unresolved exposure >7 days (SLA) |

---

## 4 Automated Playbooks

### PB1: MDE Device Isolation

> **Use case:** Employee laptop infected with RedLine Stealer. SpyCloud detects stolen credentials. Playbook auto-isolates the device in Defender before the attacker uses them.

```
Sentinel Incident (sev 20+) → Extract machine ID → Search MDE
  ├── FOUND → Isolate (Full/Selective) → Tag → Comment → Log to MDE_Logs_CL
  └── NOT FOUND → Log for manual review
```

### PB2: CA Identity Protection

> **Use case:** Corporate password appears in darknet breach. Playbook forces password reset and kills all sessions before attacker can use the credential.

```
Sentinel Incident (email) → Lookup user in Entra ID
  ├── FOUND → Reset password → Revoke sessions → Add to CA group → Log to CA_Logs_CL
  └── NOT FOUND → Log as external user
```

### PB3: Credential Response + SOC Alerts

> **Use case:** SOC wants real-time Teams and Slack notifications with automated sign-in analysis when credentials are exposed.

```
Sentinel Incident → For each account:
  → Check last 10 Entra sign-ins → Reset password → Revoke sessions
  → Send Teams MessageCard + Slack webhook → Add incident comment
```

### PB4: MDE Blocklist (Scheduled)

> **Use case:** Every 4 hours, scan for CRITICAL severity 25 infections (stolen cookies, sessions, autofill) and isolate matched devices before MFA bypass.

```
Schedule (1-24h) → Query sev 25 → Match against MDE inventory
  ├── FOUND → Full isolation → Tag "SpyCloud-Sev25-Infostealer"
  └── NOT FOUND → Skip (unmanaged device)
```

---

## Sentinel Workbook — 12 Charts

Find at: **Sentinel → Workbooks → SpyCloud Threat Intelligence Dashboard**

| Chart | Type | Shows |
|-------|------|-------|
| Exposure Summary | Tiles | Total, unique users, devices, sev 25, sev 20, plaintext passwords |
| Exposures Over Time | Timechart | Daily count by severity |
| Severity Distribution | Pie | P1 Critical / P1 High / P3 Standard / P4 Low |
| Top 25 Exposed Users | Table | Email, exposures, max severity (heatmap), plaintext count, domains |
| Password Types | Bar | MD5, SHA1, bcrypt, plaintext distribution |
| Top Targeted Domains | Bar | Most-attacked domains |
| Top 25 Infected Devices | Table | Machine ID, hostname, users, severity, domains |
| Infections by Country | Bar | Geographic distribution |
| Remediation Dashboard | Tiles | MDE actions, CA actions, high-severity user count |
| MDE Remediation Trend | Timechart | Isolation actions over time |
| CA Remediation Trend | Timechart | Password reset/revoke actions over time |
| Breach Catalog | Table | Recent breach sources with titles, status, descriptions |

> Charts show "no results" until data flows. Activate the connector (Step 2) and wait 5-10 minutes.

---

## Severity Reference

| Sev | Priority | Category | Response |
|-----|----------|----------|----------|
| **25** | 🔴 P1 Critical | Infostealer + App (cookies, sessions, autofill) | Immediate: revoke sessions, reset pw, isolate device |
| **20** | 🔴 P1 High | Infostealer Credential (malware-stolen) | Urgent: reset password, check device health |
| **5** | 🟠 P3 Standard | Breach + PII (name, phone, DOB, address) | Monitor: review scope, check reuse |
| **2** | ⚪ P4 Low | Breach Credential (email + password) | Awareness: check credential reuse patterns |

---

## Security Copilot

### Plugin — 28 KQL Skills

| Category | Skills | What They Do |
|----------|--------|-------------|
| User Investigation | 4 | Credential lookup by email, full PII profile, activity timeline, exposed passwords |
| Password Analysis | 3 | Plaintext scan, type breakdown, crackability assessment |
| Severity & Domain | 3 | High-severity filter, distribution, domain-level exposure map |
| PII & Social | 3 | SSN/financial/health scan, social media accounts, targeted domains |
| Device Forensics | 4 | Infected device inventory, malware details, user mapping, AV gaps |
| Breach Catalog | 2 | Recent breaches, enriched exposure with catalog metadata |
| MDE Remediation | 3 | All MDE actions, per-device status, remediation statistics |
| CA Remediation | 3 | All CA actions, per-user status, remediation statistics |
| Cross-Table | 3 | Full investigation, geographic analysis, health dashboard |

### Agent — 30 Interactive Skills

**Example prompts:**
- *"Show our dark web exposure"* → Org-wide summary with severity breakdown
- *"Investigate john@company.com"* → Full credential + PII + device + remediation report
- *"Which devices are infected?"* → Device forensics with AV analysis
- *"Do we have plaintext passwords exposed?"* → Critical risk list with domains
- *"What users have credentials in 3+ breaches?"* → High-sighting credential report

---

## Cross-Data-Source Correlation

Maximize value by enabling additional connectors:

| Connector | Install | Enables |
|-----------|---------|---------|
| **Entra ID** | Diagnostic Settings → SignInLogs | Rule #16 (SpyCloud × Entra), Rule #17 (Credential + Sign-In) |
| **Microsoft Defender XDR** | Content Hub | MDE alert correlation with SpyCloud infections |
| **Okta SSO** | Content Hub | Rule #13 (SpyCloud × Okta) |
| **Cisco Duo** | Content Hub | Rule #14 (SpyCloud × Duo) |
| **Ping Identity** | AMA syslog/API | Rule #15 (SpyCloud × Ping) |
| **Microsoft 365** | Content Hub | Compromised user email/file access correlation |
| **Defender for Cloud Apps** | Content Hub | SaaS app usage after credential compromise |
| **Threat Intelligence** | Content Hub | SpyCloud IOCs matched against TI feeds |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "Workspace not onboarded to Sentinel" | Fixed v6.1 — OnboardingStates API always enables Sentinel |
| "RoleAssignmentUpdateNotPermitted" | Fixed v6.4 — role assignments removed from template |
| "show_plain_password expected String" | Fixed v7.1 — all CCF dropdown params are type=array |
| "apiRegion expected String" | Fixed v7.1 — removed from connector params, hardcoded US |
| No data after connecting | Wait 5-10 min. Check: Sentinel → Data connectors → SpyCloud status |
| Workbook shows "no results" | Data needs to flow first. Tables are empty until connector activates |
| Logic App not triggering | Check deployment script logs + grant admin consent for API permissions |
| KQL parse error in workbook | Fixed v7.0 — all queries rewritten without format_datetime |

---

## Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                    ← ARM template (43 params, 41 resources)
├── azuredeploy.parameters.json         ← Sample parameters
├── createUiDefinition.json             ← Portal wizard (30 outputs, 3 steps)
├── .github/workflows/deploy.yml        ← GitHub Actions CI/CD
├── scripts/
│   ├── deploy-all.sh                   ← Interactive guided deployment (9 phases)
│   ├── post-deploy.sh                  ← Standalone RBAC + API permissions
│   └── verify-deployment.sh            ← 10-section verification with portal links
├── copilot/
│   ├── SpyCloud_Plugin.yaml            ← Security Copilot plugin (28 skills)
│   └── SpyCloud_Agent.yaml             ← Interactive Copilot agent (30 skills)
├── workbooks/
│   └── SpyCloud-ThreatIntel-Dashboard.json ← Sentinel workbook (12 charts)
└── docs/
    ├── images/ (3 logo variants)
    ├── architecture.md
    └── azure-sp-setup.md
```

---

## Roadmap

| Status | Feature |
|--------|---------|
| 🟢 Shipped | 4 playbooks, 22 rules, workbook, Copilot plugin+agent, auto-deploy script |
| 🟡 Next | Jupyter notebooks (exposure investigation, infection analysis, org report) |
| 🟡 Next | Slack webhook wired into Credential Response playbook |
| 🟡 Next | ServiceNow ticket creation in playbooks |
| 🟡 Next | Enhanced Copilot skills (cross-data-source, hunt queries, chained investigation) |
| 🔵 Planned | Multiple workbook dashboards (Executive Summary, SOC Operations, Compliance) |
| 🔵 Planned | MCP server integrations (Atlassian Jira, Gmail notifications) |
| 🔵 Planned | A2A agent orchestration for multi-step remediation |
| 🔵 Planned | Custom VIP/executive watchlist with elevated alerting |
| 🔵 Planned | EU API region support (currently hardcoded US) |
| ⚪ Future | Automated connector activation (pending Sentinel CCF platform support) |
| ⚪ Future | Sentinel SOAR notebook for guided investigation |

---

<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" width="120" style="background:#0D1B2A;padding:8px;border-radius:6px"/>
  <br/><sub>© 2026 SpyCloud, Inc. · Trusted by 7 of the Fortune 10</sub>
</p>
