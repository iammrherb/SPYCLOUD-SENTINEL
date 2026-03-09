<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" alt="SpyCloud" width="340" style="background:#0D1B2A;padding:24px;border-radius:10px"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence & Automated Response for Microsoft Sentinel</h3>

<p align="center">
  <em>Transform 600B+ recaptured darknet records into automated identity threat protection.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-7.6-00B4D8?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/sentinel-ready-0D1B2A?style=for-the-badge&logo=microsoftazure"/>
  <img src="https://img.shields.io/badge/copilot-AI%20agent-E07A5F?style=for-the-badge&logo=microsoft"/>
  <img src="https://img.shields.io/badge/playbooks-4-2D6A4F?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/analytics-38%20rules-415A77?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/dashboard-22%20charts-6B4C9A?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/integrations-6-D4A843?style=for-the-badge"/>
</p>

---

## What This Does

SpyCloud monitors the criminal underground — breaches, infostealers, phishing kits — recapturing stolen credentials, session cookies, PII, and device fingerprints before attackers can use them. This solution brings that intelligence into Microsoft Sentinel and automatically responds: isolating infected devices in Defender, resetting compromised passwords in Entra ID, revoking active sessions, and notifying your SOC through Slack, Teams, Email, ServiceNow, Jira, and Azure DevOps.

**One deployment. Four automated playbooks. 28 detection rules. 19 dashboard visualizations. Six notification channels. Zero stored credentials.**

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow Pipeline](#data-flow-pipeline)
- [Prerequisites](#prerequisites)
- [Deployment (4 Methods)](#deployment)
- [Connector Configuration](#connector-configuration)
- [Post-Deployment Verification](#post-deployment-verification)
- [4 Automated Playbooks](#4-automated-playbooks)
- [28 Analytics Rules](#28-analytics-rules)
- [Notification & Ticketing Integrations](#notification--ticketing-integrations)
- [Sentinel Workbook Dashboard](#sentinel-workbook-dashboard)
- [Security Copilot Integration](#security-copilot-integration)
- [Cross-Data-Source Correlation](#cross-data-source-correlation)
- [Severity Reference](#severity-reference)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         SPYCLOUD DARKNET INTELLIGENCE                            │
│         Breaches · Infostealers · Phishing Kits · Session Hijacking              │
│                    600B+ recaptured records · 500+ sources                        │
│                         api.spycloud.io (REST API)                               │
│                          Auth: X-Api-Key header                                  │
└──────────────────────────────┬───────────────────────────────────────────────────┘
                               │ HTTPS GET (every 30 min)
                               │ Cursor-based pagination
                               │ Severity + Type + Password filters
                               ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          MICROSOFT SENTINEL                                      │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │               CCF Connector (3 REST API Pollers)                           │  │
│  │  ┌──────────────────┐ ┌─────────────────────┐ ┌────────────────────────┐  │  │
│  │  │ Watchlist New     │ │ Watchlist Modified   │ │ Breach Catalog         │  │  │
│  │  │ Sev 2/5/20/25    │ │ 24h mod tracking     │ │ Breach metadata        │  │  │
│  │  │ 30min intervals   │ │ Daily sweep          │ │ 30min intervals        │  │  │
│  │  │ Cursor pagination │ │ Date-range queries   │ │ Source enrichment      │  │  │
│  │  └────────┬─────────┘ └──────────┬──────────┘ └───────────┬────────────┘  │  │
│  └───────────┼──────────────────────┼─────────────────────────┼──────────────┘  │
│              └──────────────────────┼─────────────────────────┘                  │
│                                     ▼                                            │
│  ┌──────────────┐      ┌───────────────────────────────────────────────────┐    │
│  │   DCE         │      │            DCR (4 KQL Transforms)                │    │
│  │   HTTPS       │─────▶│                                                   │    │
│  │   Ingest      │      │  Stream 1 → SpyCloudBreachWatchlist_CL (73 cols) │    │
│  │   Endpoint    │      │  Stream 2 → SpyCloudBreachCatalog_CL   (5 cols)  │    │
│  └──────────────┘      │  Stream 3 → Spycloud_MDE_Logs_CL       (19 cols) │    │
│                         │  Stream 4 → SpyCloud_CA_Logs_CL        (14 cols) │    │
│                         └───────────────────┬───────────────────────────────┘    │
│                                             │                                    │
│         ┌───────────────────────────────────┼─────────────────────────┐          │
│         ▼                                   ▼                         ▼          │
│  ┌──────────────┐    ┌───────────────────────────────┐    ┌──────────────────┐  │
│  │ 📊 Workbook   │    │    28 Analytics Rules           │    │ 🤖 Copilot       │  │
│  │ 19 Charts     │    │                                 │    │ 28 Plugin Skills │  │
│  │ 8 Sections    │    │  13 Core Detection              │    │ 30 Agent Skills  │  │
│  │ Executive     │    │   4 IdP Correlation             │    │ Investigation    │  │
│  │ Credentials   │    │   5 Advanced Correlation        │    │ Forensics        │  │
│  │ Devices       │    │   6 Cross-Data (DNS/IP/MDE/     │    │ Remediation      │  │
│  │ PII           │    │     Cloud Apps/Entra Risk)      │    │ Hunt Queries     │  │
│  │ Remediation   │    │                                 │    │                  │  │
│  │ Catalog       │    └────────────────┬────────────────┘    └──────────────────┘  │
│  │ Health        │                     │ creates incidents                         │
│  └──────────────┘                     ▼                                           │
│                       ┌────────────────────────────────────┐                      │
│                       │       Automation Rule               │                      │
│                       │   auto-triggers playbooks           │                      │
│                       └──┬──────┬──────────┬──────────┬────┘                      │
│                          ▼      ▼          ▼          ▼                            │
│  ┌───────────────┐┌──────────┐┌──────────────┐┌──────────────────┐               │
│  │ PB1: MDE      ││ PB2: CA  ││ PB3: Cred    ││ PB4: MDE         │               │
│  │ Isolate Device││ Reset PW ││ Response     ││ Blocklist        │               │
│  │ Tag in MDE    ││ Revoke   ││ Sign-In Check││ (Scheduled)      │               │
│  │               ││ Sessions ││ Reset+Revoke ││ Sev 25 Auto-Scan │               │
│  │  📧 Slack     ││ Add to   ││              ││                  │               │
│  │  📧 Teams     ││ CA Group ││  📧 All 6    ││  📧 Slack        │               │
│  │  📧 Email     ││          ││  Channels    ││  📧 Teams        │               │
│  │               ││ 📧 Slack ││  + ServiceNow││  📧 Email        │               │
│  │               ││ 📧 Teams ││  + Jira      ││                  │               │
│  │  → MDE API    ││ 📧 Email ││  + DevOps    ││  → MDE API       │               │
│  └───────────────┘│          ││              ││                  │               │
│                    │→ Graph   ││  → Graph API ││                  │               │
│                    └──────────┘└──────────────┘└──────────────────┘               │
│                                                                                   │
│  ┌────────────────────────────────────────────────────────────────────────────┐   │
│  │                    Health Monitoring (Action Group)                         │   │
│  │   📧 Email + 📧 MS Teams + 📧 Slack → fires when no data for 2+ hours    │   │
│  └────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Pipeline

```
SpyCloud API  ──▶  CCF Pollers  ──▶  DCE  ──▶  DCR (KQL transforms)  ──▶  4 Custom Tables
                                                                                │
  ┌─────────────────────────────────────────────────────────────────────────────┘
  │
  ├──▶  28 Analytics Rules  ──▶  Incidents  ──▶  Automation Rule  ──▶  4 Playbooks
  │                                                                        │
  ├──▶  19-Chart Workbook Dashboard                                        ├──▶  MDE API (isolate)
  │                                                                        ├──▶  Graph API (reset/revoke)
  ├──▶  Security Copilot (58 skills)                                       ├──▶  Slack / Teams / Email
  │                                                                        ├──▶  ServiceNow (ticket)
  └──▶  Health Alert ──▶ Action Group ──▶ Email + Teams + Slack            ├──▶  Jira (issue)
                                                                           └──▶  Azure DevOps (work item)
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Azure Subscription** | With permissions to create resources (Contributor role on resource group) |
| **Microsoft Sentinel** | Enabled on a Log Analytics workspace (template auto-enables if not) |
| **SpyCloud Account** | Enterprise Protection subscription with API access |
| **SpyCloud API Key** | From [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys → Enterprise API |
| **MDE License** (optional) | Required for Playbooks 1 & 4 (device isolation). Needs API enabled. |
| **Entra ID P1+** (optional) | Required for Playbooks 2 & 3 (password reset, session revocation) |
| **Network** | Outbound HTTPS to `api.spycloud.io` and `graph.microsoft.com` |

### Required Azure Permissions

| Permission | Scope | What It's For |
|-----------|-------|---------------|
| **Contributor** | Resource Group | Deploy ARM template resources |
| **Microsoft Sentinel Contributor** | Workspace | Create analytics rules, automation rules |
| **Logic App Contributor** | Resource Group | Deploy and manage playbooks |
| **Managed Identity Operator** | Resource Group | Assign permissions to Logic App identities |
| **Security Administrator** | Tenant | Grant admin consent for MDE/Graph API permissions |

---

## Deployment

### Method 1: Azure Portal (Recommended)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

<a href="https://shell.azure.com/bash#src/github.com/iammrherb/SPYCLOUD-SENTINEL" target="_blank"><img src="https://img.shields.io/badge/launch-Azure%20Cloud%20Shell-blue?style=for-the-badge&logo=microsoftazure" alt="Open in Cloud Shell"/></a>

<a href="https://github.com/iammrherb/SPYCLOUD-SENTINEL/actions/workflows/deploy.yml" target="_blank"><img src="https://img.shields.io/badge/deploy-GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions"/></a>

The portal wizard has **3 pages**:

**Page 1 — Workspace & Configuration**
- Create new workspace or select existing (dropdown populated from your subscription)
- Set data retention (30–730 days, default 90)

**Page 2 — Playbooks & Automation**
- Toggle each of the 4 playbooks independently
- Configure MDE isolation type (Full/Selective), device tag name
- Configure CA security group ID for conditional access
- Set MDE Blocklist schedule (every 1–24 hours)
- Enable/disable 38 analytics rules, automation rule, post-deploy script

**Page 3 — Security & Integrations**
- Enable workbook dashboard
- Set resource tags (environment, owner, cost center)
- Configure SOC notification channels:
  - Microsoft Teams Incoming Webhook URL
  - Slack Incoming Webhook URL
  - ServiceNow Instance URL
  - Jira Automation Webhook URL
  - Azure DevOps Service Hook URL
  - Email notification address
- Toggle identity provider correlation alerts (Okta, Duo, Ping, Entra)

### Method 2: Azure CLI

```bash
# Login and create resource group
az login
az group create --name spycloud-sentinel --location eastus

# Deploy
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters \
    workspace=my-sentinel-ws \
    retentionInDays=90 \
    enableMdePlaybook=true \
    enableCaPlaybook=true \
    enableCredResponsePlaybook=true \
    enableMdeBlocklistPlaybook=true \
    enableAnalyticsRule=true \
    enableWorkbook=true \
    slackWebhookUrl='https://hooks.slack.com/services/...' \
    teamsWebhookUrl='https://your-org.webhook.office.com/...' \
    notificationEmail='soc@company.com' \
    serviceNowInstance='https://company.service-now.com' \
    jiraWebhookUrl='https://automation.atlassian.com/pro/hooks/...' \
    azureDevOpsWebhookUrl='https://dev.azure.com/org/project/...'
```

### Method 3: PowerShell

```powershell
Connect-AzAccount
New-AzResourceGroup -Name "spycloud-sentinel" -Location "eastus"

New-AzResourceGroupDeployment `
  -Name "SpyCloud-v7.6" `
  -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "my-sentinel-ws" `
  -retentionInDays 90 `
  -enableMdePlaybook $true `
  -enableCaPlaybook $true `
  -enableCredResponsePlaybook $true `
  -enableMdeBlocklistPlaybook $true `
  -enableAnalyticsRule $true `
  -enableWorkbook $true `
  -slackWebhookUrl "https://hooks.slack.com/services/..." `
  -teamsWebhookUrl "https://your-org.webhook.office.com/..." `
  -notificationEmail "soc@company.com"
```

### Method 4: GitHub Actions CI/CD

1. **Fork** this repository
2. **Add secrets** in Settings → Secrets:
   - `AZURE_CREDENTIALS` — service principal JSON ([setup guide](docs/azure-sp-setup.md))
   - `SPYCLOUD_API_KEY` — your Enterprise API key
3. **Run**: Actions → **Deploy SpyCloud Sentinel** → Run workflow
4. **Pipeline**: Validate ARM → Deploy to Azure → Configure post-deploy

<details><summary><strong>Cloud Shell One-Liner</strong></summary>

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```
Interactive 9-phase guided deployment with prompts for resource group, workspace, and all options.
</details>

### What Gets Deployed

| Resource | Count | Description |
|----------|-------|-------------|
| Log Analytics Workspace | 1 | Created or reused (idempotent) |
| Sentinel (OnboardingStates) | 1 | Auto-enabled via API |
| Data Collection Endpoint | 1 | HTTPS ingestion endpoint for pollers |
| Data Collection Rule | 1 | 4 streams, 4 KQL transforms, 4 data flows |
| Custom Tables | 4 | Watchlist (73 cols), Catalog (5), MDE Logs (19), CA Logs (14) |
| CCF Connector Definition | 1 | 7-step UI, 12 sample queries, 4 graph queries |
| CCF REST Pollers | 3 | Watchlist New + Modified + Catalog |
| Logic App Playbooks | 4 | MDE, CA, CredResponse, MDE Blocklist |
| Analytics Rules | 28 | 13 core + 4 IdP + 5 advanced + 6 cross-data |
| Workbook Dashboard | 1 | 22 visualizations across 8 sections |
| Action Group | 1 | Email + Teams + Slack health alerts |
| Health Alert Rule | 1 | Fires when no data received for 2+ hours |
| Managed Identity | 1 | For deployment script RBAC |
| Deployment Script | 1 | 7-phase post-deploy (DCE/DCR/RBAC/API perms) |

---

## Connector Configuration

After ARM deployment, activate the connector in Sentinel:

1. **Navigate**: Sentinel → Data connectors → Search "SpyCloud"
2. **Open**: Click connector → Open connector page
3. **Follow** the 7-step wizard:

### Step 0 — Prerequisites
API key location, Azure permissions table, network requirements, capacity planning by environment size.

### Step 1 — API Authentication
Paste your Enterprise API key. Sent as `X-Api-Key: <key>` header on every request.

### Step 2 — Severity & Exposure Types

| Dropdown | Options | Default |
|----------|---------|---------|
| Severity Levels | 2 (Low), 5 (Standard), 20 (High), 25 (Critical) | All selected |
| Watchlist Types | Corporate, Infected, Compass | All selected |
| Plaintext Passwords | Show / Hide | Hide |

### Step 3 — Data Streams & Polling

| Setting | Default | Range | Description |
|---------|---------|-------|-------------|
| Polling Interval | 30 min | 5–1440 min | How often to fetch new records |
| Retry Count | 5 | 1–10 | Retries per failed API call |
| Timeout | 120 sec | 30–300 sec | Per-request timeout |
| Lookback | 365 days | 1–365 days | Historical depth on first pull |

**Pollers:**

| Poller | Endpoint | Window | Pagination |
|--------|----------|--------|-----------|
| Watchlist New | `/enterprise-v2/breach/data/watchlist` | Configurable (30min) | Cursor-based |
| Watchlist Modified | Same endpoint | 24h (fixed) | Date-range |
| Breach Catalog | `/enterprise-v2/breach/catalog` | Configurable (30min) | Since timestamp |

### Step 4 — Use Cases
10-row reference table mapping SpyCloud data to Sentinel playbooks, rules, and recommended additional connectors.

### Step 5 — Connect
Click **Connect** → data flows within 5–10 minutes.

### Step 6 — Verification
KQL verification queries and troubleshooting reference with Cloud Shell verify command.

---

## Post-Deployment Verification

### Automated Verification Script

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/verify-deployment.sh \
  | bash -s -- -g YOUR-RESOURCE-GROUP -w YOUR-WORKSPACE
```

**10-section check with color-coded PASS/WARN/FAIL and Azure Portal deep links:**

| Section | What It Checks |
|---------|---------------|
| 1. Workspace & Sentinel | Workspace exists, Sentinel enabled, retention configured |
| 2. DCE | Data Collection Endpoint created, ingestion URI resolved |
| 3. DCR | Data Collection Rule exists, immutable ID, 4 streams + 4 data flows |
| 4. Custom Tables | All 4 tables exist with correct column counts (73, 5, 19, 14) |
| 5. Connector | Activation status, last data received timestamp |
| 6. Logic Apps | All 4 exist, enabled, managed identity principal IDs |
| 7. API Permissions | MDE Machine.Isolate, Graph User.ReadWrite.All + Directory.ReadWrite.All |
| 8. Analytics Rules | 28 rules deployed, enabled/disabled status |
| 9. Workbook | Dashboard exists and attached to workspace |
| 10. Data Flow | Record counts per table, latest timestamps, pipeline health |

### Manual Verification (KQL)

```kusto
// Pipeline health — run in Sentinel → Logs
union
  (SpyCloudBreachWatchlist_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table="Watchlist"),
  (SpyCloudBreachCatalog_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table="Catalog"),
  (Spycloud_MDE_Logs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table="MDE Logs"),
  (SpyCloud_ConditionalAccessLogs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table="CA Logs")
| project Table, Records, Latest, AgeHours=datetime_diff('hour', now(), Latest)
```

### Grant API Permissions (if needed)

If the deployment script couldn't auto-grant permissions:

1. Entra ID → **Enterprise Applications** → filter **Managed Identities**
2. Find `SpyCloud-MDE-Remediation-{ws}` → Permissions → **Grant admin consent**
3. Repeat for `SpyCloud-CA-Remediation-{ws}` and `SpyCloud-CredResponse-{ws}`

---

## 4 Automated Playbooks

### PB1 — MDE Device Isolation

> **Scenario:** Employee laptop infected with RedLine Stealer. SpyCloud detects stolen credentials. Playbook auto-isolates the device before the attacker uses them.

```
Sentinel Incident (severity 20+)
  → Extract infected_machine_id + user_hostname
  → GET MDE API: search for matching device
  ├─ FOUND → POST isolate (Full/Selective) → POST tag "SpyCloud-Compromised"
  │          → Log to Spycloud_MDE_Logs_CL → Comment on incident
  │          → 📧 Slack + 📧 Teams + 📧 Email
  └─ NOT FOUND → Comment "device not in MDE inventory"
```

**Requires:** MDE license, `Machine.Isolate` + `Machine.ReadWrite.All`

### PB2 — CA Identity Protection

> **Scenario:** Corporate password appears in a darknet breach. Playbook forces reset and kills sessions before the attacker can log in.

```
Sentinel Incident (email in entities)
  → GET Graph API: lookup user in Entra ID
  ├─ FOUND → PATCH force password reset → POST revoke all sessions
  │          → POST add to CA security group (if configured)
  │          → Log to SpyCloud_CA_Logs_CL → Comment on incident
  │          → 📧 Slack + 📧 Teams + 📧 Email
  └─ NOT FOUND → Comment "external user, not in Entra ID"
```

**Requires:** Entra ID P1+, `User.ReadWrite.All` + `Directory.ReadWrite.All`

### PB3 — Credential Response (Full SOC Workflow)

> **Scenario:** SOC wants complete automated response with investigation context, password reset, session revocation, and multi-channel notifications including ticketing.

```
Sentinel Incident (credential exposure)
  → For each account entity:
    → GET Graph: user profile
    → GET Graph: last 10 sign-ins (investigation context)
    → PATCH: force password reset
    → POST: revoke all sessions
    → Comment on incident with sign-in analysis
    → 📧 Slack notification
    → 📧 Teams MessageCard (with SpyCloud logo)
    → 📧 Email notification
    → 🎫 ServiceNow incident (if configured)
    → 🎫 Jira issue (if configured)
    → 🎫 Azure DevOps work item (if configured)
```

**Requires:** Security Administrator, `IdentityRisk.ReadWrite.All`

### PB4 — MDE Blocklist (Scheduled)

> **Scenario:** Every 2–4 hours, automatically scan for CRITICAL severity 25 infections (cookies, sessions, autofill) and isolate matched devices.

```
Schedule Trigger (configurable 1–24h)
  → KQL: query severity 25 records from SpyCloudBreachWatchlist_CL
  → For each infected device:
    → GET MDE API: search by machine ID / hostname
    ├─ FOUND → POST full isolation → POST tag "SpyCloud-Sev25-Infostealer"
    │          → 📧 Slack + 📧 Teams + 📧 Email
    └─ NOT FOUND → skip (unmanaged device)
```

**Requires:** MDE with API enabled, `Machine.Isolate`

---

## 38 Analytics Rules

All rules deploy **disabled** — enable individually in Sentinel → Analytics.

### Core Detection (13 Rules)

| # | Rule | Sev | MITRE | What It Detects |
|---|------|-----|-------|-----------------|
| 1 | Infostealer Exposure | High | T1555, T1078 | Severity 20+ malware-stolen credentials |
| 2 | Infostealer Credential Exposure | High | T1555 | Malware-specific credential theft |
| 3 | Plaintext Password | High | T1552 | Cleartext passwords — immediate attacker access |
| 4 | Sensitive PII (SSN/Financial/Health) | High | T1530 | Compliance-critical data exposure |
| 5 | Session Cookie / Token Theft | High | T1539, T1550 | Stolen cookies bypass MFA entirely |
| 6 | Device Re-Infection | High | T1547, T1555 | Same device compromised again after remediation |
| 7 | Multi-Domain Exposure | Medium | T1078 | Credentials for 5+ different domains |
| 8 | Geographic Anomaly | Medium | T1078 | Infections from unusual countries |
| 9 | High-Sighting Credential | Medium | T1110 | Same credential in 3+ breach sources |
| 10 | Remediation Gap | High | T1078 | No automated response after 2+ hours |
| 11 | AV Bypass | Info | T1562 | Antivirus present but failed to prevent stealer |
| 12 | New Malware Family | Info | T1589 | New breach source in catalog |
| 13 | Data Ingestion Health | Medium | — | No data received for 3+ hours |

### Identity Provider Correlation (4 Rules)

| # | Rule | Correlates With | Requires |
|---|------|----------------|----------|
| 14 | SpyCloud × Okta | `Okta_CL` | Content Hub → "Okta SSO" |
| 15 | SpyCloud × Duo | `Duo_CL` | Content Hub → "Cisco Duo" |
| 16 | SpyCloud × Ping | `PingFederate_CL` | AMA syslog/API |
| 17 | SpyCloud × Entra ID | `SigninLogs` | Entra ID → Diagnostic Settings |

### Advanced Correlation (5 Rules)

| # | Rule | Sev | What It Detects |
|---|------|-----|-----------------|
| 18 | Credential + Recent Sign-In | High | Exposed user signed in within 24h — active takeover risk |
| 19 | Breach Source Enrichment | Medium | Joins watchlist with catalog for breach_title context |
| 20 | Executive / VIP Exposure | High | CEO/CFO/CISO/admin accounts exposed |
| 21 | Password Reuse Across Domains | High | Same password hash for 3+ target domains |
| 22 | Stale Exposure (7+ Days) | Medium | SLA/compliance — unresolved beyond window |

### Cross-Data Correlation (6 Rules)

| # | Rule | Correlates With | What It Detects |
|---|------|----------------|-----------------|
| 23 | SpyCloud × DNS | `DnsEvents` | Infected users resolving malicious target domains |
| 24 | SpyCloud × Network | `DeviceNetworkEvents` | Infected IPs appearing in network traffic |
| 25 | SpyCloud × MDE Devices | `DeviceInfo` | Infected hostnames found in Defender inventory |
| 26 | SpyCloud × MDE Alerts | `AlertInfo` + `AlertEvidence` | Exposure correlated with active Defender alert |
| 27 | SpyCloud × Cloud Apps | `CloudAppEvents` | Compromised user downloading/sharing files in SaaS |
| 28 | SpyCloud × Entra Risk | `AADUserRiskEvents` | Exposed user also flagged risky by Microsoft |

---

## Notification & Ticketing Integrations

All integrations are **conditional** — only fire when the corresponding URL or email is configured. Leave blank to skip.

| Channel | Playbooks | Health Monitoring | How to Configure |
|---------|:---------:|:-----------------:|-----------------|
| **Slack** | All 4 | ✅ | `slackWebhookUrl` — api.slack.com → Incoming Webhooks |
| **MS Teams** | All 4 | ✅ | `teamsWebhookUrl` — Teams channel → Connectors → Incoming Webhook |
| **Email** | All 4 | ✅ | `notificationEmail` — sends via Microsoft Graph sendMail |
| **ServiceNow** | CredResponse | — | `serviceNowInstance` — REST API to /api/now/table/incident |
| **Jira** | CredResponse | — | `jiraWebhookUrl` — Jira Automation → Incoming Webhook |
| **Azure DevOps** | CredResponse | — | `azureDevOpsWebhookUrl` — DevOps Service Hooks |

### Notification Matrix

| Playbook | Slack | Teams | Email | ServiceNow | Jira | DevOps |
|----------|:-----:|:-----:|:-----:|:----------:|:----:|:------:|
| MDE Device Isolation | ✅ | ✅ | ✅ | — | — | — |
| CA Identity Protection | ✅ | ✅ | ✅ | — | — | — |
| Credential Response | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MDE Blocklist | ✅ | ✅ | ✅ | — | — | — |
| Health Monitoring | ✅ | ✅ | ✅ | — | — | — |

---

## Sentinel Workbook Dashboard

**22 visualizations** across **8 sections**. Find at: Sentinel → Workbooks → **SpyCloud Threat Intelligence Dashboard**

> **All charts render gracefully before data flows.** Every query uses `union isfuzzy=true` with typed `datatable()` fallbacks — tiles show zeros, tables show empty, health shows "🔴 No Data" status. Once the connector is activated, real data replaces the defaults within 5–10 minutes.

### Executive Summary
- **Exposure Tiles** — 8 KPIs: total exposures, unique users, infected devices, sev 25, sev 20, plaintext passwords, MDE actions, CA actions
- **Exposure Trend** — Area chart showing daily exposure count by severity (color-coded)
- **Severity Distribution** — Pie chart: P1 Critical / P1 High / P3 Standard / P4 Low
- **Breach Category** — Pie chart: infostealer / phished / breach / unknown

### Credential Exposure Analysis
- **Top 25 Exposed Users** — Table with severity indicators, exposure count, plaintext passwords, domains, sources
- **Password Types** — Bar chart: MD5, SHA1, bcrypt, plaintext, unknown
- **Top Targeted Domains** — Bar chart with exposure count and unique user count
- **Top Email Domains** — Bar chart showing most-exposed organizational domains

### Device Forensics
- **Top 25 Infected Devices** — Table with hostname, user count, severity, domains
- **Malware Families** — Bar chart from breach catalog: Vidar, LummaC2, RedLine, RisePro, etc.
- **Infections by Country** — Bar chart geographic distribution
- **OS Distribution** — Pie chart of infected device operating systems

### PII & Identity
- **PII Types Exposed** — Bar chart: emails, phones, SSNs, DOBs, addresses, full names

### Remediation
- **Remediation Tiles** — MDE isolations, CA resets, high-severity users, critical devices
- **MDE Timeline** — Area chart of device isolation actions over time
- **CA Timeline** — Area chart of password reset/revoke actions over time

### Compass Consumer Intelligence
- **Compass Exposures by Category** — Bar chart of consumer identity exposures by breach type
- **Top Compass Infected Devices** — Table with hostname, OS, infection count, app count
- **Compass + Corporate Overlap** — Table showing users in both consumer and corporate datasets

### Breach Catalog
- **Recent Entries** — Table showing top 50 breach sources with IDs, titles, status

### Connector Health
- **Pipeline Status** — Table per table: record count, earliest/latest, age, status indicator (🟢/🟡/🟠/🔴)
- **Daily Ingestion Volume** — Bar chart of watchlist + catalog records per day

---

## Sentinel Hunting Queries

**8 saved hunting queries** available in Sentinel → Hunting → filter "SpyCloud":

| Hunt | What It Finds | Tables |
|------|-------------|--------|
| Exposed Users with Active Sign-Ins | Highest priority — stolen creds + recent logins | Watchlist + SigninLogs |
| Infected IPs Across Network | Network-wide sweep across MDE, DNS, firewall, TI | Watchlist + 4 network tables |
| Password Reuse Across Domains | Same password hash on 3+ domains | Watchlist |
| Devices Infected Multiple Times | Failed remediation or persistent compromise | Watchlist |
| Plaintext Passwords by Domain | Immediate-access credentials by organization | Watchlist |
| Compass + Corporate Overlap | Consumer credential reuse in corporate accounts | Compass + Watchlist |
| Unremediated High-Severity | Sev 20+ without password reset | Watchlist + CA Logs |
| Risk Score Dashboard | Composite score per user: severity + plaintext + devices + recency | Watchlist |

## VIP/Executive Watchlist

Editable Sentinel Watchlist (`SpyCloud-VIP-Watchlist`) for executive email monitoring. Rule #20 dynamically queries this list — add/remove VIPs in Sentinel → Watchlists without editing KQL.

Default entries: CEO, CFO, CTO, CISO, IT Admin. Edit to match your organization.

---

## Security Copilot Integration

### Plugin — 42 KQL Skills

| Category | Skills | What They Do |
|----------|--------|-------------|
| User Investigation | 4 | Credential lookup, PII profile, activity timeline, exposed passwords |
| Password Analysis | 3 | Plaintext scan, type breakdown, crackability assessment |
| Severity & Domain | 3 | High-severity filter, distribution, domain exposure map |
| PII & Social | 3 | SSN/financial scan, social media accounts, targeted domains |
| Device Forensics | 4 | Infected device inventory, malware details, user mapping, AV gaps |
| Breach Catalog | 2 | Recent breaches, enriched exposure with catalog metadata |
| MDE Remediation | 3 | All MDE actions, per-device status, statistics |
| CA Remediation | 3 | All CA actions, per-user status, statistics |
| Cross-Table | 3 | Full investigation, geographic analysis, health dashboard |

### Agent — 30 Interactive Skills

**Example prompts:** "Show our dark web exposure" · "Investigate john@company.com" · "Which devices are infected?" · "Do we have plaintext passwords exposed?" · "What users have credentials in 3+ breaches?" · "Show remediation gaps"

### New Skills (v8.5)

| Category | Skills | Capabilities |
|----------|--------|-------------|
| Compass Investigation | 4 | Consumer exposure search, device inventory, corporate overlap, reinfection detection |
| Cross-Connector Hunting | 4 | Sign-in hunting, email activity, Azure resource changes, network-wide IP sweep |
| Risk Scoring | 3 | Per-user composite risk score, org-wide dashboard, priority action items for SOC |

**Example prompts:** "What's the risk score for john@company.com?" · "Show me priority actions for our SOC right now" · "Hunt all network logs for SpyCloud infection IPs" · "Which Compass devices are reinfected?" · "Show organization risk summary"

Upload: `copilot/SpyCloud_Plugin.yaml` → Sources → Custom Plugin · `copilot/SpyCloud_Agent.yaml` → Build → Upload YAML

---

## Cross-Data-Source Correlation

Maximize visibility by enabling these additional Sentinel connectors:

| Connector | Install From | What SpyCloud Enables |
|-----------|-------------|----------------------|
| **Entra ID** | Diagnostic Settings → SignInLogs | Rules #17, #18 — compromised credential + recent sign-in |
| **Microsoft Defender XDR** | Content Hub | Rules #25, #26 — device inventory + alert correlation |
| **DNS** | Azure Monitor Agent | Rule #23 — infected user DNS resolution tracking |
| **Okta SSO** | Content Hub | Rule #14 — exposed creds in Okta sign-ins |
| **Cisco Duo** | Content Hub | Rule #15 — exposed creds in Duo MFA |
| **Ping Identity** | AMA syslog/API | Rule #16 — exposed creds in Ping auth |
| **Microsoft 365** | Content Hub | Compromised user email/file access |
| **Defender for Cloud Apps** | Content Hub | Rule #27 — SaaS activity after exposure |
| **Azure AD Identity Protection** | Built-in | Rule #28 — cross-reference with Entra risk levels |
| **Threat Intelligence** | Content Hub | SpyCloud IOCs matched against TI feeds |

---

## Severity Reference

| Sev | Priority | Category | Contains | Response |
|-----|----------|----------|----------|----------|
| **25** | 🔴 P1 Critical | Infostealer + App | Cookies, sessions, autofill, browser data | Immediate: revoke sessions, reset password, isolate device, investigate |
| **20** | 🔴 P1 High | Infostealer | Email + password stolen by malware | Urgent: reset password, check device health |
| **5** | 🟠 P3 Standard | Breach + PII | Credential + name, phone, DOB, address | Monitor: review scope, check credential reuse |
| **2** | ⚪ P4 Low | Breach Credential | Email + password from third-party breach | Awareness: check reuse patterns |

---

## Use Cases

### 1. Proactive Infostealer Remediation
SpyCloud detects a severity 25 infection (LummaC2 stealer captured browser cookies, passwords, and autofill data). The MDE Blocklist playbook auto-isolates the device in Defender within minutes. SOC receives Slack + Teams alerts. ServiceNow ticket created for incident management.

### 2. Compromised Executive Protection
Rule #20 detects the CFO's credentials in a phishing kit dataset. The Credential Response playbook checks recent sign-in activity, forces password reset, revokes all sessions, and creates a Jira issue for the security team's VIP response process.

### 3. Post-Breach Credential Sweep
After a third-party vendor breach, SpyCloud ingests the exposed credentials. Rules #7 (multi-domain) and #21 (password reuse) identify employees reusing the same password across corporate and personal accounts. CA playbook enforces MFA and adds users to a conditional access group.

### 4. Compliance & SLA Monitoring
Rule #22 alerts when exposures remain unresolved for 7+ days. Rule #10 alerts when no automated remediation fires within 2 hours. The workbook Remediation section provides executives with real-time SLA compliance metrics.

### 5. Cross-Platform Threat Hunting
Rule #23 (DNS) detects an infected user resolving domains matching SpyCloud's target_domain field. Rule #24 (Network) finds the infection source IP in your network traffic. Rule #25 (MDE Devices) confirms the machine is in your Defender inventory. Combined investigation through Security Copilot provides a complete infection-to-remediation timeline.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| **401 Unauthorized on Connect** | Wrong auth header | Fixed in v7.3 — connector uses `X-Api-Key` header |
| **403 Forbidden on Connect** | API key doesn't have enterprise-v2 access | Use Enterprise API key from portal.spycloud.com |
| **No data after connecting** | Normal startup delay | Wait 5–10 minutes, then check connector status |
| **"Workspace not onboarded to Sentinel"** | Sentinel wasn't enabled | Fixed — OnboardingStates API auto-enables Sentinel |
| **"RoleAssignmentUpdateNotPermitted"** | Static role assignment GUIDs | Fixed — removed all role assignments from template |
| **"show_plain_password expected String"** | CCF sends dropdowns as arrays | Fixed — type=array for all dropdown params |
| **Workbook "no results"** | Tables empty until data flows | Activate connector first, wait 5–10 min |
| **KQL parse error line 7 pos 24** | datatable() comma syntax | Fixed — all queries rewritten without datatable fallbacks |
| **"Invalid hidden-title tag"** | displayName ≠ hidden-title | Fixed — both set to same value |
| **"Unable to parse @type"** | ARM interprets @type as expression | Fixed — escaped to @@type/@@context |
| **"runAfter non-existent action"** | Deleted action left dangling reference | Fixed — all runAfter chains validated |
| **Logic Apps not triggering** | Missing API permissions | Grant admin consent: Entra ID → Enterprise Apps → Managed Identities |

---

## Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                    ← ARM template (45 params, 47 resources)
├── azuredeploy.parameters.json         ← Sample parameters file
├── createUiDefinition.json             ← Portal wizard (32 outputs, 3 pages)
├── README.md                           ← This file
├── .gitignore
│
├── .github/workflows/
│   └── deploy.yml                      ← GitHub Actions CI/CD (validate → deploy → configure)
│
├── scripts/
│   ├── deploy-all.sh                   ← Interactive guided deployment (9 phases)
│   ├── post-deploy.sh                  ← Standalone RBAC + API permissions (7 phases)
│   └── verify-deployment.sh            ← 10-section health check with portal links
│
├── copilot/
│   ├── SpyCloud_Plugin.yaml            ← Security Copilot plugin (42 KQL skills)
│   └── SpyCloud_Agent.yaml             ← Interactive Copilot agent (30 skills)
│
├── workbooks/
│   └── SpyCloud-ThreatIntel-Dashboard.json ← Sentinel workbook (19 charts)
│
└── docs/
    ├── images/
    │   ├── SpyCloud-Logo-white.png     ← White logo (dark backgrounds)
    │   ├── SpyCloud_wordmark-black.png ← Black wordmark (light backgrounds)
    │   └── SpyCloud-icon-SC_2.png      ← SC icon (connector, Logic Apps, Teams cards)
    ├── architecture.md                 ← Detailed architecture documentation
    └── azure-sp-setup.md              ← Service principal setup for GitHub Actions
```

---

## Roadmap

| Status | Feature |
|--------|---------|
| 🟢 Shipped | 4 playbooks with Slack + Teams + Email + ServiceNow + Jira + Azure DevOps |
| 🟢 Shipped | 38 analytics rules (13 core + 4 IdP + 5 advanced + 6 cross-data) |
| 🟢 Shipped | 19-chart workbook dashboard across 8 sections |
| 🟢 Shipped | Health monitoring: Action Group with Email + Teams + Slack |
| 🟢 Shipped | Security Copilot plugin (28 skills) + agent (30 skills) |
| 🟢 Shipped | Configurable connector: polling, retries, timeout, lookback (365 days) |
| 🟢 Shipped | X-Api-Key auth, OnboardingStates, no role assignments, no Key Vault |
| 🟢 Shipped | GitHub Actions CI/CD, verify script, deploy-all script |
### Extended Cross-Data Correlation (10 Rules — NEW in v8.5)

| # | Rule | Correlates With | What It Detects |
|---|------|----------------|-----------------|
| 29 | SpyCloud × Office 365 | `OfficeActivity` | Exposed user creating mail forwarding rules |
| 30 | SpyCloud × Email | `EmailEvents` | Phishing campaigns targeting exposed users |
| 31 | SpyCloud × Identity | `IdentityLogonEvents` | Lateral movement by exposed users |
| 32 | SpyCloud × TI | `ThreatIntelligenceIndicator` | Infection IPs matching threat intelligence feeds |
| 33 | SpyCloud × UEBA | `BehaviorAnalytics` | Anomalous behavior from exposed users |
| 34 | SpyCloud × Azure | `AzureActivity` | Exposed user modifying cloud resources |
| 35 | SpyCloud Compass | `SpyCloudCompassData_CL` | Consumer + corporate credential overlap |
| 36 | SpyCloud × Firewall | `CommonSecurityLog` | Infected IPs in CEF/syslog firewall logs |
| 37 | SpyCloud × Impossible Travel | `SigninLogs` | Sign-in from different country than infection |
| 38 | SpyCloud Compass Devices | `SpyCloudCompassDevices_CL` | Device reinfection detection |

| 🟡 Next | Jupyter notebooks: Exposure Investigation, Infection Analysis, Org Report |
| 🟡 Next | Enhanced Copilot: cross-data chained investigation, hunt queries |
| 🟡 Next | Additional workbooks: Executive Summary, SOC Operations, Compliance |
| 🔵 Planned | EU API region support (currently hardcoded US) |
| 🔵 Planned | MCP integrations: Atlassian Jira, Gmail, Slack (direct MCP) |
| 🔵 Planned | A2A agent orchestration for multi-step cross-platform remediation |
| 🔵 Planned | Custom VIP/executive watchlist with elevated alerting |
| 🔵 Planned | Hugging Face ML-based credential risk scoring |
| ⚪ Future | Auto-connector activation (pending Sentinel CCF platform support) |
| ⚪ Future | SOAR notebook for guided investigation workflows |
| ⚪ Future | Context7 MCP for live API documentation in Copilot |

---

<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" width="140" style="background:#0D1B2A;padding:10px;border-radius:6px"/>
  <br/><br/>
  <sub>© 2026 SpyCloud, Inc. All rights reserved.</sub><br/>
  <sub><em>SpyCloud transforms recaptured darknet data to disrupt cybercrime.</em></sub><br/>
  <sub><em>Trusted by 7 of the Fortune 10 and hundreds of global enterprises.</em></sub>
</p>
