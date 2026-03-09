<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" alt="SpyCloud" width="340" style="background:#0D1B2A;padding:24px;border-radius:10px"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence & Automated Response for Microsoft Sentinel</h3>

<p align="center">
  <em>Transform 600B+ recaptured darknet records into automated identity threat protection.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-5.0-00B4D8?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/resources-96-0D1B2A?style=for-the-badge&logo=microsoftazure"/>
  <img src="https://img.shields.io/badge/copilot-70%2B%20skills-E07A5F?style=for-the-badge&logo=microsoft"/>
  <img src="https://img.shields.io/badge/playbooks-5-2D6A4F?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/analytics-44%20rules-415A77?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/hunting-15%20queries-6B4C9A?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/integrations-6-D4A843?style=for-the-badge"/>
</p>

---

## What This Does

SpyCloud monitors the criminal underground — breaches, infostealers, phishing kits — recapturing stolen credentials, session cookies, PII, and device fingerprints before attackers can use them. This solution brings that intelligence into Microsoft Sentinel and automatically responds: isolating infected devices in Defender, resetting compromised passwords in Entra ID, revoking active sessions, enriching incidents with VirusTotal/AbuseIPDB threat intelligence, and notifying your SOC through 6 channels.

**One deployment. 96 resources. 44 analytics rules. 15 hunting queries. 5 automated playbooks. Fusion ML detection. UEBA behavioral analytics. Zero stored credentials.**

---

## Table of Contents

- [Architecture](#architecture)
- [What Gets Deployed (96 Resources)](#what-gets-deployed-96-resources)
- [Prerequisites](#prerequisites)
- [Licensing Matrix](#licensing-matrix)
- [Deployment (4 Methods)](#deployment)
- [Post-Deployment Configuration](#post-deployment-configuration)
- [Recommended Data Connectors](#recommended-data-connectors)
- [5 Automated Playbooks](#5-automated-playbooks)
- [44 Analytics Rules](#44-analytics-rules)
- [15 Hunting Queries](#15-hunting-queries)
- [4 Automation Rules](#4-automation-rules)
- [4 Watchlists](#4-watchlists)
- [Sentinel Platform Settings](#sentinel-platform-settings)
- [Sentinel Workbook Dashboard](#sentinel-workbook-dashboard)
- [Security Copilot Integration](#security-copilot-integration)
- [Notification & Ticketing Integrations](#notification--ticketing-integrations)
- [Severity Reference](#severity-reference)
- [Troubleshooting](#troubleshooting)
- [Repository Structure](#repository-structure)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         SPYCLOUD DARKNET INTELLIGENCE                            │
│         Breaches · Infostealers · Phishing Kits · Session Hijacking              │
│                    600B+ recaptured records · 500+ sources                        │
│                         api.spycloud.io (REST API)                               │
└──────────────────────────────┬───────────────────────────────────────────────────┘
                               │ HTTPS GET (every 30 min)
                               │ Cursor-based pagination
                               ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          MICROSOFT SENTINEL (96 Resources)                       │
│                                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────┐   │
│  │               CCF Connector (5 REST API Pollers)                          │   │
│  │  Watchlist New · Watchlist Modified · Breach Catalog                      │   │
│  │  Compass Data (Enterprise+) · Compass Devices (Enterprise+)              │   │
│  └───────────────────────────┬───────────────────────────────────────────────┘   │
│                               ▼                                                  │
│  ┌──────────────┐  ┌──────────────────────────────────────────────────────────┐  │
│  │   DCE         │  │           DCR (KQL Transforms → 6 Custom Tables)        │  │
│  │   HTTPS       │──│  SpyCloudBreachWatchlist_CL  (73 cols)                  │  │
│  │   Ingest      │  │  SpyCloudBreachCatalog_CL    (13 cols)                  │  │
│  │   Endpoint    │  │  SpyCloudCompassData_CL      (29 cols)                  │  │
│  └──────────────┘  │  SpyCloudCompassDevices_CL    (8 cols)                   │  │
│                     │  Spycloud_MDE_Logs_CL         (19 cols)                  │  │
│                     │  SpyCloud_ConditionalAccessLogs_CL (14 cols)             │  │
│                     └──────────────────────┬─────────────────────────────────┘  │
│                                            │                                    │
│  ┌─────────────────────────────────────────┼──────────────────────────────────┐ │
│  │                                         ▼                                  │ │
│  │  44 Analytics Rules ──▶ Incidents ──▶ 4 Automation Rules ──▶ 5 Playbooks  │ │
│  │  (38 Scheduled + 1 Fusion + 5 MSIC)   (auto-triage, tasks, close)        │ │
│  │                                                                            │ │
│  │  15 Hunting Queries    4 Watchlists    UEBA + Anomalies + Fusion          │ │
│  │  1 Workbook (19+ viz)  Copilot (70+ skills)   TI Enrichment Playbook     │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │  5 Playbooks: MDE Isolate · CA Reset · Credential Response ·              │  │
│  │               MDE Blocklist · TI Enrichment (VT + AbuseIPDB)              │  │
│  │  ──▶ MDE API · Graph API · Slack · Teams · Email · ServiceNow · Jira     │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## What Gets Deployed (96 Resources)

| Category | Count | Details |
|----------|-------|---------|
| **CCF Data Connector** | 1 definition + 5 pollers | Watchlist New, Watchlist Modified, Breach Catalog, Compass Data, Compass Devices |
| **Custom Tables** | 6 | 156 columns total across all tables |
| **Analytics Rules (Scheduled)** | 38 | SpyCloud + Entra ID, MDE, Office 365, DNS, TI, UEBA, Okta, Duo, Ping, Firewall, Cloud Apps, Compass |
| **Analytics Rules (Fusion)** | 1 | Advanced Multistage Attack Detection (ML correlation) |
| **Analytics Rules (MSIC)** | 5 | Defender XDR, Entra ID Protection, Defender for Cloud, MCAS, Defender for Identity |
| **Hunting Queries** | 15 | Session cookies, lateral movement, data exfil, mailbox, priv esc, malware trends, breach impact |
| **Playbooks (Logic Apps)** | 5 | MDE Isolation, CA Reset, Credential Response, MDE Blocklist, TI Enrichment |
| **Automation Rules** | 4 | Auto-trigger, auto-escalate critical, auto-task devices, auto-close informational |
| **Watchlists** | 4 | VIP/Executive, IOC Blocklist, Approved Domains, High-Value Assets |
| **Sentinel Settings** | 4 | UEBA (EntityAnalytics + Ueba), Anomaly Detection, EyesOn |
| **Workbook** | 1 | 19+ interactive visualizations |
| **Infrastructure** | 12 | DCE, DCR, workspace, onboarding, content package, templates, metadata, action group, API connection |
| **Total** | **96** | All deployable via single ARM template |

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Azure Subscription** | Contributor role on the target resource group |
| **Microsoft Sentinel** | Enabled on a Log Analytics workspace (or template creates one) |
| **SpyCloud API Key** | Enterprise Protection subscription — [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys |
| **Network** | Outbound HTTPS (443) to `api.spycloud.io` — no inbound rules required |

### Required Azure RBAC Roles

| Role | Scope | Purpose |
|------|-------|---------|
| **Microsoft Sentinel Contributor** | Workspace | Create analytics rules, automation rules, watchlists, hunting queries |
| **Log Analytics Contributor** | Workspace | Create tables, DCR, DCE |
| **Monitoring Metrics Publisher** | DCR | Required for data ingestion via DCE |
| **Logic App Contributor** | Resource Group | Deploy and manage playbooks (if enabling playbooks) |
| **Managed Identity Operator** | Resource Group | Assign managed identity to Logic Apps (if enabling playbooks) |
| **Security Administrator** | Workspace | Configure UEBA/EntityAnalytics settings (if enabling UEBA) |

### Validate Permissions

```bash
# Check your current roles
az role assignment list \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --query '[].{Role:roleDefinitionName, Scope:scope}' -o table

# Assign missing roles (requires Owner/User Access Administrator)
SUB_ID=$(az account show --query id -o tsv)
RG="your-resource-group"
USER_ID=$(az ad signed-in-user show --query id -o tsv)
az role assignment create --assignee $USER_ID --role 'Microsoft Sentinel Contributor' --scope /subscriptions/$SUB_ID/resourceGroups/$RG
az role assignment create --assignee $USER_ID --role 'Log Analytics Contributor' --scope /subscriptions/$SUB_ID/resourceGroups/$RG
az role assignment create --assignee $USER_ID --role 'Logic App Contributor' --scope /subscriptions/$SUB_ID/resourceGroups/$RG
```

---

## Licensing Matrix

### Works Without Extra Licenses (Microsoft Sentinel Only)

| Component | License | Status |
|-----------|---------|--------|
| 5 SpyCloud data pollers (CCF connector) | SpyCloud Enterprise API key | Required |
| 6 custom log tables (156 columns) | Azure Monitor (included with Sentinel) | Included |
| 44 analytics rules + Fusion + MSIC | Microsoft Sentinel | Included |
| 15 hunting queries | Microsoft Sentinel | Included |
| 4 watchlists | Microsoft Sentinel | Included |
| 4 automation rules | Microsoft Sentinel | Included |
| UEBA, Anomaly Detection, EyesOn | Microsoft Sentinel | Included |
| Workbook dashboard (19+ visualizations) | Microsoft Sentinel | Included |
| 6 notification channels (Slack/Teams/Email/ServiceNow/Jira/DevOps) | None | Included |
| TI Enrichment playbook | VirusTotal free API key | Free |
| 70+ Copilot skills | Security Copilot license | Separate license |

### Playbook License Requirements

| Playbook | License Required | Cost | What Happens Without It |
|----------|-----------------|------|------------------------|
| **MDE Device Isolation** | Defender for Endpoint P2 | ~$5.20/user/month (incl. in M365 E5) | Deploys but isolation returns 403 |
| **MDE Blocklist** | Defender for Endpoint P2 | Same as above | Deploys but blocklist updates fail |
| **CA Identity Protection** | Entra ID P1+ | P1 ~$6/user/month (incl. in M365 E3) | Deploys but password reset fails |
| **Credential Response** | Entra ID P1+ | Same as above | Notifications work, reset fails |
| **TI Enrichment** | None (free APIs) | Free | Fully functional |

### MSIC Rule Dependencies

| MSIC Rule | Required Product | Included In |
|-----------|-----------------|-------------|
| Defender XDR | Microsoft 365 E5, E5 Security, or standalone Defender plans | M365 E5 |
| Entra ID Protection | Microsoft Entra ID P2 | M365 E5 |
| Defender for Cloud | Microsoft Defender for Cloud (per-resource pricing) | Separate |
| Cloud App Security | Microsoft Defender for Cloud Apps | M365 E5 |
| Defender for Identity | Microsoft Defender for Identity (~$5.50/user/month) | M365 E5 |

> **Note:** MSIC rules deploy regardless of licensing. Without the corresponding product, the rule simply has no source alerts to create incidents from.

---

## Deployment

### Method 1: Azure Portal (Recommended)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

The portal wizard has **6 pages**:

| Page | What You Configure |
|------|--------------------|
| **1. Workspace & SpyCloud API** | Create/select workspace, set retention, configure SpyCloud API key |
| **2. Playbooks & Automation** | Toggle 5 playbooks, configure MDE isolation type, CA group, blocklist schedule, analytics rules |
| **3. Security & Integrations** | Workbook, resource tags, 6 SOC notification channels, IdP correlation (Okta/Duo/Ping) |
| **4. Sentinel Platform Settings** | UEBA, Anomaly Detection, Fusion, 5 MSIC rules, TI Enrichment playbook + VirusTotal key |
| **5. Prerequisites & Licensing** | Pre-deployment validation checklist, licensing matrix by feature, permission validation commands |
| **6. Connector & Integration Guide** | Tier 1-3 recommended connectors with step-by-step setup instructions, post-deployment features |

### Method 2: Azure CLI

```bash
az login
az group create --name spycloud-sentinel --location eastus

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
    enableTiEnrichmentPlaybook=true \
    enableAnalyticsRule=true \
    enableUEBA=true \
    enableAnomalies=true \
    enableFusionRule=true \
    enableMicrosoftSecurityIncidentRules=true \
    enableWorkbook=true
```

### Method 3: PowerShell

```powershell
Connect-AzAccount
New-AzResourceGroup -Name "spycloud-sentinel" -Location "eastus"

New-AzResourceGroupDeployment `
  -Name "SpyCloud-v5.0" `
  -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "my-sentinel-ws" `
  -enableMdePlaybook $true `
  -enableCaPlaybook $true `
  -enableTiEnrichmentPlaybook $true `
  -enableUEBA $true `
  -enableFusionRule $true `
  -enableMicrosoftSecurityIncidentRules $true
```

### Method 4: Guided Deployment Script

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```

---

## Post-Deployment Configuration

### Immediate (Day 1)

1. **Grant playbook permissions** — Run `scripts/grant-permissions.sh` from Cloud Shell
2. **Verify data ingestion** — Check all 6 tables have data (query in connector Step 7)
3. **Review analytics rules** — Sentinel → Analytics → filter "SpyCloud" → enable rules
4. **Populate watchlists** — Add your VIP emails, corporate domains, high-value assets, known IOCs
5. **Upload Copilot files** — Security Copilot → Settings → Custom Plugins → Upload YAML files

### Week 1 Tuning

1. Enable analytics rules in phases — start with severity 20+ infostealer rules
2. Configure VIP watchlist with executive/admin email addresses
3. Review incident volume and adjust thresholds if needed
4. Test playbooks manually with a sample incident

### Ongoing Operations

| Frequency | Action |
|-----------|--------|
| **Daily** | Review SpyCloud incidents, triage infostealer alerts (severity 20+) first |
| **Weekly** | Check workbook for exposure trends, review top-exposed domains and users |
| **Monthly** | Review playbook execution logs, update VIP watchlist, assess remediation rates |
| **Quarterly** | Review data retention, assess API usage, evaluate Compass data value, rotate API key |

---

## Recommended Data Connectors

These connectors are **not deployed by this template** but are **strongly recommended** for maximum SpyCloud detection coverage.

### Tier 1: Critical (Required for Core SpyCloud Rules)

| Connector | Cost | SpyCloud Rules Enabled | Setup |
|-----------|------|----------------------|-------|
| **Microsoft Entra ID** | Free | #6, #7, #10, #18, #29 + 7 hunting queries | Entra ID → Diagnostic Settings → Send to LAW |
| **Microsoft Defender XDR** | M365 E5 | #11, #12, #13, Fusion source, lateral movement hunting | Content Hub → Microsoft Defender XDR → Install |
| **Azure Activity** | Free | #2 (cloud admin activity), UEBA data source | Data Connectors → Azure Activity → Policy assignment |
| **Office 365** | Free (M365) | #14 (email compromise), mailbox hunting, data exfil hunting | Data Connectors → Office 365 → Enable Exchange/SharePoint/Teams |

### Tier 2: High Value (Advanced Correlation)

| Connector | Cost | SpyCloud Integration | Setup |
|-----------|------|---------------------|-------|
| **Defender for Cloud** | Per-resource | MSIC rule, Fusion source | Defender for Cloud → Continuous Export to LAW |
| **Cloud App Security** | M365 E5 | MSIC rule, impossible travel, OAuth abuse | Content Hub → Microsoft Defender for Cloud Apps |
| **Defender for Identity** | ~$5.50/user/mo | MSIC rule, pass-the-hash, golden ticket | Content Hub → Microsoft Defender for Identity |
| **DNS Analytics** | Free (Windows DNS) | #3 (DNS + infected IP correlation) | Content Hub → DNS → Configure AMA agent |
| **Threat Intelligence (TAXII)** | Free | #17 (TI cross-reference), Fusion source | Data Connectors → TI - TAXII → Configure |

### Tier 3: Extended Coverage

| Connector | SpyCloud Rule | Setup |
|-----------|--------------|-------|
| **Okta SSO** | #15 (Okta sign-in from exposed user) | Content Hub → Okta Single Sign-On |
| **Cisco Duo** | #4 (Duo auth from exposed user) | Content Hub → Cisco Duo Security |
| **Palo Alto Networks** | #32 (firewall + infected IP), Fusion source | Content Hub → Palo Alto Networks |
| **AWS CloudTrail** | Multi-cloud compromised account detection | Content Hub → Amazon Web Services |
| **CrowdStrike Falcon** | Alternative EDR correlation | Content Hub → CrowdStrike Falcon |

---

## 5 Automated Playbooks

| # | Playbook | Trigger | Actions | License |
|---|----------|---------|---------|---------|
| 1 | **MDE Device Isolation** | Incident creation | Isolate device, apply security tag, log to `Spycloud_MDE_Logs_CL` | MDE P2 |
| 2 | **CA Identity Protection** | Incident creation | Force password reset, revoke sessions, add to CA group, log to `SpyCloud_ConditionalAccessLogs_CL` | Entra P1+ |
| 3 | **Credential Response** | Incident creation | UPN-based targeted reset + Teams/Slack/Email/ServiceNow/Jira/DevOps notifications | Entra P1+ |
| 4 | **MDE Blocklist** | Scheduled (every 1-24 hours) | Scan for severity 25 matches, block malicious IPs/domains via MDE custom indicators | MDE P2 |
| 5 | **TI Enrichment** | Incident creation | VirusTotal IP lookup + AbuseIPDB check, adds enrichment as incident comment | Free APIs |

### Granting Playbook Permissions

```bash
# From Cloud Shell:
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh | bash -s -- -g YOUR-RG -w YOUR-WS

# Or manually:
# Entra ID → Enterprise Applications → filter "Managed Identities" → find SpyCloud Logic Apps → Permissions → Grant admin consent
```

---

## 44 Analytics Rules

### Core SpyCloud Detection (13 rules)

| # | Rule | Severity | Trigger |
|---|------|----------|---------|
| 1 | Infostealer Detection (Primary) | High | severity >= 20 exposure detected |
| 2 | Exposed User Cloud Admin Activity | High | Exposed user + Azure Activity |
| 3 | DNS + SpyCloud Infected IP | Medium | Infected IP in DNS events |
| 4 | Duo Auth from Exposed User | High | SpyCloud + Duo sign-in |
| 5 | Password Reuse Across Domains | Medium | Same password hash on 3+ domains |
| 6 | Exposed User Active Sign-In | High | SpyCloud + successful Entra sign-in |
| 7 | Risky Sign-In After Exposure | High | SpyCloud + Entra risky sign-in |
| 8 | Plaintext Password Exposure | High | Plaintext passwords detected |
| 9 | Device Reinfection Pattern | High | Same machine_id in multiple sources |
| 10 | MFA Bypass via Session Cookies | Critical | severity 25 + session token theft |
| 11-13 | MDE Correlation (3 rules) | varies | SpyCloud + MDE devices/alerts/network |

### Cross-Connector Correlation (15 rules)

Rules correlating SpyCloud with: Entra Risk, Office 365, Cloud Apps, Okta, Ping Identity, UEBA, Firewall, Impossible Travel, TI feeds, Compass consumer data, Azure Activity, and more.

### Identity Provider Alerts (4 rules)

Cross-reference SpyCloud with Okta, Duo, Ping Identity, and Entra ID sign-in logs.

### Advanced Detection (6 rules)

VIP/executive exposure, new malware family detection, AV-present-but-failed, bulk credential theft, dark web marketplace listings, brand impersonation.

### Fusion + MSIC Rules (6 rules)

| Rule | Type | Source |
|------|------|--------|
| **Advanced Multistage Attack Detection** | Fusion (ML) | All Microsoft security products + SpyCloud scheduled rules |
| **Defender XDR Incidents** | MSIC | Microsoft 365 Defender alerts |
| **Entra ID Protection Incidents** | MSIC | Risky users/sign-ins |
| **Defender for Cloud Incidents** | MSIC | Azure Defender alerts |
| **Cloud App Security Incidents** | MSIC | MCAS alerts |
| **Defender for Identity Incidents** | MSIC | On-prem AD threat detections |

> All 38 scheduled SpyCloud rules deploy **disabled** by default for SOC review. Fusion, MSIC, and automation rules deploy **enabled**.

---

## 15 Hunting Queries

| # | Query | MITRE Tactic | What It Finds |
|---|-------|-------------|---------------|
| 1 | Exposed Users with Active Sign-Ins | Credential Access (T1078) | Users with stolen creds who logged in recently |
| 2 | Infected IPs Across All Network Logs | C2 (T1071) | Infected IPs in MDE, DNS, firewall, TI feeds |
| 3 | Password Reuse Across Domains | Credential Access (T1110) | Same password on 3+ target domains |
| 4 | Devices Infected Multiple Times | Persistence (T1547) | Unmediated or reinfected devices |
| 5 | Plaintext Passwords by Domain | Credential Access (T1552) | Cleartext password exposure aggregation |
| 6 | Compass + Corporate Overlap | Credential Access (T1078) | Consumer/personal credential reuse on corporate |
| 7 | Unremediated High-Severity Exposures | Initial Access (T1078) | Severity 20+ without CA playbook action |
| 8 | Risk Score Dashboard | Initial Access (T1078) | Composite risk scoring for prioritization |
| 9 | **Stolen Session Cookies / MFA Bypass** | Defense Evasion (T1539) | Token replay from multiple IPs |
| 10 | **Lateral Movement from Compromised Accounts** | Lateral Movement (T1021) | RDP/SMB to 3+ machines |
| 11 | **Data Exfiltration After Exposure** | Exfiltration (T1530) | Mass file downloads by exposed users |
| 12 | **Mailbox Compromise & Forwarding Rules** | Collection (T1114) | Inbox forwarding/redirect rules by exposed users |
| 13 | **Privilege Escalation by Compromised Users** | Privilege Escalation (T1098) | Role assignments, group additions, app consents |
| 14 | **Malware Family Trends** | Collection (T1005) | RedLine, LummaC2, Vidar, Raccoon, StealC tracking |
| 15 | **Third-Party Breach Impact Assessment** | Initial Access (T1078) | Organizational impact per breach source |

---

## 4 Automation Rules

| Rule | Trigger | Action | Default State |
|------|---------|--------|---------------|
| **Auto-Response** | Incident created by SpyCloud analytics rule | Triggers MDE + CA playbooks | Enabled |
| **Auto-Escalate Critical** | Incident title contains "Plaintext Password", "Session Cookies", "MFA Bypass" | Set severity to High, status to Active, add investigation task | Enabled |
| **Auto-Task Device Infections** | Incident title contains "Device", "Infection", "Reinfection" | Add 2 investigation tasks (device forensics + credential reset) | Enabled |
| **Auto-Close Informational** | Informational severity + "Antivirus Present" or "New Malware Family" | Close as BenignPositive, tag as SpyCloud-AutoClosed | **Disabled** |

---

## 4 Watchlists

| Watchlist | Key Field | Purpose |
|-----------|-----------|---------|
| **SpyCloud-VIP-Watchlist** | Email | VIP/executive accounts for priority alerting (Rule #20) |
| **SpyCloud-IOC-Blocklist** | Indicator | Malicious IPs/domains/URLs from infostealer data |
| **SpyCloud-Approved-Domains** | Domain | Corporate email domains for analytics rule scoping |
| **SpyCloud-HighValue-Assets** | AssetName | Critical servers, DCs, VPN gateways for elevated monitoring |

---

## Sentinel Platform Settings

| Setting | What It Does | Deploys As |
|---------|-------------|------------|
| **EntityAnalytics** | Entra ID entity provider for user/entity profiling | `Microsoft.SecurityInsights/settings` (kind: EntityAnalytics) |
| **UEBA** | Behavioral analytics on SigninLogs, AuditLogs, AzureActivity, SecurityEvent | `Microsoft.SecurityInsights/settings` (kind: Ueba) |
| **Anomalies** | ML-powered anomaly detection rules | `Microsoft.SecurityInsights/settings` (kind: Anomalies) |
| **EyesOn** | Audit trail of analyst activity in Sentinel | `Microsoft.SecurityInsights/settings` (kind: EyesOn) |

---

## Sentinel Workbook Dashboard

19+ interactive visualizations across 8 sections:

1. **Executive Summary** — Total exposures, severity distribution, trend lines
2. **Credential Analysis** — Password types, plaintext exposure, reuse patterns
3. **Device Intelligence** — Infected devices, malware families, geographic distribution
4. **PII Exposure** — SSN, financial, health data breach notification assessment
5. **Remediation Tracking** — MDE isolation status, CA password reset status, gaps
6. **Breach Catalog** — Source intelligence, breach categories, record counts
7. **Domain Analysis** — Exposure by corporate domain, target domain analysis
8. **Health Monitoring** — Table ingestion rates, poller health, data freshness

---

## Security Copilot Integration

### Plugin (52 KQL Skills)

Upload `copilot/SpyCloud_Plugin.yaml` to Security Copilot → Settings → Custom Plugins.

**Skill categories:**
- User credential investigation (email lookup, password analysis, PII exposure)
- Breach metadata and intelligence (catalog queries, confidence scoring)
- Infostealer forensics and device tracking (malware families, machine IDs)
- Compass intelligence (consumer/partner exposure correlation)
- Remediation tracking (MDE isolation audit, CA reset audit)
- Cross-table correlation and hunting (multi-table joins, risk assessment)
- **UEBA correlation** (behavioral anomalies for exposed users)
- **Fusion incident analysis** (multistage attack investigation)
- **TI enrichment results** (VirusTotal/AbuseIPDB lookup results)
- **Automation rule metrics** (execution success/failure rates)
- **Session cookie theft hunting** (MFA bypass detection)
- **Lateral movement detection** (RDP/SMB from compromised accounts)
- **Data exfiltration detection** (mass downloads by exposed users)
- **Malware family tracking** (RedLine, LummaC2, Vidar trends)
- **Watchlist management** (IOC Blocklist, High-Value Assets, Approved Domains)
- **MSIC incident correlation** (Defender XDR/Entra/Cloud alerts)
- **Executive summary generation** (comprehensive reporting)

### Agent (9 Autonomous Agents + 31 KQL Skills)

Upload `copilot/SpyCloud_Agent.yaml` to Security Copilot → Settings → Custom Plugins.

**SENTINEL** is a personality-driven security analyst agent that:
- Handles typos, misspellings, and shorthand gracefully
- Provides proactive risk assessments and recommendations after every response
- Uses humor and personality while maintaining analytical precision
- Investigates autonomously across all 6 SpyCloud tables + Sentinel native tables
- Correlates with UEBA, Fusion, MSIC incidents, TI feeds, and all Microsoft security products

**Autonomous agent capabilities:**
1. **SpyCloud Investigation Agent** — Full-spectrum credential and exposure investigation
2. **UEBA Behavioral Analysis Agent** — Anomalous behavior correlation
3. **Fusion Multistage Attack Agent** — ML-detected attack chain investigation
4. **TI Enrichment & IOC Analysis Agent** — Threat intelligence correlation
5. **Session Cookie & MFA Bypass Agent** — Token replay and session hijacking
6. **Lateral Movement Investigation Agent** — RDP/SMB movement tracking
7. **Data Exfiltration Detection Agent** — Mass download and mailbox compromise
8. **Executive Summary & Compliance Agent** — Reporting and compliance assessment
9. **Watchlist & Asset Management Agent** — VIP, IOC, domain, and asset management

---

## Notification & Ticketing Integrations

| Channel | Parameter | Format |
|---------|-----------|--------|
| **Microsoft Teams** | `teamsChannelWebhook` | Incoming Webhook URL |
| **Slack** | `slackWebhookUrl` | Incoming Webhook URL |
| **Email** | `notificationEmail` | Email address |
| **ServiceNow** | `serviceNowInstance` | Instance URL (e.g., `https://company.service-now.com`) |
| **Jira** | `jiraWebhookUrl` | Automation Webhook URL |
| **Azure DevOps** | `azureDevOpsWebhookUrl` | Service Hook URL |

---

## Severity Reference

| Severity | Category | Risk Level | Recommended Response |
|----------|----------|-----------|---------------------|
| **2** | Breach Credential | Medium | Monitor, schedule password reset |
| **5** | Breach + PII | Medium-High | Password reset, PII review |
| **20** | Infostealer | High (URGENT) | Immediate password reset, device investigation |
| **25** | Infostealer + App Data | Critical | Session revocation, device isolation, full investigation |

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| No data after 15 minutes | API key invalid | Test: `curl -H 'X-Api-Key: KEY' https://api.spycloud.io/enterprise-v2/breach/catalog/1` |
| 401 Unauthorized | Wrong API tier | Ensure Enterprise (not SaaS) key from portal.spycloud.com |
| Compass tables empty | Need Enterprise+ | Compass endpoints require Enterprise+ subscription |
| Playbooks not triggering | Analytics rule disabled | Sentinel → Analytics → verify SpyCloud rules are Enabled |
| Playbooks failing (403) | Missing permissions | Run `scripts/grant-permissions.sh` |
| MDE playbook fails | No MDE P2 license | Device isolation requires Defender for Endpoint Plan 2 |
| CA playbook fails | No Entra P1+ | Password reset requires Entra ID P1 or P2 |
| High ingestion costs | Large watchlist | Reduce severity levels or increase polling interval |

### Diagnostic Queries

```kql
-- Overall health check (run first)
union
  (SpyCloudBreachWatchlist_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Watchlist'),
  (SpyCloudBreachCatalog_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Catalog'),
  (SpyCloudCompassData_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Compass Data'),
  (SpyCloudCompassDevices_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Compass Devices')
| project Table, Records, Latest | order by Table asc

-- Check connector health
SentinelHealth
| where OperationName contains 'SpyCloud' or OperationName contains 'DataConnector'
| where TimeGenerated > ago(1h)
| order by TimeGenerated desc

-- Automation rule health
SentinelHealth
| where SentinelResourceType == "Automation rule"
| where SentinelResourceName startswith "SpyCloud"
| summarize Executions=count(), Succeeded=countif(Status=="Success") by SentinelResourceName
```

---

## Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json              # Main ARM template (96 resources, 8000+ lines)
├── azuredeploy.parameters.json   # Parameter file template
├── createUiDefinition.json       # Azure Portal deployment wizard (6 pages)
├── README.md                     # This file
├── copilot/
│   ├── SpyCloud_Plugin.yaml      # Security Copilot plugin (52 KQL skills)
│   └── SpyCloud_Agent.yaml       # Security Copilot agent (9 agents + 31 KQL + personality)
├── docs/
│   ├── architecture.md           # Detailed deployment architecture
│   ├── ROADMAP.md                # Enhancement roadmap
│   ├── azure-sp-setup.md         # GitHub Actions service principal setup
│   └── images/                   # Logo and branding assets
├── scripts/
│   ├── deploy-all.sh             # Interactive guided deployment (v4.0)
│   ├── post-deploy.sh            # Post-deployment configuration
│   ├── verify-deployment.sh      # 10-section deployment verification
│   ├── grant-permissions.sh      # Playbook API permission grants
│   └── cleanup-tables.sh         # Table cleanup for redeployment
├── workbooks/
│   └── SpyCloud-ThreatIntel-Dashboard.json  # Workbook with 19+ visualizations
└── .github/
    └── workflows/
        └── deploy.yml            # GitHub Actions CI/CD deployment
```

---

## Support

- **SpyCloud API issues:** support@spycloud.com
- **Sentinel connector issues:** [Open a GitHub issue](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues)
- **Documentation:** [Architecture](docs/architecture.md) · [Roadmap](docs/ROADMAP.md)
