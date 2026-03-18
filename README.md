<div align="center">

<img src="docs/images/spycloud-sentinel-banner-dark.svg" alt="SpyCloud × Sentinel" width="720"/>

<br><br>

# SpyCloud Sentinel Supreme

### Darknet Identity Threat Intelligence for Microsoft Sentinel

**Recaptured credentials. Stolen cookies. Infected devices.**
**Detected in minutes — remediated automatically.**

<br>

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

<br>

![Version](https://img.shields.io/badge/v11.0-00C7B7?style=flat-square&logo=semver&logoColor=white)
![Tables](https://img.shields.io/badge/14_Tables-417_Columns-0078D4?style=flat-square)
![Rules](https://img.shields.io/badge/38_Analytics_Rules-FF3E00?style=flat-square)
![Copilot](https://img.shields.io/badge/400+_Copilot_Skills-6366F1?style=flat-square)
![Playbooks](https://img.shields.io/badge/5_Playbooks-22C55E?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

</div>

---

## What This Does

SpyCloud continuously recaptures data from the criminal underground — stolen credentials, session cookies, infostealer logs, and compromised PII. This solution ingests that intelligence directly into Microsoft Sentinel, correlates it with your existing security telemetry, and triggers automated remediation through Defender for Endpoint and Entra ID.

**The result:** When an employee's credentials appear on a dark web marketplace at 2:00 AM, their password is reset, sessions are revoked, and their device is isolated — all before anyone opens a laptop.

---

## Architecture

```
                        ┌─────────────────────────────────┐
                        │     SpyCloud Intelligence        │
                        │  ┌───────────┐  ┌────────────┐  │
                        │  │ Breach     │  │ Compass    │  │
                        │  │ Watchlist  │  │ Malware    │  │
                        │  │ Catalog    │  │ Devices    │  │
                        │  │ Identities │  │ Apps       │  │
                        │  └─────┬─────┘  └─────┬──────┘  │
                        └───────┬───────────────┬──────────┘
                                │  SpyCloud API │
                                │  (13 pollers) │
                                ▼               ▼
                   ┌────────────────────────────────────────┐
                   │         Azure Monitor Pipeline          │
                   │  ┌──────┐   ┌──────┐   ┌───────────┐  │
                   │  │ DCE  │──▶│ DCR  │──▶│ 14 Tables │  │
                   │  └──────┘   └──────┘   └─────┬─────┘  │
                   └──────────────────────────────┬────────┘
                                                  │
                          ┌───────────────────────┼───────────────────────┐
                          │                       │                       │
                          ▼                       ▼                       ▼
                 ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐
                 │  38 Analytics   │   │   5 Playbooks    │   │    Workbook      │
                 │  Rules          │   │                  │   │    22+ panels    │
                 │                 │   │  MDE Isolation   │   │                  │
                 │  Infostealer    │   │  CA Remediation  │   │  Exposure trends │
                 │  Credential     │   │  CredResponse    │   │  Device status   │
                 │  Cookie theft   │   │  MDE Blocklist   │   │  Remediation     │
                 │  VIP exposure   │   │  TI Enrichment   │   │  Executive view  │
                 │  Reinfection    │   │                  │   │                  │
                 └────────┬────────┘   └────────┬─────────┘   └──────────────────┘
                          │                     │
                          ▼                     ▼
                 ┌──────────────────────────────────────────┐
                 │           Automated Response              │
                 │                                          │
                 │  Defender ──▶ Isolate device              │
                 │  Entra ID ──▶ Reset password              │
                 │  Entra ID ──▶ Revoke sessions             │
                 │  Entra ID ──▶ Add to CA group             │
                 │  Slack/Teams ──▶ Alert SOC                │
                 │  ServiceNow ──▶ Create ticket             │
                 │  Jira/DevOps ──▶ Track remediation        │
                 └──────────────────────────────────────────┘
```

---

## What Ships in the Box

| Component | Count | Details |
|-----------|-------|---------|
| **Custom Log Tables** | 14 | 417 total columns — schemas verified against live SpyCloud API |
| **Data Pollers** | 13 | 3 always-on + 10 license-gated with enable/disable controls |
| **Analytics Rules** | 38 | MITRE ATT&CK mapped — from basic exposure to advanced cross-source correlation |
| **Playbooks** | 5 | MDE isolation, CA remediation, full credential response, blocklist sweep, TI enrichment |
| **Automation Rules** | 4 | Auto-enrich, auto-escalate critical, auto-task infections, auto-close low-risk |
| **Hunting Queries** | 8 | Password reuse, lateral movement, cookie abuse, VIP exposure, geographic anomaly |
| **Workbook** | 4 tabs | Overview, Infostealer Analysis, Remediation Tracking, Executive Dashboard |
| **Watchlists** | 3 | VIP users, critical assets, known malware families |
| **Parser Function** | 1 | `get_Spycloud_enriched_data()` — joins Watchlist + Catalog for enriched queries |
| **Copilot Skills** | 400+ | Plugin (192), Agent (223), API Plugin (203) |

---

## Data Tables

### Core Tables (Enterprise API — Always Active)

| Table | Columns | Source | What It Contains |
|-------|---------|--------|-----------------|
| `SpyCloudBreachWatchlist_CL` | 84 | `/breach/data/watchlist` | Every credential exposure: email, password, severity, PII, infection data, device forensics |
| `SpyCloudBreachCatalog_CL` | 29 | `/breach/catalog` | Breach metadata: malware family, record counts, confidence, targeted industries |
| `SpyCloudIdentityExposure_CL` | 11 | `/watchlist/identifiers` | Monitored domain summary: record counts by category, verification status |

### Compass Tables (Compass License)

| Table | Columns | Source | What It Contains |
|-------|---------|--------|-----------------|
| `SpyCloudCompassData_CL` | 32 | `/compass/data` | Consumer identity exposures with device context, infection paths, malware families |
| `SpyCloudCompassDevices_CL` | 10 | `/compass/devices` | Infected device inventory: hostname, OS, IP, application counts |
| `SpyCloudCompassApplications_CL` | 9 | `/compass/applications` | Per-application compromise stats: credential counts, device counts |

### Advanced Tables (Separate Licenses)

| Table | Columns | Source | License |
|-------|---------|--------|---------|
| `SpyCloudSipCookies_CL` | 33 | `/sip/cookies` | SIP — Stolen session cookies |
| `SpyCloudInvestigations_CL` | 84 | `/investigations-v2` | Investigations — Full breach records |
| `SpyCloudIdLink_CL` | 29 | `/idlink` | IdLink — Identity correlation |
| `SpyCloudDataPartnership_CL` | 29 | `/data-partnership` | Data Partnership |
| `SpyCloudExposure_CL` | 21 | `/exposure` | Exposure statistics |
| `SpyCloudCAP_CL` | 16 | `/cap` | Credential Access Protection |

### Remediation Audit Tables (Created by Playbooks)

| Table | Columns | What It Tracks |
|-------|---------|---------------|
| `Spycloud_MDE_Logs_CL` | 13 | Device isolation: device, type, status, tags |
| `SpyCloud_ConditionalAccessLogs_CL` | 17 | Identity: password resets, session revocations, CA group |

---

## Quick Start

### Prerequisites

- Microsoft Sentinel workspace
- SpyCloud Enterprise API key from [portal.spycloud.com](https://portal.spycloud.com)
- Sentinel Contributor + Log Analytics Contributor roles
- Outbound HTTPS to `api.spycloud.io`

### 1. Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

### 2. Connect

Sentinel → Data connectors → SpyCloud → Open connector page → Enter API key → Click Connect.

### 3. Grant Playbook Permissions

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh | bash -s -- -g <RG> -w <WS>
```

### 4. Verify

```kusto
SpyCloudBreachWatchlist_CL
| summarize Records = count(), Latest = max(TimeGenerated) by severity
| order by severity desc
```

---

## Playbook Decision Logic

### MDE Device Remediation

```
Incident (severity ≥ 20)
    │
    ├── Extract infected_machine_id + hostname
    ├── Search MDE for device
    │     │
    │     ├── Found + Online ──▶ Isolate → Tag → Log → Notify
    │     ├── Found + Offline ──▶ Tag → Schedule → Log
    │     └── Not Found ──▶ Log → Create task
    │
    └── Log all actions to Spycloud_MDE_Logs_CL
```

### Conditional Access Remediation

```
Incident (credential exposure)
    │
    ├── Look up user in Entra ID
    │     │
    │     ├── Severity ≥ 25 ──▶ DISABLE + Reset + Revoke + CA group
    │     ├── Severity ≥ 20 ──▶ Reset + Revoke + CA group
    │     ├── Severity < 20 ──▶ Reset + Notify user
    │     └── Not Found ──▶ Log → Investigation task
    │
    └── Log all actions to SpyCloud_ConditionalAccessLogs_CL
```

### Credential Response (Full Investigation)

```
Any SpyCloud Incident
    │
    ├── ENRICH: User role? Admin? VIP? Last sign-in? Anomalies?
    ├── ASSESS: Plaintext? Cookies? Multi-breach? Reinfection?
    ├── REMEDIATE: Reset + Revoke (escalate if VIP)
    └── NOTIFY: Slack + Teams + Email + SNOW + Jira + DevOps
```

---

## Managed Identity & Permissions

| Playbook | Permissions | License Required |
|----------|------------|-----------------|
| **MDE Remediation** | MDE: Machine.Isolate, Machine.ReadWrite.All / Graph: Mail.Send | MDE P2 |
| **CA Remediation** | Graph: User.ReadWrite.All, Directory.ReadWrite.All, Mail.Send | Entra P1+ |
| **CredResponse** | Graph: User.ReadWrite.All, AuditLog.Read.All, Mail.Send | Entra P1+ |
| **MDE Blocklist** | MDE: Machine.Isolate, Machine.ReadWrite.All / Log Analytics Reader | MDE P2 |
| **TI Enrichment** | VirusTotal + AbuseIPDB API keys (parameters) | Free tier |

---

## QA Testing

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/spycloud-qa.sh | bash
```

7 options: Validate Environment, Generate & Ingest 732 test records, Test Analytics Rules, Verify Playbooks, Full QA Report, Run ALL, Grant Permissions.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No data after 10 min | Check DCR in Monitor → Data Collection Rules |
| 401 on connect | Verify API key at portal.spycloud.com |
| 403 on pollers | Disable unlicensed pollers in Step 3 |
| Playbooks fail | Run `grant-permissions.sh` — may need MDE P2 or Entra P1+ |
| Schema mismatch | Run `cleanup-tables.sh` then redeploy |

---

## Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                 # ARM template (105 resources)
├── createUiDefinition.json          # Deployment wizard
├── copilot/                         # Security Copilot (400+ skills)
├── scripts/                         # QA, deployment, permissions
│   ├── spycloud-qa.sh              # Menu-driven QA framework
│   ├── generate-test-data.py       # Test data generator
│   ├── grant-permissions.sh        # API permissions
│   └── cleanup-tables.sh           # Schema migration
├── test-data/                       # 13 JSON files + ingestion script
├── templates/                       # Analytics, automations, workbooks
├── docs/                            # Permissions, architecture, roadmap
├── workbooks/                       # Workbook definitions
└── notebooks/                       # Jupyter hunting notebooks
```

---

<div align="center">

**Built with** ❤️ **by the SpyCloud Integration Engineering team**

<sub>SpyCloud recaptures data from the criminal underground — so you can act before attackers do.</sub>

<br>

[SpyCloud Docs](https://docs.spycloud.com) · [SpyCloud Portal](https://portal.spycloud.com) · [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel) · [Security Copilot](https://learn.microsoft.com/security-copilot)

</div>
