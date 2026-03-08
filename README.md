<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" alt="SpyCloud" width="320" style="background:#0D1B2A;padding:20px;border-radius:8px"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence for Microsoft Sentinel</h3>

<p align="center">
  <em>Transform recaptured darknet data into automated identity threat protection.</em><br/>
  <em>4 playbooks · 22 analytics rules · Security Copilot AI agent · One-click deployment</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-5.1.0-00B4D8?style=for-the-badge" alt="v5.1"/>
  <img src="https://img.shields.io/badge/sentinel-ready-0D1B2A?style=for-the-badge&logo=microsoftazure" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft" alt="Copilot"/>
  <img src="https://img.shields.io/badge/playbooks-4-2D6A4F?style=for-the-badge" alt="4 Playbooks"/>
  <img src="https://img.shields.io/badge/rules-22-415A77?style=for-the-badge" alt="22 Rules"/>
  <img src="https://img.shields.io/badge/powershell-not%20required-6B7280?style=for-the-badge" alt="No PS"/>
</p>

---

## 🚀 Deploy Now

### ☁️ One-Click Deploy to Azure

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank">
  <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

> Opens a **custom 3-step wizard** in the Azure Portal — not the default parameter list.
> Select subscription, resource group, region, then configure every feature through guided steps.

### 🐚 Azure Cloud Shell (Interactive Wizard)

<a href="https://shell.azure.com" target="_blank">
  <img src="https://learn.microsoft.com/azure/cloud-shell/media/embed-cloud-shell/launch-cloud-shell-1.png" alt="Launch Cloud Shell" width="180"/>
</a>

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```

### 💻 Azure CLI

```bash
az login
az group create --name spycloud-sentinel --location eastus
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY createNewWorkspace=true \
    enableMdePlaybook=true enableCaPlaybook=true enableCredResponsePlaybook=true \
    enableMdeBlocklistPlaybook=true enableKeyVault=true enableAnalyticsRulesLibrary=true \
    enablePostDeployScript=true
```

<details>
<summary><strong>🔄 GitHub Actions CI/CD</strong></summary>

1. Fork → add secrets `AZURE_CREDENTIALS` + `SPYCLOUD_API_KEY` ([setup guide](docs/azure-sp-setup.md))
2. Actions → **Deploy SpyCloud Sentinel** → Run workflow → fill form → Run
3. Workflow: **Validate** → **Deploy** → **Configure** (auto RBAC + API perms)
</details>

<details>
<summary><strong>⚡ PowerShell</strong></summary>

```powershell
Connect-AzAccount
New-AzResourceGroupDeployment -Name "SpyCloud-Supreme" `
  -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "spycloud-ws" -createNewWorkspace $true `
  -spycloudApiKey (Read-Host -AsSecureString "API Key") `
  -enablePostDeployScript $true
```
</details>

---

## 🏗️ Architecture

```
                    ┌──────────────────────────────────────┐
                    │         SpyCloud Darknet Intel        │
                    │    Breaches · Malware · Phishing      │
                    │    api.spycloud.io (REST API)         │
                    └──────────────┬───────────────────────┘
                                   │ Bearer Token Auth
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     Microsoft Sentinel (Log Analytics)                    │
│                                                                          │
│  ┌────────────────┐    ┌──────────┐    ┌──────────────────────────────┐ │
│  │  CCF Connector  │───▶│   DCE    │───▶│    DCR (KQL Transform)      │ │
│  │ 3 REST Pollers  │    │ HTTPS    │    │ Stream → Table mapping      │ │
│  │ • Watchlist New │    │ Ingest   │    │ • Custom-SpyCloudBreach...  │ │
│  │ • Watchlist Mod │    └──────────┘    │ • Custom-SpyCloudCatalog... │ │
│  │ • Catalog       │                    │ • Custom-Spycloud_MDE...    │ │
│  └────────────────┘                    │ • Custom-SpyCloud_CA...     │ │
│                                         └─────────────┬──────────────┘ │
│                                                       │                 │
│  ┌────────────────────────────────────────────────────┼───────────────┐ │
│  │                    4 Custom Tables                  │               │ │
│  │                                                     ▼               │ │
│  │  ┌───────────────────┐  ┌──────────────────┐  ┌──────────────┐   │ │
│  │  │ SpyCloudBreach    │  │ SpyCloudBreach   │  │ Spycloud_MDE │   │ │
│  │  │ Watchlist_CL      │  │ Catalog_CL       │  │ _Logs_CL     │   │ │
│  │  │ (73 columns)      │  │ (13 columns)     │  │ (19 columns) │   │ │
│  │  │                   │  │                   │  │              │   │ │
│  │  │ Credentials       │  │ breach_title      │  │ IsolationReq │   │ │
│  │  │ PII (SSN/DOB)     │  │ description       │  │ DeviceId     │   │ │
│  │  │ Device forensics  │  │ status            │  │ RiskScore    │   │ │
│  │  │ Account metadata  │  │ source_id         │  │ HostName     │   │ │
│  │  └───────┬───────────┘  └──────────────────┘  └──────────────┘   │ │
│  │          │                                                        │ │
│  │          │         ┌──────────────────┐                           │ │
│  │          │         │ SpyCloud_CA      │                           │ │
│  │          │         │ _Logs_CL         │                           │ │
│  │          │         │ (14 columns)     │                           │ │
│  │          │         │ PasswordReset    │                           │ │
│  │          │         │ SessionRevoked   │                           │ │
│  │          │         └──────────────────┘                           │ │
│  └──────────┼────────────────────────────────────────────────────────┘ │
│             │                                                          │
│             ▼                                                          │
│  ┌─────────────────────┐     ┌──────────────────────────────────────┐ │
│  │  22 Analytics Rules  │────▶│  Sentinel Incidents                  │ │
│  │  (all disabled by    │     │  • Auto-created from rule matches    │ │
│  │   default for review)│     │  • Entity mapping (Account, Host)    │ │
│  └─────────────────────┘     │  • Severity from SpyCloud data       │ │
│                               └──────────────┬───────────────────────┘ │
│                                              │                         │
│                                              ▼                         │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                      Automation Rule                              │ │
│  │              Triggers playbooks on incident creation               │ │
│  └──────────┬──────────┬──────────────┬─────────────────────────────┘ │
│             │          │              │                                │
│             ▼          ▼              ▼                                │
│  ┌──────────────┐ ┌──────────┐ ┌───────────────┐ ┌───────────────┐  │
│  │ Playbook 1   │ │Playbook 2│ │ Playbook 3    │ │ Playbook 4    │  │
│  │ MDE Device   │ │ CA       │ │ Credential    │ │ MDE Blocklist │  │
│  │ Isolation    │ │ Identity │ │ Response      │ │ (Scheduled)   │  │
│  │              │ │ Protect  │ │ + Teams Alert │ │ Sev 25 Scan   │  │
│  └──────┬───────┘ └────┬─────┘ └──────┬────────┘ └──────┬────────┘  │
│         │              │              │                   │           │
│         ▼              ▼              ▼                   ▼           │
│    ┌─────────┐   ┌──────────┐  ┌──────────┐      ┌──────────────┐   │
│    │ MDE API │   │Graph API │  │Graph API │      │  MDE API     │   │
│    │Isolate  │   │Password  │  │Sign-Ins  │      │  Search +    │   │
│    │Tag      │   │Reset     │  │Reset     │      │  Isolate     │   │
│    │         │   │Session   │  │Revoke    │      │  Tag         │   │
│    │         │   │Revoke    │  │Teams     │      │              │   │
│    └─────────┘   └──────────┘  └──────────┘      └──────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
              ┌─────────────────────────────────┐
              │    Microsoft Security Copilot    │
              │    Plugin: 28 KQL Skills         │
              │    Agent: 30 Interactive Skills   │
              │    "Investigate john@company.com" │
              └─────────────────────────────────┘
```

---

## 📦 Resource Inventory

### 50 Parameters · 45 Resources · 20 Outputs

| Tier | Resource | Toggle | Default |
|------|----------|--------|---------|
| 🏗️ **Foundation** | Workspace + Sentinel | `createNewWorkspace` | ✅ |
| | DCE + DCR + 4 Tables + 3 Pollers + Content Package | Always | — |
| 🔐 **Security** | Key Vault + Secret | `enableKeyVault` | ✅ |
| ⚙️ **Playbook 1** | MDE Device Isolation | `enableMdePlaybook` | ✅ |
| ⚙️ **Playbook 2** | CA Identity Protection | `enableCaPlaybook` | ✅ |
| ⚙️ **Playbook 3** | Credential Response + Teams | `enableCredResponsePlaybook` | ❌ |
| ⚙️ **Playbook 4** | MDE Blocklist (Scheduled) | `enableMdeBlocklistPlaybook` | ❌ |
| 🎯 **Detection** | 22 Analytics Rules (ALL disabled) | `enableAnalyticsRulesLibrary` | ❌ |
| 🤖 **Auto-Config** | Deployment Script (DCE/DCR/RBAC) | `enablePostDeployScript` | ✅ |
| 🔔 **Monitoring** | Action Group + Health Alert | `enableNotifications` | ❌ |

---

## ⚙️ Playbook Workflows

<p align="center"><img src="docs/images/SpyCloud-Logo-white.png" width="160" style="background:#0D1B2A;padding:10px;border-radius:6px"/></p>

### Playbook 1 — MDE Device Isolation

```
Sentinel Incident (severity 20+)
       │
       ▼
  Extract infected_machine_id + user_hostname
       │
       ▼
  Search MDE API for matching device
       │
  ┌────┴────┐
  │ FOUND   │ NOT FOUND
  ▼         ▼
Isolate   Log for
device    manual review
  │
  ▼
Tag: "SpyCloud-Infostealer"
  │
  ▼
Add incident comment → Log to Spycloud_MDE_Logs_CL
```

### Playbook 2 — CA Identity Protection

```
Sentinel Incident (email in entities)
       │
       ▼
  Extract compromised email addresses
       │
       ▼
  Look up user in Entra ID (Graph API)
       │
  ┌────┴────┐
  │ FOUND   │ NOT FOUND
  ▼         ▼
Force     Log as
password  external user
reset
  │
  ▼
Revoke all sessions + tokens
  │
  ▼
Add to CA exclusion group (optional)
  │
  ▼
Add incident comment → Log to SpyCloud_ConditionalAccessLogs_CL
```

### Playbook 3 — Credential Response + Teams Alert *(New)*

```
Sentinel Incident (credential exposure)
       │
       ▼
  For each compromised account:
       │
       ├──▶ Check recent Entra sign-in activity (last 10 events)
       ├──▶ Force password reset on next sign-in
       ├──▶ Revoke all active sessions
       ├──▶ Send Teams MessageCard to SOC channel
       │         ┌──────────────────────────────┐
       │         │ 🛡️ SpyCloud Alert            │
       │         │ User: john@company.com       │
       │         │ Severity: High               │
       │         │ Actions: Reset + Revoke      │
       │         └──────────────────────────────┘
       └──▶ Add investigation comment to incident
```

### Playbook 4 — MDE Blocklist *(New — Scheduled)*

```
Recurrence Trigger (every 1-24 hours)
       │
       ▼
  Query severity 25 records from SpyCloudBreachWatchlist_CL
  (CRITICAL: stolen cookies, sessions, autofill — MFA bypass risk)
       │
       ▼
  For each infostealer infection:
       │
       ├──▶ Match infected_machine_id against MDE device inventory
       │
       ├── FOUND ──▶ Full device isolation + Tag "SpyCloud-Sev25-Infostealer"
       │
       └── NOT FOUND ──▶ Skip (unmanaged/external device)
```

---

## 🎯 22 Analytics Rules

All rules deploy **DISABLED**. Review each in Sentinel → Analytics, then enable individually.

### Core Detection (12)

| # | Rule | Sev | Use Case |
|---|------|-----|----------|
| 1 | Infostealer Exposure | 🔴 High | Severity 20+ credentials stolen by malware |
| 2 | Plaintext Password | 🔴 High | Cleartext passwords — immediate attacker access |
| 3 | Sensitive PII | 🔴 High | SSN, bank, tax ID, health insurance — compliance trigger |
| 4 | Session Cookie Theft | 🔴 High | Severity 25 — stolen cookies bypass MFA |
| 5 | Device Re-Infection | 🔴 High | Same device compromised again after remediation |
| 6 | Multi-Domain Exposure | 🟠 Med | Credentials for 5+ domains — credential reuse |
| 7 | Geographic Anomaly | 🟠 Med | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 Med | Same creds in 3+ breach sources |
| 9 | Remediation Gap | 🔴 High | No auto-response after 2+ hours |
| 10 | AV Bypass | 🟢 Info | AV present but failed |
| 11 | New Malware Family | 🟢 Info | New breach source in catalog |
| 12 | Data Ingestion Health | 🟠 Med | No data for 3+ hours |

### Identity Provider Correlation (4)

| # | Rule | Correlates | Enables |
|---|------|-----------|---------|
| 13 | SpyCloud × Okta | `Okta_CL` | Catch compromised creds in Okta sign-ins |
| 14 | SpyCloud × Duo | `Duo_CL` | Catch compromised creds in Duo MFA |
| 15 | SpyCloud × Ping | `PingFederate_CL` | Catch compromised creds in Ping auth |
| 16 | SpyCloud × Entra ID | `SigninLogs` | Catch compromised creds in Entra sign-ins |

### Advanced Correlation (5 — New in v5.0)

| # | Rule | Sev | Use Case |
|---|------|-----|----------|
| 18 | Credential + Recent Sign-In | 🔴 High | Compromised user signed in within 24h |
| 19 | Breach Source Enrichment | 🟠 Med | Joins with catalog for breach_title context |
| 20 | Executive / VIP Exposure | 🔴 High | CEO/CFO/CISO/admin accounts detected |
| 21 | Password Reuse Across Domains | 🔴 High | Same password hash for 3+ target domains |
| 22 | Stale Exposure (7+ Days) | 🟠 Med | SLA alert — exposure unresolved beyond window |

---

## 🤖 Security Copilot

<p align="center"><img src="docs/images/SpyCloud-Logo-white.png" width="140" style="background:#0D1B2A;padding:8px;border-radius:6px"/></p>

### Plugin — 28 KQL Skills

**Upload:** `copilot/SpyCloud_Plugin.yaml` → **Sources → Custom → Upload Plugin**

| Category | Skills | What They Do |
|----------|--------|-------------|
| User Investigation | 4 | Credential lookup, full PII profile, account activity, passwords |
| Password Analysis | 3 | Plaintext scan, type breakdown, crackability |
| Severity & Domain | 3 | High-severity filter, distribution, domain exposure |
| PII & Social | 3 | SSN/financial/health, social media, targeted domains |
| Device Forensics | 4 | Infected devices, malware details, user mapping, AV gaps |
| Breach Catalog | 2 | Recent breaches, enriched exposure |
| MDE Remediation | 3 | Actions, per-device status, statistics |
| CA Remediation | 3 | Actions, per-user status, statistics |
| Cross-Table | 3 | Full investigation, geographic analysis, health |

### Agent — 30 Interactive Skills

**Upload:** `copilot/SpyCloud_Agent.yaml` → **Build → Upload YAML → Publish**

**Example prompts:**
- *"What can you help me investigate?"*
- *"Show me our dark web exposure"*
- *"Investigate john@company.com"*
- *"Which users have plaintext passwords?"*
- *"Are any devices infected with infostealers?"*

---

## 🔄 Deployment Lifecycle

```
  ┌──────────────────────────────────────────────────────────┐
  │  Phase 1: Deploy (5-10 min)                              │
  │  ARM template → Workspace, Sentinel, DCE, DCR, Tables,  │
  │  Connector, Key Vault, 4 Playbooks, 22 Rules             │
  ├──────────────────────────────────────────────────────────┤
  │  Phase 2: Auto Post-Deploy (3-5 min)                     │
  │  deploymentScript → DCE/DCR resolution + RBAC            │
  ├──────────────────────────────────────────────────────────┤
  │  Phase 3: API Permissions (2-3 min)                      │
  │  post-deploy.sh → MDE + Graph API app role assignments   │
  ├──────────────────────────────────────────────────────────┤
  │  Phase 4: Manual Config (10-15 min)                      │
  │  Upload Copilot files, enable rules, Entra ID logs, IdPs │
  ├──────────────────────────────────────────────────────────┤
  │  Phase 5: Verify (5 min)                                 │
  │  Data connectors, KQL queries, Logic App runs, Copilot   │
  └──────────────────────────────────────────────────────────┘
```

---

## 🔧 Post-Deployment

### Run Post-Deploy Script

```bash
chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

**What it does:** Resolves DCE/DCR → assigns RBAC → grants MDE permissions (Machine.Isolate, Machine.ReadWrite.All) → grants Graph permissions (User.ReadWrite.All, Directory.ReadWrite.All) → provides admin consent URLs → verifies resources.

### Verify Data Flow

```kusto
SpyCloudBreachWatchlist_CL
| summarize Count=count(), Latest=max(TimeGenerated) by bin(TimeGenerated, 1h)
| order by TimeGenerated desc

SpyCloudBreachCatalog_CL | summarize count(), max(TimeGenerated)
```

### Verify Resources

```bash
az resource list -g spycloud-sentinel --query "[].{Type:type,Name:name}" -o table
az logic workflow list -g spycloud-sentinel --query "[].{Name:name,State:state}" -o table
az monitor data-collection endpoint show --name dce-spycloud-spycloud-ws -g spycloud-sentinel --query "logsIngestion.endpoint" -o tsv
az monitor data-collection rule show --name dcr-spycloud-spycloud-ws -g spycloud-sentinel --query "immutableId" -o tsv
```

---

## 🔍 Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ResourceNotFound` for workspace | Set `createNewWorkspace=true` |
| `Missing required permissions for Sentinel on playbook` | Fixed v5.1 — uses Sentinel Automation Contributor role |
| `RoleDefinitionDoesNotExist` | Fixed v5.1 — correct role GUIDs |
| `No valid tactic for T1078/T1589` | Fixed v5.1 — all MITRE mappings validated |
| `GroupByEntities Account invalid` | Fixed v5.0 — entity types validated |
| `EntityMappings length 0` | Fixed v5.0 — empty arrays removed |
| Deployment script stuck deploying | Fixed v5.0 — reduced timeouts (15m/60s/20s) |
| No data in watchlist table | Check Sentinel → Data connectors → SpyCloud status |
| Logic Apps not triggering | Verify automation rule exists + `enableAutomationRule=true` |
| Copilot skills empty | Verify TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| Teams alerts not sending | Regenerate webhook: Teams → Channel → Connectors |
| MDE playbook fails | Run `post-deploy.sh` or grant Machine.Isolate in Portal |

---

## 📁 Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                 ← ARM template (50 params, 45 resources)
├── azuredeploy.parameters.json      ← Sample parameters
├── createUiDefinition.json          ← Custom portal wizard (28 outputs)
├── README.md
├── .github/workflows/
│   └── deploy.yml                   ← GitHub Actions (validate → deploy → configure)
├── scripts/
│   ├── deploy-all.sh                ← Interactive guided deployment (9 phases)
│   └── post-deploy.sh              ← Post-deploy RBAC + API permissions (7 phases)
├── copilot/
│   ├── SpyCloud_Plugin.yaml         ← Security Copilot plugin (28 skills)
│   └── SpyCloud_Agent.yaml          ← Interactive agent (30 skills)
└── docs/
    ├── images/
    │   └── SpyCloud-Logo-white.png  ← Official SpyCloud logo
    ├── architecture.md              ← Architecture and data flow docs
    └── azure-sp-setup.md           ← Service principal setup guide
```

---

## 🔒 Security

| Layer | Protection |
|-------|-----------|
| API Key | SecureString + Azure Key Vault (RBAC, soft delete, purge protection) |
| Logic Apps | System-assigned managed identity (zero credentials in workflows) |
| MDE/Graph API | App role assignments via managed identity |
| DCE Ingestion | Monitoring Metrics Publisher role on DCR |
| Deployment Script | Temporary container, auto-cleanup on success |
| Network | Outbound HTTPS: `api.spycloud.io:443`, `*.ingest.monitor.azure.com:443` |

---

<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" width="120" style="background:#0D1B2A;padding:8px;border-radius:6px"/>
  <br/><br/>
  <sub>© 2026 SpyCloud, Inc. All rights reserved.</sub><br/>
  <sub><em>SpyCloud transforms recaptured darknet data to disrupt cybercrime.</em></sub><br/>
  <sub><em>Trusted by 7 of the Fortune 10 and hundreds of global enterprises.</em></sub>
</p>
