<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" alt="SpyCloud" width="320" style="background:#0D1B2A;padding:20px;border-radius:8px"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence for Microsoft Sentinel</h3>

<p align="center">
  <em>4 playbooks · 22 analytics rules · Sentinel workbook dashboard · Security Copilot AI agent</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-5.6-00B4D8?style=for-the-badge" alt="v5.6"/>
  <img src="https://img.shields.io/badge/sentinel-ready-0D1B2A?style=for-the-badge&logo=microsoftazure" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft" alt="Copilot"/>
  <img src="https://img.shields.io/badge/playbooks-4-2D6A4F?style=for-the-badge" alt="4 Playbooks"/>
  <img src="https://img.shields.io/badge/rules-22-415A77?style=for-the-badge" alt="22 Rules"/>
</p>

---

## 🚀 Deploy

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/></a>   <a href="https://shell.azure.com" target="_blank"><img src="https://learn.microsoft.com/azure/cloud-shell/media/embed-cloud-shell/launch-cloud-shell-1.png" alt="Cloud Shell" width="140"/></a>

**Deploy to Azure** opens a custom 3-step wizard. **Cloud Shell** lets you run the interactive script:

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```

<details><summary><strong>Azure CLI</strong></summary>

```bash
az login && az group create -n spycloud-sentinel -l eastus
az deployment group create -g spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY createNewWorkspace=true
```
</details>

<details><summary><strong>PowerShell</strong></summary>

```powershell
Connect-AzAccount
New-AzResourceGroupDeployment -Name "SpyCloud" -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "spycloud-ws" -createNewWorkspace $true -spycloudApiKey (Read-Host -AsSecureString "Key")
```
</details>

<details><summary><strong>GitHub Actions</strong></summary>

Fork → add secrets `AZURE_CREDENTIALS` + `SPYCLOUD_API_KEY` → Actions → Run workflow
</details>

---

## 🏗️ Architecture

```
                        ┌─────────────────────────────────────┐
                        │      SpyCloud Darknet Intelligence   │
                        │   Breaches · Infostealers · Phishing │
                        │         api.spycloud.io              │
                        └────────────────┬────────────────────┘
                                         │ HTTPS / Bearer Token
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                        MICROSOFT SENTINEL                                    │
│                                                                              │
│  ┌─────────────────┐      ┌────────┐      ┌───────────────────────────────┐ │
│  │  CCF Connector   │─────▶│  DCE   │─────▶│      DCR (KQL Transform)     │ │
│  │ ┌─────────────┐  │      │ HTTPS  │      │                               │ │
│  │ │ Watchlist    │  │      │ Ingest │      │  Stream → Table mapping:      │ │
│  │ │  New + Mod   │  │      └────────┘      │  ┌─────────────────────────┐ │ │
│  │ ├─────────────┤  │                       │  │ SpyCloudBreachWatchlist │ │ │
│  │ │  Catalog     │  │                       │  │ _CL (73 columns)       │ │ │
│  │ └─────────────┘  │                       │  ├─────────────────────────┤ │ │
│  └─────────────────┘                       │  │ SpyCloudBreachCatalog  │ │ │
│                                             │  │ _CL (13 columns)       │ │ │
│                                             │  ├─────────────────────────┤ │ │
│                                             │  │ Spycloud_MDE_Logs_CL   │ │ │
│                                             │  │ (19 cols - audit)       │ │ │
│                                             │  ├─────────────────────────┤ │ │
│                                             │  │ SpyCloud_CA_Logs_CL    │ │ │
│                                             │  │ (14 cols - audit)       │ │ │
│                                             │  └─────────────────────────┘ │ │
│                                             └──────────────┬──────────────┘ │
│                                                            │                 │
│  ┌─────────────────────────────┐                          │                 │
│  │   📊 Sentinel Workbook      │◀─────────────────────────┤                 │
│  │   10 interactive charts      │                          │                 │
│  │   Exposure · Severity ·      │                          │                 │
│  │   Devices · Remediation      │                          │                 │
│  └─────────────────────────────┘                          │                 │
│                                                            ▼                 │
│  ┌───────────────────────────────────────────────────────────┐              │
│  │                    22 Analytics Rules                       │              │
│  │  (all deploy DISABLED — review + enable individually)      │              │
│  │                                                             │              │
│  │  Core: infostealer, plaintext pw, PII, cookies, reinfect   │              │
│  │  IdP:  Okta, Duo, Ping, Entra cross-correlation            │              │
│  │  Adv:  VIP, pw reuse, sign-in correlation, SLA, enrichment │              │
│  └──────────────────────┬────────────────────────────────────┘              │
│                          │ creates                                           │
│                          ▼                                                   │
│  ┌───────────────────────────────┐                                          │
│  │      Sentinel Incidents        │                                          │
│  │  severity + entity mapping     │                                          │
│  └──────────────┬────────────────┘                                          │
│                  │ triggers                                                   │
│                  ▼                                                            │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        Automation Rule                                  │ │
│  └──┬──────────┬──────────────┬────────────────────────────┬─────────────┘ │
│     │          │              │                             │               │
│     ▼          ▼              ▼                             ▼               │
│  ┌────────┐┌────────┐ ┌─────────────┐             ┌──────────────┐        │
│  │  PB 1  ││  PB 2  │ │   PB 3      │             │    PB 4      │        │
│  │  MDE   ││  CA    │ │   Cred      │             │  MDE Block   │        │
│  │Isolate ││Identity│ │  Response   │             │  (Scheduled) │        │
│  │+ Tag   ││Protect │ │ + Teams     │             │  Sev 25 Scan │        │
│  └───┬────┘└───┬────┘ └─────┬───────┘             └──────┬───────┘        │
│      │         │             │                            │                │
│      ▼         ▼             ▼                            ▼                │
│   MDE API   Graph API    Graph API                    MDE API              │
│   Isolate   PW Reset     Sign-In Check               Search               │
│   Tag       Revoke       PW Reset                    Isolate               │
│             Session      Revoke + Teams              Tag Sev25             │
│                                                                             │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                   ┌──────────────────────────────┐
                   │   Microsoft Security Copilot   │
                   │   Plugin: 28 KQL skills        │
                   │   Agent: 30 interactive skills  │
                   └──────────────────────────────┘
```

---

## 📦 What Gets Deployed

| Tier | Resource | Count | Toggle | Default |
|------|----------|-------|--------|---------|
| 🏗️ Foundation | Workspace + Sentinel | 1 | `createNewWorkspace` | ✅ On |
| | DCE + DCR + 4 Tables + 3 Pollers | 8 | Always | — |
| 🔐 Security | Key Vault + Secret | 2 | `enableKeyVault` | ✅ On |
| ⚙️ Playbook 1 | MDE Device Isolation | 1 | `enableMdePlaybook` | ✅ On |
| ⚙️ Playbook 2 | CA Identity Protection | 1 | `enableCaPlaybook` | ✅ On |
| ⚙️ Playbook 3 | Credential Response + Teams | 1 | `enableCredResponsePlaybook` | ❌ Off |
| ⚙️ Playbook 4 | MDE Blocklist (Scheduled) | 1 | `enableMdeBlocklistPlaybook` | ❌ Off |
| 🎯 Detection | 22 Analytics Rules (ALL disabled) | 22 | `enableAnalyticsRulesLibrary` | ❌ Off |
| 📊 Dashboard | Sentinel Workbook (10 charts) | 1 | `enableWorkbook` | ✅ On |
| 🤖 Auto-Config | Deployment Script (DCE/DCR/RBAC) | 1 | `enablePostDeployScript` | ✅ On |
| 🔔 Monitoring | Action Group + Health Alert | 2 | `enableNotifications` | ❌ Off |

**Total: 54 parameters · 46 resources · 21 outputs**

---

## ⚙️ 4 Playbooks

### PB1: MDE Device Isolation

> **Use case:** An employee's laptop is infected with RedLine Stealer. SpyCloud detects the stolen credentials. This playbook auto-isolates the device in Defender.

```
Sentinel Incident (sev 20+) → Extract machine ID → Search MDE
  ├─ FOUND → Isolate (Full/Selective) → Tag → Comment → Log
  └─ NOT FOUND → Log for manual review
```

### PB2: CA Identity Protection

> **Use case:** A user's corporate password appears in a darknet breach. This playbook forces a password reset and kills all sessions before the attacker can use it.

```
Sentinel Incident (email) → Lookup user in Entra ID
  ├─ FOUND → Reset password → Revoke sessions → Add to CA group → Log
  └─ NOT FOUND → Log as external
```

### PB3: Credential Response + Teams Alert

> **Use case:** SOC wants real-time Teams notifications when credentials are exposed, plus automated sign-in activity analysis.

```
Sentinel Incident → For each account:
  → Check last 10 Entra sign-ins
  → Force password reset
  → Revoke sessions
  → Send Teams MessageCard to SOC channel
  → Add incident comment
```

### PB4: MDE Blocklist (Scheduled)

> **Use case:** Every 4 hours, automatically scan for CRITICAL severity 25 infections and isolate matched devices before attackers can use stolen cookies/sessions.

```
Schedule (1-24h) → Query sev 25 records
  → Match against MDE inventory
  → Isolate + Tag "SpyCloud-Sev25-Infostealer"
```

---

## 🎯 22 Analytics Rules (All Disabled by Default)

| # | Rule | Sev | Use Case |
|---|------|-----|----------|
| 1 | Infostealer Exposure | 🔴 | Sev 20+ malware-stolen credentials |
| 2 | Plaintext Password | 🔴 | Cleartext passwords — immediate attacker use |
| 3 | Sensitive PII | 🔴 | SSN, bank, tax, health — compliance trigger |
| 4 | Session Cookie Theft | 🔴 | Sev 25 — stolen cookies bypass MFA |
| 5 | Device Re-Infection | 🔴 | Same device compromised again |
| 6 | Multi-Domain Exposure | 🟠 | Creds for 5+ domains |
| 7 | Geographic Anomaly | 🟠 | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 | Same creds in 3+ sources |
| 9 | Remediation Gap | 🔴 | No response after 2+ hours |
| 10 | AV Bypass | 🟢 | AV present but failed |
| 11 | New Malware Family | 🟢 | New breach in catalog |
| 12 | Data Health | 🟠 | No data for 3+ hours |
| 13-16 | IdP Correlation (×4) | 🔴 | Okta, Duo, Ping, Entra |
| 17 | Credential + Recent Sign-In | 🔴 | Compromised user signed in within 24h |
| 18 | Breach Source Enrichment | 🟠 | Joins catalog for breach_title |
| 19 | Executive/VIP Exposure | 🔴 | CEO/CFO/CISO accounts |
| 20 | Password Reuse | 🔴 | Same password for 3+ domains |
| 21 | Stale Exposure (7+ days) | 🟠 | SLA/compliance alert |

---

## 📊 Sentinel Workbook Dashboard

Deploys to: **Sentinel → Workbooks → SpyCloud Threat Intelligence Dashboard**

| Chart | Type | Shows |
|-------|------|-------|
| Exposure Overview | Tiles | Total, users, devices, sev 25, plaintext passwords |
| Exposure Trend | Timechart | Daily count by severity |
| Severity Distribution | Pie | 2/5/20/25 breakdown |
| Top 20 Exposed Users | Table | Severity heatmap, plaintext count |
| Password Types | Bar | MD5/SHA1/bcrypt/plaintext |
| Top Targeted Domains | Bar | Most-attacked domains |
| Top 20 Infected Devices | Table | Machine ID, hostname, severity |
| Infections by Country | Bar | Geographic distribution |
| Remediation Dashboard | Tiles | MDE + CA actions, remediation rate % |
| Breach Catalog | Table | Recent breach sources |

---

## 🤖 Security Copilot

Upload `copilot/SpyCloud_Plugin.yaml` → **Sources → Custom** (28 KQL skills)
Upload `copilot/SpyCloud_Agent.yaml` → **Build → Upload YAML** (30 skills + AI)

---

## 🔧 Post-Deployment

### Step 1: Run post-deploy script (grants MDE + Graph API permissions)

```bash
chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

### Step 2: Verify data flow

```kusto
SpyCloudBreachWatchlist_CL | summarize count(), max(TimeGenerated)
SpyCloudBreachCatalog_CL | summarize count(), max(TimeGenerated)
```

### Step 3: Enable analytics rules

Sentinel → Analytics → filter "SpyCloud" → review → enable individually

### Step 4: Upload Copilot files

| File | Destination | Settings |
|------|------------|----------|
| `copilot/SpyCloud_Plugin.yaml` | Sources → Custom → Upload | TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| `copilot/SpyCloud_Agent.yaml` | Build → Upload YAML → Publish | Same settings |

### Step 5: Configure Entra ID logs (manual — cannot be automated)

Entra ID → Monitoring → Diagnostic settings → Add → check SignInLogs, AuditLogs, RiskyUsers → Send to workspace

### Step 6: Install IdP connectors (optional)

| Provider | Install | Enables Rule |
|----------|---------|-------------|
| Okta | Content Hub → "Okta SSO" | #13 |
| Duo | Content Hub → "Cisco Duo" | #14 |
| Ping | AMA syslog/API | #15 |
| Entra | Diagnostic settings | #16 |

### Verification commands

```bash
az resource list -g spycloud-sentinel --query "[].{Type:type,Name:name}" -o table
az logic workflow list -g spycloud-sentinel --query "[].{Name:name,State:state}" -o table
az monitor data-collection endpoint show --name dce-spycloud-spycloud-ws -g spycloud-sentinel --query logsIngestion.endpoint -o tsv
az monitor data-collection rule show --name dcr-spycloud-spycloud-ws -g spycloud-sentinel --query immutableId -o tsv
```

---

## 🔍 Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Missing required permissions for Sentinel on playbook` | Fixed v5.6 — role assignments use Sentinel Automation Contributor + automation rule depends on role completion |
| `RoleAssignmentUpdateNotPermitted` | Fixed v5.6 — new GUID seeds per version to avoid collision with old deployments |
| `No valid tactic for T1078` | Fixed v5.6 — ALL T1078 rules include InitialAccess |
| `table not found` in workbook | Fixed v5.6 — queries use `union isfuzzy=true` fallback |
| `ResourceNotFound` for workspace | Set `createNewWorkspace=true` |
| No data flowing | Check Sentinel → Data connectors → SpyCloud status |
| Logic Apps not triggering | Run `post-deploy.sh` to grant API permissions |
| Copilot skills empty | Verify TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| Teams alerts not sending | Regenerate webhook: Teams → Channel → Connectors |

---

## 📁 Repository

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                 ← ARM template (54 params, 46 resources)
├── azuredeploy.parameters.json      ← Sample parameters
├── createUiDefinition.json          ← Custom portal wizard (39 outputs)
├── .github/workflows/deploy.yml     ← GitHub Actions CI/CD
├── scripts/
│   ├── deploy-all.sh                ← Interactive guided deployment
│   └── post-deploy.sh              ← Post-deploy RBAC + API perms
├── copilot/
│   ├── SpyCloud_Plugin.yaml         ← 28 KQL skills
│   └── SpyCloud_Agent.yaml          ← 30 skills + AI agent
├── workbooks/
│   └── SpyCloud-ThreatIntel-Dashboard.json ← Sentinel workbook
└── docs/
    ├── images/SpyCloud-Logo-white.png
    ├── architecture.md
    └── azure-sp-setup.md
```

---

<p align="center">
  <img src="docs/images/SpyCloud-Logo-white.png" width="120" style="background:#0D1B2A;padding:8px;border-radius:6px"/>
  <br/><sub>© 2026 SpyCloud, Inc. · Trusted by 7 of the Fortune 10</sub>
</p>
