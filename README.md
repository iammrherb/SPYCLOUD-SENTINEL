<p align="center">
  <img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/SpyCloud_Enterprise_Protection.svg" alt="SpyCloud" width="280"/>
</p>

<h1 align="center">SpyCloud Sentinel Supreme</h1>
<h3 align="center">Unified Darknet Threat Intelligence for Microsoft Sentinel</h3>

<p align="center">
  <strong>4 automated playbooks · 22 analytics rules · 50 deployment parameters<br/>
  Custom Azure Portal wizard · Automated post-deployment · Security Copilot AI agent</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-5.0.0-00B4D8?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/sentinel-ready-0D1B2A?style=for-the-badge&logo=microsoftazure" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft" alt="Copilot"/>
  <img src="https://img.shields.io/badge/playbooks-4-2D6A4F?style=for-the-badge" alt="Playbooks"/>
  <img src="https://img.shields.io/badge/rules-22-415A77?style=for-the-badge" alt="Rules"/>
</p>

---

## 🚀 Deploy Now

### ☁️ One-Click Deploy to Azure (Recommended)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json" target="_blank">
  <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

Opens a **custom 3-step wizard** in the Azure Portal:

| Step | What You Configure |
|------|-------------------|
| **Basics** | Subscription, resource group (create new or existing), region |
| **Step 1: Workspace & Data** | Workspace name, SpyCloud API key, severity levels (2/5/20/25), password redaction, polling interval, lookback period |
| **Step 2: Automation** | 4 playbooks (MDE, CA, Credential Response, MDE Blocklist), Key Vault, 22 analytics rules, automation rules, post-deploy script |
| **Step 3: Monitoring** | Teams webhook, ServiceNow instance, MDE scan frequency, email notifications, IdP correlation (Okta/Duo/Ping/Entra), session cookie detection |

After clicking **Create**, the ARM template deploys all resources AND runs an automated post-deployment script inside the deployment that resolves DCE/DCR values and assigns RBAC — no manual steps for core setup.

### 🐚 Azure Cloud Shell (Interactive Guided Wizard)

<a href="https://shell.azure.com" target="_blank">
  <img src="https://learn.microsoft.com/azure/cloud-shell/media/embed-cloud-shell/launch-cloud-shell-1.png" alt="Launch Cloud Shell" width="200"/>
</a>

Paste this single command — it launches an interactive wizard with ASCII art, menus, and progress tracking:

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```

The wizard prompts for every setting, shows a confirmation summary, deploys the ARM template, waits for content template resources, resolves DCE/DCR, assigns RBAC, grants MDE + Graph API permissions, and verifies everything. Full logging to `/tmp/spycloud-deploy-*.log`.

### 💻 Azure CLI (Non-Interactive)

```bash
# Login
az login

# Create resource group
az group create --name spycloud-sentinel --location eastus

# Deploy everything
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters \
    workspace=spycloud-ws \
    createNewWorkspace=true \
    spycloudApiKey=YOUR-KEY \
    enableMdePlaybook=true \
    enableCaPlaybook=true \
    enableCredResponsePlaybook=true \
    enableMdeBlocklistPlaybook=true \
    enableKeyVault=true \
    enableAnalyticsRulesLibrary=true \
    enablePostDeployScript=true

# Complete API permissions (MDE + Graph)
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git
chmod +x SPYCLOUD-SENTINEL/scripts/post-deploy.sh
./SPYCLOUD-SENTINEL/scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

<details>
<summary><strong>🔄 GitHub Actions (CI/CD Pipeline)</strong></summary>

1. **Fork** this repository
2. Add **GitHub Secrets** (Settings → Secrets → Actions):

   | Secret | Value | How to Get It |
   |--------|-------|--------------|
   | `AZURE_CREDENTIALS` | Service principal JSON | [Setup guide](docs/azure-sp-setup.md) |
   | `SPYCLOUD_API_KEY` | SpyCloud Enterprise API key | [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys |

3. Go to **Actions** → **Deploy SpyCloud Sentinel** → **Run workflow**
4. Fill in: resource group, workspace, region, feature toggles
5. Click **Run workflow**

The workflow runs 3 jobs: **Validate** (template syntax check) → **Deploy** (ARM deployment) → **Configure** (DCE/DCR resolution + RBAC assignment).
</details>

<details>
<summary><strong>📋 Azure Portal (Manual Template Upload)</strong></summary>

1. Azure Portal → search **"Deploy a custom template"**
2. Click **"Build your own template in the editor"**
3. Click **Load file** → select `azuredeploy.json`
4. Click **Save** → fill in parameters → **Review + create**
5. After deployment, run `scripts/post-deploy.sh` for API permissions
</details>

<details>
<summary><strong>⚡ PowerShell (Alternative)</strong></summary>

```powershell
# Login
Connect-AzAccount

# Deploy
New-AzResourceGroupDeployment `
  -Name "SpyCloud-Supreme" `
  -ResourceGroupName "spycloud-sentinel" `
  -TemplateUri "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json" `
  -workspace "spycloud-ws" `
  -createNewWorkspace $true `
  -spycloudApiKey (Read-Host -AsSecureString "SpyCloud API Key") `
  -enableMdePlaybook $true `
  -enableCaPlaybook $true `
  -enableKeyVault $true `
  -enablePostDeployScript $true
```
</details>

---

## 🔄 Complete Deployment Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  PHASE 1: Deploy Infrastructure (automated)                5-10 min    │
│  ══════════════════════════════════════════                              │
│  ARM template creates:                                                  │
│  • Log Analytics Workspace + Microsoft Sentinel                         │
│  • Data Collection Endpoint (DCE) + Rule (DCR) + 4 Custom Tables       │
│  • 3 CCF REST API Pollers (Watchlist New + Modified + Catalog)          │
│  • Azure Key Vault + Secret (API key)                                   │
│  • 4 Logic App Playbooks (MDE, CA, CredResponse, MDE-Blocklist)         │
│  • Up to 22 Analytics Rules (all disabled for review)                   │
│  • Automation Rule (auto-trigger playbooks on incidents)                │
│  • Action Group + Health Alert (optional)                               │
│                                                                         │
│  PHASE 2: Automated Post-Deploy (runs inside ARM)          3-5 min     │
│  ════════════════════════════════════════════                            │
│  deploymentScript container automatically:                              │
│  • Waits for Sentinel content template to finalize                      │
│  • Resolves DCE Logs Ingestion URI (5 retry attempts)                   │
│  • Resolves DCR Immutable ID (5 retry attempts)                         │
│  • Assigns Monitoring Metrics Publisher RBAC to all Logic Apps           │
│  • Outputs resolved values to ARM deployment outputs                    │
│                                                                         │
│  PHASE 3: API Permissions (run post-deploy.sh)             2-3 min     │
│  ═════════════════════════════════════════════                           │
│  scripts/post-deploy.sh grants:                                         │
│  • MDE: Machine.Isolate + Machine.ReadWrite.All                         │
│  • Graph: User.ReadWrite.All + Directory.ReadWrite.All                  │
│  • Graph: GroupMember.ReadWrite.All + IdentityRisk.ReadWrite.All        │
│  • Admin consent portal URLs                                            │
│                                                                         │
│  PHASE 4: Manual Configuration                             10-15 min   │
│  ═════════════════════════════                                          │
│  • Upload Security Copilot plugin + agent (copilot/ directory)          │
│  • Review and enable analytics rules in Sentinel → Analytics            │
│  • Configure Entra ID diagnostic settings (SignInLogs, AuditLogs)       │
│  • Install IdP connectors from Content Hub (Okta/Duo/Ping/CyberArk)    │
│  • Grant admin consent if permissions show "Pending"                    │
│                                                                         │
│  PHASE 5: Verify                                           5 min       │
│  ════════                                                               │
│  • Sentinel → Data connectors → SpyCloud (status: Connected)           │
│  • Sentinel → Logs → SpyCloudBreachWatchlist_CL | count                │
│  • Logic Apps → Run history (triggers active)                           │
│  • Security Copilot → "What can you help me investigate?"               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 What Gets Deployed

### Resource Inventory (50 Parameters · 45 Resources · 20 Outputs)

| Tier | Resource | Count | Toggle | Default |
|------|----------|-------|--------|---------|
| 🏗️ **Foundation** | Workspace + Sentinel | 1 | `createNewWorkspace` | ✅ On |
| | Data Collection Endpoint + Rule | 2 | Always | — |
| | Custom Tables (Watchlist 73col, Catalog, MDE, CA) | 4 | Always | — |
| | CCF REST API Pollers | 3 | Always | — |
| | Content Package | 1 | Always | — |
| 🔐 **Security** | Key Vault + Secret | 2 | `enableKeyVault` | ✅ On |
| ⚙️ **Playbook 1** | MDE Device Isolation | 1 | `enableMdePlaybook` | ✅ On |
| ⚙️ **Playbook 2** | CA Identity Protection | 1 | `enableCaPlaybook` | ✅ On |
| ⚙️ **Playbook 3** | Credential Response + Teams | 1 | `enableCredResponsePlaybook` | ❌ Off |
| ⚙️ **Playbook 4** | MDE Blocklist (Scheduled) | 1 | `enableMdeBlocklistPlaybook` | ❌ Off |
| 🎯 **Detection** | Analytics Rules (all DISABLED) | 22 | `enableAnalyticsRulesLibrary` | ❌ Off |
| 🤖 **Auto-Config** | Deployment Script (DCE/DCR/RBAC) | 1 | `enablePostDeployScript` | ✅ On |
| 🔔 **Monitoring** | Action Group + Health Alert | 2 | `enableNotifications` | ❌ Off |

---

## ⚙️ Playbook Workflows

### Playbook 1: MDE Device Isolation

```
Sentinel Incident (severity 20+)
    │
    ▼
Extract infected_machine_id + user_hostname from SpyCloud data
    │
    ▼
Search Microsoft Defender for Endpoint API for matching devices
    │
    ├── Device FOUND ──→ Isolate device (Full isolation)
    │                    Tag with "SpyCloud-Infostealer"
    │                    Add incident comment with device details
    │                    Log to Spycloud_MDE_Logs_CL
    │
    └── Device NOT FOUND ──→ Log as "unmatched" for manual review
```

**Requires:** MDE license, `Machine.Isolate` + `Machine.ReadWrite.All`

### Playbook 2: Conditional Access Identity Protection

```
Sentinel Incident (any severity with email)
    │
    ▼
Extract compromised email addresses from SpyCloud data
    │
    ▼
Look up user in Entra ID via Microsoft Graph
    │
    ├── User FOUND ──→ Force password reset on next sign-in
    │                  Revoke all active sessions + refresh tokens
    │                  Add to CA exclusion group (optional)
    │                  Add incident comment with remediation details
    │                  Log to SpyCloud_ConditionalAccessLogs_CL
    │
    └── User NOT FOUND ──→ Log as "external user" for review
```

**Requires:** Entra ID P1+, `User.ReadWrite.All` + `Directory.ReadWrite.All`

### Playbook 3: Credential Exposure → Automated Identity Response *(New)*

```
Sentinel Incident (SpyCloud credential exposure)
    │
    ▼
Extract compromised accounts from incident entities
    │
    ▼
For each account:
    ├── Check recent sign-in activity (last 10 events from Entra audit logs)
    ├── Force password reset on next sign-in
    ├── Revoke all active sessions
    ├── Send Teams alert to SOC channel (MessageCard with user, severity, actions taken)
    └── Add investigation comment to Sentinel incident
```

**Requires:** Security Administrator, `IdentityRisk.ReadWrite.All`, Teams webhook URL

### Playbook 4: SpyCloud Threat Feed → MDE Blocklist *(New)*

```
Scheduled trigger (every 1-24 hours, configurable)
    │
    ▼
Query SpyCloudBreachWatchlist_CL for severity 25 records (last 24h)
    │
    ▼
For each infostealer infection:
    ├── Match infected_machine_id / user_hostname against MDE device inventory
    │
    ├── Device FOUND in MDE ──→ Full device isolation
    │                          Tag: "SpyCloud-Sev25-Infostealer"
    │
    └── Device NOT FOUND ──→ Skip (external/unmanaged device)
```

**Requires:** MDE with API enabled, `Machine.Isolate` + `Machine.ReadWrite.All`

---

## 🎯 22 Analytics Rules (All Deploy DISABLED)

### SpyCloud Core Detection (12 Rules)

| # | Rule | Sev | MITRE | Use Case |
|---|------|-----|-------|----------|
| 1 | Infostealer Exposure | 🔴 High | T1555, T1078 | Severity 20+ malware-stolen credentials detected |
| 2 | Plaintext Password | 🔴 High | T1552 | Cleartext passwords available to attackers immediately |
| 3 | Sensitive PII | 🔴 High | T1530 | SSN, bank accounts, tax IDs, health insurance exposed |
| 4 | Session Cookie Theft | 🔴 High | T1539, T1550 | Stolen cookies and tokens enable MFA bypass |
| 5 | Device Re-Infection | 🔴 High | T1547, T1555 | Previously remediated device compromised again |
| 6 | Multi-Domain Exposure | 🟠 Med | T1078 | User credentials stolen for 5+ different domains |
| 7 | Geographic Anomaly | 🟠 Med | T1078 | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 Med | T1110 | Same credential in 3+ breach sources |
| 9 | Remediation Gap | 🔴 High | T1078 | No automated response after 2+ hours |
| 10 | AV Bypass | 🟢 Info | T1562 | AV present but failed to prevent infostealer |
| 11 | New Malware Family | 🟢 Info | T1589 | New breach source in catalog |
| 12 | Data Ingestion Health | 🟠 Med | — | No data received for 3+ hours |

### Identity Provider Correlation (4 Rules)

| # | Rule | Correlates | Requires |
|---|------|-----------|----------|
| 13 | SpyCloud × Okta | `Okta_CL` | Okta SSO connector from Content Hub |
| 14 | SpyCloud × Duo | `Duo_CL` | Cisco Duo connector from Content Hub |
| 15 | SpyCloud × Ping | `PingFederate_CL` | Ping syslog/API via AMA |
| 16 | SpyCloud × Entra ID | `SigninLogs` | Entra diagnostic settings |

### Advanced Correlation (5 Rules) *(New)*

| # | Rule | Sev | Use Case |
|---|------|-----|----------|
| 18 | Credential + Recent Entra Sign-In | 🔴 High | Compromised user has signed in within 24h — active takeover risk |
| 19 | Breach Source Enrichment | 🟠 Med | Joins watchlist with catalog for breach_title context |
| 20 | Executive / VIP Exposure | 🔴 High | CEO/CFO/CISO/admin accounts exposed |
| 21 | Password Reuse Across Domains | 🔴 High | Same password hash for 3+ target domains |
| 22 | Stale Exposure (7+ Days) | 🟠 Med | SLA/compliance alert — unresolved for 7+ days |

### Severity Reference

| Severity | Priority | Meaning | Required Response |
|----------|----------|---------|-------------------|
| **25** | 🔴 P1 Critical | Infostealer + app data (cookies, sessions, autofill) | Immediate: revoke sessions, reset password, isolate device, investigate malware |
| **20** | 🔴 P1 High | Infostealer credential (email + password from malware) | Urgent: reset password, investigate device health |
| **5** | 🟠 P3 Standard | Breach + PII (credential + name, phone, DOB) | Monitor: review exposure scope, check for reuse |
| **2** | ⚪ P4 Low | Breach credential (email + password from breach) | Awareness: check for credential reuse patterns |

---

## 🤖 Security Copilot Integration

### Plugin (28 KQL Skills)

**Upload:** `copilot/SpyCloud_Plugin.yaml` → securitycopilot.microsoft.com → **Sources** → **Custom** → **Upload Plugin**

**Required settings during upload:** TenantId, SubscriptionId, ResourceGroupName, WorkspaceName

| Category | Skills | Capabilities |
|----------|--------|-------------|
| User Investigation | 4 | Credential lookup by email, full PII profile, account activity timeline, exposed passwords |
| Password Analysis | 3 | Plaintext exposure scan, password type breakdown, crackability assessment |
| Severity & Domain | 3 | High-severity filter, severity distribution, domain-level exposure map |
| PII & Social | 3 | SSN/financial/health data scan, social media accounts, targeted domain analysis |
| Device Forensics | 4 | Infected device inventory, malware path/AV/OS details, device-to-user mapping, AV gap analysis |
| Breach Catalog | 2 | Recent breaches, enriched exposure with catalog metadata |
| MDE Remediation | 3 | All MDE actions, per-device status, remediation statistics |
| CA Remediation | 3 | All CA actions, per-user status, remediation statistics |
| Cross-Table | 3 | Full user investigation, geographic analysis, health dashboard |

### Agent (30 Skills — Interactive AI)

**Upload:** `copilot/SpyCloud_Agent.yaml` → securitycopilot.microsoft.com → **Build** → **Upload YAML Manifest** → configure settings → **Publish**

**Example conversations:**
- *"What can you help me investigate?"* → Overview of all capabilities
- *"Show me our dark web exposure"* → Org-wide exposure summary with severity breakdown
- *"Investigate john@company.com"* → Full credential + PII + device + remediation report
- *"Are any devices infected with infostealer malware?"* → Device forensics with AV analysis
- *"Which users have plaintext passwords exposed?"* → Critical risk list with target domains
- *"Do we have sensitive PII requiring breach notification?"* → Compliance-ready SSN/financial report

---

## 🔧 Post-Deployment Guide

### Step 1: Verify ARM Deployment Succeeded

```bash
# Check deployment status
az deployment group show \
  --name YOUR-DEPLOYMENT-NAME \
  --resource-group spycloud-sentinel \
  --query "properties.provisioningState" -o tsv

# List all deployed resources
az resource list --resource-group spycloud-sentinel \
  --query "[].{Type:type, Name:name}" -o table
```

### Step 2: Run Post-Deploy Script (for API Permissions)

The ARM deployment handles DCE/DCR and RBAC automatically. The post-deploy script handles MDE + Graph API permissions that require Graph API calls:

```bash
chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

**Options:**
```
-g, --resource-group    Resource group (required)
-w, --workspace         Workspace name (required)
-s, --subscription      Subscription ID (optional)
--skip-mde              Skip MDE API permissions
--skip-graph            Skip Graph API permissions
--dry-run               Preview changes without applying
```

### Step 3: Verify Data Flow

```kusto
// Check watchlist data is flowing (run in Sentinel → Logs)
SpyCloudBreachWatchlist_CL
| summarize Count = count(), Latest = max(TimeGenerated) by bin(TimeGenerated, 1h)
| order by TimeGenerated desc

// Check catalog data
SpyCloudBreachCatalog_CL
| summarize count(), max(TimeGenerated)

// Check connector health
SentinelHealth
| where OperationName == "Data fetch"
| where SentinelResourceName contains "SpyCloud"
| project TimeGenerated, Status, Description
| order by TimeGenerated desc
```

### Step 4: Upload Security Copilot Files

| File | Upload Location | Settings |
|------|----------------|----------|
| `copilot/SpyCloud_Plugin.yaml` | Sources → Custom → Upload Plugin | TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| `copilot/SpyCloud_Agent.yaml` | Build → Upload YAML Manifest → Publish | Same settings |

### Step 5: Enable Analytics Rules

1. **Sentinel** → **Analytics** → **Active rules**
2. Filter by name containing "SpyCloud"
3. Review each rule's KQL query
4. Enable rules appropriate for your environment
5. Recommended priority: Rules 1, 2, 4, 9, 12 first (highest impact)

### Step 6: Configure Entra ID Diagnostic Logs

> ⚠️ Cannot be automated via ARM — must be configured in the Entra ID portal.

1. **Entra ID** → **Monitoring** → **Diagnostic settings** → **+ Add**
2. Check: `SignInLogs`, `NonInteractiveUserSignInLogs`, `AuditLogs`, `RiskyUsers`, `UserRiskEvents`
3. Destination: **Send to Log Analytics workspace** → select your workspace

### Step 7: Install Identity Provider Connectors (Optional)

| Provider | Install | Table | Enables Rule |
|----------|---------|-------|-------------|
| Okta | Content Hub → "Okta SSO" | `Okta_CL` | #13 SpyCloud × Okta |
| Cisco Duo | Content Hub → "Cisco Duo" | `Duo_CL` | #14 SpyCloud × Duo |
| Ping Identity | AMA syslog/API | `PingFederate_CL` | #15 SpyCloud × Ping |
| CyberArk | Content Hub → "CyberArk EPM" | `CyberArk_CL` | — |
| Defender XDR | Content Hub → "Microsoft Defender XDR" | `AlertInfo` | Enhanced MDE correlation |
| Microsoft 365 | Content Hub → "Microsoft 365" | `OfficeActivity` | Phishing correlation |

---

## 📁 Repository Structure

```
SPYCLOUD-SENTINEL/
│
├── azuredeploy.json                    ← ARM template (50 params, 45 resources, 20 outputs)
├── azuredeploy.parameters.json         ← Sample parameters file
├── createUiDefinition.json             ← Custom Azure Portal wizard (3 steps, 28 outputs)
├── README.md                           ← This file
├── .gitignore
│
├── .github/workflows/
│   └── deploy.yml                      ← GitHub Actions CI/CD (3 jobs: validate/deploy/configure)
│
├── scripts/
│   ├── deploy-all.sh                   ← One-command guided deployment (9 phases, interactive)
│   └── post-deploy.sh                  ← Post-deploy only (7 phases: DCE/DCR + RBAC + API perms)
│
├── copilot/
│   ├── SpyCloud_Plugin.yaml            ← Security Copilot plugin (28 KQL skills)
│   └── SpyCloud_Agent.yaml             ← Interactive Copilot agent (30 skills + AI)
│
└── docs/
    ├── architecture.md                 ← Architecture, data flow, table schemas
    └── azure-sp-setup.md              ← Service principal setup for GitHub Actions
```

---

## 🔍 Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ResourceNotFound` for workspace | Workspace doesn't exist | Set `createNewWorkspace=true` |
| `ResourceDeploymentFailure` on resolver | Nested deployment trying to reference content template DCR | Fixed in v5.0 — resolver removed, deploymentScript handles it |
| `EntityMappings length 0` | Analytics rule had empty entityMappings array | Fixed in v5.0 — removed empty arrays |
| `No valid tactic for T1078` | MITRE technique without matching tactic | Fixed in v5.0 — added InitialAccess + CredentialAccess |
| `GroupByEntities Account invalid` | groupByEntities referenced entity type not in entityMappings | Fixed in v5.0 — validated all entity type references |
| `VaultNameNotValid` | Key Vault name > 24 chars or special chars | Auto-generated name is safe (kvsc + uniqueString) |
| Deployment script stuck "deploying" | Container timeout too long | Fixed in v5.0 — reduced to 15m total, 60s wait, 20s retry |
| No data in watchlist table | API key invalid, rate limited, or wrong region | Check connector in Sentinel → Data connectors → SpyCloud |
| Logic Apps not triggering | Automation rule not created or wrong trigger type | Verify `enableAutomationRule=true` and rule exists in Sentinel → Automation |
| Copilot skills return empty | Wrong workspace settings in plugin | Verify TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| MDE playbook fails | Missing Machine.Isolate permission | Run `post-deploy.sh` or grant in Portal → Enterprise Apps |
| CA playbook fails | Missing User.ReadWrite.All permission | Run `post-deploy.sh` or grant in Portal → Enterprise Apps |
| Teams alerts not sending | Webhook URL invalid or expired | Regenerate webhook in Teams → Channel → Connectors |

### Verification Commands

```bash
# Check all resources deployed
az resource list -g spycloud-sentinel --query "[].{Type:type,Name:name}" -o table

# Check DCE
az monitor data-collection endpoint show --name dce-spycloud-spycloud-ws -g spycloud-sentinel --query "logsIngestion.endpoint" -o tsv

# Check DCR
az monitor data-collection rule show --name dcr-spycloud-spycloud-ws -g spycloud-sentinel --query "immutableId" -o tsv

# Check Logic App status
az logic workflow list -g spycloud-sentinel --query "[].{Name:name,State:state}" -o table

# Check Key Vault
az keyvault list -g spycloud-sentinel --query "[].{Name:name,Uri:properties.vaultUri}" -o table

# Check analytics rules
az sentinel alert-rule list --workspace-name spycloud-ws -g spycloud-sentinel --query "[?contains(displayName,'SpyCloud')].{Name:displayName,Enabled:enabled}" -o table
```

---

## 🔒 Security Model

| Layer | Protection |
|-------|-----------|
| API Key | SecureString in ARM + Azure Key Vault with RBAC authorization |
| Logic Apps | System-assigned managed identity — zero credentials in workflows |
| MDE API | App role assignments via managed identity principal |
| Graph API | App role assignments via managed identity principal |
| DCE Ingestion | Monitoring Metrics Publisher role on DCR |
| Key Vault | Soft delete + purge protection enabled |
| Network | Outbound HTTPS only: `api.spycloud.io:443`, `*.ingest.monitor.azure.com:443` |
| Deployment Script | Temporary container with user-assigned identity, auto-cleanup on success |

---

## 📄 Support

| Channel | Contact |
|---------|---------|
| SpyCloud API & Data | [support@spycloud.com](mailto:support@spycloud.com) · [portal.spycloud.com](https://portal.spycloud.com) |
| Azure & Sentinel | Azure Portal → Help + Support |
| This Integration | [GitHub Issues](../../issues) |

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/SpyCloud_Enterprise_Protection.svg" alt="SpyCloud" width="120"/>
  <br/>
  <sub>© 2026 SpyCloud, Inc. All rights reserved.</sub><br/>
  <sub><em>SpyCloud transforms recaptured darknet data to disrupt cybercrime.</em></sub><br/>
  <sub><em>Trusted by 7 of the Fortune 10 and hundreds of global enterprises worldwide.</em></sub>
</p>
