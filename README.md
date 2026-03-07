<p align="center">
  <img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/SpyCloud_Enterprise_Protection.svg" alt="SpyCloud" width="280"/>
</p>

<h1 align="center">SpyCloud Sentinel — Unified Threat Intelligence Platform</h1>

<p align="center">
  <strong>Transform recaptured darknet data into automated identity threat protection</strong><br/>
  One-click deployment of SpyCloud's breach, malware, and phishing intelligence into Microsoft Sentinel<br/>
  with automated remediation, 17 analytics rules, and Security Copilot AI agent integration.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-00B4D8?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/sentinel-compatible-0D1B2A?style=for-the-badge&logo=microsoftazure" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft" alt="Copilot"/>
  <img src="https://img.shields.io/badge/ARM-validated-2D6A4F?style=for-the-badge" alt="ARM"/>
  <img src="https://img.shields.io/badge/powershell-NOT%20REQUIRED-415A77?style=for-the-badge" alt="No PowerShell"/>
</p>

---

## 🚀 Deploy Now

### Option 1: One-Click Deploy to Azure (Recommended)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json" target="_blank">
  <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

> **You need:** SpyCloud API key from [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys

**What happens when you click:**
1. Azure Portal opens the custom deployment wizard
2. Select or create a resource group
3. Enter your workspace name and SpyCloud API key
4. Toggle the features you want (playbooks, Key Vault, analytics rules)
5. Click **Review + create** — everything deploys in 5-10 minutes
6. Run the post-deploy script to complete RBAC and API permissions

### Option 2: GitHub Actions CI/CD

1. **Fork** this repository
2. Add **GitHub Secrets** (Settings → Secrets and variables → Actions):

   | Secret | Value |
   |--------|-------|
   | `AZURE_CREDENTIALS` | Service principal JSON (see [docs/azure-sp-setup.md](docs/azure-sp-setup.md)) |
   | `SPYCLOUD_API_KEY` | Your SpyCloud Enterprise API key |

3. Go to **Actions** → **Deploy SpyCloud Sentinel** → **Run workflow**
4. Fill in the form (resource group, workspace, region, feature toggles)
5. Click **Run workflow** — validates, deploys, and configures automatically

### Option 3: Azure CLI (Bash — Zero PowerShell)

```bash
# Login
az login

# Create resource group
az group create --name spycloud-sentinel --location eastus

# Deploy everything
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY createNewWorkspace=true

# Complete post-deployment (RBAC + API permissions + admin consent)
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git
chmod +x SPYCLOUD-SENTINEL/scripts/post-deploy.sh
./SPYCLOUD-SENTINEL/scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

### Option 4: Azure Cloud Shell (Browser Only — No Local Tooling)

Open [Azure Cloud Shell](https://shell.azure.com) and run:

```bash
# Everything in the browser — no local tools needed
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git
cd SPYCLOUD-SENTINEL

az deployment group create \
  --resource-group spycloud-sentinel \
  --template-file azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY createNewWorkspace=true

chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
```

### Option 5: One-Command Deploy (Cloud Shell / Bash)

Open [Azure Cloud Shell](https://shell.azure.com) (or any bash terminal) and run a single command:

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash -s -- \
  --resource-group spycloud-sentinel \
  --workspace spycloud-ws \
  --api-key YOUR-SPYCLOUD-API-KEY \
  --location eastus
```

This single command does **everything** — creates the resource group, deploys the ARM template, waits for content template resources, resolves DCE/DCR values, assigns all RBAC roles, grants MDE and Graph API permissions, provides admin consent URLs, and verifies the entire deployment. Zero cloning, zero PowerShell.

Or clone first for offline/modified deployment:

```bash
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git && cd SPYCLOUD-SENTINEL
chmod +x scripts/deploy-all.sh
./scripts/deploy-all.sh -g spycloud-sentinel -w spycloud-ws -k YOUR-KEY
```

---

## 📦 What Gets Deployed

### Resource Inventory (42 Parameters · 36 Resources · 17 Outputs)

| Tier | Resource | Count | Toggle | Default |
|------|----------|-------|--------|---------|
| **🏗️ Foundation** | Log Analytics Workspace + Sentinel | 1 | `createNewWorkspace` | ✅ On |
| | Data Collection Endpoint (DCE) | 1 | Always | — |
| | Data Collection Rule (DCR) + KQL Transforms | 1 | Always | — |
| | Custom Tables (Watchlist · Catalog · MDE · CA) | 4 | Always | — |
| | CCF REST API Pollers (New + Modified + Catalog) | 3 | Always | — |
| | Sentinel Content Package | 1 | Always | — |
| **🔐 Security** | Azure Key Vault | 1 | `enableKeyVault` | ✅ On |
| | Key Vault Secret (API key as SecureString) | 1 | `enableKeyVault` | ✅ On |
| **⚙️ Automation** | MDE Logic App (device isolation + tagging) | 1 | `enableMdePlaybook` | ✅ On |
| | CA Logic App (password reset + session revoke) | 1 | `enableCaPlaybook` | ✅ On |
| | Primary Analytics Rule (infostealer detection) | 1 | `enableAnalyticsRule` | ✅ On |
| | Automation Rule (auto-trigger playbooks) | 1 | `enableAutomationRule` | ✅ On |
| | RBAC Role Assignments (Sentinel Responder) | 2 | With playbooks | — |
| **🔔 Monitoring** | Action Group (email + Teams webhook) | 1 | `enableNotifications` | ❌ Off |
| | Data Health Alert (no data for 3h) | 1 | `enableNotifications` | ❌ Off |
| **🎯 Detection** | Analytics Rules Library | 17 | `enableAnalyticsRulesLibrary` | ❌ Off |

> **All analytics rules deploy DISABLED.** Review each rule in Sentinel → Analytics, then enable individually.

### Custom Tables Schema

| Table | Columns | Contents |
|-------|---------|----------|
| `SpyCloudBreachWatchlist_CL` | 73 | Credentials, PII, device forensics, account metadata |
| `SpyCloudBreachCatalog_CL` | 13 | Breach source metadata, status, severity |
| `Spycloud_MDE_Logs_CL` | 19 | MDE remediation audit trail |
| `SpyCloud_ConditionalAccessLogs_CL` | 14 | CA remediation audit trail |

---

## 🎯 Analytics Rules Library

### SpyCloud Detection Rules (12)

| # | Rule | Sev | MITRE | Detects |
|---|------|-----|-------|---------|
| 1 | Infostealer Exposure | 🔴 High | T1555, T1078 | Severity 20+ malware-stolen credentials |
| 2 | Plaintext Password | 🔴 High | T1552 | Cleartext passwords — immediate use by attacker |
| 3 | Sensitive PII Exposure | 🔴 High | T1530 | SSN, bank accounts, tax IDs, health insurance |
| 4 | Session Cookie Theft | 🔴 High | T1539, T1550 | Severity 25 — stolen cookies bypass MFA |
| 5 | Device Re-Infection | 🔴 High | T1547, T1555 | Same device compromised again after remediation |
| 6 | Multi-Domain Exposure | 🟠 Med | T1078 | User credentials stolen for 5+ domains |
| 7 | Geographic Anomaly | 🟠 Med | T1078 | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 Med | T1110 | Same credential in 3+ breach sources |
| 9 | Remediation Gap | 🔴 High | T1078 | No automated response for critical exposure |
| 10 | AV Bypass | 🟢 Info | T1562 | AV present but failed to prevent infostealer |
| 11 | New Malware Family | 🟢 Info | T1589 | New breach source in catalog |
| 12 | Data Ingestion Health | 🟠 Med | — | Connector stopped receiving data |

### Identity Provider Correlation Rules (4)

| # | Rule | Correlates With | Requires |
|---|------|----------------|----------|
| 13 | SpyCloud × Okta | `Okta_CL` | Okta SSO connector |
| 14 | SpyCloud × Duo | `Duo_CL` | Cisco Duo connector |
| 15 | SpyCloud × Ping | `PingFederate_CL` | Ping syslog/API |
| 16 | SpyCloud × Entra ID | `SigninLogs` | Entra diagnostic settings |

### Severity Reference

| Severity | Priority | Meaning | Action Required |
|----------|----------|---------|-----------------|
| **25** | 🔴 P1 Critical | Infostealer + application data (cookies, sessions, autofill) | Immediate — revoke sessions, reset password, isolate device |
| **20** | 🔴 P1 High | Infostealer credential (email + password from malware) | Urgent — reset password, investigate device |
| **5** | 🟠 P3 Standard | Breach + PII (credential + name, phone, DOB) | Monitor — review exposure scope |
| **2** | ⚪ P4 Low | Breach credential (email + password from third-party breach) | Awareness — check for credential reuse |

---

## 🤖 Security Copilot Integration

### Plugin: 28 KQL Skills

**Upload:** `copilot/SpyCloud_Plugin.yaml` → securitycopilot.microsoft.com → **Sources** → **Custom** → **Upload Plugin**

| Category | Skills | What They Do |
|----------|--------|-------------|
| User Investigation | 4 | Credential lookup, full PII profile, account activity, exposed passwords |
| Password Analysis | 3 | Plaintext exposure, password type breakdown, crackability assessment |
| Severity & Domain | 3 | High-severity filter, severity summary, domain-level exposure |
| PII & Social | 3 | SSN/financial/health data, social media accounts, targeted domains |
| Device Forensics | 4 | Infected devices, malware path/AV/OS, device-to-user correlation, AV gaps |
| Breach Catalog | 2 | Recent breaches, enriched exposure with catalog metadata |
| MDE Remediation | 3 | All MDE actions, per-device status, remediation statistics |
| CA Remediation | 3 | All CA actions, per-user status, remediation statistics |
| Cross-Table | 3 | Full user investigation, geographic analysis, health dashboard |

### Agent: Interactive AI Investigation

**Upload:** `copilot/SpyCloud_Agent.yaml` → securitycopilot.microsoft.com → **Build** → **Upload YAML Manifest**

| Feature | Details |
|---------|---------|
| Architecture | 1 AGENT skill + 1 GPT skill + 28 KQL data skills |
| Starter Prompts | 6 prompts covering exposure overview, critical users, infected devices, plaintext passwords, PII compliance |
| Follow-up Suggestions | 20 contextual pivots for deep investigation |
| Personas | SOC Analyst, Threat Intel, IT Admin, CISO |

---

## 🔧 Post-Deployment Guide

### Step 1: Run the Post-Deploy Script (Required)

The post-deploy script completes everything the ARM template cannot automate:

```bash
chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh -g YOUR-RESOURCE-GROUP -w YOUR-WORKSPACE
```

**What the script does (7 phases):**

| Phase | Action | Why ARM Can't Do This |
|-------|--------|-----------------------|
| 1 | Authenticate to Azure | Script needs interactive login |
| 2 | Resolve DCE Logs Ingestion URI | DCE is top-level but URI only available after creation |
| 3 | Resolve DCR Immutable ID | DCR is inside a nested content template |
| 4 | Assign Monitoring Metrics Publisher on DCR | Cross-resource RBAC on nested resource |
| 5 | Grant MDE API permissions (Machine.Isolate) | Requires Graph API calls to service principals |
| 6 | Grant Graph API permissions (User.ReadWrite.All) | Requires Graph API calls to service principals |
| 7 | Verify all resources + provide admin consent URLs | Portal navigation for manual consent |

**Script options:**
```
-g, --resource-group    Resource group name (required)
-w, --workspace         Workspace name (required)
-s, --subscription      Subscription ID (optional)
--skip-mde              Skip MDE permissions
--skip-graph            Skip Graph permissions
--dry-run               Preview without making changes
```

### Step 2: Admin Consent (If Prompted)

Some API permissions require **tenant admin consent**. The post-deploy script provides direct portal URLs, or navigate manually:

1. **Azure Portal** → **Enterprise Applications**
2. Search for the Logic App managed identity name
3. Click → **Permissions** → **Grant admin consent for [tenant]**

### Step 3: Verify Data Flow

```bash
# Check if SpyCloud data is flowing (run in Sentinel → Logs)
SpyCloudBreachWatchlist_CL | summarize count() by bin(TimeGenerated, 1h) | order by TimeGenerated desc
SpyCloudBreachCatalog_CL | summarize max(TimeGenerated)
```

### Step 4: Upload Security Copilot Files

| File | Upload Location | Settings Required |
|------|----------------|-------------------|
| `copilot/SpyCloud_Plugin.yaml` | Sources → Custom → Upload Plugin | TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| `copilot/SpyCloud_Agent.yaml` | Build → Upload YAML Manifest | Same settings, then Publish |

### Step 5: Enable Analytics Rules

1. **Sentinel** → **Analytics** → **Active rules**
2. Filter by name containing "SpyCloud"
3. Review each rule's KQL query
4. Enable the rules appropriate for your environment

### Step 6: Configure Entra ID Logs (Optional)

> ⚠️ **Cannot be automated via ARM templates** — Entra ID diagnostic settings live at the tenant level.

1. **Entra ID** → **Monitoring** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Check: `SignInLogs`, `NonInteractiveUserSignInLogs`, `AuditLogs`, `RiskyUsers`, `UserRiskEvents`
4. Destination: **Send to Log Analytics workspace** → select your workspace

### Step 7: Install Identity Provider Connectors (Optional)

| Provider | Install Method | Sentinel Table |
|----------|---------------|----------------|
| Okta | Content Hub → "Okta SSO" → Install + Configure | `Okta_CL` |
| Cisco Duo | Content Hub → "Cisco Duo Security" → Install | `Duo_CL` |
| Ping Identity | AMA agent syslog or API connector | `PingFederate_CL` |
| CyberArk | Content Hub → "CyberArk EPM" → Install | `CyberArk_CL` |
| Defender XDR | Content Hub → "Microsoft Defender XDR" → Connect | `AlertInfo`, `DeviceEvents` |
| Microsoft 365 | Content Hub → "Microsoft 365" → Connect | `OfficeActivity`, `EmailEvents` |

---

## 📁 Repository Structure

```
SPYCLOUD-SENTINEL/
│
├── azuredeploy.json                    ← ARM template (42 params, 36 resources)
├── azuredeploy.parameters.json         ← Sample parameters file
├── README.md                           ← This file
├── .gitignore                          ← Excludes secrets and IDE files
│
├── .github/
│   └── workflows/
│       └── deploy.yml                  ← GitHub Actions CI/CD (3 jobs)
│
├── scripts/
│   └── post-deploy.sh                  ← Bash post-deploy (7 phases, no PowerShell)
│
├── copilot/
│   ├── SpyCloud_Plugin.yaml            ← Security Copilot plugin (28 KQL skills)
│   └── SpyCloud_Agent.yaml             ← Interactive agent (30 skills + AI)
│
└── docs/
    └── architecture.md                 ← Architecture, data flow, severity guide
```

---

## 🔒 Security Model

| Layer | Protection |
|-------|-----------|
| API Key Storage | SecureString in ARM + Azure Key Vault secret |
| Logic App Auth | System Managed Identity (no credentials in workflows) |
| MDE API | App role assignments via managed identity |
| Graph API | App role assignments via managed identity |
| DCE Ingestion | Managed identity with Monitoring Metrics Publisher role |
| Key Vault | RBAC authorization + soft delete + purge protection |
| Network | Outbound HTTPS only: `api.spycloud.io:443`, `*.ingest.monitor.azure.com:443` |

---

## 🔍 Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ResourceNotFound` for workspace | Workspace doesn't exist | Set `createNewWorkspace=true` |
| `ResourceNotFound` for DCR | Content template still deploying | Wait 2-3 min, run post-deploy.sh again |
| `VaultNameNotValid` | Key Vault name > 24 chars or has special chars | Auto-generated name is safe; override with `keyVaultName` param |
| No data in watchlist table | API key invalid or rate limited | Check connector status in Sentinel → Data Connectors |
| Logic App runs failing | Missing DCE/DCR values or API permissions | Run `post-deploy.sh` to resolve all |
| Analytics rules not firing | Rules are disabled by default | Enable in Sentinel → Analytics |
| `reference()` errors | ARM can't reference nested template resources | Use the resolver deployment (built in) |
| Copilot skills return empty | Wrong workspace settings in plugin | Verify TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |

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
  <sub><em>Trusted by 7 of the Fortune 10 and hundreds of global enterprises.</em></sub>
</p>
