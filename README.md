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
  <img src="https://img.shields.io/badge/powershell-NOT%20REQUIRED-415A77?style=for-the-badge" alt="No PowerShell"/>
</p>

---

## 🚀 Deploy Now — Choose Your Method

### ☁️ Deploy to Azure (One Click)

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json" target="_blank">
  <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

> Opens the Azure Portal deployment wizard. Enter your workspace name, SpyCloud API key, toggle features → click Create.

### 🐚 Launch in Azure Cloud Shell (Guided Interactive Setup)

<a href="https://shell.azure.com" target="_blank">
  <img src="https://learn.microsoft.com/azure/cloud-shell/media/embed-cloud-shell/launch-cloud-shell-1.png" alt="Launch Cloud Shell" width="200"/>
</a>

**Paste this one command** — it launches a fully interactive, guided wizard with menus:

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
```

**What the interactive wizard does:**
1. Authenticates to Azure
2. Prompts for resource group, workspace, API key, region
3. Shows feature toggle menu (playbooks, Key Vault, rules, notifications)
4. Displays confirmation summary before deploying
5. Deploys the ARM template
6. Waits for Sentinel content template to create DCR + tables
7. Resolves DCE URI and DCR Immutable ID automatically
8. Assigns Monitoring Metrics Publisher RBAC to Logic Apps
9. Grants MDE API permissions (Machine.Isolate, Machine.ReadWrite.All)
10. Grants Graph API permissions (User.ReadWrite.All, Directory.ReadWrite.All)
11. Provides admin consent portal URLs
12. Verifies all deployed resources
13. Prints deployment summary with next steps

All logging written to `/tmp/spycloud-deploy-*.log` for debugging.

### 💻 Non-Interactive (CLI with Arguments)

```bash
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash -s -- \
  --resource-group spycloud-sentinel \
  --workspace spycloud-ws \
  --api-key YOUR-SPYCLOUD-API-KEY \
  --location eastus
```

Or clone and run locally:

```bash
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git && cd SPYCLOUD-SENTINEL
chmod +x scripts/deploy-all.sh
./scripts/deploy-all.sh -g spycloud-sentinel -w spycloud-ws -k YOUR-KEY -l eastus
```

<details>
<summary><strong>🔄 GitHub Actions (CI/CD Pipeline)</strong></summary>

1. Fork this repository
2. Add GitHub Secrets:

   | Secret | Value |
   |--------|-------|
   | `AZURE_CREDENTIALS` | Service principal JSON ([setup guide](docs/azure-sp-setup.md)) |
   | `SPYCLOUD_API_KEY` | Your SpyCloud Enterprise API key |

3. Go to **Actions** → **Deploy SpyCloud Sentinel** → **Run workflow**
4. Fill in the form → click **Run**

The workflow runs 3 jobs: **Validate** → **Deploy** → **Configure** (post-deploy RBAC + API perms).
</details>

<details>
<summary><strong>📋 Azure Portal (Manual Template)</strong></summary>

1. Azure Portal → search **"Deploy a custom template"**
2. Click **"Build your own template in the editor"**
3. Paste contents of [`azuredeploy.json`](./azuredeploy.json) → **Save**
4. Fill in parameters → **Review + create**
5. After deployment, run `scripts/post-deploy.sh` for RBAC + API permissions
</details>

---

## 🔄 Complete Deployment Lifecycle

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  STEP 1: Deploy Infrastructure                                     │
│  ─────────────────────────────                                     │
│  Choose: Deploy to Azure button │ Cloud Shell │ CLI │ GitHub Actions│
│                                                                    │
│  Creates: Workspace, Sentinel, DCE, DCR, Tables, Connector,       │
│           Key Vault, Logic Apps, Analytics Rules, Action Groups    │
│                                                                    │
│  STEP 2: Post-Deployment (automated by deploy-all.sh)              │
│  ────────────────────────────────────────────────────              │
│  • Resolve DCE URI + DCR Immutable ID                              │
│  • Assign Monitoring Metrics Publisher on DCR                      │
│  • Grant MDE API: Machine.Isolate, Machine.ReadWrite.All           │
│  • Grant Graph API: User.ReadWrite.All, Directory.ReadWrite.All    │
│  • Admin consent (portal URL provided)                             │
│                                                                    │
│  STEP 3: Manual Configuration                                      │
│  ────────────────────────────                                      │
│  • Upload Security Copilot plugin + agent (YAML files in copilot/) │
│  • Enable analytics rules in Sentinel → Analytics                  │
│  • Configure Entra ID diagnostic settings                          │
│  • Install IdP connectors: Okta / Duo / Ping / CyberArk           │
│                                                                    │
│  STEP 4: Verify                                                    │
│  ─────────                                                         │
│  • Check SpyCloud data connector status                            │
│  • Query: SpyCloudBreachWatchlist_CL | count                       │
│  • Test Copilot: "What can you help me investigate?"               │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 📦 What Gets Deployed

### Resources (44 Parameters · 35 Resources · 17 Outputs)

| Tier | Resource | Count | Toggle | Default |
|------|----------|-------|--------|---------|
| 🏗️ **Foundation** | Workspace + Sentinel | 1 | `createNewWorkspace` | ✅ |
| | Data Collection Endpoint | 1 | Always | — |
| | DCR + KQL Transforms + 4 Custom Tables | 1 | Always | — |
| | CCF REST API Pollers | 3 | Always | — |
| 🔐 **Security** | Key Vault + Secret | 2 | `enableKeyVault` | ✅ |
| ⚙️ **Automation** | MDE Logic App (isolate + tag) | 1 | `enableMdePlaybook` | ✅ |
| | CA Logic App (reset + revoke) | 1 | `enableCaPlaybook` | ✅ |
| | Analytics + Automation Rules | 2 | `enableAnalyticsRule` | ✅ |
| 🔔 **Monitoring** | Action Group + Health Alert | 2 | `enableNotifications` | ❌ |
| 🎯 **Detection** | Analytics Rules Library | 17 | `enableAnalyticsRulesLibrary` | ❌ |

### 17 Analytics Rules (All Deploy DISABLED)

| # | Rule | Sev | MITRE | Detects |
|---|------|-----|-------|---------|
| 1 | Infostealer Exposure | 🔴 High | T1555, T1078 | Severity 20+ malware-stolen credentials |
| 2 | Plaintext Password | 🔴 High | T1552 | Cleartext passwords in criminal hands |
| 3 | Sensitive PII | 🔴 High | T1530 | SSN, bank, tax, health data |
| 4 | Session Cookie Theft | 🔴 High | T1539, T1550 | Stolen cookies = MFA bypass |
| 5 | Device Re-Infection | 🔴 High | T1547, T1555 | Same device compromised again |
| 6 | Multi-Domain Exposure | 🟠 Med | T1078 | Creds stolen for 5+ domains |
| 7 | Geographic Anomaly | 🟠 Med | T1078 | Infections from unusual countries |
| 8 | High-Sighting Credential | 🟠 Med | T1110 | Same creds in 3+ breach sources |
| 9 | Remediation Gap | 🔴 High | T1078 | No auto-response for critical exposure |
| 10 | AV Bypass | 🟢 Info | T1562 | AV present but failed |
| 11 | New Malware Family | 🟢 Info | T1589 | New breach source in catalog |
| 12 | Data Ingestion Health | 🟠 Med | — | Connector stopped receiving data |
| 13–16 | IdP Correlation (×4) | 🔴 High | T1078 | Okta, Duo, Ping, Entra sign-in |

---

## 🤖 Security Copilot

| File | Skills | Upload To |
|------|--------|-----------|
| `copilot/SpyCloud_Plugin.yaml` | 28 KQL skills | Sources → Custom → Upload Plugin |
| `copilot/SpyCloud_Agent.yaml` | 30 skills + AI agent | Build → Upload YAML Manifest |

**Plugin:** User investigation, password analysis, PII exposure, device forensics, MDE/CA remediation audit, breach catalog, geographic analysis, health monitoring.

**Agent:** Interactive investigation with 6 starter prompts, 20 follow-up suggestions, autonomous workflows for SOC analysts, threat intel, IT admins, and CISOs.

---

## 📁 Repository Structure

```
SPYCLOUD-SENTINEL/
├── azuredeploy.json                 ← ARM template (44 params, 35 resources)
├── azuredeploy.parameters.json      ← Sample parameters file
├── README.md                        ← This file
├── .github/workflows/
│   └── deploy.yml                   ← GitHub Actions (3 jobs: validate/deploy/configure)
├── scripts/
│   ├── deploy-all.sh                ← One-command guided deployment (9 phases)
│   └── post-deploy.sh               ← Post-deploy only (7 phases, if ARM deployed separately)
├── copilot/
│   ├── SpyCloud_Plugin.yaml         ← Security Copilot plugin (28 skills)
│   └── SpyCloud_Agent.yaml          ← Interactive Copilot agent (30 skills)
└── docs/
    ├── architecture.md              ← Architecture, data flow, severity guide
    └── azure-sp-setup.md            ← Service principal setup for GitHub Actions
```

---

## 🔍 Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ResourceNotFound` for workspace | Set `createNewWorkspace=true` |
| `ResourceDeploymentFailure` on resolver | Already fixed in v4.0 — resolver removed |
| `EntityMappings length 0` | Already fixed in v4.0 — empty arrays removed |
| `No valid tactic for T1078` | Already fixed in v4.0 — tactics added |
| No data flowing | Check Sentinel → Data Connectors → SpyCloud status |
| Logic Apps failing | Run `scripts/post-deploy.sh` to fix DCE/DCR + RBAC |
| Copilot skills empty | Verify settings: TenantId, SubscriptionId, ResourceGroupName, WorkspaceName |
| Deploy-all.sh errors | Check log at `/tmp/spycloud-deploy-*.log` |

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/SpyCloud_Enterprise_Protection.svg" alt="SpyCloud" width="120"/>
  <br/>
  <sub>© 2026 SpyCloud, Inc. All rights reserved.</sub><br/>
  <sub><em>SpyCloud transforms recaptured darknet data to disrupt cybercrime.</em></sub><br/>
  <sub><em>Trusted by 7 of the Fortune 10 and hundreds of global enterprises.</em></sub>
</p>
