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
  <img src="https://img.shields.io/badge/sentinel-compatible-0D1B2A?style=for-the-badge&logo=microsoft" alt="Sentinel"/>
  <img src="https://img.shields.io/badge/copilot-integrated-E07A5F?style=for-the-badge&logo=microsoft" alt="Copilot"/>
  <img src="https://img.shields.io/badge/license-proprietary-415A77?style=for-the-badge" alt="License"/>
</p>

---

## 🚀 Deploy Now

### One-Click Deploy to Azure

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fspycloud%2Fspycloud-sentinel-integration%2Fmain%2Fazuredeploy.json" target="_blank">
  <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

> **Prerequisites:** SpyCloud Enterprise API key ([portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys) and Azure Contributor role on the target subscription.

### Alternative Deployment Methods

<details>
<summary><strong>🔄 GitHub Actions (CI/CD)</strong></summary>

1. Fork this repository
2. Add GitHub Secrets:
   ```
   AZURE_CREDENTIALS  →  Service principal JSON (see docs/azure-sp-setup.md)
   SPYCLOUD_API_KEY   →  Your SpyCloud Enterprise API key
   ```
3. Go to **Actions** → **Deploy SpyCloud Sentinel** → **Run workflow**
4. Fill in the deployment form and click **Run**

The workflow validates the template, deploys all resources, resolves DCE/DCR values, and assigns RBAC permissions automatically.
</details>

<details>
<summary><strong>💻 Azure CLI (Bash — no PowerShell)</strong></summary>

```bash
# Login and set subscription
az login
az account set --subscription "YOUR-SUBSCRIPTION-ID"

# Create resource group
az group create --name spycloud-sentinel --location eastus

# Deploy (creates workspace, Sentinel, connector, playbooks, rules, Key Vault)
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-uri https://raw.githubusercontent.com/spycloud/spycloud-sentinel-integration/main/azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY-HERE createNewWorkspace=true

# Post-deployment: resolve DCE/DCR and assign permissions
./scripts/post-deploy.sh --resource-group spycloud-sentinel --workspace spycloud-ws
```
</details>

<details>
<summary><strong>📋 Azure Portal (Manual)</strong></summary>

1. Azure Portal → search **"Deploy a custom template"**
2. Click **"Build your own template in the editor"**
3. Paste contents of [`azuredeploy.json`](./azuredeploy.json)
4. Click **Save** → fill in parameters → **Review + create**
</details>

---

## 📦 What Gets Deployed

<table>
<tr>
<th>Tier</th>
<th>Resource</th>
<th>Count</th>
<th>Toggle</th>
</tr>
<tr style="background:#0D1B2A;color:white">
<td rowspan="6"><strong>🏗️ Foundation</strong></td>
<td>Log Analytics Workspace + Sentinel</td><td>1</td><td><code>createNewWorkspace</code></td>
</tr>
<tr><td>Data Collection Endpoint (DCE)</td><td>1</td><td>Always</td></tr>
<tr><td>Data Collection Rule (DCR) + KQL Transforms</td><td>1</td><td>Always</td></tr>
<tr><td>Custom Tables (Watchlist, Catalog, MDE, CA)</td><td>4</td><td>Always</td></tr>
<tr><td>CCF REST API Pollers (Watchlist New/Mod + Catalog)</td><td>3</td><td>Always</td></tr>
<tr><td>Content Package</td><td>1</td><td>Always</td></tr>
<tr style="background:#1B2838;color:white">
<td rowspan="2"><strong>🔐 Security</strong></td>
<td>Azure Key Vault</td><td>1</td><td><code>enableKeyVault</code></td>
</tr>
<tr><td>Key Vault Secret (SpyCloud API Key)</td><td>1</td><td><code>enableKeyVault</code></td></tr>
<tr style="background:#415A77;color:white">
<td rowspan="5"><strong>⚙️ Automation</strong></td>
<td>MDE Remediation Logic App (device isolation + tagging)</td><td>1</td><td><code>enableMdePlaybook</code></td>
</tr>
<tr><td>CA Remediation Logic App (password reset + session revoke)</td><td>1</td><td><code>enableCaPlaybook</code></td></tr>
<tr><td>Analytics Rule (infostealer detection)</td><td>1</td><td><code>enableAnalyticsRule</code></td></tr>
<tr><td>Automation Rule (auto-trigger playbooks)</td><td>1</td><td><code>enableAutomationRule</code></td></tr>
<tr><td>RBAC Role Assignments</td><td>2</td><td>With playbooks</td></tr>
<tr style="background:#00B4D8;color:white">
<td rowspan="2"><strong>🔔 Notifications</strong></td>
<td>Action Group (email + Teams webhook)</td><td>1</td><td><code>enableNotifications</code></td>
</tr>
<tr><td>Data Health Alert (fires when ingestion stops)</td><td>1</td><td><code>enableNotifications</code></td></tr>
<tr style="background:#E07A5F;color:white">
<td><strong>🎯 Detection</strong></td>
<td>Analytics Rules Library (all DISABLED by default)</td><td>17</td><td><code>enableAnalyticsRulesLibrary</code></td>
</tr>
</table>

---

## 🎯 Analytics Rules Library

All rules deploy **DISABLED** by default. Review each rule's KQL logic in Sentinel → Analytics, then enable individually.

### SpyCloud Detection Rules

| # | Rule | Sev | Detects |
|---|------|-----|---------|
| 1 | 🔴 Infostealer Exposure | High | Severity 20+ malware-stolen credentials |
| 2 | 🔴 Plaintext Password | High | Cleartext passwords in criminal hands |
| 3 | 🔴 Sensitive PII Exposure | High | SSN, bank accounts, tax IDs, health data |
| 4 | 🔴 Session Cookie Theft | High | Severity 25 — stolen cookies enable MFA bypass |
| 5 | 🔴 Device Re-Infection | High | Same device compromised again after remediation |
| 6 | 🟠 Multi-Domain Exposure | Med | User credentials stolen for 5+ different domains |
| 7 | 🟠 Geographic Anomaly | Med | Infections from unusual countries |
| 8 | 🟠 High-Sighting Credential | Med | Same credential observed in 3+ breach sources |
| 9 | 🔴 Remediation Gap | High | No automated response for critical exposure |
| 10 | 🟢 AV Bypass | Info | Endpoint protection present but failed |
| 11 | 🟢 New Malware Family | Info | New breach source in catalog |
| 12 | 🟠 Data Ingestion Health | Med | Connector stopped receiving data |

### Identity Provider Correlation Rules

| # | Rule | Correlates | Detects |
|---|------|-----------|---------|
| 13 | 🔴 SpyCloud × Okta | Okta SSO | Compromised creds used in Okta sign-in |
| 14 | 🔴 SpyCloud × Duo | Cisco Duo | Compromised creds in Duo MFA |
| 15 | 🔴 SpyCloud × Ping | PingOne | Compromised creds in Ping auth |
| 16 | 🔴 SpyCloud × Entra ID | SigninLogs | Compromised creds in Entra sign-in |

> **IdP rules require** those providers' logs already ingested into Sentinel via their Content Hub connectors.

---

## 🤖 Security Copilot Integration

This repository includes a **28-skill KQL plugin** and a **30-skill interactive AI agent** for Microsoft Security Copilot.

### Plugin (28 KQL Skills)

Upload `copilot/SpyCloud_Plugin.yaml` via **Sources → Custom → Upload Plugin**

Skills cover: user credential lookup, password analysis (plaintext/hashed/type breakdown), full PII profile (SSN/financial/health), device forensics (malware path, AV gaps, IPs), MDE remediation audit, CA remediation audit, breach catalog enrichment, cross-table correlation, geographic analysis, and health monitoring.

### Interactive Agent (30 Skills)

Upload `copilot/SpyCloud_Agent.yaml` via **Build → Upload YAML Manifest**

The agent provides a **conversational chat experience** with:
- 🎯 6 starter prompts for common investigation scenarios
- 💬 20 follow-up suggestions for pivoting deeper
- 🧠 Autonomous investigation workflows for emails, devices, malware, and org-wide overviews
- 📊 Rich formatted output with severity indicators, data tables, timelines, and remediation gap analysis
- 🔍 Contextual follow-up questions at the end of every response

**Example prompts:**
- *"What can you help me investigate?"*
- *"Show me an overview of our dark web exposure"*
- *"Which users have plaintext passwords exposed?"*
- *"Are any devices infected with infostealer malware?"*

---

## 🔧 Post-Deployment

### Required: Run Post-Deploy Script

```bash
# Pure bash — no PowerShell required
chmod +x scripts/post-deploy.sh
./scripts/post-deploy.sh \
  --resource-group spycloud-sentinel \
  --workspace spycloud-ws
```

This script resolves DCE/DCR values and assigns RBAC permissions automatically.

### Required: API Permissions (Azure Portal)

| Playbook | Permission | Where to Assign |
|----------|-----------|-----------------|
| MDE Remediation | Machine.Isolate, Machine.ReadWrite.All | Logic App → Identity → Azure role assignments |
| CA Remediation | User.ReadWrite.All, Directory.ReadWrite.All | Logic App → Identity → Azure role assignments |

### Optional: Entra ID Diagnostic Logs

Configure manually in the Entra ID portal:
- **Entra ID** → **Monitoring** → **Diagnostic settings** → **Add diagnostic setting**
- Check: `SignInLogs`, `NonInteractiveUserSignInLogs`, `AuditLogs`, `RiskyUsers`
- Destination: Send to your Log Analytics workspace

### Optional: Identity Provider Connectors

| Provider | How to Connect |
|----------|---------------|
| Okta | Sentinel → Content Hub → "Okta SSO" → Install |
| Cisco Duo | Sentinel → Content Hub → "Cisco Duo" → Install |
| Ping Identity | Syslog/API ingestion via AMA agent |
| CyberArk | Sentinel → Content Hub → "CyberArk" → Install |
| Microsoft Defender XDR | Sentinel → Content Hub → "Microsoft Defender XDR" → Install |
| Microsoft 365 / Exchange | Sentinel → Content Hub → "Microsoft 365" → Install |

---

## 📁 Repository Structure

```
spycloud-sentinel-integration/
│
├── azuredeploy.json                    ← ARM template (Deploy to Azure button)
├── azuredeploy.parameters.json         ← Sample parameters file
│
├── .github/
│   └── workflows/
│       └── deploy.yml                  ← GitHub Actions CI/CD workflow
│
├── scripts/
│   └── post-deploy.sh                  ← Bash post-deployment (no PowerShell)
│
├── copilot/
│   ├── SpyCloud_Plugin.yaml            ← Security Copilot plugin (28 KQL skills)
│   └── SpyCloud_Agent.yaml             ← Interactive Copilot agent (30 skills)
│
└── docs/
    └── architecture.md                 ← Architecture diagrams and data flow
```

---

## 📊 Data Flow

```
SpyCloud API ──Bearer Token──→ CCF Poller ──→ DCE ──→ DCR (KQL Transform)
                                                          │
                    ┌─────────────────────────────────────┼─────────────────┐
                    ▼                    ▼                 ▼                 ▼
          SpyCloudBreach       SpyCloudBreach      Spycloud_MDE    SpyCloud_CA
          Watchlist_CL         Catalog_CL          Logs_CL         Logs_CL
          (73 columns)         (13 columns)        (19 columns)    (14 columns)
                    │                                     ▲                 ▲
                    ▼                                     │                 │
            Analytics Rule ──→ Incident ──→ Automation ──→ Playbooks
                    │                           │          (MDE + CA)
                    ▼                           ▼
            Action Group              Sentinel Incident
            (Email/Teams)             Comments + Tags
```

---

## 🔒 Security

- SpyCloud API key stored as `SecureString` in ARM and optionally in Azure Key Vault
- Logic Apps use **System Managed Identity** — no credentials stored in workflows
- All API calls authenticated via Managed Identity (Defender, Graph, DCE)
- Key Vault uses **RBAC authorization** with soft delete enabled
- Network access: outbound HTTPS to `api.spycloud.io` (443) and `*.ingest.monitor.azure.com` (443)

---

## 📄 Support

| Issue | Contact |
|-------|---------|
| SpyCloud API / Data | [support@spycloud.com](mailto:support@spycloud.com) or [portal.spycloud.com](https://portal.spycloud.com) |
| Azure / Sentinel | Azure Portal → Help + Support |
| This Integration | [GitHub Issues](../../issues) |

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/SpyCloud_Enterprise_Protection.svg" alt="SpyCloud" width="120"/>
  <br/>
  <sub>© 2026 SpyCloud, Inc. All rights reserved.</sub>
  <br/>
  <sub>SpyCloud transforms recaptured darknet data to disrupt cybercrime.</sub>
</p>
