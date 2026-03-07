# 🛡️ SpyCloud Sentinel — Unified Threat Intelligence Platform

> **One-click deployment** of SpyCloud's dark web threat intelligence into Microsoft Sentinel with automated remediation, 17 analytics rules, Key Vault secrets management, and Security Copilot integration.

## 🚀 Deploy Now

Choose your deployment method:

### Option 1: One-Click Deploy (Recommended)

Click the button below to open the Azure Portal with the deployment wizard pre-configured:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fspycloud%2Fspycloud-sentinel-integration%2Fmain%2Fazuredeploy.json)

> **What you need:** Your SpyCloud API key from [portal.spycloud.com](https://portal.spycloud.com) → Settings → API Keys

### Option 2: GitHub Actions (CI/CD)

Fork this repo, add your Azure credentials and SpyCloud API key as GitHub Secrets, then trigger the deployment workflow:

```bash
# Fork the repo, then set secrets:
gh secret set AZURE_CREDENTIALS --body '{"clientId":"...","clientSecret":"...","subscriptionId":"...","tenantId":"..."}'
gh secret set SPYCLOUD_API_KEY --body 'your-api-key-here'

# Trigger deployment:
gh workflow run deploy.yml -f resource_group=spycloud-sentinel -f workspace=spycloud-ws -f location=eastus
```

### Option 3: Azure CLI (No PowerShell Required)

```bash
# Login
az login

# Create resource group
az group create --name spycloud-sentinel --location eastus

# Deploy
az deployment group create \
  --resource-group spycloud-sentinel \
  --template-file azuredeploy.json \
  --parameters workspace=spycloud-ws spycloudApiKey=YOUR-KEY-HERE

# After deployment: get the DCE URI and DCR Immutable ID
az monitor data-collection endpoint show \
  --name dce-spycloud-spycloud-ws \
  --resource-group spycloud-sentinel \
  --query logsIngestion.endpoint -o tsv

az monitor data-collection rule show \
  --name dcr-spycloud-spycloud-ws \
  --resource-group spycloud-sentinel \
  --query immutableId -o tsv
```

### Option 4: Terraform

See the [`terraform/`](./terraform/) directory for the Terraform equivalent.

---

## 📦 What Gets Deployed

| Resource | Count | Description |
|----------|-------|-------------|
| Log Analytics Workspace | 1 | With Microsoft Sentinel enabled |
| Data Collection Endpoint | 1 | HTTPS ingestion for SpyCloud data |
| Data Collection Rule | 1 | KQL transforms for 4 data streams |
| Custom Tables | 4 | Watchlist, Catalog, MDE Logs, CA Logs |
| CCF Connector | 3 pollers | Watchlist (new + modified) + Catalog |
| Key Vault | 1 | Stores SpyCloud API key as a secret |
| Logic Apps | 2 | MDE device isolation + CA identity protection |
| Analytics Rules | 17 | All **disabled** by default for review |
| Action Group | 1 | Email/Teams alert notifications |
| Health Alert | 1 | Fires when data ingestion stops |
| RBAC Assignments | 2 | Sentinel Responder for Logic Apps |

**All optional resources are toggle-controlled via parameters.**

---

## 📊 Analytics Rules Library (All Disabled by Default)

### SpyCloud Detection Rules
| # | Rule | Severity | What It Detects |
|---|------|----------|-----------------|
| 1 | Infostealer Exposure | High | Severity 20+ malware-stolen credentials |
| 2 | Plaintext Password | High | Cleartext passwords in criminal hands |
| 3 | Sensitive PII (SSN/Financial) | High | Data requiring breach notification |
| 4 | Session Cookie Theft | High | Severity 25 — MFA bypass risk |
| 5 | Device Re-Infection | High | Same device compromised again |
| 6 | Multi-Domain Exposure | Medium | Credentials stolen for 5+ domains |
| 7 | Geographic Anomaly | Medium | Infections from unusual countries |
| 8 | High-Sighting Credential | Medium | Same creds in 3+ breach sources |
| 9 | Remediation Gap | High | No auto-response for critical exposure |
| 10 | AV Bypass | Info | Endpoint protection failure analysis |
| 11 | New Malware Family | Info | New breach source in catalog |
| 12 | Data Ingestion Health | Medium | Connector stopped receiving data |

### Identity Provider Correlation Rules
| # | Rule | Correlates With | What It Detects |
|---|------|----------------|-----------------|
| 13 | SpyCloud × Okta | Okta SSO logs | Compromised creds used in Okta sign-in |
| 14 | SpyCloud × Duo | Cisco Duo logs | Compromised creds in Duo auth |
| 15 | SpyCloud × Ping | PingOne logs | Compromised creds in Ping auth |
| 16 | SpyCloud × Entra ID | SigninLogs | Compromised creds in Entra sign-in |

> **All rules deploy DISABLED.** Review each rule in Sentinel → Analytics, then enable individually.

---

## 🤖 Security Copilot Integration

After deployment, upload these files to Security Copilot:

| File | Type | Upload Location |
|------|------|----------------|
| `copilot/SpyCloud_Plugin.yaml` | Plugin (28 KQL skills) | Sources → Custom → Upload Plugin |
| `copilot/SpyCloud_Agent.yaml` | Interactive Agent (30 skills) | Build → Upload YAML Manifest |

The **agent** provides an interactive chat experience with 6 starter prompts, 20 follow-up suggestions, and autonomous investigation workflows.

---

## 🔧 Post-Deployment Steps

### Required: Update Logic Apps with DCE/DCR Values

The ARM template creates everything, but the Logic Apps need the DCE URI and DCR Immutable ID to write audit logs. Run the post-deploy script:

```bash
# Bash (no PowerShell!)
./scripts/post-deploy.sh --resource-group spycloud-sentinel --workspace spycloud-ws
```

Or manually:
1. **Azure Portal** → **Monitor** → **Data Collection Endpoints** → copy Logs Ingestion URI
2. **Azure Portal** → **Monitor** → **Data Collection Rules** → JSON View → copy `immutableId`
3. Update each Logic App: **Logic App** → **Logic app designer** → **Parameters** → paste values

### Required: API Permissions (via Azure Portal)

1. **MDE Playbook**: Azure Portal → Logic App → Identity → Azure role assignments → Add **Machine.Isolate** and **Machine.ReadWrite.All**
2. **CA Playbook**: Azure Portal → Logic App → Identity → Azure role assignments → Add **User.ReadWrite.All** and **Directory.ReadWrite.All**

### Optional: Entra ID Logs

Configure in Entra ID portal (cannot be automated via ARM):
- **Entra ID** → **Monitoring** → **Diagnostic settings** → **Add diagnostic setting**
- Check: SignInLogs, AuditLogs, RiskyUsers
- Send to: your Sentinel workspace

### Optional: Identity Provider Connectors

| Provider | How to Connect |
|----------|---------------|
| Okta | Sentinel → Content Hub → "Okta SSO" → Install |
| Cisco Duo | Sentinel → Content Hub → "Cisco Duo" → Install |
| Ping Identity | Syslog/API ingestion via AMA agent |
| CyberArk | Sentinel → Content Hub → "CyberArk" → Install |
| Defender XDR | Sentinel → Content Hub → "Microsoft Defender XDR" → Install |
| Exchange/O365 | Sentinel → Content Hub → "Microsoft 365" → Install |

---

## 📁 Repository Structure

```
spycloud-sentinel-integration/
├── azuredeploy.json              ← Main ARM template (Deploy to Azure button)
├── azuredeploy.parameters.json   ← Sample parameters file
├── .github/
│   └── workflows/
│       └── deploy.yml            ← GitHub Actions deployment workflow
├── scripts/
│   ├── post-deploy.sh            ← Bash post-deployment script
│   └── validate.sh               ← Deployment validation script
├── copilot/
│   ├── SpyCloud_Plugin.yaml      ← Security Copilot plugin (28 skills)
│   └── SpyCloud_Agent.yaml       ← Security Copilot agent (interactive)
├── terraform/
│   └── main.tf                   ← Terraform equivalent (future)
└── docs/
    ├── architecture.md           ← Architecture diagram and data flow
    └── troubleshooting.md        ← Common issues and fixes
```

---

## 📄 License

Copyright © 2026 SpyCloud, Inc. All rights reserved.
