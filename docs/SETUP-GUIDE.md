# SpyCloud Identity Exposure Intelligence for Sentinel — Setup Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Content Hub Installation](#content-hub-installation)
3. [Data Connector Configuration](#data-connector-configuration)
4. [SpyCloud API Setup](#spycloud-api-setup)
5. [Sentinel Analytics Rules](#sentinel-analytics-rules)
6. [Playbook (Logic App) Configuration](#playbook-configuration)
7. [Workbook Deployment](#workbook-deployment)
8. [Microsoft Defender for Endpoint (MDE/XDR)](#mde-xdr-configuration)
9. [Conditional Access Policies](#conditional-access-policies)
10. [Microsoft Intune Integration](#intune-integration)
11. [Microsoft Purview Integration](#purview-integration)
12. [AI Engine Setup](#ai-engine-setup)
13. [MCP Server Setup](#mcp-server-setup)
14. [Security Copilot Integration](#security-copilot-integration)
15. [Sentinel Graph Configuration](#sentinel-graph-configuration)
16. [Jupyter Notebook Environment](#jupyter-notebook-environment)
17. [Validation & Testing](#validation-testing)
18. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Azure Subscriptions & Licenses

| Requirement | Purpose | Required |
|-------------|---------|----------|
| Azure Subscription | Host all resources | Yes |
| Microsoft Sentinel | SIEM platform | Yes |
| Log Analytics Workspace | Data storage | Yes |
| Microsoft Entra ID P1/P2 | Sign-in logs, Conditional Access | Yes |
| Microsoft Defender for Endpoint P2 | Device isolation, forensics | Recommended |
| Microsoft Security Copilot | AI-powered investigation | Optional |
| Microsoft Purview | Data governance integration | Optional |
| Azure OpenAI or OpenAI API | AI Engine for SCORCH agent | Optional |

### SpyCloud Requirements

| Requirement | Details |
|-------------|---------|
| SpyCloud API Key | Obtain from SpyCloud portal (api.spycloud.io) |
| SpyCloud Subscription | Enterprise tier required for full API access |
| API Endpoints | Breach Watchlist, Compass, SIP, IDLink, CAP |

### Azure RBAC Permissions

The deploying user needs these minimum roles:

| Role | Scope | Purpose |
|------|-------|---------|
| Microsoft Sentinel Contributor | Resource Group | Deploy analytics rules, workbooks |
| Logic App Contributor | Resource Group | Deploy and configure playbooks |
| Monitoring Contributor | Resource Group | Configure DCR, DCE |
| Key Vault Administrator | Key Vault | Store SpyCloud API key |
| User Access Administrator | Subscription | Assign managed identity permissions |

---

## Content Hub Installation

### Step 1: Navigate to Content Hub

1. Open Azure Portal → Microsoft Sentinel → your workspace
2. Go to **Content management** → **Content hub**
3. Search for **"SpyCloud"** in the search bar

### Step 2: Install the Solution

1. Select **SpyCloud Identity Exposure Intelligence for Sentinel**
2. Click **Install** / **Update**
3. Select your workspace and resource group
4. Review the components that will be installed:
   - 14 Data Connectors (CCF-based)
   - 49 Analytics Rules
   - 28 Hunting Queries
   - 10 Playbooks (Logic Apps)
   - 3 Workbooks
   - 1 Watchlist

### Step 3: Post-Installation

After installation, you must configure each component individually:
- Data connectors need API keys
- Playbooks need managed identity permissions
- Analytics rules need to be enabled

---

## Data Connector Configuration

### SpyCloud Custom Log Tables

The solution creates 14 custom log tables via the Codeless Connector Framework (CCF):

| Table | Description | Polling Interval |
|-------|-------------|-----------------|
| `SpyCloudBreachWatchlist_CL` | Monitored email/domain exposures | 6 hours |
| `SpyCloudBreachCatalog_CL` | Breach source metadata | 24 hours |
| `SpyCloudCompassData_CL` | Deep forensic device data | 6 hours |
| `SpyCloudCompassDevices_CL` | Infected device inventory | 12 hours |
| `SpyCloudCompassApplications_CL` | Compromised applications | 12 hours |
| `SpyCloudSipCookies_CL` | Stolen session cookies | 6 hours |
| `SpyCloudSipKeystrokes_CL` | Captured keystrokes | 6 hours |
| `SpyCloudIdLink_CL` | Identity correlation data | 12 hours |
| `SpyCloudCAP_CL` | Credential access events | 6 hours |
| `SpyCloudAlerts_CL` | Alert notifications | 1 hour |
| `SpyCloudInvestigations_CL` | Investigation data | On-demand |
| `SpyCloudEnrichment_CL` | Enrichment results | On-demand |
| `SpyCloudRiskScores_CL` | Risk scoring data | 12 hours |
| `SpyCloudThreatActors_CL` | Threat actor profiles | 24 hours |

### Configuration Steps

1. **Navigate to Data Connectors:**
   - Sentinel → Configuration → Data connectors
   - Filter by "SpyCloud"

2. **Configure Each Connector:**
   - Click on the connector → Open connector page
   - Enter your SpyCloud API Key
   - Configure polling interval
   - Select severity levels to ingest (2, 5, 20, 25)
   - Click Connect

3. **Verify Ingestion:**
   ```kql
   SpyCloudBreachWatchlist_CL
   | where TimeGenerated >= ago(24h)
   | count
   ```

### Data Collection Rule (DCR) Setup

The ARM template creates a DCR named `dcr-ccf-{workspace_name}` that handles:
- JSON payload transformation via KQL
- Field mapping to custom log schema
- Routing to appropriate custom tables

### Data Collection Endpoint (DCE) Setup

A regional DCE is created automatically. Verify it exists:
1. Azure Portal → Monitor → Data Collection Endpoints
2. Confirm the endpoint matches your workspace region

---

## SpyCloud API Setup

### Store API Key in Key Vault

```bash
# Create Key Vault (if not exists)
az keyvault create \
  --name "kv-spycloud-sentinel" \
  --resource-group "rg-sentinel" \
  --location "eastus"

# Store API key
az keyvault secret set \
  --vault-name "kv-spycloud-sentinel" \
  --name "SpyCloudApiKey" \
  --value "YOUR_SPYCLOUD_API_KEY"
```

### API Rate Limits

SpyCloud API enforces daily rate limits. The solution uses Azure Table Storage (`SpyCloudRateLimits`) for persistent tracking with file-based fallback:

| Endpoint | Daily Limit | Recommended Polling |
|----------|------------|-------------------|
| Breach Watchlist | 200 calls/day | Every 6 hours |
| Compass Data | 200 calls/day | Every 6 hours |
| SIP Cookies | 200 calls/day | Every 6 hours |
| Breach Catalog | 100 calls/day | Every 24 hours |

---

## Sentinel Analytics Rules

### Severity-Based Detection

Enable analytics rules based on SpyCloud severity levels:

| Severity | Meaning | Rule Priority | Auto-Incident |
|----------|---------|--------------|---------------|
| 2 | Breach credential (hash only) | Low | Optional |
| 5 | Breach credential + PII | Medium | Yes |
| 20 | Infostealer credential | High | Yes |
| 25 | Infostealer + app data/cookies | Critical | Yes + Auto-Remediate |

### Enable Rules

1. Sentinel → Configuration → Analytics
2. Filter by "SpyCloud" in the search
3. Enable rules by severity tier:
   - **Critical (Sev 25):** Enable all infostealer + session rules
   - **High (Sev 20):** Enable infostealer credential rules
   - **Medium (Sev 5):** Enable breach + PII rules
   - **Low (Sev 2):** Enable based on organizational risk appetite

### Key Analytics Rules

| Rule Name | Severity | Description |
|-----------|----------|-------------|
| SpyCloud: Infostealer Credentials with Active Sessions | Critical | Severity 25 with stolen cookies |
| SpyCloud: Infostealer Plaintext Credential Detected | High | Severity 20 with plaintext password |
| SpyCloud: Multiple Exposures Same Device | High | Device with 3+ unique credentials stolen |
| SpyCloud: Executive Account Exposure | High | C-suite/VIP breach detection |
| SpyCloud: Credential Reuse Detected | Medium | Same password across multiple services |
| SpyCloud: Third-Party Breach Notification | Medium | Severity 5 new breach exposure |

---

## Playbook Configuration

### Managed Identity Setup

Each playbook requires a managed identity with specific permissions:

```bash
# Get the managed identity object ID for each Logic App
LOGIC_APP_IDENTITY=$(az logic workflow show \
  --name "SpyCloud-ForcePasswordReset" \
  --resource-group "rg-sentinel" \
  --query "identity.principalId" -o tsv)

# Assign Graph API permissions
az ad app permission grant \
  --id "$LOGIC_APP_IDENTITY" \
  --api "00000003-0000-0000-c000-000000000000" \
  --scope "User.ReadWrite.All Directory.ReadWrite.All"
```

### Playbook Permissions Matrix

| Playbook | Graph API | MDE API | Sentinel |
|----------|-----------|---------|----------|
| ForcePasswordReset | User.ReadWrite.All | — | Incident.ReadWrite |
| RevokeSession | User.ReadWrite.All | — | Incident.ReadWrite |
| IsolateDevice | — | Machine.Isolate | Incident.ReadWrite |
| BlockConditionalAccess | GroupMember.ReadWrite.All | — | Incident.ReadWrite |
| EnrichIncident | User.Read.All, AuditLog.Read.All | — | Incident.ReadWrite |
| FullRemediation | User.ReadWrite.All, Group.ReadWrite.All | Machine.Isolate | Incident.ReadWrite |
| EmailNotify | Mail.Send | — | Incident.Read |
| SlackNotify | — | — | Incident.Read |
| WebhookNotify | — | — | Incident.Read |
| JiraTicket | — | — | Incident.Read |

---

## Workbook Deployment

### Available Workbooks

1. **Executive Dashboard** — Board-level exposure metrics, trends, risk posture
2. **SOC Operations** — Real-time investigation, severity tracking, MTTR
3. **Threat Intelligence** — Malware families, breach sources, credential analysis
4. **Defender & CA Response** — MDE isolation, CA blocking, remediation tracking

### Configuration

1. Sentinel → Threat management → Workbooks
2. Search "SpyCloud" → Select workbook → View saved workbook
3. Configure parameters:
   - Time range (default: 30 days)
   - Severity filter (select: 2, 5, 20, 25)
   - Domain filter (your monitored domains)

---

## MDE/XDR Configuration

### Enable MDE Integration with Sentinel

1. **Connect MDE to Sentinel:**
   - Sentinel → Configuration → Data connectors
   - Search "Microsoft Defender for Endpoint"
   - Enable the connector

2. **Configure Device Isolation:**
   - Defender Security Center → Settings → Advanced features
   - Enable "Allow or block file" and "Custom network indicators"
   - Ensure the managed identity has `Machine.Isolate` permission

3. **Enable XDR Incident Correlation:**
   - Sentinel → Configuration → Settings → Microsoft 365 Defender
   - Enable incident creation for MDE alerts
   - This allows SpyCloud playbooks to correlate with MDE alerts

### Required MDE Permissions

```bash
# Grant MDE API permissions to playbook managed identity
az ad app permission add \
  --id "$LOGIC_APP_IDENTITY" \
  --api "fc780465-2017-40d4-a0c5-307022471b92" \
  --api-permissions "Machine.Isolate=Role Machine.Read.All=Role"
```

---

## Conditional Access Policies

### Create SpyCloud Block Group

```bash
# Create the security group used by CA blocking playbook
az ad group create \
  --display-name "SpyCloud-Block-CompromisedUsers" \
  --mail-nickname "spycloud-block" \
  --description "Users blocked by SpyCloud due to confirmed credential exposure"
```

### Configure CA Policy

1. **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Name:** SpyCloud — Block Compromised Identities
3. **Assignments:**
   - Users: Include "SpyCloud-Block-CompromisedUsers" group
   - Cloud apps: All cloud apps
   - Conditions: All platforms, all locations
4. **Access controls:**
   - Grant: Block access
5. **Enable policy:** On

### Token Protection (Recommended)

For Severity 25 exposures (stolen session cookies):

1. CA → New policy → "SpyCloud — Require Token Protection"
2. Assignments: All users in monitored groups
3. Session controls: Enable "Require token protection for sign-in sessions"
4. This prevents stolen cookie replay attacks

---

## Intune Integration

### Device Compliance for Infected Devices

When SpyCloud detects an infostealer infection on a managed device:

1. **Create Compliance Policy:**
   - Intune → Devices → Compliance policies → Create policy
   - Platform: Windows 10 and later
   - Settings: Device health → Require antimalware
   - Actions for noncompliance: Mark device as noncompliant → Block access

2. **Integration with SpyCloud Playbooks:**
   - The `IsolateDevice` playbook can trigger Intune compliance checks
   - Noncompliant devices are automatically blocked from corporate resources

3. **Remediation Actions:**
   - Intune → Devices → Scripts → Add remediation script
   - Script should force AV scan and remove known infostealer paths

---

## Purview Integration

### Microsoft Purview for Data Governance

SpyCloud exposure data can be classified and protected using Purview:

1. **Sensitivity Labels:**
   - Create labels for SpyCloud incident data (Confidential, Highly Confidential)
   - Apply to incident reports and executive summaries

2. **Data Loss Prevention:**
   - Create DLP policy to prevent SpyCloud breach data from being shared externally
   - Monitor for credential data in emails, Teams, SharePoint

3. **Compliance Manager:**
   - Use SpyCloud exposure metrics in compliance assessments
   - Track remediation progress against compliance frameworks

4. **Copilot Integration:**
   - When Security Copilot summarizes incidents, Purview ensures sensitive data is properly labeled
   - Purview audits all Copilot interactions with SpyCloud data

---

## AI Engine Setup

### Deploy the SpyCloud AI Engine

The AI Engine is an Azure Function App that provides AI-powered investigation capabilities.

#### Prerequisites
- Azure OpenAI resource with GPT-4o deployment, OR OpenAI API key
- Azure Function App (Python 3.11 runtime)

#### Deployment

```bash
# Create Function App
az functionapp create \
  --name "func-spycloud-ai-engine" \
  --resource-group "rg-sentinel" \
  --storage-account "stspycloudai" \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type linux

# Configure environment variables
az functionapp config appsettings set \
  --name "func-spycloud-ai-engine" \
  --resource-group "rg-sentinel" \
  --settings \
    AI_PROVIDER="azure_openai" \
    AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/" \
    AZURE_OPENAI_KEY="@Microsoft.KeyVault(SecretUri=https://kv-spycloud.vault.azure.net/secrets/AzureOpenAIKey)" \
    AZURE_OPENAI_DEPLOYMENT="gpt-4o" \
    SPYCLOUD_API_KEY="@Microsoft.KeyVault(SecretUri=https://kv-spycloud.vault.azure.net/secrets/SpyCloudApiKey)" \
    LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id" \
    LOG_ANALYTICS_KEY="@Microsoft.KeyVault(SecretUri=https://kv-spycloud.vault.azure.net/secrets/LAKey)" \
    GRAPH_TENANT_ID="your-tenant-id"

# Deploy function code
cd functions/SpyCloudAIEngine
func azure functionapp publish "func-spycloud-ai-engine"
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ai/investigate` | POST | Deep investigation of exposed identity |
| `/api/ai/executive-report` | POST | Board-ready exposure summary |
| `/api/ai/threat-research` | POST | Threat actor/malware research |
| `/api/ai/incident-report` | POST | Detailed incident documentation |
| `/api/ai/remediation-plan` | POST | Prioritized remediation steps |
| `/api/ai/health` | GET | Health check and configuration status |

#### Supported AI Providers

| Provider | Configuration |
|----------|--------------|
| Azure OpenAI | Set `AI_PROVIDER=azure_openai`, configure endpoint, key, deployment |
| OpenAI | Set `AI_PROVIDER=openai`, configure `OPENAI_API_KEY` |
| Custom | Implement custom provider via `AI_PROVIDER=custom`, set `AI_CUSTOM_ENDPOINT` |

---

## MCP Server Setup

### Deploy the MCP Server

The MCP (Model Context Protocol) server exposes SpyCloud tools to AI agents.

```bash
# Build and run with Docker
cd mcp-server
docker build -t spycloud-mcp-server .
docker run -d \
  --name spycloud-mcp \
  -p 3001:3001 \
  -e SPYCLOUD_API_KEY="your-api-key" \
  -e MCP_AUTH_TOKEN="your-mcp-token" \
  -e SENTINEL_WORKSPACE_ID="your-workspace-id" \
  -e SENTINEL_TENANT_ID="your-tenant-id" \
  -e AZURE_CLIENT_ID="your-client-id" \
  -e AZURE_CLIENT_SECRET="your-client-secret" \
  spycloud-mcp-server
```

### Available MCP Tools (26 Total)

| Category | Tools |
|----------|-------|
| SpyCloud API | `lookup_email`, `lookup_domain`, `lookup_ip`, `breach_catalog`, `compass_device` |
| Sentinel KQL | `query_sentinel`, `list_incidents`, `get_incident_details` |
| Graph Analysis | `find_blast_radius`, `find_walkable_paths`, `exposure_perimeter`, `graph_materialization_status` |
| AI Integration | `ai_investigate_entity`, `spycloud_exposure_summary` |
| Enrichment | `enrich_incident`, `check_credential`, `correlate_entities` |

---

## Security Copilot Integration

### Option 1: Custom Plugin (Recommended)

1. Navigate to Security Copilot → Settings → Plugins → Custom
2. Upload `copilot/SecurityCopilotAgent.json`
3. Configure the AI Engine URL in plugin settings
4. Test with: "Investigate the exposure for user@contoso.com"

### Option 2: Copilot Studio

1. Go to https://copilotstudio.microsoft.com
2. Create new custom copilot
3. Add SpyCloud as a custom connector
4. Map skills from `SecurityCopilotAgent.json` to topics
5. Publish to Teams, Slack, or web channels

### Option 3: VS Code GitHub Copilot (MCP)

Configure the MCP server in VS Code:

```json
{
  "mcp.servers": {
    "spycloud": {
      "url": "http://localhost:3001/sse",
      "headers": {
        "Authorization": "Bearer your-mcp-token"
      }
    }
  }
}
```

---

## Sentinel Graph Configuration

### Enable Sentinel Graph (GA since Dec 2025)

1. **Prerequisites:**
   - Microsoft Sentinel workspace
   - UEBA enabled with entity data sources configured

2. **Enable Graph:**
   ```bash
   az rest --method PUT \
     --url "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/settings/EntityAnalytics?api-version=2024-09-01" \
     --body '{"kind": "EntityAnalytics", "properties": {"entityProviders": ["AzureActiveDirectory", "ActiveDirectory"]}}'
   ```

3. **Configure Graph Materialization:**
   - Sentinel → Settings → Entity behavior → Graph materialization
   - Enable scheduled materialization (recommended: daily)
   - Select entity types: Account, Host, IP, Application

4. **Verify Graph Access:**
   ```kql
   // Check graph entities
   IdentityInfo
   | where TimeGenerated >= ago(24h)
   | summarize count() by AccountObjectId
   | take 10
   ```

---

## Jupyter Notebook Environment

### VSCode Setup

1. **Install VS Code extensions** (auto-prompted if `.vscode/extensions.json` exists):
   - Python, Pylance, Jupyter, Azure Functions, Data Wrangler

2. **Create Python virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r notebooks/requirements.txt
   ```

3. **Configure Sentinel connection:**
   - Open any notebook in the `notebooks/` folder
   - Follow the connection setup cell (uses MSTICPy QueryProvider)
   - Enter your Tenant ID and Workspace ID when prompted

### Available Notebooks

| Notebook | Purpose |
|----------|---------|
| `SpyCloud-Graph-Investigation.ipynb` | Identity exposure → attack path analysis with Sentinel Graph |
| `SpyCloud-Simulated-Scenarios.ipynb` | 5 purple team training scenarios with simulated data |
| `SpyCloud-Incident-Triage.ipynb` | Step-by-step incident triage workflow |
| `SpyCloud-Threat-Landscape.ipynb` | Organization-wide threat landscape analysis |
| `SpyCloud-ThreatHunting.ipynb` | Proactive threat hunting queries and techniques |

---

## Validation & Testing

### Deployment Validation Checklist

```bash
# Run the automated validation script
./scripts/qa-validation.sh

# Or verify manually:
```

| # | Check | KQL / Command | Expected |
|---|-------|--------------|----------|
| 1 | Data ingestion | `SpyCloudBreachWatchlist_CL \| count` | > 0 records |
| 2 | Analytics rules | Sentinel → Analytics → Filter "SpyCloud" | Rules enabled |
| 3 | Playbook health | Logic Apps → Overview → Run history | No failures |
| 4 | Workbook rendering | Sentinel → Workbooks → "SpyCloud" | Visualizations load |
| 5 | AI Engine health | `curl https://func-ai.azurewebsites.net/api/ai/health` | `{"status": "healthy"}` |
| 6 | MCP server | `curl http://mcp-server:3001/health` | `{"status": "ok"}` |
| 7 | Sentinel Graph | `IdentityInfo \| count` | > 0 records |
| 8 | CA policy active | Entra → CA → SpyCloud policy | Enabled |

---

## Troubleshooting

### Common Issues

#### Data Not Ingesting

```kql
// Check connector health
SpyCloudBreachWatchlist_CL
| where TimeGenerated >= ago(48h)
| summarize LastIngestion = max(TimeGenerated), RecordCount = count()
```

**Causes:**
- Invalid API key → Verify in Key Vault
- Rate limit exceeded → Check `SpyCloudRateLimits` table
- DCR misconfiguration → Verify DCR in Monitor → Data Collection Rules
- Network connectivity → Ensure Function App can reach api.spycloud.io

#### Playbook Failures

1. Check Logic App run history for specific error
2. Common issues:
   - **403 Forbidden:** Managed identity missing permissions
   - **404 Not Found:** Incorrect API endpoint URL
   - **429 Too Many Requests:** Rate limit → increase polling interval

#### Analytics Rules Not Firing

1. Verify data exists in the target table
2. Check rule query manually in Log Analytics
3. Ensure `queryFrequency` <= `suppressionDuration`
4. Verify rule is enabled (not in "Auto disabled" state)

#### AI Engine Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `AI provider not configured` | Missing API key | Set `AZURE_OPENAI_KEY` or `OPENAI_API_KEY` |
| `Model deployment not found` | Wrong deployment name | Verify `AZURE_OPENAI_DEPLOYMENT` matches your deployment |
| `Rate limit exceeded` | Too many AI requests | Implement request queuing or upgrade tier |
| `Token limit exceeded` | Context too large | Reduce investigation scope or use summarization |

### Log Locations

| Component | Log Location |
|-----------|-------------|
| Data Connector | Azure Monitor → Activity Log |
| Analytics Rules | Sentinel → Analytics → Rule runs |
| Playbooks | Logic Apps → Run history |
| Function Apps | Application Insights |
| MCP Server | Container logs / stdout |

### Support Contacts

- **SpyCloud Support:** support@spycloud.com
- **Azure Sentinel:** https://learn.microsoft.com/azure/sentinel/
- **GitHub Issues:** https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues
