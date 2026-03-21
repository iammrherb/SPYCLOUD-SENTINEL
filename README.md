<div align="center">

<img src="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-white.png" alt="SpyCloud" width="400">

# SpyCloud Identity Exposure Intelligence for Sentinel v2.0.0

### The Most Powerful Darknet Identity Threat Intelligence Platform for Microsoft Sentinel

[![Version](https://img.shields.io/badge/version-2.0.0-00D4AA?style=for-the-badge)](#) [![ARM Resources](https://img.shields.io/badge/ARM_Resources-144-0097A7?style=for-the-badge)](#) [![Analytics Rules](https://img.shields.io/badge/Analytics_Rules-38+-E91E63?style=for-the-badge)](#) [![Playbooks](https://img.shields.io/badge/Playbooks-19-9C27B0?style=for-the-badge)](#) [![AI Skills](https://img.shields.io/badge/Copilot_Skills-28+-FF9800?style=for-the-badge)](#) [![Terraform](https://img.shields.io/badge/Terraform-Ready-844FBA?style=for-the-badge)](#)

**19 playbooks** | **4 workbooks + 13 templates** | **38 analytics rules** | **3 notebooks** | **12 scripts** | **5 promptbooks** | **MCP server** | **Terraform module** | **13 test data sets**

---

*When infostealers strike, SpyCloud knows what was stolen -- and SpyCloud Identity Exposure Intelligence for Sentinel makes sure you act on it before the attackers do.*

</div>

---

## Table of Contents

- [Why SpyCloud Identity Exposure Intelligence for Sentinel?](#why-spycloud-sentinel-supreme)
- [Architecture](#architecture)
- [Deployment](#deployment)
- [Post-Deployment Setup](#post-deployment-setup)
- [Prerequisites and Permissions](#prerequisites--permissions)
- [SpyCloud API and Severity Levels](#spycloud-api--severity-levels)
- [SCORCH Agent](#scorch----the-autonomous-security-agent)
- [Security Copilot and Defender Portal](#security-copilot--defender-portal-publishing)
- [MCP Server](#mcp-server----ai-native-protocol)
- [Notebooks and Graph Integration](#notebooks--graph-integration)
- [Workbooks and Dashboards](#workbooks--dashboards)
- [Purple Team Testing](#purple-team-testing--benchmarking)
- [CI/CD and GitHub Actions](#cicd--github-actions)
- [Cost Optimization](#cost-optimization)
- [Troubleshooting](#troubleshooting)
- [Licensing](#licensing)
- [Support](#support)

---

## Why SpyCloud Identity Exposure Intelligence for Sentinel?

Every 39 seconds, an infostealer malware infection steals an employee's credentials, session cookies, browser autofill, VPN tokens, and SSO sessions. Traditional EDR might catch the malware. **SpyCloud tells you exactly what was stolen and from whom** -- hours after exposure, straight from the criminal underground.

**No other Sentinel integration offers this:**

| What Others Do | What SpyCloud Supreme Does |
|:---:|:---:|
| Alert on suspicious sign-ins | Know **which credentials are stolen** before they are used |
| Detect anomalies after the fact | **Quantify identity risk** with a 0-100 composite score |
| Require manual investigation | **Auto-remediate** -- isolate devices, reset passwords, revoke sessions |
| Provide generic threat intel | Deliver **device-specific forensics** -- exactly which apps, cookies, and tokens were stolen |
| Offer basic playbooks | Deploy **19 playbooks** with autonomous AI agent investigation |
| Static dashboards | **4 workbooks + 13 templates** for SOC, executives, IR, and threat intel |
| Simple API lookups | **17-endpoint Function App** with centralized Key Vault and risk scoring |
| No AI integration | **SCORCH Agent** -- autonomous Security Copilot AI that investigates, scores, and recommends |

---

## Architecture

### Data Flow -- From Criminal Underground to Automated Response

<div align="center">
<img src="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/architecture-overview.svg" alt="SpyCloud Sentinel Architecture" width="900">
</div>

```
                     +==============================+
                     |    CRIMINAL UNDERGROUND       |
                     |  Infostealer Malware -->      |
                     |  Stolen Creds + Cookies -->   |
                     |  Dark Web Markets             |
                     +==============|===============+
                                    |
                        SpyCloud Recaptures
                        (hours, not weeks)
                                    |
                                    v
                     +==============================+
                     |      SpyCloud API             |
                     |   api.spycloud.io             |
                     |  11 API Endpoints:            |
                     |  Enterprise | Compass | SIP   |
                     |  Investigations | IdLink      |
                     |  Exposure | CAP | Partnership |
                     +=|============|============|==+
                       |            |            |
          +------------+            |            +------------+
          |                         |                         |
          v                         v                         v
+==================+ +=====================+ +==================+
| CCF POLLERS (13) | | FUNCTION APP (17)   | | LOGIC APPS (19)  |
| Bulk scheduled   | | Risk Score Engine   | | Response:        |
| data ingestion   | | 7 Enrichment APIs   | | MDE Isolate      |
| across 15 tables | | Investigation Orch  | | CA Password Reset|
| Watchlist (New)  | | Reporting APIs      | | Session Revoke   |
| Watchlist (Mod)  | | Health & Audit      | | Notify SOC       |
| Breach Catalog   | | Key Vault Backed    | | Block/Enforce    |
| Compass x3       | | Rate Limiting       | | Enrichment:      |
| SIP Cookies      | | Circuit Breaker     | | Email/Domain/IP  |
| + 6 more         | | Audit Logging       | | Compass/SIP      |
+========|=========+ +=========|===========+ | ITSM:            |
         |                     |              | ServiceNow/Jira  |
         +----------+----------+              +========|=========+
                    |                                   |
                    v                                   v
+=================================================================+
|                MICROSOFT SENTINEL WORKSPACE                      |
|                                                                  |
| +-------------+ +------------+ +----------+ +----------------+  |
| | 15 Custom   | | 38 Analyt. | | 4 Wkbook | | SCORCH Agent   |  |
| | Tables      | | Rules      | | + 13 Tpl | | 28+ KQL skills |  |
| | 600B+ recs  | | Core/IdP   | | SOC Ops  | | 5 promptbooks  |  |
| |             | | Network    | | Executive| | Risk scoring   |  |
| +-------------+ +------------+ +----------+ +----------------+  |
|                                                                  |
| +-------------+ +------------+ +----------+ +----------------+  |
| | 16 Hunting  | | 4 Automat. | | 3 Jupyter| | MCP Server     |  |
| | Queries     | | Rules      | | Notebooks| | AI-native      |  |
| +-------------+ +------------+ +----------+ +----------------+  |
+=======|===============|===============|=========================+
        |               |               |
        v               v               v
+=============+ +===============+ +================+
| DEFENDER    | | ENTRA ID      | | NOTIFICATIONS  |
| Device Isol.| | Password Reset| | Teams / Slack  |
| IOC Submit  | | Session Revoke| | Email/Webhooks |
| Device Tag  | | CA Group Add  | | ServiceNow     |
| Blocklist   | | Risk Score -> | | Jira / AzDO    |
|             | | Custom Attr   | |                |
|             | | -> CA Policy  | |                |
+=============+ +===============+ +================+
```

### The Identity Risk Score -- A Closed Loop

```
+----------------------------------------------------------------------+
|  EXPOSURE          SCORE           POLICY          RESPONSE          |
|  ------------------------------------------------------------------ |
|                                                                      |
|  SpyCloud       +---------+    Entra ID CA     Password Reset       |
|  detects        |  0-100  |    Custom Security  + Session Revoke    |
|  stolen ------->|  Risk   |--->Attribute ------>+ Device Isolate    |
|  credentials    |  Score  |                     + Notify SOC        |
|                 +---------+                            |            |
|                      |                                 |            |
|  5 Components:       |     Score > 80 --> Block access |            |
|  - Severity  0-30    |     Score 61-80 --> HW MFA     |            |
|  - Credential 0-25   |     Score 41-60 --> Hourly auth |            |
|  - Session   0-25    |     Score 21-40 --> Normal MFA  |            |
|  - Device    0-10    |     Score 0-20  --> Passwordless|            |
|  - Temporal  x0.2-1  |                                 |            |
|                      |         +-----------------------+            |
|  + Remediation       |         v                                    |
|    Credit: -20/act <-+-- SCORE DECREASES                            |
|                      |   Password reset = -10 pts                   |
|                      |   Session revoke = -5 pts                    |
|                      |   Account disable = -15 pts                  |
|                      |                                              |
|  Score decays:       |   Remediation actions REDUCE the score       |
|  24h=full weight     |   automatically. No other vendor offers      |
|  365d=20% weight     |   this closed-loop integration.              |
+----------------------------------------------------------------------+
```

---

## Deployment

### Option 1: Deploy to Azure (Commercial)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

> The deployment wizard (10-step createUiDefinition) guides you through all configuration: API keys, severity thresholds, polling intervals, Key Vault settings, App Service, permissions, and optional purple team testing.

### Option 2: Deploy to Azure Government

[![Deploy to Azure Gov](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazuregov.svg?sanitize=true)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

> Supports Azure Government regions: US Gov Virginia, US Gov Arizona, US Gov Texas.

### Option 3: Deploy via Azure Cloud Shell

```bash
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git
cd SPYCLOUD-SENTINEL
chmod +x scripts/deploy-cloudshell.sh
./scripts/deploy-cloudshell.sh
```

The Cloud Shell script will:
1. Validate your Azure subscription and permissions
2. Prompt for configuration (or accept an answer file: `--answer-file config.json`)
3. Create the resource group and deploy the ARM template
4. Configure managed identities and RBAC for all playbooks
5. Enable analytics rules and automation rules
6. Run a post-deployment health check

### Option 4: Deploy via Terraform

```bash
cd terraform/
terraform init

# Azure Commercial
terraform plan -var="spycloud_api_key=YOUR_KEY" -var="monitored_domain=contoso.com"

# Azure Government
terraform plan -var="spycloud_api_key=YOUR_KEY" -var="monitored_domain=contoso.com" \
  -var="cloud_environment=AzureUSGovernment" -var="location=usgovvirginia"

terraform apply
```

| Variable | Default | Description |
|----------|---------|-------------|
| `spycloud_api_key` | *(required)* | SpyCloud Enterprise API key |
| `monitored_domain` | `""` | Primary corporate domain to monitor |
| `cloud_environment` | `AzureCloud` | `AzureCloud` or `AzureUSGovernment` |
| `location` | `eastus` | Azure region (incl. Gov regions) |
| `severity_threshold` | `2` | Min SpyCloud severity: 2, 5, 20, or 25 |
| `polling_interval` | `4h` | Data polling: 1h, 4h, 8h, 12h, 24h |
| `enable_plaintext_passwords` | `false` | Include plaintext passwords in records |

---

## Post-Deployment Setup

### 1. Content Hub Configuration

1. Navigate to **Microsoft Sentinel** > **Content Hub**
2. Search for **SpyCloud** and click **Install**
3. Wait for installation to complete (2-5 minutes)
4. Verify installed items:
   - **Analytics** > **Rule Templates** -- 38 SpyCloud rules
   - **Hunting** > **Queries** -- 16 SpyCloud hunting queries
   - **Workbooks** > **Templates** -- SpyCloud workbook templates
   - **Automation** > **Playbook Templates** -- SpyCloud playbook templates

### 2. Data Connector Setup

1. Navigate to **Sentinel** > **Data Connectors**
2. Find **SpyCloud Enterprise Protection** > **Open connector page**
3. Enter your API keys:

| Key | Required | Products Enabled |
|-----|:--------:|-----------------|
| Enterprise API Key | **Yes** | Watchlist, Breach Catalog, core detections |
| Compass API Key | Optional | Application-level credential data |
| SIP API Key | Optional | Stolen session cookies (MFA bypass detection) |
| Investigations API Key | Optional | Full SpyCloud database search |
| IdLink API Key | Optional | Cross-identity correlation |
| Exposure API Key | Optional | Domain-level aggregate metrics |
| CAP API Key | Optional | Curated alerting data |
| Data Partnership API Key | Optional | Partner data feeds |

4. Configure your **monitored domain** (e.g., `contoso.com`)
5. Set **severity threshold**:

| Level | Description | Recommended For |
|:-----:|------------|-----------------|
| **2** | All breaches including public datasets | Full visibility, higher volume |
| **5** | Combo lists and targeted attacks | Balanced coverage |
| **20** | Infostealer-stolen credentials only | High-fidelity alerts |
| **25** | Infostealers + stolen session cookies | Maximum severity only |

6. Toggle **plaintext password** inclusion (disabled by default for SIEM compliance)
7. Click **Connect** -- data begins flowing within 15-30 minutes

### 3. Analytics Rules

1. Navigate to **Sentinel** > **Analytics** > **Rule Templates**
2. Filter by source: **SpyCloud**

| Category | Rules | Description |
|----------|:-----:|-------------|
| **Core Detection** | 8 | New exposures, high severity, VIP users, password reuse |
| **Identity Provider Correlation** | 6 | Cross-reference with Entra ID sign-in logs |
| **Network & Endpoint** | 5 | Correlate with firewall, VPN, MDE alerts |
| **UEBA Fusion** | 4 | Combine with User Entity Behavior Analytics |
| **Office 365 & Entra** | 6 | Email forwarding, OAuth app consent, admin changes |
| **Operations** | 5 | Connector health, ingestion gaps, API errors |
| **Risk Score** | 4 | Threshold-based alerting on composite risk scores |

### 4. Playbook Permissions (RBAC)

```bash
chmod +x scripts/grant-permissions.sh
./scripts/grant-permissions.sh -g <resource-group> -s <subscription-id>
```

| Playbook | Required Permissions | API |
|----------|---------------------|-----|
| **SpyCloud-ForcePasswordReset** | `User.ReadWrite.All` | Microsoft Graph |
| **SpyCloud-IsolateDevice** | `Machine.Isolate` | Microsoft Defender ATP |
| **SpyCloud-RevokeSession** | `User.RevokeSessions.All` | Microsoft Graph |
| **SpyCloud-DisableAccount** | `User.ReadWrite.All` | Microsoft Graph |
| **SpyCloud-AddToSecurityGroup** | `GroupMember.ReadWrite.All` | Microsoft Graph |
| **SpyCloud-BlockConditionalAccess** | `Policy.ReadWrite.ConditionalAccess` | Microsoft Graph |
| **SpyCloud-FullRemediation** | All of the above | Graph + MDE |
| **SpyCloud-EmailNotify** | `Mail.Send` | Microsoft Graph |
| **SpyCloud-SlackNotify** | Webhook URL | Slack Incoming Webhook |
| **SpyCloud-ServiceNowIncident** | ServiceNow credentials | ServiceNow API |
| **SpyCloud-JiraTicket** | Jira API token | Jira REST API |

> **Managed Identity**: All playbooks use system-assigned managed identity. The deployment wizard auto-creates the identities; you only need to grant API permissions.

---

## Prerequisites & Permissions

### Azure Resource Permissions

| Resource | Required Role | Purpose |
|----------|--------------|---------|
| **Subscription** | Contributor | Deploy ARM template resources |
| **Resource Group** | Owner (or Contributor + User Access Admin) | Assign RBAC to managed identities |
| **Log Analytics Workspace** | Log Analytics Contributor | Create custom tables, DCR/DCE |
| **Microsoft Sentinel** | Microsoft Sentinel Contributor | Enable analytics, automation, workbooks |
| **Key Vault** | Key Vault Administrator | Store and manage API keys |
| **Logic Apps** | Logic App Contributor | Deploy and manage playbooks |
| **Function App** | Website Contributor | Deploy enrichment functions |

### Microsoft Defender for Endpoint (MDE)

1. **License**: Microsoft Defender for Endpoint Plan 2 (P2)
2. **Permissions** for `SpyCloud-IsolateDevice` managed identity:
   - `Machine.Isolate` -- Isolate compromised devices
   - `Machine.ReadWrite.All` -- Tag devices, submit IOCs
   - `Alert.ReadWrite.All` -- Create and update alerts
3. **Configuration**:
   - Enable **Advanced Features** > **Allow partner access** in MDE settings
   - Ensure devices are onboarded and reporting to MDE
   - Enable **Automated Investigation and Response** (AIR)

### Microsoft Entra ID & Conditional Access

1. **License**: Entra ID P1 (minimum); P2 for Identity Protection
2. **App Registration Permissions**:
   - `User.ReadWrite.All` -- Password reset, account disable
   - `User.RevokeSessions.All` -- Revoke refresh tokens
   - `GroupMember.ReadWrite.All` -- Add users to security groups
   - `Policy.ReadWrite.ConditionalAccess` -- Modify CA policies
   - `Directory.ReadWrite.All` -- Write custom security attributes
3. **Conditional Access Setup**:
   - Create a **Custom Security Attribute** named `SpyCloudRiskScore` (type: Integer)
   - Create CA policies referencing this attribute:
     - Score > 80: Block access except from compliant devices
     - Score 61-80: Require hardware security key
     - Score 41-60: Require re-authentication every hour
     - Score 21-40: Require MFA

### Microsoft Intune

1. Enable **Intune integration** with Defender for Endpoint
2. Create a **compliance policy** marking devices non-compliant when MDE risk level is "High"
3. Configure **remediation actions**: wipe corporate data, require re-enrollment

### Key Vault Configuration

The deployment creates an Azure Key Vault for SpyCloud API keys, Function App secrets, and managed identity credentials.

**Best Practices:**
- Enable **soft delete** and **purge protection** (default in wizard)
- Use **Premium SKU** for HSM-backed keys in production
- Enable **diagnostic logging** to Sentinel workspace
- Restrict **network access** to Function App and Logic Apps only
- Rotate API keys on a 90-day schedule

---

## SpyCloud API & Severity Levels

### Severity Mapping

| Severity | Source Type | Risk Level | Description |
|:--------:|-----------|:----------:|-------------|
| **2** | Public breach data | Low | Credentials from publicly known breaches |
| **5** | Combo lists | Medium | Aggregated credential lists traded on dark web |
| **20** | Infostealer malware | High | Credentials stolen by malware from victim devices |
| **25** | Infostealer + active sessions | Critical | Stolen credentials AND session cookies (MFA bypass) |

### Data Collection

- **DCE**: `dce-spycloud-<workspace>` -- Regional HTTP endpoint for custom logs
- **DCR**: `dcr-spycloud-<workspace>` and `dcr-spycloud-ccf-<workspace>` -- Schema transformation and routing

### Custom Tables (15)

| Table | Data Source | Key Fields |
|-------|-----------|------------|
| `SpyCloudBreachWatchlist_CL` | Enterprise Watchlist (new) | email, severity, source_id, password_type |
| `SpyCloudBreachWatchlistModified_CL` | Enterprise Watchlist (modified) | email, severity, modified_date |
| `SpyCloudBreachCatalog_CL` | Breach Catalog | breach_id, title, type, num_records |
| `SpyCloudCompassData_CL` | Compass | target_url, email, domain, application |
| `SpyCloudCompassDevices_CL` | Compass Devices | infected_machine_id, ip_addresses |
| `SpyCloudCompassApplications_CL` | Compass Applications | target_application, credential_count |
| `SpyCloudSipCookies_CL` | SIP Stolen Cookies | cookie_domain, session_valid, expiry |
| `SpyCloudInvestigations_CL` | Investigations API | query, result_count, records |
| `SpyCloudIdLink_CL` | IdLink | identity_chain, linked_accounts |
| `SpyCloudExposure_CL` | Exposure Stats | domain, exposure_count, trend |
| `SpyCloudCAP_CL` | Curated Alerting | alert_type, priority, entity |
| `SpyCloudDataPartnership_CL` | Data Partnership | partner_source, record_type |
| `SpyCloudEnrichmentAudit_CL` | Enrichment Function | endpoint, status, latency |
| `SpyCloudMDE_Logs_CL` | MDE Correlation | device_id, action, result |
| `SpyCloudCA_Logs_CL` | Conditional Access | user, policy, action, result |

---

## SCORCH -- The Autonomous Security Agent

**SCORCH** (SpyCloud Orchestrated Response and Contextual Hunting) is an AI-powered Security Copilot agent that investigates, scores, correlates, and recommends autonomously.

| Feature | Details |
|---------|---------|
| **28+ KQL Skills** | User exposures, device forensics, password analysis, malware intel, breach catalog, MDE correlation, CA audit, geographic analysis, remediation stats |
| **5 Promptbooks** | Incident Triage, Threat Hunt, User Investigation, Org Risk Assessment, Compliance Audit |
| **Risk Scoring** | Composite 0-100 score with 5 weighted components |
| **Natural Language** | "Investigate user@company.com" triggers full cross-table analysis |
| **Follow-up Questions** | Suggests deeper investigation paths after initial analysis |

### Agent Build

```bash
chmod +x scripts/build-agent.sh
./scripts/build-agent.sh
```

### Promptbooks

| Promptbook | Purpose | Flow |
|-----------|---------|------|
| **Incident Triage** | Rapid assessment | Exposure > Risk > Device > Remediation status |
| **Threat Hunt** | Proactive hunting | High-severity scan > Password analysis > Device correlation |
| **User Investigation** | Deep dive on identity | Cross-table > Identity graph > Timeline > Recommendations |
| **Org Risk Assessment** | Org-wide posture | Domain risk > Distribution > Top risks > Trend analysis |
| **Compliance Audit** | Evidence package | Detection coverage > Remediation rates > SLA compliance |

---

## Security Copilot & Defender Portal Publishing

### Publishing the Agent to Defender Portal

1. **Prepare the Plugin Package**:
   - `copilot/SpyCloud_Plugin.yaml` -- Plugin manifest
   - `copilot/SpyCloud_API_Plugin.yaml` -- API-backed plugin
   - `copilot/SpyCloud_API_Plugin_OpenAPI.yaml` -- OpenAPI specification
   - `copilot/manifest.json` -- Package manifest

2. **Upload to Security Copilot**:
   - Navigate to **Security Copilot** > **Plugins** > **Manage plugins**
   - Click **Upload plugin** and select the plugin YAML
   - Configure the SpyCloud API key connection

3. **Enable the Agent in Defender Portal**:
   - Navigate to **Defender Portal** > **Settings** > **Security Copilot**
   - Enable **Custom plugins**
   - SCORCH appears under **Security Copilot** > **Agents**
   - Invoke via: "Ask SpyCloud about user@company.com"

4. **Verify Agent Capabilities**:
   - Test each promptbook: Incident Triage, Threat Hunt, User Investigation
   - Verify KQL skill execution against your Sentinel workspace
   - Confirm risk scoring produces accurate 0-100 composite scores

### Available Plugins

| Plugin | Type | Description |
|--------|------|-------------|
| `SpyCloud_Plugin.yaml` | KQL Skills | 28+ Sentinel KQL queries |
| `SpyCloud_API_Plugin.yaml` | API Skills | Direct SpyCloud API access |
| `SpyCloud_FullAPI_Plugin.yaml` | Full API | Complete API coverage |
| `SpyCloud_LogicApp_Plugin.yaml` | Logic Apps | Trigger playbooks from Copilot |
| `SpyCloud_MCP_Plugin.yaml` | MCP | Model Context Protocol integration |

---

## MCP Server -- AI-Native Protocol

The MCP server enables any AI platform to interact with SpyCloud data.

### Setup

```bash
cd mcp-server/
npm install
export SPYCLOUD_API_KEY="your-key"
export SENTINEL_WORKSPACE_ID="your-workspace-id"
export MCP_API_KEY="your-mcp-auth-key"
npm start  # Port 3001
```

### Docker

```bash
cd mcp-server/
docker build -t spycloud-mcp-server .
docker run -p 3001:3001 \
  -e SPYCLOUD_API_KEY="your-key" \
  -e SENTINEL_WORKSPACE_ID="your-workspace-id" \
  -e MCP_API_KEY="your-mcp-auth-key" \
  spycloud-mcp-server
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `lookup_email` | Check email against SpyCloud breach database |
| `lookup_domain` | Get domain-wide exposure data |
| `lookup_ip` | Check IP address for breach associations |
| `get_breach_catalog` | Get details on specific breaches |
| `check_compass` | Application-level credential exposure |
| `check_sip_cookies` | Stolen session cookie analysis |
| `get_risk_score` | Calculate composite identity risk score |
| `investigate_user` | Full cross-table investigation |
| `get_exposure_stats` | Domain exposure trends |

---

## Notebooks & Graph Integration

### Jupyter Notebooks

| Notebook | Purpose | Key Capabilities |
|----------|---------|-----------------|
| **Incident Triage** | Rapid incident assessment | Cross-table correlation, risk scoring, device forensics, remediation tracking |
| **Threat Landscape** | Organization-wide exposure | Domain trends, severity distribution, product coverage, geographic heat maps |
| **Threat Hunting** | Proactive compromise detection | Pattern matching, anomaly detection, historical analysis, IOC enrichment |

### Sentinel Custom Graphs (Preview)

```bash
chmod +x scripts/setup-sentinel-graph.sh
./scripts/setup-sentinel-graph.sh
```

**Graph MCP Tools:**
- `exposure_perimeter` -- Map the exposure boundary of a user or domain
- `find_blastRadius` -- Calculate the blast radius of a compromised credential
- `find_walkable_paths` -- Discover lateral movement paths from an exposure

**Graph Materialization** -- Schedule computation jobs:
- Identity exposure graphs (daily)
- Credential relationship graphs (hourly)
- Device infection chains (on-demand)

**GQL Queries:**
```gql
MATCH (u:User)-[:EXPOSED_IN]->(b:Breach)
WHERE b.severity >= 20
RETURN u.email, count(b) as breach_count
ORDER BY breach_count DESC
```

### Copilot + Notebooks

1. Install `azure-ai-security-copilot` Python package
2. Configure authentication via managed identity
3. Use `CopilotClient` to invoke SCORCH skills from notebook cells
4. Combine KQL results with natural language analysis

---

## Workbooks & Dashboards

### Included Workbooks

| Workbook | Audience | Key Metrics |
|----------|----------|-------------|
| **SOC Operations** | SOC Analysts | Real-time exposure feed, incident queue, remediation status, SLA tracking |
| **Executive Dashboard** | CISOs & Leadership | Risk trends, exposure posture, ROI metrics, compliance status |
| **Defender & CA** | Security Engineers | MDE correlation, CA policy effectiveness, device compliance |
| **Threat Intelligence** | Threat Hunters | Breach source analysis, malware family trends, geographic distribution |

### Workbook Templates (13)

Per-table workbooks for each SpyCloud data source:
- Watchlist New/Modified, Breach Catalog, Compass (Data/Devices/Apps)
- SIP Cookies, Investigations, IdLink, Exposure, CAP, Data Partnership
- Enrichment Audit, Connector Health

---

## Purple Team Testing & Benchmarking

### Automated QA Script

```bash
chmod +x scripts/spycloud-qa.sh
./scripts/spycloud-qa.sh --mode full
# Modes: full | smoke | security | simulate
```

### Test Data

13 test data sets in `test-data/` for all custom tables:

```bash
python3 scripts/ingest-test-data.py --workspace <workspace-id> --all-tables
```

### Purple Team Simulation

1. **Enable in Wizard**: Check "Enable Purple Team Simulation" in Advanced Settings
2. **Test Data Generation**: Synthetic breach records trigger analytics rules
3. **MDE Simulation**: Test device isolation and IOC submission workflows
4. **Conditional Access Testing**: Simulate risk score updates, verify CA policy enforcement
5. **Benchmarking Targets**:
   - Ingestion to alert: < 5 minutes
   - Alert to automated response: < 2 minutes
   - Risk score calculation: < 30 seconds
   - End-to-end detection-to-remediation: < 10 minutes

---

## CI/CD & GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **PR Validation** (`pr-validation.yml`) | Pull requests | Lint ARM templates, validate Function App, check MCP server |
| **Deploy** (`sentinel-deploy.yml`) | `workflow_dispatch` | Deploy to staging/production with rollback on failure |

### Deployment with Rollback

- **Staging** deployment for pre-production testing
- **Production** with automatic rollback on failure
- **Error reporting** -- failures logged with full diagnostics
- **Cleanup on failure** -- resources automatically deleted
- **Notifications** -- GitHub Actions annotations + optional Teams/Slack webhooks

```yaml
gh workflow run sentinel-deploy.yml \
  -f environment=production \
  -f spycloud_api_key=$SPYCLOUD_API_KEY \
  -f monitored_domain=contoso.com
```

---

## Cost Optimization

| Strategy | Savings | How |
|---------|:-------:|-----|
| Severity filter >= 20 | **50-70%** | Skip low-severity public breach credentials |
| Analytics plan tables | **50%** | Cheaper per-GB than Log Analytics plan |
| 60-min polling | **50%** | Instead of 30-min default |
| Conditional pollers | **100%** | Only enable products you are licensed for |
| Function App Consumption | **Free** | First 1M executions/month included |
| Retention tiering | **80%** | 90-day hot, archive for compliance |

| Environment | Users | Daily Ingestion | Est. Monthly Cost |
|:------------|------:|:---------------:|:-----------------:|
| POC | < 1K | 1-10 MB | **$5-15** |
| Medium | 1K-10K | 10-100 MB | **$15-75** |
| Large | 10K-100K | 100-500 MB | **$75-400** |
| Enterprise | 100K+ | 500+ MB | Contact SpyCloud |

---

## Troubleshooting

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| No data after connecting | API key invalid/expired | Verify at [portal.spycloud.com](https://portal.spycloud.com) |
| Rules not in Analytics blade | Content Hub not installed | Content Hub > Search "SpyCloud" > Install |
| MDE playbook fails | Missing Defender P2 | Upgrade to MDE P2 |
| Domain pollers fail | `monitoredDomain` blank | Enter domain on connector page |
| Workbook shows no data | Tables not populated | Wait 15-30 min after first connect |
| Function App 429 | Rate limit exceeded | Check `SpyCloudEnrichmentAudit_CL`; increase polling interval |
| Key Vault access denied | Managed identity missing | Run `scripts/grant-permissions.sh` |
| Risk score not calculating | Watchlist table empty | Verify Enterprise API key is connected |
| CA policies not enforcing | Custom attribute missing | Create `SpyCloudRiskScore` attribute in Entra ID |
| Graph features unavailable | Preview not enabled | Run `scripts/setup-sentinel-graph.sh` |

### Health Check KQL

```kql
// Data ingestion status
union withsource=TableName SpyCloud*
| summarize LastRecord=max(TimeGenerated), RecordCount=count() by TableName
| order by LastRecord desc

// Connector health
SpyCloudEnrichmentAudit_CL
| where TimeGenerated > ago(1h)
| summarize Success=countif(status_s == "success"), Fail=countif(status_s == "error")
| extend HealthPct = round(100.0 * Success / (Success + Fail), 1)
```

### Log Locations

| Component | Log Location |
|-----------|-------------|
| Function App | Application Insights > Live Metrics / Logs |
| Logic Apps | Logic App > Run History |
| Data Connector | `SpyCloudEnrichmentAudit_CL` table |
| MDE Actions | `SpyCloudMDE_Logs_CL` table |
| CA Actions | `SpyCloudCA_Logs_CL` table |
| Deployment | Azure Activity Log > Resource Group |

---

## Licensing

### SpyCloud License Requirements

| Product | License Tier | Required For |
|---------|-------------|-------------|
| **Enterprise Protection** | Enterprise | Core: watchlist, breach catalog, all analytics rules |
| **Compass** | Enterprise + Compass | Application-level credential exposure |
| **Session Identity Protection** | Enterprise + SIP | Stolen session cookie detection (MFA bypass) |
| **Investigations** | Enterprise + Investigations | Full database search capabilities |
| **IdLink** | Enterprise + IdLink | Cross-identity correlation |

### Microsoft License Requirements

| Service | License | Required For |
|---------|---------|-------------|
| **Microsoft Sentinel** | Pay-as-you-go or Commitment Tier | Core SIEM functionality |
| **Defender for Endpoint P2** | M365 E5 or standalone | Device isolation, IOC submission |
| **Entra ID P1** | M365 E3 or standalone | Password reset, session revocation |
| **Entra ID P2** | M365 E5 or standalone | Identity Protection, risk-based CA |
| **Security Copilot** | Security Copilot license | SCORCH agent, promptbooks, AI skills |

### Repository License

This repository is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## SpyCloud Products & Cross-Product Power

| Product | What It Detects | Sentinel Value |
|---------|----------------|----------------|
| **Enterprise Watchlist** | Stolen credentials + PII + device forensics | Core: 38 rules, all playbooks, 4 workbooks |
| **Breach Catalog** | Breach source metadata | Enriches every incident with attribution |
| **Compass Data** | Application-level stolen credentials | Blast radius: VPN, SSO, cloud apps |
| **Compass Devices** | Infected device fingerprints | MDE correlation: match to your fleet |
| **SIP Cookies** | Stolen session cookies | **MFA bypass detection** |
| **Investigations** | Full SpyCloud database | Threat hunting: 600B+ records |
| **IdLink** | Cross-identity correlation | One person, many accounts |
| **Exposure Stats** | Domain-level metrics | Executive dashboards |

### Multi-Product Fusion

| Combination | Detection | Impact |
|------------|-----------|--------|
| Enterprise + SIP | Credential + Cookie Double Exposure | Complete MFA bypass |
| Enterprise + Compass | Infection with App Blast Radius | VPN, SSO, AWS, Okta compromised |
| Compass + SIP | Device Infection + Active Sessions | Stolen cookies STILL VALID |
| Enterprise + Exposure | Spike + New Breach | Massive org impact |
| Enterprise + IdLink | Linked Identity Chain | 1 email maps to 5 accounts |

---

## Documentation

| Document | Focus |
|----------|-------|
| [Product Catalog](docs/PRODUCT-CATALOG-v12.md) | All 8 SpyCloud products with pollers, playbooks, rules |
| [Enrichment Architecture](docs/ENRICHMENT-ARCHITECTURE-v12.md) | Enrichment design, cross-platform correlations |
| [Cross-Ecosystem Map](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) | 100+ vendor integrations |
| [ISV Strategy](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) | Azure Functions, Key Vault, marketplace |
| [Security Copilot Spec](docs/SECURITY-COPILOT-SPEC.md) | Copilot plugin, SCORCH agent, promptbooks |
| [Agents & Plugins](docs/AGENTS-AND-PLUGINS-GUIDE.md) | AI agent configuration and capabilities |
| [Permissions Guide](docs/PERMISSIONS-AND-PLAYBOOKS.md) | Required roles and API permissions |
| [API Setup](docs/API-SETUP-GUIDE.md) | SpyCloud API configuration |
| [Production Readiness](docs/PRODUCTION-READINESS-v12.10.md) | Deployment checklist and validation |
| [Roadmap](docs/ROADMAP.md) | Release history and future vision |

---

## Support

| Channel | Contact |
|---------|---------|
| **SpyCloud Support** | [support@spycloud.com](mailto:support@spycloud.com) |
| **Integration Help** | [integrations@spycloud.com](mailto:integrations@spycloud.com) |
| **SpyCloud Portal** | [portal.spycloud.com](https://portal.spycloud.com) |
| **GitHub Issues** | [Issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues) |

---

<div align="center">

<img src="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-200.png" alt="SpyCloud" width="200">

**Built by SpyCloud for the Microsoft Sentinel community.**

*Protecting identities. Preventing breaches. Powering SOCs.*

v2.0.0

</div>
