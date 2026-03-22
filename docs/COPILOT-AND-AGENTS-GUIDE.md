# SpyCloud Identity Exposure Intelligence for Sentinel — Copilot, Agents & Plugins Guide

> **Version 2.0** | Complete guide to all Security Copilot plugins, the SCORCH Agent, MCP integration, and the OpenAI manifest

---

## Table of Contents

1. [Plugin Architecture Overview](#plugin-architecture-overview)
2. [Which Plugin Should I Use?](#which-plugin-should-i-use)
3. [KQL Plugin](#kql-plugin)
4. [API Plugin](#api-plugin)
5. [Full API Plugin](#full-api-plugin)
6. [Logic App Plugin](#logic-app-plugin)
7. [MCP Plugin](#mcp-plugin)
8. [SCORCH Agent](#scorch-agent)
9. [OpenAI Manifest — manifest.json](#openai-manifest)
10. [Manifest Formats: Security Copilot YAML vs OpenAI JSON](#manifest-formats)
11. [API Key Architecture](#api-key-architecture)
12. [OpenAI and Azure AI Integration](#openai-and-azure-ai-integration)
13. [Purview Integration Skills](#purview-integration-skills)
14. [Playbook Automations](#playbook-automations)
15. [Personas and AI Queries](#personas-and-ai-queries)
16. [Troubleshooting YAML Upload Errors](#troubleshooting-yaml-upload-errors)

---

## Plugin Architecture Overview

The SpyCloud Sentinel solution provides **6 plugin files** and **1 OpenAI manifest** for integrating with Microsoft Security Copilot. Each serves a distinct purpose:

| File | Type | Format | Skills | Auth | Purpose |
|------|------|--------|--------|------|---------|
| `SpyCloud_Plugin.yaml` | Plugin | KQL | 138 | None (Sentinel workspace) | Query 14 SpyCloud Sentinel log tables via natural language |
| `SpyCloud_API_Plugin.yaml` | Plugin | API | 38 | API Key (X-API-Key header) | Real-time REST API lookups across all 9 SpyCloud APIs |
| `SpyCloud_FullAPI_Plugin.yaml` | Plugin | API | Auto-discovered | API Key (X-API-Key header) | Full OpenAPI spec with 50+ endpoints auto-discovered by Copilot |
| `SpyCloud_LogicApp_Plugin.yaml` | Plugin | LogicApp | 8 | Managed Identity | Trigger remediation Logic App playbooks from Copilot |
| `SpyCloud_MCP_Plugin.yaml` | Plugin | MCP | Auto-discovered | None | Graph analysis via MCP server (blast radius, path discovery) |
| `SpyCloud_Agent.yaml` | Agent | AGENT+GPT+KQL | 128 (27 agents + 22 GPT + 79 KQL) | Mixed | Autonomous AI investigation agent with 27 sub-agents |
| `manifest.json` | OpenAI Manifest | JSON | References above | API Key | OpenAI-format manifest for alternative upload path |

---

## Which Plugin Should I Use?

### Decision Matrix

| Scenario | Recommended Plugin(s) | Why |
|----------|----------------------|-----|
| "I just deployed Sentinel tables and want to query them" | **KQL Plugin** | Queries your already-ingested Sentinel data. No API keys needed. |
| "I need real-time lookups against SpyCloud APIs" | **API Plugin** or **Full API Plugin** | Calls SpyCloud REST APIs directly for live data. |
| "I want the most complete API coverage with auto-discovery" | **Full API Plugin** | Uses the full OpenAPI spec. Copilot auto-discovers 50+ endpoints. |
| "I want to trigger password resets and device isolation" | **Logic App Plugin** | Invokes deployed Logic App playbooks for automated remediation. |
| "I need graph analysis, blast radius, attack paths" | **MCP Plugin** | Connects to the SpyCloud MCP server for graph-based investigation. |
| "I want an AI agent that investigates autonomously" | **SCORCH Agent** | 27 sub-agents that orchestrate investigation across all data sources. |
| "I am uploading via the OpenAI plugin format" | **manifest.json** | Use this if Security Copilot "Add Plugin" > "OpenAI Plugin" is your upload path. |

### Recommended Deployment Order

1. **Start with KQL Plugin** — works immediately after Sentinel data connector is configured
2. **Add API Plugin** — enables real-time lookups (requires SpyCloud API key)
3. **Add Logic App Plugin** — enables remediation actions (requires deployed playbooks)
4. **Deploy SCORCH Agent** — for autonomous AI-powered investigation
5. **Add MCP Plugin** — for advanced graph analysis (requires deployed MCP server)

---

## KQL Plugin

**File:** `copilot/SpyCloud_Plugin.yaml`
**Format:** KQL | **Skills:** 138 | **Auth:** None (uses Sentinel workspace connection)

### What It Does

Enables Security Copilot to query all 14 SpyCloud custom log tables in your Sentinel workspace using natural language. Copilot automatically translates your questions into KQL queries.

### When to Use

- You have SpyCloud data already ingested into Sentinel via the data connector
- You want to investigate users, devices, breaches, and exposures using natural language
- You do not need real-time API lookups (data freshness depends on your polling interval)
- You want the broadest skill coverage (138 skills across 14 tables)

### Required Settings

| Setting | What to Enter | Where to Find It |
|---------|--------------|------------------|
| **TenantId** | Azure Tenant ID in GUID format | Azure Portal > Microsoft Entra ID > Overview > Tenant ID |
| **SubscriptionId** | Azure Subscription ID where Sentinel workspace lives | Azure Portal > Subscriptions |
| **ResourceGroupName** | Resource Group containing the Sentinel workspace | Azure Portal > Resource Groups |
| **WorkspaceName** | Name of your Log Analytics workspace | Azure Portal > Log Analytics workspaces |

> **Important:** TenantId must be a GUID, not a domain name or URL.

### Setup Steps

1. Navigate to **Security Copilot** > **Settings** > **Plugins**
2. Click **"Add Plugin"** > **"Security Copilot Plugin"** > **"Upload from file"**
3. Upload `copilot/SpyCloud_Plugin.yaml`
4. Fill in the 4 required settings (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName)
5. Click **Save**

### Example Prompts

```
"Show me all exposed credentials with severity 25 in the last 7 days"
"Which users have plaintext passwords in SpyCloud data?"
"What are the top 10 most-exposed email domains?"
"Show infostealer infections from the last 30 days with device details"
"Check SpyCloud health status across all 14 tables"
```

---

## API Plugin

**File:** `copilot/SpyCloud_API_Plugin.yaml`
**OpenAPI Spec:** `copilot/SpyCloud_API_Plugin_OpenAPI.yaml`
**Format:** API | **Skills:** 38 | **Auth:** API Key (X-API-Key header)

### What It Does

Performs real-time REST API lookups against the live SpyCloud darknet intelligence database directly from Security Copilot. Unlike the KQL Plugin which queries ingested data, this queries the SpyCloud API for the most current data.

### When to Use

- You need **real-time, on-demand lookups** that are not limited to your polling interval
- You want to investigate emails, domains, IPs, or usernames **not yet ingested** into Sentinel
- You need to **validate API connectivity** and check which SpyCloud products you are licensed for
- You want **targeted API calls** with explicit control over which endpoint is called

### When NOT to Use (Use Full API Plugin Instead)

- If you want Copilot to **auto-discover all 50+ endpoints** from the OpenAPI spec
- If you prefer the **full OpenAPI specification** approach over hand-crafted skill definitions
- If you want the **broadest possible coverage** without manually updating the plugin

### Required Settings

| Setting | What to Enter | Where to Find It |
|---------|--------------|------------------|
| **SpyCloudApiKey** | Your SpyCloud Enterprise/Compass API key value | portal.spycloud.com > Account Settings > API Keys |

> **Important:** Enter ONLY the key value (e.g., `abc123def456...`), NOT the header name `X-API-Key`.

### Optional Settings (Per-API Keys)

| Setting | When Needed |
|---------|-------------|
| **InvestigationsApiKey** | Dedicated Investigations API entitlement (broadest dataset: phishing, paste sites, combo lists, forum dumps NOT in Enterprise/Compass) |
| **SipApiKey** | Session Identity Protection entitlement (stolen cookies, MFA bypass detection) |
| **IdLinkApiKey** | Dedicated IDLINK key (identity correlation graph) |
| **DataPartnershipApiKey** | Dedicated Data Partnership key |
| **ExposureApiKey** | Dedicated Exposure risk assessment key |
| **CAPApiKey** | Dedicated Credential Automated Protection key |

### Setup Steps

1. Navigate to **Security Copilot** > **Settings** > **Plugins**
2. Click **"Add Plugin"** > **"Security Copilot Plugin"** > **"Upload from file"**
3. Upload `copilot/SpyCloud_API_Plugin.yaml`
4. Enter your SpyCloud API key in the **SpyCloudApiKey** field
5. Optionally configure additional API keys for Investigations, SIP, IDLINK, etc.
6. Click **Save**

### API Coverage (38 Skills)

| API Product | Key Required |
|-------------|--------------|
| Enterprise Breach API | SpyCloudApiKey |
| Compass Investigation API | SpyCloudApiKey |
| Identity Exposure API | SpyCloudApiKey |
| SIP API | SipApiKey |
| Investigations API | InvestigationsApiKey |
| IDLINK API | IdLinkApiKey |
| Data Partnership API | DataPartnershipApiKey |
| Exposure API | ExposureApiKey |
| CAP API | CAPApiKey |
| Health Check | Any configured key |

---

## Full API Plugin

**File:** `copilot/SpyCloud_FullAPI_Plugin.yaml`
**OpenAPI Spec:** `copilot/SpyCloud_FullAPI_OpenAPI.yaml`
**Format:** API (OpenAPI auto-discovery) | **Skills:** Auto-discovered (50+) | **Auth:** API Key

### What It Does

Provides the **complete SpyCloud API surface** to Security Copilot using the full OpenAPI specification. Security Copilot automatically discovers all available endpoints from the spec and creates skills for each one.

### When to Use

- You want **maximum API coverage** without manually maintaining skill definitions
- You want Copilot to **automatically discover new endpoints** as SpyCloud adds them
- You prefer the **OpenAPI-first approach** where the spec drives skill creation
- You want **all 8 SpyCloud API products** available in a single plugin

### When NOT to Use (Use API Plugin Instead)

- If you want **hand-crafted skill descriptions** with detailed prompts and examples
- If you need **per-API key configuration** (Full API Plugin uses a single key)
- If you want **more control** over which skills appear and how they are described

### Required Configuration

| Setting | What to Enter | Where to Find It |
|---------|--------------|------------------|
| **API Key** | Your SpyCloud API key | Configured during plugin upload via the API Key auth prompt |

> **Note:** This plugin uses a single API key for all endpoints. If you need separate keys per API product, use the **API Plugin** instead.

### Difference from API Plugin

| Aspect | API Plugin (38 skills) | Full API Plugin (50+ auto-discovered) |
|--------|----------------------|--------------------------------------|
| Skill definitions | Hand-crafted with detailed descriptions | Auto-discovered from OpenAPI spec |
| API key model | Separate key per API product | Single key for all endpoints |
| Maintenance | Manual updates needed | Auto-updates when spec changes |
| Control | Full control over each skill | Less control, more coverage |

---

## Logic App Plugin

**File:** `copilot/SpyCloud_LogicApp_Plugin.yaml`
**Format:** LogicApp | **Skills:** 8 | **Auth:** Managed Identity

### What It Does

Enables Security Copilot to trigger remediation actions via deployed Azure Logic App playbooks. This is the **action layer** — while other plugins investigate and analyze, this one takes action.

### When to Use

- You have deployed SpyCloud Logic App playbooks in your Azure subscription
- You want to trigger **automated remediation** (password resets, device isolation, etc.) directly from a Copilot conversation
- You want the agent to be able to **act** on findings, not just report them

### Required Settings

| Setting | What to Enter | Where to Find It |
|---------|--------------|------------------|
| **SubscriptionId** | Azure Subscription ID where Logic Apps are deployed | Azure Portal > Subscriptions |
| **ResourceGroup** | Resource Group containing the Logic Apps | Azure Portal > Resource Groups |

### Setup Steps

1. **First:** Deploy the SpyCloud Logic App playbooks using the Content Hub or azuredeploy.json
2. Navigate to **Security Copilot** > **Settings** > **Plugins**
3. Click **"Add Plugin"** > **"Security Copilot Plugin"** > **"Upload from file"**
4. Upload `copilot/SpyCloud_LogicApp_Plugin.yaml`
5. Enter SubscriptionId and ResourceGroup
6. Click **Save**

### Available Remediation Skills (8)

| Skill | Action |
|-------|--------|
| ResetUserPassword | Force password reset for exposed user via Entra ID |
| IsolateDevice | Isolate infected device via MDE |
| RevokeUserSessions | Revoke all active sessions for compromised user |
| BlockUser | Temporarily block sign-in for exposed account |
| NotifyAdmin | Send Teams/email notification to security team |
| CreateIncident | Create Sentinel incident from exposure finding |
| EnrichIncident | Add SpyCloud context to existing Sentinel incident |
| FullInvestigation | Trigger comprehensive investigation workflow |

---

## MCP Plugin

**File:** `copilot/SpyCloud_MCP_Plugin.yaml`
**Format:** MCP (Model Context Protocol) | **Skills:** Auto-discovered | **Auth:** None (MCP server handles auth)

### What It Does

Connects Security Copilot to the SpyCloud MCP Server for advanced graph-based analysis. The MCP server materializes SpyCloud data into a graph structure and provides tools for blast radius analysis, attack path discovery, and exposure perimeter mapping.

### When to Use

- You need **graph-based investigation** — understanding relationships between users, devices, breaches
- You want to map **blast radius** — "if this user is compromised, what else is at risk?"
- You need **attack path discovery** — "how could an attacker move from point A to point B?"
- You want **exposure perimeter mapping** — "what is the full attack surface for our domain?"

### Required Settings

| Setting | What to Enter |
|---------|--------------|
| **McpServerUrl** | URL of the SpyCloud MCP Server SSE endpoint (e.g., `https://spycloud-mcp.azurewebsites.net/sse`) |

### Graph Tools (Auto-Discovered)

| Tool | Description |
|------|-------------|
| `blast_radius` | Find all entities connected to a compromised identity |
| `path_discovery` | Find shortest path between two entities in the graph |
| `exposure_perimeter` | Map the attack surface for a domain or user group |
| `identity_cluster` | Group related identities by shared attributes |
| `temporal_analysis` | Analyze exposure patterns over time |

---

## SCORCH Agent

**File:** `copilot/SpyCloud_Agent.yaml`
**Format:** AGENT + GPT + KQL (3 SkillGroups)
**Skills:** 128 total (27 AGENT sub-agents + 22 GPT analysis skills + 79 KQL data retrieval skills)
**Auth:** Mixed (Sentinel workspace + optional API keys + optional OpenAI)

### What It Does

The SCORCH (SpyCloud Compromised Operations Research & Credential Hunter) Agent is an **autonomous AI-powered investigation engine**. It receives a natural language investigation request and orchestrates 27 specialized sub-agents to produce comprehensive threat analysis, enriched with 22 GPT-4o AI analysis skills and backed by 79 KQL data retrieval skills.

### When to Use

- You want a **conversational investigation experience** — ask questions, get detailed answers, drill deeper
- You need **autonomous investigation** — the agent plans and executes multi-step workflows
- You want **AI-generated reports** — executive summaries, board presentations, compliance assessments
- You need **cross-source correlation** — combines SpyCloud, Sentinel, Defender XDR, Entra ID, and Intune data

### Required Settings

| Setting | What to Enter | Where to Find It |
|---------|--------------|------------------|
| **TenantId** | Azure Tenant ID (GUID format only) | Azure Portal > Entra ID > Overview > Tenant ID |
| **SubscriptionId** | Azure Subscription ID | Azure Portal > Subscriptions |
| **ResourceGroupName** | Resource Group with Sentinel workspace | Azure Portal > Resource Groups |
| **WorkspaceName** | Log Analytics workspace name | Azure Portal > Log Analytics workspaces |

### Optional Settings

| Setting | When Needed | Where to Find It |
|---------|-------------|------------------|
| **SpyCloudApiKey** | Enables API-backed skills for real-time data | portal.spycloud.com > API Keys |
| **InvestigationsApiKey** | Broadest dataset (phishing, paste sites, combo lists) | portal.spycloud.com (separate entitlement) |
| **SipApiKey** | Stolen cookie lookups and MFA bypass detection | portal.spycloud.com (separate entitlement) |
| **IdLinkApiKey** | Identity correlation graph | portal.spycloud.com |
| **DataPartnershipApiKey** | Partner intelligence | portal.spycloud.com |
| **ExposureApiKey** | Exposure risk assessments | portal.spycloud.com |
| **CAPApiKey** | Credential automated protection | portal.spycloud.com |
| **OpenAIApiKey** | Enables 22 GPT-4o AI analysis skills (starts with `sk-...`) | platform.openai.com > API Keys |
| **AzureOpenAIEndpoint** | Use Azure-hosted AI instead of OpenAI | Azure Portal > OpenAI Resource > Endpoint |
| **AzureOpenAIKey** | Required with AzureOpenAIEndpoint | Azure Portal > OpenAI Resource > Keys |
| **AzureOpenAIDeployment** | Model deployment name (e.g., `gpt-4o`) | Azure Portal > OpenAI Resource > Deployments |
| **AIEngineUrl** | Enables deep AI investigation engine | Deployed Function App URL |
| **MCPServerUrl** | Enables graph analysis tools | Deployed MCP server URL |

### Setup Steps

1. Navigate to **Security Copilot** > **Settings** > **Agents**
2. Click **"Add Agent"** > **"Upload YAML"**
3. Upload `copilot/SpyCloud_Agent.yaml`
4. Fill in the 4 required settings (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName)
5. Optionally configure API keys and AI settings
6. Click **Save**

### 27 Sub-Agents

| # | Sub-Agent | Investigation Domain |
|---|-----------|---------------------|
| 1 | SpyCloudInvestigationAgent | Primary orchestrator — triages and delegates |
| 2 | UEBABehavioralAnalysisAgent | User behavior anomalies + credential exposure |
| 3 | FusionMultistageAttackAgent | Fusion-detected multistage attacks |
| 4 | TIEnrichmentIOCAnalysisAgent | Threat intelligence and IOC enrichment |
| 5 | SessionCookieMFABypassAgent | Stolen cookies and MFA bypass |
| 6 | LateralMovementInvestigationAgent | Lateral movement from compromised accounts |
| 7 | DataExfiltrationDetectionAgent | Data theft via cloud apps and mailbox |
| 8 | ExecutiveSummaryComplianceAgent | Executive reports and compliance assessment |
| 9 | WatchlistAssetManagementAgent | Watchlist and VIP monitoring |
| 10 | RansomwareImpactAssessmentAgent | Ransomware exposure risk |
| 11 | IdentityRiskScoringAgent | Composite identity risk scores |
| 12 | SupplyChainExposureAgent | Third-party and supply chain exposure |
| 13 | DarkWebMonitoringAlertAgent | Real-time dark web monitoring |
| 14 | DefenderXDREndpointAgent | MDE device timeline and alerts |
| 15 | IntuneDeviceComplianceAgent | Intune compliance posture |
| 16 | CASBCloudAppSecurityAgent | Cloud app security risks |
| 17 | CompassDeepForensicsAgent | Compass infostealer deep forensics |
| 18 | IdLinkIdentityCorrelationAgent | Identity graph correlations |
| 19 | DataPartnershipIntelligenceAgent | Partner intelligence analysis |
| 20 | ExposureRiskAssessmentAgent | Exposure risk profiling |
| 21 | CAPResponseManagementAgent | Credential automated protection |
| 22 | SipSessionProtectionAgent | Session Identity Protection |
| 23 | InvestigationsDeepDiveAgent | Investigations API deep analysis |
| 24 | EnhancedThreatResearchAgent | CVE, TLP, IOC, blog research |
| 25 | CommunicationTemplatesAgent | Notifications and briefings |
| 26 | OpenAIAdvancedAnalysisAgent | GPT-4o powered analysis |
| 27 | CrossAPIInvestigationAgent | Multi-API orchestration |

### 22 GPT-4o AI Analysis Skills

These skills require either **OpenAIApiKey** or **AzureOpenAIEndpoint + AzureOpenAIKey** to be configured.

| Skill | Output |
|-------|--------|
| AnalyzeExposureData | Structured analysis report from raw SpyCloud data |
| SynthesizeInvestigation | Multi-source investigation synthesis |
| AssessCompliance | GDPR/CCPA/HIPAA/PCI compliance assessment |
| GenerateThreatNarrative | Chronological threat narrative |
| CorrelateIndicators | IOC correlation across sources |
| DesignResponsePlaybook | Custom response playbook design |
| GenerateExecutiveReport | C-level executive summary |
| CreateBoardPresentation | Board-level presentation content |
| PredictExposureTrends | Exposure trend forecasting |
| SimulateAttackScenario | Red team attack simulation |
| GenerateRiskHeatmap | Domain risk heatmap visualization |
| ComposeIncidentNarrative | Detailed incident narrative |
| ResearchCVEExploitation | CVE research and exploitation analysis |
| ClassifyThreatLevel | TLP classification and assessment |
| SynthesizeThreatIntel | Threat intel synthesis from research |
| EnrichIOCContext | IOC contextual enrichment |
| AnalyzeDarkWebCampaign | Dark web campaign analysis |
| GenerateUserNotification | Professional user notification |
| CreateExternalCommunication | External stakeholder communication |
| ComposeManagementBriefing | Management briefing document |
| GenerateRegulatoryNotification | Regulatory compliance notification |
| GenerateSOCHandoff | SOC shift handoff briefing |

---

## OpenAI Manifest

**File:** `copilot/manifest.json`
**Format:** OpenAI Plugin Manifest (JSON)
**Purpose:** Alternative upload path for Security Copilot using the OpenAI plugin format

### What It Is

The `manifest.json` file follows the **OpenAI Plugin Manifest specification** (schema v2). This is an industry-standard format originally designed for ChatGPT plugins that Microsoft Security Copilot also supports.

### When to Use manifest.json (vs YAML files)

| Use manifest.json When... | Use YAML files When... |
|---------------------------|----------------------|
| Uploading via **"Add Plugin" > "OpenAI Plugin"** | Uploading via **"Add Plugin" > "Security Copilot Plugin"** |
| You want a **single file** that references the OpenAPI spec | You want **granular control** over each skill definition |
| You need **programmatic plugin registration** via API | You are using the **Security Copilot UI** to upload |
| You are familiar with **ChatGPT/OpenAI plugin development** | You are following **Microsoft Security Copilot documentation** |
| You want **auto-translation** to Security Copilot format | You want **direct control** over the manifest |

### Why Both Formats Exist

Security Copilot supports two manifest formats:

1. **Security Copilot Native YAML** — The native format with `Descriptor` + `SkillGroups`. Offers full control over skill definitions, settings, and agent configuration. Supports KQL, API, GPT, AGENT, LogicApp, and MCP formats. This is what the `.yaml` files use.

2. **OpenAI Plugin JSON** — The OpenAI-standard format with `name_for_human`, `name_for_model`, `description_for_model`, etc. When uploaded, Security Copilot **translates this to its native format** internally. Only supports API plugins (not agents, KQL, LogicApp, or MCP). This is what `manifest.json` uses.

### Key Differences

| Aspect | Security Copilot YAML | OpenAI Manifest JSON |
|--------|----------------------|---------------------|
| Upload path | "Security Copilot Plugin" > "Upload from file" | "OpenAI Plugin" > "Upload from file" or URL |
| Skill definitions | Explicit per-skill (Name, Description, Inputs, Settings) | Auto-discovered from referenced OpenAPI spec |
| Agent support | Full (Format: AGENT with Instructions, ChildSkills) | Not supported (plugins only, no agents) |
| KQL support | Full (Format: KQL with Template) | Not supported (API only) |
| LogicApp support | Full (Format: LogicApp) | Not supported (API only) |
| MCP support | Full (Format: MCP) | Not supported (API only) |
| Auth configuration | Per-skill granular auth | Single auth for entire plugin |
| Settings/Config | Custom settings with types, hints, validation | Limited to auth configuration |

### manifest.json Structure

```json
{
  "schema_version": "v2",
  "name_for_human": "SpyCloud Threat Intelligence",
  "name_for_model": "SpyCloudSentinel",
  "description_for_human": "Short description shown to users...",
  "description_for_model": "Detailed description for the AI model...",
  "auth": {
    "type": "service_http",
    "authorization_type": "custom",
    "custom_auth_header": "X-API-Key"
  },
  "api": {
    "type": "openapi",
    "url": "https://...SpyCloud_API_Plugin_OpenAPI.yaml"
  },
  "logo_url": "https://...SpyCloud-icon-SC_2.png",
  "publisher": "SpyCloud",
  "version": "2.0.0"
}
```

### Setup Steps (OpenAI Manifest)

1. Navigate to **Security Copilot** > **Settings** > **Plugins**
2. Click **"Add Plugin"** > **"OpenAI Plugin"**
3. Enter the URL: `https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/copilot/manifest.json`
   - Or click **"Upload from file"** and select `copilot/manifest.json`
4. Security Copilot will fetch the referenced OpenAPI spec and auto-discover endpoints
5. Enter your SpyCloud API key when prompted
6. Click **Save**

### What manifest.json Includes

The manifest references the `SpyCloud_API_Plugin_OpenAPI.yaml` spec, which gives Copilot access to all 9 SpyCloud API products (38 skills). It does **NOT** include:
- KQL skills (use `SpyCloud_Plugin.yaml` separately)
- Agent/sub-agent capabilities (use `SpyCloud_Agent.yaml` separately)
- Logic App remediation actions (use `SpyCloud_LogicApp_Plugin.yaml` separately)
- MCP graph tools (use `SpyCloud_MCP_Plugin.yaml` separately)

### Recommendation

For most deployments, use the **YAML files directly** (Security Copilot native format). They provide:
- Full agent support with 27 sub-agents
- KQL skills for Sentinel table queries
- Logic App integration for remediation
- MCP integration for graph analysis
- Granular per-skill control

Use `manifest.json` only if you specifically need the OpenAI plugin upload path or are integrating via the Security Copilot API programmatically.

---

## Manifest Formats

### Security Copilot YAML Format (Native)

```yaml
Descriptor:
  Name: MyPlugin
  DisplayName: My Plugin
  Description: "What this plugin does"
  Settings:
    - Name: ApiKey
      Description: "Your API key"
      SettingType: SecretString
      Required: true
  SupportedAuthTypes:
    - ApiKey

SkillGroups:
  - Format: KQL  # or API, GPT, AGENT, LogicApp, MCP
    Skills:
      - Name: MySkill
        DisplayName: My Skill
        Description: "What this skill does"
        Inputs:
          - Name: email
            Description: "Email to look up"
            Required: true
        Settings:
          Target: Sentinel
          Template: |-
            MyTable_CL | where email == "{{email}}"
```

### OpenAI Manifest Format (JSON)

```json
{
  "schema_version": "v2",
  "name_for_human": "My Plugin",
  "name_for_model": "MyPlugin",
  "description_for_human": "Short user-facing description",
  "description_for_model": "Detailed description for the AI...",
  "auth": { "type": "service_http", "authorization_type": "custom", "custom_auth_header": "X-API-Key" },
  "api": { "type": "openapi", "url": "https://example.com/openapi.yaml" }
}
```

---

## API Key Architecture

SpyCloud uses **separate API keys per product line**. Understanding which key unlocks which capabilities is critical:

| API Product | Key Setting | Data Coverage | Shared Key? |
|-------------|------------|---------------|-------------|
| **Enterprise Breach API** | SpyCloudApiKey | Breach credentials, watchlist, catalog | Shared with Compass |
| **Compass Investigation API** | SpyCloudApiKey | Consumer identity, device forensics | Shared with Enterprise |
| **Investigations API** | InvestigationsApiKey | **BROADEST** — phishing, paste sites, combo lists, forum dumps (NOT in Enterprise/Compass) | **SEPARATE dedicated key** |
| **Session Identity Protection (SIP)** | SipApiKey | Stolen session cookies, MFA bypass | **SEPARATE dedicated key** |
| **IDLINK API** | IdLinkApiKey | Identity correlation graph | Separate (or falls back to SpyCloudApiKey) |
| **Data Partnership API** | DataPartnershipApiKey | Partner-contributed intelligence | Separate (if dedicated key) |
| **Exposure API** | ExposureApiKey | Exposure risk assessments | Separate (if dedicated key) |
| **CAP API** | CAPApiKey | Credential automated protection | Separate (if dedicated key) |

> **Key Insight:** Enterprise and Compass share ONE key. Investigations API requires a completely SEPARATE key and provides data that Enterprise/Compass do NOT have. SIP also requires its own dedicated key.

---

## OpenAI and Azure AI Integration

The SCORCH Agent supports two AI providers for its 22 GPT-powered analysis skills:

### Option 1: OpenAI (Direct)

| Setting | Value |
|---------|-------|
| **OpenAIApiKey** | Your OpenAI API key (starts with `sk-...`) from platform.openai.com |

- Uses **GPT-4o** for all analysis
- Requires an OpenAI subscription (not free tier)
- Data is sent to OpenAI API servers
- **This is NOT Azure OpenAI** — it is the standard OpenAI platform

### Option 2: Azure OpenAI

| Setting | Value |
|---------|-------|
| **AzureOpenAIEndpoint** | `https://your-resource.openai.azure.com/` |
| **AzureOpenAIKey** | API key from Azure Portal > OpenAI Resource > Keys |
| **AzureOpenAIDeployment** | Model deployment name (e.g., `gpt-4o`) |

- Data stays within your Azure tenant
- Compliant with Azure data residency policies
- Recommended for **government and regulated industries**
- Requires an Azure OpenAI Service resource with a GPT-4o deployment

### Option 3: No AI (Default)

If neither OpenAI nor Azure OpenAI keys are configured, the Agent works fully with all non-AI skills (27 agents + 79 KQL skills). The 22 GPT analysis skills simply will not be available.

### What AI Enables

| Capability | Without AI | With AI |
|-----------|-----------|---------|
| User investigation | KQL queries + data tables | + AI-synthesized narrative |
| Executive reports | Raw data summaries | + Polished executive briefing |
| Compliance assessment | Raw exposure data | + Framework-mapped compliance report |
| Threat research | IOC lookups | + CVE analysis, TLP classification |
| Incident narratives | Timeline data | + Chronological narrative |
| Board presentations | Metric summaries | + Board-ready presentation content |
| Attack simulation | Exposure data | + Red team scenario simulation |

---

## Purview Integration Skills

The SCORCH Agent includes Purview-aware investigation capabilities:

| Sub-Agent | Purview Capabilities |
|-----------|---------------------|
| ExecutiveSummaryComplianceAgent | Compliance assessment against GDPR, CCPA, HIPAA, PCI DSS |
| DataExfiltrationDetectionAgent | DLP policy correlation with exposure data |
| IdentityRiskScoringAgent | Sensitivity label assessment for exposed data |
| SupplyChainExposureAgent | Third-party data classification review |

### Purview-Related KQL Skills

- Risk scoring skills assess sensitivity of exposed data types
- Compliance skills map exposures to regulatory notification requirements
- Executive report skills include Purview classification status

---

## Playbook Automations

The Logic App Plugin provides 8 remediation actions that trigger deployed playbooks:

| Playbook | Trigger | Action | Dependencies |
|----------|---------|--------|--------------|
| SpyCloud-ResetPassword | Manual/Copilot | Force Entra ID password reset | Entra ID permissions |
| SpyCloud-IsolateDevice | Manual/Copilot | MDE device isolation | MDE API access |
| SpyCloud-RevokeSessions | Manual/Copilot | Revoke all user sessions | Entra ID permissions |
| SpyCloud-BlockUser | Manual/Copilot | Disable user sign-in | Entra ID permissions |
| SpyCloud-NotifyAdmin | Manual/Copilot | Teams/email notification | Office 365 connector |
| SpyCloud-CreateIncident | Manual/Copilot | Create Sentinel incident | Sentinel API access |
| SpyCloud-EnrichIncident | Manual/Copilot | Add SpyCloud context to incident | Sentinel API access |
| SpyCloud-FullInvestigation | Manual/Copilot | Comprehensive investigation workflow | All connectors |

---

## Personas and AI Queries

The SCORCH Agent supports 6 investigation personas, each with tailored suggested prompts:

| Persona | Role | Focus Area |
|---------|------|------------|
| 0 | CISO / Executive | Strategic risk, compliance, board reporting |
| 1 | SOC Analyst | Triage, investigation, incident response |
| 2 | Threat Hunter | Proactive hunting, malware analysis, campaign tracking |
| 3 | Compliance Officer | Regulatory requirements, breach notification, audit evidence |
| 4 | IT Administrator | Device management, permissions, connector health |
| 5 | Executive / Board Member | High-level summaries, business impact |

### Sample Investigation Queries

**SOC Analyst:**
```
"Investigate user@company.com for credential exposure and recommend remediation"
"Show me all high-severity infostealer infections from the last 7 days"
"What devices are infected and have not been isolated yet?"
```

**Threat Hunter:**
```
"Hunt for RedLine infostealer infections across our environment"
"Show attack timelines for all users compromised in breach source 54321"
"Find lateral movement paths from compromised accounts"
```

**CISO / Executive:**
```
"Generate an executive report on our exposure posture for the last 90 days"
"What is our mean time to remediate credential exposures?"
"Compare our exposure this month vs last month"
```

**Compliance Officer:**
```
"What PII exposures require GDPR notification?"
"Generate a compliance report for cyber insurance renewal"
"Show exposure metrics formatted for SOC2 audit evidence"
```

---

## Troubleshooting YAML Upload Errors

### Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `Expected 'StreamEnd', got 'DocumentStart'` | File contains `---` document separator creating multiple YAML documents | Remove all `---` separators. Security Copilot expects a single YAML document. |
| `While scanning a multiline plain scalar, found invalid mapping` | Unquoted string value containing colons (`:`) or special characters | Quote all Description, DisplayName, and HintText values with double quotes |
| `Exception during deserialization. Failed to create an instance of type 'System.String'` | Single-quoted JSON strings or multiline strings the C# parser cannot handle | Use double-quoted strings for JSON values, block scalars for long text |
| `Duplicate key` | Same key appears twice in a YAML mapping | Remove duplicate keys |
| `Tab character in indentation` | File uses tabs instead of spaces | Replace all tabs with spaces (2-space indentation) |

### YAML Best Practices for Security Copilot

1. **Always quote Description values** — use double quotes (`"..."`) for single-line, block scalar (`|`) for multi-line
2. **No document separators** — never use `---` in plugin YAML files
3. **No tabs** — use spaces only (2-space indentation)
4. **Quote special characters** — colons, em-dashes, brackets, braces
5. **Use block scalars for long text** — `|` preserves newlines, `>` folds them
6. **Double-quote JSON strings** — `Body: "{\"key\": \"value\"}"` not `Body: '{"key": "value"}'`
7. **Single YAML document per file** — each plugin/agent file must contain exactly one document

---

## Publishing Agent to Defender Portal

After installing the SCORCH Agent in Security Copilot, it becomes available in the Microsoft Defender portal:

1. **Verify Installation:** Security Copilot > Settings > Agents > Verify "SCORCH" appears
2. **Defender Portal Access:** Go to security.microsoft.com > Copilot
3. **Agent Availability:** The SCORCH agent skills appear automatically in the Defender Copilot sidebar
4. **Custom Prompts:** Create saved prompts for common investigation workflows
5. **Automation:** Connect agent skills to automation rules for hands-free investigation

---

## Jupyter Notebook Integration

### VSCode Configuration

The repository includes VSCode configuration for Jupyter notebook development:

- `.vscode/settings.json` - Python interpreter, Jupyter server settings
- `.vscode/extensions.json` - Recommended extensions (Jupyter, Python, Azure)

### Notebook Catalog

| Notebook | Purpose | Key Features |
|----------|---------|-------------|
| `SpyCloud-ThreatHunting.ipynb` | Proactive threat hunting | Multi-table correlation, anomaly detection |
| `SpyCloud-Incident-Triage.ipynb` | Incident investigation | Timeline visualization, entity mapping |
| `SpyCloud-Threat-Landscape.ipynb` | Threat landscape analysis | Trend analysis, breach source profiling |
| `SpyCloud-Graph-Investigation.ipynb` | Graph-based investigation | NetworkX visualization, path analysis |
| `SpyCloud-Simulated-Scenarios.ipynb` | Training and testing | Simulated breach scenarios, response validation |

### Connecting Notebooks to Copilot

Notebooks can invoke Security Copilot skills programmatically:

```python
from azure.identity import DefaultAzureCredential
import requests

credential = DefaultAzureCredential()
token = credential.get_token("https://securitycopilot.microsoft.com/.default")

# Invoke SCORCH agent skill
response = requests.post(
    "https://securitycopilot.microsoft.com/api/skills/invoke",
    headers={"Authorization": f"Bearer {token.token}"},
    json={
        "skillName": "SpyCloud-Investigate",
        "parameters": {"email": "user@company.com"}
    }
)
```
