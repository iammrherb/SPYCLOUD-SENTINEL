<div align="center">

<img src="images/SpyCloud-Logo-white.png" alt="SpyCloud" width="300" style="background:#0D1B2A;padding:20px;border-radius:10px"/>

# The Ultimate Guide to SpyCloud Agents & Plugins
### *A No-BS, All-Levels Walkthrough for Security Teams*

**From Helpdesk Hero to CISO Sensei — This Guide Has You Covered**

![Version](https://img.shields.io/badge/version-9.0.0-00C7B7?style=flat-square&logo=semver&logoColor=white)
![Copilot](https://img.shields.io/badge/Security_Copilot-Enabled-6366F1?style=flat-square&logo=githubcopilot&logoColor=white)

</div>

---

## Table of Contents

1. [TL;DR — What Are We Dealing With?](#tldr)
2. [CRITICAL: One Agent or Multiple? The Architecture Answer](#architecture-answer)
3. [Agents vs. Plugins — The Eternal Question](#agents-vs-plugins)
4. [The Three Amigos: Your Plugin Lineup](#the-three-amigos)
5. [How They Work Together](#how-they-work-together)
6. [Setup Guide: Step-by-Step](#setup-guide)
7. [API Keys & The "Value" Field — Demystified](#api-keys-demystified)
8. [OpenAI API — What It Is and What It Isn't](#openai-clarification)
9. [Health Check & Testing — Validate Everything Works](#health-check-testing)
10. [Connector Ecosystem & Recommendations](#connector-ecosystem)
11. [Your 14 Custom Tables](#custom-tables)
12. [Use Cases by Role](#use-cases-by-role)
13. [Optimization Tips & Best Practices](#optimization)
14. [Troubleshooting Guide](#troubleshooting)
15. [Admin Recommendations Checklist](#admin-checklist)

---

<a name="tldr"></a>
## TL;DR — What Are We Dealing With?

**SpyCloud Sentinel** is a complete dark web intelligence platform that lives inside Microsoft Sentinel and Security Copilot. It has **three plugin files** that you upload separately to Security Copilot:

| Component | Type | What It Does | Skills |
|-----------|------|-------------|--------|
| **SpyCloud Investigation Agent** | Agent | Interactive conversational analyst that orchestrates **23 sub-agents** with **12 GPT-4o AI analysis skills** and **65+ KQL data skills** | 100+ |
| **SpyCloud KQL Plugin** | Plugin (KQL) | Pre-built Kusto queries against **14 Sentinel custom tables** | 120+ |
| **SpyCloud API Plugin** | Plugin (API) | Direct REST API access to **all 9 SpyCloud APIs** with health check validation | 38+ |

**Together they give you:** 250+ skills, 23 sub-agents, 14 custom Sentinel tables, coverage across 9 SpyCloud APIs and 11 Microsoft security products.

---

<a name="architecture-answer"></a>
## CRITICAL: One Agent or Multiple? The Architecture Answer

**This is the #1 question everyone asks. Here is the definitive answer:**

### You upload 3 YAML files. That's it.

You do NOT need to publish multiple agents. You do NOT need to set up separate agents for KQL, API, Threat Intelligence, Investigations, etc. **It is ONE solution with 3 complementary files:**

| File to Upload | What It Is | Can It Work Alone? |
|---------------|-----------|-------------------|
| `SpyCloud_Plugin.yaml` | KQL Plugin (120+ skills) | YES — queries Sentinel data, no API key needed |
| `SpyCloud_API_Plugin.yaml` | API Plugin (38+ skills) | YES — calls SpyCloud REST APIs directly |
| `SpyCloud_Agent.yaml` | Investigation Agent (23 sub-agents) | YES — but works BEST when KQL Plugin is also uploaded |

### How the 3 files relate:

```
                    +-----------------------------------------+
                    |        SECURITY COPILOT                  |
                    |                                         |
                    |   +----------------------------------+  |
                    |   | SpyCloud Investigation Agent     |  |
                    |   | (SpyCloud_Agent.yaml)            |  |
                    |   |                                  |  |
                    |   | The "brain" - orchestrates       |  |
                    |   | 23 sub-agents, remembers         |  |
                    |   | context, chains skills,          |  |
                    |   | provides analysis & advice       |  |
                    |   |                                  |  |
                    |   |   USES skills from:              |  |
                    |   |   +-------------+ +------------+ |  |
                    |   |   | KQL Plugin  | | API Plugin | |  |
                    |   |   | (120+ KQL   | | (38+ REST  | |  |
                    |   |   |  queries)   | |  API calls)| |  |
                    |   |   +-------------+ +------------+ |  |
                    |   +----------------------------------+  |
                    +-----------------------------------------+
```

### Why NOT a single monolithic agent?

Security Copilot's plugin architecture is designed for **separation of concerns**:

- **KQL Plugin** = Data layer (reads from Sentinel tables). No API key needed. Works for any SOC analyst with workspace reader access.
- **API Plugin** = Real-time layer (calls SpyCloud APIs). Requires API key. Used for fresh/real-time data not yet in Sentinel.
- **Agent** = Intelligence layer (orchestrates, correlates, advises). Invokes skills from both plugins. Optional API keys for enhanced capabilities.

**This means:**
- A SOC analyst who only has workspace access can use the KQL Plugin alone
- An incident responder who needs real-time data can use the API Plugin alone
- The Agent combines both for the richest experience
- You can update one plugin without touching the others

### Do NOT upload manifest.json

The `manifest.json` file in the copilot folder is a **metadata reference file** for developers and documentation. It describes the entire solution. **Do NOT upload it to Security Copilot.** Only upload the 3 individual YAML files.

---

<a name="agents-vs-plugins"></a>
## Agents vs. Plugins — The Eternal Question

### What IS a Plugin?

A **Plugin** is a collection of **skills** — discrete, well-defined operations that Security Copilot can call. Think of each skill as a single tool in a toolbox:

- "Look up this email in SpyCloud" (one skill)
- "Show me password types across all exposures" (one skill)
- "Run a health check on all 14 tables" (one skill)

**Plugins are reactive.** You ask, they answer. One question, one answer. They don't have memory, personality, or the ability to chain actions together on their own.

#### Two Flavors of Plugins:

| Plugin Type | Data Source | Speed | Use Case |
|------------|------------|-------|----------|
| **KQL Plugin** | Queries data already in your Sentinel workspace | Fast (data is local) | Historical analysis, trending, correlation with other Sentinel data |
| **API Plugin** | Calls SpyCloud REST API in real-time | Real-time (hits SpyCloud servers) | Latest data, records not yet ingested, API health validation |

### What IS an Agent?

An **Agent** is a **conversational AI personality** that can:

- **Remember context** across a conversation ("you asked about user X earlier — let me connect that to this new finding")
- **Chain multiple skills** together ("let me check the user, then their device, then the malware, then the remediation status")
- **Make recommendations** ("Based on what I found, here's what I'd do...")
- **Adapt its communication style** (brief for quick checks, thorough for deep dives)
- **Interpret vague requests** ("show me stuff" → runs an org-wide exposure assessment)
- **Orchestrate 23 sub-agents** for specialized investigations

**Agents are proactive.** They don't just answer — they investigate, correlate, and advise.

### The Car Analogy

- **Plugin** = Individual car parts (engine, transmission, brakes)
- **Agent** = The fully assembled car with a GPS, a skilled driver, and a co-pilot who knows every shortcut

You *can* use parts individually. But the car is a lot more fun.

---

<a name="the-three-amigos"></a>
## The Three Amigos: Your Plugin Lineup

### 1. SpyCloud KQL Plugin (`SpyCloud_Plugin.yaml`)

**What it does:** Runs 120+ pre-built Kusto (KQL) queries against your Sentinel Log Analytics workspace across ALL 14 SpyCloud custom tables.

**Authentication:** None required — uses your Sentinel workspace connection (Azure RBAC).

**Skill Categories:**

| Category | Table(s) | Skills | What You Get |
|----------|----------|--------|-------------|
| User Credential Investigation | BreachWatchlist | 5 | Full exposure, PII profile, account activity, passwords, full investigation |
| Password Analysis | BreachWatchlist | 2 | Plaintext passwords, type breakdown |
| Severity & Domain Analysis | BreachWatchlist | 4 | By severity, domain, target sites |
| PII & Social Media | BreachWatchlist | 2 | SSN/financial/health, social media |
| Device Forensics | BreachWatchlist, CompassDevices | 4 | Infected devices, forensics, user correlation, AV gaps |
| Breach Catalog & Malware | BreachCatalog | 3 | Malware lookup, recent breaches, enriched exposures |
| MDE Remediation Audit | MDE_Logs | 3 | MDE actions, device remediation, stats |
| Conditional Access Audit | ConditionalAccessLogs | 3 | CA actions, user remediation, stats |
| Geographic Analysis | BreachWatchlist | 1 | Geographic distribution of infections |
| **Health & Operations** | **All 14 Tables** | **1** | **Comprehensive ingestion health check with status indicators** |
| IDLINK Correlation | IdLink | 8 | Identity graphs, shared devices, breach overlap |
| Data Partnership | DataPartnership | 6 | Partner intelligence, sources, trends |
| Exposure Risk | Exposure | 8 | Risk profiles, remediation gaps, timelines |
| CAP Protection | CAP | 8 | Action tracking, SLA compliance, policies |
| Compass Applications | CompassApplications | 3 | Stolen app credentials, stats |
| SIP Cookies | SipCookies | 4 | Stolen cookies, high-risk sessions |
| Identity Exposure | IdentityExposure | 3 | Identity profiles, stats |
| Investigations | Investigations | 3 | Full database search records, stats |

### 2. SpyCloud API Plugin (`SpyCloud_API_Plugin.yaml`)

**What it does:** Calls all 9 SpyCloud REST APIs directly for real-time intelligence plus health check validation.

**Authentication:** API Key (X-API-Key header — configured once during plugin setup).

**API Coverage (38+ Skills):**

| API | Skills | What You Get |
|-----|--------|-------------|
| Enterprise Breach | 7 | Email/domain/IP/username/password lookup, breach catalog |
| Compass Investigation | 3 | Deep infostealer data by email/domain/IP |
| Identity Exposure | 2 | Identity profiles, watchlist status |
| Session Identity Protection (SIP) | 3 | Stolen cookies, SIP catalog |
| Investigations | 5 | Full database search by email/domain/IP/username/password |
| IDLINK | 4 | Identity links, relationship graphs |
| Data Partnership | 3 | Partner data, partner catalog |
| Exposure | 4 | Risk profiles by email/domain/IP, org summary |
| CAP | 4 | Credential actions, policies, trigger reset |
| **Health Check & Validation** | **3** | **API connectivity testing across all endpoints** |

### 3. SpyCloud Investigation Agent (`SpyCloud_Agent.yaml`)

**What it does:** An interactive, conversational AI analyst named **SENTINEL** that orchestrates **23 specialized sub-agents** with **12 GPT-4o AI analysis skills** and **65+ KQL data retrieval skills**.

**Authentication:** None for base functionality (uses Sentinel workspace). Optional API keys for enhanced capabilities.

**All 23 Sub-Agents:**

| # | Sub-Agent | Specialization |
|---|-----------|---------------|
| 1 | SpyCloudInvestigationAgent | Primary orchestrator — triages, delegates, synthesizes |
| 2 | UEBABehavioralAnalysisAgent | Behavioral anomaly correlation |
| 3 | FusionMultistageAttackAgent | ML-detected multi-stage attacks |
| 4 | TIEnrichmentIOCAnalysisAgent | Threat intel enrichment & IOC analysis |
| 5 | SessionCookieMFABypassAgent | Stolen cookies & MFA bypass |
| 6 | LateralMovementInvestigationAgent | Credential-based lateral movement |
| 7 | DataExfiltrationDetectionAgent | Data theft from compromised accounts |
| 8 | ExecutiveSummaryComplianceAgent | Executive reports & compliance |
| 9 | WatchlistAssetManagementAgent | VIP/IOC/asset watchlist management |
| 10 | RansomwareImpactAssessmentAgent | Ransomware exposure risk |
| 11 | IdentityRiskScoringAgent | Composite identity risk scoring |
| 12 | SupplyChainExposureAgent | Third-party credential exposure |
| 13 | DarkWebMonitoringAlertAgent | Dark web trend monitoring |
| 14 | DefenderXDREndpointAgent | Defender XDR cross-product investigation |
| 15 | IntuneDeviceComplianceAgent | Intune MDM & compliance |
| 16 | CASBCloudAppSecurityAgent | Cloud app security & shadow IT |
| 17 | CompassDeepInvestigationAgent | Deep infostealer forensics |
| 18 | IdLinkCorrelationAgent | Identity graph correlation |
| 19 | DataPartnershipIntelAgent | Partner intelligence analysis |
| 20 | ExposureRiskAgent | Exposure risk profiling |
| 21 | CAPResponseAgent | Credential automated protection |
| 22 | OpenAIAdvancedAnalysisAgent | Executive reports, board presentations, predictive analytics |
| 23 | CrossAPIInvestigationAgent | Multi-API super-orchestrator |

**12 GPT-4o AI Analysis Skills:**

| Skill | What It Produces |
|-------|-----------------|
| AnalyzeAndSummarize | Structured investigation reports with risk scoring |
| BuildThreatNarrative | Chronological attack narratives with MITRE ATT&CK mapping |
| GenerateComplianceAssessment | GDPR/CCPA/HIPAA/PCI-DSS assessment |
| GenerateExecutiveBriefing | Board-level executive briefings |
| CorrelateExternalThreatIntel | Malware family analysis & threat actor attribution |
| DesignResponsePlaybook | Custom incident response playbooks |
| GenerateExecutiveReport | Polished executive reports with metrics |
| GenerateBoardPresentation | Board-ready presentation materials |
| PredictExposureTrend | Exposure forecasting & risk trends |
| BuildAttackSimulation | Attack simulation scenarios |
| GenerateRiskHeatmap | Risk heatmaps by business unit/geography |
| ComposeIncidentNarrative | Professional incident narratives for post-mortem |

---

<a name="how-they-work-together"></a>
## How They Work Together

**You don't have to choose.** Upload all three and they complement each other:

```
User: "Investigate suspicious.user@company.com"
                    |
                    v
         +---------------------+
         |  SENTINEL Agent     |  <-- Understands intent
         |  "Got it - full     |
         |  investigation      |
         |  coming up!"        |
         +--------+------------+
                  |
    +-------------+-------------+
    v             v             v
+---------+  +---------+  +---------+
|KQL Plugin|  |KQL Plugin|  |API Plugin|
|GetUser   |  |GetExposed|  |GetBreach |
|Exposures |  |Passwords |  |DataBy    |
|(Sentinel)|  |(Sentinel)|  |Email     |
|          |  |          |  |(Real-time|
+----+-----+  +----+-----+  +----+-----+
     |             |             |
     +-------------+-------------+
                   v
         +---------------------+
         |  SENTINEL Agent     |  <-- Correlates & interprets
         |  combines all       |
         |  results into a     |
         |  rich narrative     |
         |  with risk rating,  |
         |  MITRE mapping,     |
         |  and next steps     |
         +---------------------+
```

### The Workflow in Practice

1. **User asks a question** -> Agent interprets intent
2. **Agent selects sub-agent(s)** -> Routes to specialists
3. **Sub-agents invoke KQL and/or API skills** -> Gets raw data
4. **Agent correlates results** -> Connects the dots across sources
5. **Agent presents findings** -> Rich narrative with tables, severity indicators, MITRE mapping
6. **Agent suggests next steps** -> "Want me to check Defender XDR? Intune compliance? Build an attack timeline?"
7. **User follows up** -> Agent remembers context and goes deeper

---

<a name="setup-guide"></a>
## Setup Guide: Step-by-Step

### Prerequisites

| Requirement | Details |
|------------|---------|
| **Microsoft Sentinel** | Active workspace with SpyCloud data connector configured |
| **Security Copilot** | Licensed and provisioned in your tenant |
| **SpyCloud API Key** | Required for API Plugin; optional for KQL-only usage |
| **Permissions** | Security Admin or Copilot Owner to upload plugins |
| **SpyCloud Subscription** | Enterprise (standard) or Enterprise+ (for Compass) |

### Step 1: Deploy SpyCloud Sentinel Solution

If you haven't already deployed the base solution:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

This deploys: 14 custom tables, CCF data connector, analytics rules, playbooks, workbooks, watchlists, and automation rules.

### Step 2: Upload the KQL Plugin (No API Key Required)

1. Open **Microsoft Security Copilot** -> **Sources** -> **Manage plugins** -> **Custom** -> **Add plugin**
2. Upload format: **Security Copilot plugin**
3. Upload file: `copilot/SpyCloud_Plugin.yaml`
4. Configure settings when prompted:

| Setting | What to Enter | Where to Find It |
|---------|--------------|-----------------|
| **TenantId** | Your Azure AD tenant GUID (e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) | Azure Portal > Microsoft Entra ID > Overview > Tenant ID |
| **SubscriptionId** | Azure subscription GUID | Azure Portal > Subscriptions |
| **ResourceGroupName** | Exact resource group name containing your Sentinel workspace | Azure Portal > Resource Groups |
| **WorkspaceName** | Exact Log Analytics workspace name | Azure Portal > Log Analytics Workspaces |

5. Click **Save**

**IMPORTANT:** TenantId and SubscriptionId must be GUIDs (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Do NOT enter a domain name, URL, or friendly name.

### Step 3: Upload the API Plugin (API Key Required)

1. Same path: **Sources** -> **Manage plugins** -> **Custom** -> **Add plugin**
2. Upload file: `copilot/SpyCloud_API_Plugin.yaml`
3. **When prompted for API Key authentication**, you will see a "Value" field:

> **THE "VALUE" FIELD EXPLAINED** (See [detailed section below](#api-keys-demystified))
>
> Enter your **actual SpyCloud API key string** (e.g., `abc123def456ghi789...`).
>
> Do NOT enter `X-API-Key` or any header name — just the raw key value.
>
> The plugin automatically sends it as the `X-API-Key` header.

4. Configure optional settings for additional API keys (see API Keys section below)
5. Click **Save**

### Step 4: Upload the Investigation Agent (Optional API Keys)

1. Same path: **Sources** -> **Manage plugins** -> **Custom** -> **Add plugin**
2. Upload file: `copilot/SpyCloud_Agent.yaml`
3. Configure the same 4 workspace settings as the KQL Plugin (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName)
4. Optionally configure API keys for enhanced capabilities (all are optional — the Agent works with just workspace settings)
5. Click **Save**

### Step 5: Validate Everything — Run Health Checks

**This is the most important step.** After uploading all 3 plugins, verify connectivity:

```
"Run a SpyCloud health check"                    <-- KQL Plugin: checks all 14 Sentinel tables
"Test my SpyCloud Enterprise API key"             <-- API Plugin: validates API authentication
"Run a full SpyCloud API health check"            <-- API Plugin: tests all 9 API endpoints
```

See the [Health Check & Testing section](#health-check-testing) for details.

---

<a name="api-keys-demystified"></a>
## API Keys & The "Value" Field — Demystified

### The #1 Source of Confusion

When you configure the API Plugin in Security Copilot, you see fields like:

```
API Key Authentication
  Value: [_______________]
```

**What goes in "Value"?** Your actual API key string. NOT the header name. NOT `X-API-Key`. Just the key itself.

### Visual Example

```
WRONG:  Value: [X-API-Key]           <-- This is the header NAME, not your key
WRONG:  Value: [X-API-Key: abc123]   <-- Don't include the header name
WRONG:  Value: [Bearer abc123]       <-- No Bearer prefix needed
RIGHT:  Value: [abc123def456ghi789]  <-- Just the raw key value
```

The plugin's YAML already defines `Key: X-API-Key` and `Location: Header`. When you enter your key in the Value field, Security Copilot automatically constructs the header: `X-API-Key: <your-value>`.

### Complete API Key Architecture

| API | Key Setting Name | Required? | Shares Key With | How to Get |
|-----|-----------------|-----------|----------------|-----------|
| **Enterprise Breach** | SpyCloudApiKey | YES (mandatory) | Compass, Identity Exposure | portal.spycloud.com > Account Settings > API Keys |
| **Compass Investigation** | SpyCloudApiKey | Same key | Enterprise | Same key (Enterprise+ tier required) |
| **Identity Exposure** | SpyCloudApiKey | Same key | Enterprise | Same key (auto-enabled) |
| **SIP (Session Cookies)** | SpyCloudApiKey | Same key* | — | Same key (SIP entitlement required) |
| **Investigations** | SpyCloudApiKey | Same key* | — | Same key (Investigations tier required) |
| **IDLINK** | IdLinkApiKey | OPTIONAL separate key | — | Contact SpyCloud for dedicated IDLINK key |
| **Data Partnership** | DataPartnershipApiKey | OPTIONAL separate key | — | Contact SpyCloud for dedicated key |
| **Exposure** | ExposureApiKey | OPTIONAL separate key | — | Contact SpyCloud for dedicated key |
| **CAP** | CAPApiKey | OPTIONAL separate key | — | Contact SpyCloud for dedicated key |
| **OpenAI** | OpenAIApiKey | OPTIONAL | — | platform.openai.com (NOT Azure OpenAI) |

*SIP and Investigations use the same SpyCloudApiKey but require specific entitlements in your SpyCloud subscription.

### What Each Setting Expects

For EVERY setting that asks for a key, enter ONLY the raw key value:

| Setting Name | What to Enter in "Value" | Example |
|-------------|------------------------|---------|
| SpyCloudApiKey | Your SpyCloud API key | `a1b2c3d4e5f6g7h8i9j0...` |
| IdLinkApiKey | Your IDLINK API key (or leave blank) | `x9y8z7w6v5u4t3s2r1q0...` |
| DataPartnershipApiKey | Your Data Partnership key (or leave blank) | Same format |
| ExposureApiKey | Your Exposure key (or leave blank) | Same format |
| CAPApiKey | Your CAP key (or leave blank) | Same format |
| OpenAIApiKey | Your OpenAI key (starts with `sk-`) | `sk-proj-abc123def456...` |

### If You Only Have One SpyCloud Key

**Most users only need ONE key.** If you have a standard SpyCloud Enterprise subscription:

1. Enter your single API key as `SpyCloudApiKey` (mandatory)
2. Leave all other key fields **blank** — the plugin falls back to the primary key
3. APIs you don't have entitlements for will return 401/403 — this is normal and expected

### Testing Your Key Before Uploading

From any terminal:
```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: YOUR_KEY_HERE" \
  "https://api.spycloud.io/enterprise-v2/breach/catalog?limit=1"
```

- `200` = Key is valid
- `401` = Invalid key
- `403` = Key valid but lacking entitlement for this endpoint

---

<a name="openai-clarification"></a>
## OpenAI API — What It Is and What It Isn't

### The Question Everyone Asks

> "Does this use Microsoft Azure OpenAI Service? Or regular OpenAI? Or is OpenAI built into Security Copilot?"

### The Clear Answer

**There are TWO separate AI systems at play:**

| System | What It Is | How It's Used | Do You Need a Key? |
|--------|-----------|--------------|-------------------|
| **Microsoft Security Copilot** | Microsoft's security AI product (powered by Azure OpenAI internally) | Processes your prompts, orchestrates plugins, interprets results | NO — it's part of your Security Copilot license |
| **OpenAI API (optional)** | OpenAI's direct API (platform.openai.com) | Powers 12 advanced AI analysis skills in the Investigation Agent | OPTIONAL — only if you want advanced AI features |

### What Security Copilot Provides (No Extra Key Needed)

Security Copilot already uses Azure OpenAI internally. When you:
- Ask the Agent a question -> Security Copilot's built-in AI understands your intent
- Get results back -> Security Copilot's built-in AI helps format and present them
- Have a conversation -> Security Copilot's built-in AI maintains context

**You do NOT need any OpenAI key for this.** It's built into Security Copilot.

### What the Optional OpenAI Key Adds (12 Extra Skills)

If you provide a standard OpenAI API key (`sk-...` from platform.openai.com), the Investigation Agent gains 12 advanced analysis skills:

- Executive report generation
- Board presentation materials
- Threat narrative construction
- Compliance assessments (GDPR, CCPA, HIPAA, PCI-DSS)
- Predictive exposure forecasting
- Attack simulation scenarios
- Risk heatmaps
- Professional incident narratives

### Important Distinctions

| | Microsoft Azure OpenAI Service | Standard OpenAI API |
|---|---|---|
| **Provider** | Microsoft (Azure) | OpenAI (directly) |
| **Portal** | portal.azure.com | platform.openai.com |
| **Key format** | Azure endpoint + key | `sk-...` key |
| **Used by SpyCloud Agent** | NO | YES (optional) |
| **Built into Security Copilot** | YES (internally) | NO |

**Bottom line:** Security Copilot gives you AI for free. The OpenAI key is an optional upgrade for 12 specialized analysis skills. If you don't want to pay for a separate OpenAI subscription, skip it — the Agent works fully without it.

---

<a name="health-check-testing"></a>
## Health Check & Testing — Validate Everything Works

### Why This Matters

After deploying the solution and uploading plugins, you MUST verify that:
1. Data is flowing into all expected Sentinel tables
2. API keys are valid and have the right entitlements
3. All 9 SpyCloud API endpoints are reachable
4. The plugins are responding correctly in Security Copilot

### Test 1: Sentinel Data Ingestion Health (KQL Plugin)

**Ask Security Copilot:**
```
"Check SpyCloud data ingestion health"
```

**What it does:** The `GetSpyCloudHealthStatus` skill queries ALL 14 SpyCloud custom tables and reports:
- Record count per table
- Latest ingestion timestamp
- Hours since last update
- Status: Healthy / Stale (48h+) / Empty/Not Deployed
- Required tier for each table

**Expected results for a basic Enterprise deployment:**

| Table | Expected Status |
|-------|----------------|
| 1. Breach Watchlist | Healthy (should have records) |
| 2. Breach Catalog | Healthy (should have records) |
| 3. Compass Data | Empty if not Enterprise+ tier |
| 4. Compass Devices | Empty if not Enterprise+ tier |
| 5. Compass Applications | Empty if not Enterprise+ tier |
| 6. SIP Cookies | Empty if no SIP entitlement |
| 7. Identity Exposure | Healthy (auto-enabled with Enterprise) |
| 8. Investigations | Empty if no Investigations tier |
| 9. IDLINK | Empty if no IDLINK key |
| 10. Data Partnership | Empty if no Data Partnership key |
| 11. Exposure | Empty if no Exposure key |
| 12. CAP | Empty if no CAP key |
| 13. MDE Remediation | Empty until playbook runs |
| 14. Conditional Access | Empty until playbook runs |

**Tables showing "Empty" for APIs you don't subscribe to is NORMAL.** Only flag tables that should have data but show "Stale" or "Empty."

### Test 2: API Key Validation (API Plugin)

**Ask Security Copilot:**
```
"Test my SpyCloud Enterprise API key"
```

**What it does:** The `HealthCheckEnterprise` skill calls the breach catalog with `limit=1` to verify:
- API key is valid (not expired, not malformed)
- Network path is open (no firewall blocking)
- Enterprise API endpoint is reachable

**Expected result:** A single breach catalog entry returned. If you get a 401/403, your key is invalid or expired.

### Test 3: SIP API Validation (API Plugin)

```
"Test my SpyCloud SIP API access"
```

**What it does:** The `HealthCheckSIP` skill calls the SIP breach catalog. If you get a 401/403, your key doesn't have SIP entitlement — this is expected if you don't subscribe to SIP.

### Test 4: Full API Health Check (API Plugin)

```
"Run a full SpyCloud API health check"
```

**What it does:** The `HealthCheckAllAPIs` skill tests connectivity across all 9 SpyCloud API endpoints and reports which ones your key(s) can access.

### Test 5: Agent Conversational Test

```
"What can you help me investigate?"
```

**Expected:** SENTINEL responds with its full capability menu including all 23 sub-agents.

```
"Show me an overview of our dark web exposure"
```

**Expected:** SENTINEL runs the overview workflow (multiple KQL queries) and presents a risk summary.

### Troubleshooting Health Check Results

| Symptom | Cause | Fix |
|---------|-------|-----|
| All 14 tables show "Empty" | CCF connector not deployed or API key wrong | Redeploy ARM template, verify apiKey parameter |
| Tables 1-2 have data, all others empty | Only base Enterprise deployment | Normal — enable optional APIs for more data |
| Healthy tables show "Stale (48h+)" | Connector polling stopped | Check DCR/DCE in Azure Portal, verify connector is running |
| API health check returns 401 | Invalid or expired API key | Regenerate key at portal.spycloud.com |
| API health check returns 403 | Key valid but missing entitlement | Contact SpyCloud to enable API access |
| API health check times out | Network/firewall issue | Ensure outbound HTTPS to api.spycloud.io is allowed |
| Agent doesn't respond | YAML upload failed | Re-upload SpyCloud_Agent.yaml, check for format errors |
| Agent works but no API data | API Plugin not uploaded or not configured | Upload SpyCloud_API_Plugin.yaml separately |

---

<a name="connector-ecosystem"></a>
## Connector Ecosystem & Recommendations

### What SENTINEL Can See (When Everything Is Connected)

```
                        +------------------------------+
                        |    SENTINEL Agent's Vision     |
                        +--------------+---------------+
                                       |
    +----------------------------------+----------------------------------+
    |                                  |                                  |
    v                                  v                                  v
+----------+                    +----------+                    +----------+
|DARK WEB  |                    |IDENTITY  |                    |ENDPOINT  |
|SpyCloud  |                    |Entra ID  |                    |Defender  |
|9 APIs    |                    |Sign-ins  |                    |for EP    |
|14 tables |                    |Audit     |                    |Process   |
|Breach    |                    |Risky     |                    |Network   |
|Compass   |                    |Users     |                    |File      |
|IDLINK    |                    |CA Eval   |                    |Alert     |
+----------+                    +----------+                    +----------+
    |                                  |                                  |
    |              +-------------------+-------------------+              |
    |              |                   |                   |              |
    v              v                   v                   v              v
+----------+ +----------+      +----------+      +----------+ +----------+
|EMAIL     | |CLOUD APP |      |MDM/DEVICE|      |IDENTITY  | |NETWORK   |
|Defender  | |CASB      |      |Intune    |      |ATTACKS   | |Firewall  |
|for O365  | |Defender  |      |Compliance|      |Defender  | |DNS       |
|Phishing  | |for Cloud |      |Enrollment|      |for ID    | |CEF/Syslog|
|Harvest   | |Apps      |      |Patching  | 	   |PtH, GT   | |TI Feeds  |
+----------+ +----------+      +----------+      +----------+ +----------+
```

### Connector Maturity Model

**Level 1 — Foundation (Start Here)**
- SpyCloud Data Connector (CCF)
- SpyCloud KQL Plugin
- Microsoft Entra ID connector

**Level 2 — Core Security**
- SpyCloud API Plugin
- SpyCloud Investigation Agent
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity

**Level 3 — Extended Detection**
- Microsoft Defender for Office 365
- Microsoft Defender for Cloud Apps
- Microsoft Intune
- UEBA enabled

**Level 4 — Full Ecosystem**
- DNS Analytics
- Firewall logs (CEF/Syslog)
- Threat Intelligence feeds
- Azure Activity logs
- Fusion enabled
- SpyCloud Compass (Enterprise+)
- IDLINK, Exposure, CAP, Data Partnership APIs

**Level 5 — Expert Mode**
- Custom watchlists populated
- All playbooks configured with permissions
- Automation rules enabled
- ServiceNow/Jira integration
- Teams/Slack notification channels
- Custom analytics rules tuned

---

<a name="custom-tables"></a>
## Your 14 Custom Tables

| # | Table Name | Source | Tier Required | Description |
|---|-----------|--------|--------------|-------------|
| 1 | `SpyCloudBreachWatchlist_CL` | Enterprise Breach API | Base | Primary table — credentials, PII, device forensics, passwords |
| 2 | `SpyCloudBreachCatalog_CL` | Enterprise Catalog API | Base | Breach metadata — title, category, record counts, malware family |
| 3 | `SpyCloudCompassData_CL` | Compass Investigation API | Enterprise+ | Deep infostealer records — cookies, browser data, crypto wallets |
| 4 | `SpyCloudCompassDevices_CL` | Compass Devices API | Enterprise+ | Infected device fingerprints — hostname, OS, IPs |
| 5 | `SpyCloudCompassApplications_CL` | Compass Applications API | Enterprise+ | Stolen application credentials per infected machine |
| 6 | `SpyCloudSipCookies_CL` | SIP API | SIP Entitlement | Stolen session cookies by domain |
| 7 | `SpyCloudIdentityExposure_CL` | Identity Exposure API | Base | Deduplicated identity risk posture per user |
| 8 | `SpyCloudInvestigations_CL` | Investigations API | Investigations Tier | Full database searches across all breach types |
| 9 | `SpyCloudIdLink_CL` | IDLINK API | Separate Key | Identity graphs — linked accounts, shared devices |
| 10 | `SpyCloudDataPartnership_CL` | Data Partnership API | Separate Key | Partner-contributed darknet intelligence |
| 11 | `SpyCloudExposure_CL` | Exposure API | Separate Key | Aggregated exposure risk assessments |
| 12 | `SpyCloudCAP_CL` | CAP API | Separate Key | Credential protection policies and actions |
| 13 | `Spycloud_MDE_Logs_CL` | Internal (Playbook) | Playbook | MDE remediation audit log |
| 14 | `SpyCloud_ConditionalAccessLogs_CL` | Internal (Playbook) | Playbook | CA remediation audit log |

---

<a name="use-cases-by-role"></a>
## Use Cases by Role

### Helpdesk / IT Support

**Your scenario:** A user calls in saying their account got compromised. You need to check fast.

**What to ask SENTINEL:**
```
"Check if john.doe@company.com has been exposed"
"Was this user's password reset after the exposure?"
"Is this user's device managed and compliant in Intune?"
```

### SOC Analyst (Tier 1-2)

**What to ask SENTINEL:**
```
"Show me an overview of our dark web exposure"
"Which users have the most critical credential exposures?"
"Build a complete attack timeline for this user"
"What Defender XDR alerts correlate with SpyCloud exposures?"
"If you were an attacker with our exposed data, what would you do?"
```

### SOC Manager / Team Lead

```
"What's our mean time to remediate credential exposures?"
"How many playbook executions succeeded vs failed this week?"
"Compare our exposure this month vs last month"
"Run a full SpyCloud API health check"
```

### CISO / Security Leadership

```
"Generate a compliance report for cyber insurance renewal"
"What would you present to the board right now?"
"Generate a board-level threat summary with recommendations"
"Predict our exposure trajectory — are things getting better or worse?"
```

### Security Engineer / Architect

```
"Run a SpyCloud health check"
"What data sources am I missing?"
"Test all SpyCloud API connections"
"Show me the connector health and ingestion status"
"Which SpyCloud APIs can I access with my current keys?"
```

---

<a name="optimization"></a>
## Optimization Tips & Best Practices

### Performance Optimization

1. **Enable UEBA** — Behavioral analytics dramatically improves the Agent's ability to detect post-compromise activity
2. **Enable Fusion** — ML-based multi-stage attack detection catches sophisticated attack chains
3. **Populate Watchlists** — VIP watchlist enables executive monitoring; IOC blocklist enables automated blocking
4. **Grant Playbook Permissions** — Each playbook needs specific Graph API and MDE permissions to function
5. **Tune Analytics Rules** — Adjust severity thresholds based on your risk tolerance

### Cost Optimization

- KQL Plugin queries consume **Log Analytics query credits** (minimal cost)
- API Plugin calls consume **SpyCloud API quota** (check your subscription limits)
- Agent orchestration uses **Security Copilot compute units** (SCUs)
- **Tip:** Use KQL Plugin for routine checks (cheaper), API Plugin for real-time incidents (targeted)

---

<a name="troubleshooting"></a>
## Troubleshooting Guide

### "The Plugin Won't Upload!"
**Likely cause:** YAML formatting error.
**Fix:** Ensure you're uploading the `.yaml` file directly, not the `manifest.json`. The manifest is for documentation only.

### "KQL Queries Return Empty Results"
**Likely cause:** Data connector not configured or API key invalid.
**Fix:** Run the health check: ask Copilot "Check SpyCloud data ingestion health." If tables are empty, verify the CCF connector deployment.

### "API Plugin Returns 401 Unauthorized"
**Likely cause:** API key not configured correctly in the "Value" field, or key is expired.
**Fix:** Verify you entered the raw API key value (not `X-API-Key`, not a URL). Test with: `curl -H "X-API-Key: YOUR_KEY" https://api.spycloud.io/enterprise-v2/breach/catalog?limit=1`

### "API Plugin Returns 403 Forbidden"
**Likely cause:** Your API key is valid but doesn't have entitlement for that specific API.
**Fix:** This is expected for APIs you don't subscribe to (e.g., Compass, SIP, IDLINK). Contact SpyCloud to enable additional API access.

### "Agent Works But Has No API Data"
**Likely cause:** The API Plugin is not uploaded or the Agent's optional SpyCloudApiKey setting is empty.
**Fix:** The Agent uses KQL skills by default. For API-backed skills, either: (a) upload the API Plugin separately, or (b) add your SpyCloudApiKey to the Agent's optional settings.

### "Compass Data Is Empty"
**Likely cause:** You're on SpyCloud Enterprise (standard), not Enterprise+.
**Fix:** Expected behavior. Compass requires Enterprise+ subscription. Contact SpyCloud for upgrade.

### "Playbooks Aren't Running"
**Likely cause:** Missing managed identity permissions.
**Fix:** Run `scripts/post-deploy-auto.sh` or manually grant the required Graph API permissions.

### "OpenAI Skills Don't Work"
**Likely cause:** OpenAI API key not provided or invalid.
**Fix:** The OpenAI key must be from platform.openai.com (starts with `sk-`). Azure OpenAI keys do NOT work. This is optional — Agent works without it.

### "I'm Confused About Which API Key Goes Where"
**Fix:** You only NEED one key: your SpyCloud Enterprise API key. Enter it as `SpyCloudApiKey` everywhere. All other key fields are optional and for specialized API access. Run "Test my SpyCloud Enterprise API key" to validate.

---

<a name="admin-checklist"></a>
## Admin Recommendations Checklist

### Immediate (Week 1)
- [ ] Deploy SpyCloud Sentinel solution via ARM template
- [ ] Configure SpyCloud API key in data connector
- [ ] Upload all 3 Copilot plugins (KQL, API, Agent) as separate YAML files
- [ ] Run health check: "Check SpyCloud data ingestion health"
- [ ] Run API validation: "Run a full SpyCloud API health check"
- [ ] Enable Microsoft Entra ID connector (sign-in + audit logs)
- [ ] Enable Microsoft Defender for Endpoint connector

### Short-term (Week 2-3)
- [ ] Enable Microsoft Defender for Identity connector
- [ ] Enable Microsoft Defender for Office 365 connector
- [ ] Enable Microsoft Defender for Cloud Apps connector
- [ ] Enable UEBA in Sentinel settings
- [ ] Enable Fusion rule in analytics rules
- [ ] Populate VIP watchlist with executive email addresses
- [ ] Test each playbook manually to verify permissions

### Medium-term (Month 1-2)
- [ ] Enable Microsoft Intune connector
- [ ] Configure firewall log ingestion (CEF/Syslog)
- [ ] Enable DNS analytics
- [ ] Configure Threat Intelligence connector
- [ ] Set up Teams notification channel for SOC alerts
- [ ] Tune analytics rule thresholds based on alert volume

### Ongoing
- [ ] Monthly: Run health checks to verify all data flows
- [ ] Monthly: Review analytics rule false positive rates
- [ ] Monthly: Update VIP and IOC watchlists
- [ ] Quarterly: Review SpyCloud API usage and subscription tier
- [ ] Quarterly: Run SENTINEL's connector recommendation assessment
- [ ] Annually: Review and optimize playbook workflows

---

<div align="center">

## Ready to Get Started?

Upload the three YAML plugins, run the health checks, and let the dark web intelligence flow.

**Remember:** Every compromised credential you catch is an attack you prevented.

---

**Built by the SpyCloud Sentinel team**

*v9.0.0 — 250+ skills, 23 sub-agents, 14 tables, 9 APIs*

</div>
