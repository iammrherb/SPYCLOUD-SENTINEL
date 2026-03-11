<div align="center">

<img src="images/SpyCloud-Logo-white.png" alt="SpyCloud" width="300" style="background:#0D1B2A;padding:20px;border-radius:10px"/>

# The Ultimate Guide to SpyCloud Agents & Plugins
### *A No-BS, All-Levels Walkthrough for Security Teams*

**From Helpdesk Hero to CISO Sensei — This Guide Has You Covered**

![Version](https://img.shields.io/badge/version-8.0.0-00C7B7?style=flat-square&logo=semver&logoColor=white)
![Copilot](https://img.shields.io/badge/Security_Copilot-Enabled-6366F1?style=flat-square&logo=githubcopilot&logoColor=white)

</div>

---

## 📖 Table of Contents

1. [TL;DR — What Are We Dealing With?](#tldr)
2. [Agents vs. Plugins — The Eternal Question](#agents-vs-plugins)
3. [The Three Amigos: Your Plugin Lineup](#the-three-amigos)
4. [How They Work Together](#how-they-work-together)
5. [Setup Guide: Step-by-Step](#setup-guide)
6. [Connector Ecosystem & Recommendations](#connector-ecosystem)
7. [OpenAI API, Kusto & Other Superpowers](#openai-kusto-superpowers)
8. [Use Cases by Role](#use-cases-by-role)
9. [Optimization Tips & Best Practices](#optimization)
10. [Missing Connectors? SENTINEL Will Tell You](#missing-connectors)
11. [Admin Recommendations Checklist](#admin-checklist)
12. [Troubleshooting with Style](#troubleshooting)
13. [Fun Stuff & Easter Eggs](#fun-stuff)

---

<a name="tldr"></a>
## 🎯 TL;DR — What Are We Dealing With?

**SpyCloud Sentinel** is a complete dark web intelligence platform that lives inside Microsoft Sentinel and Security Copilot. It has **three plugin types** that work together like a well-oiled security operations machine:

| Component | Type | What It Does | Think of It As... |
|-----------|------|-------------|-------------------|
| **SpyCloud Investigation Agent** | 🤖 Agent | Interactive conversational analyst that orchestrates 17 sub-agents | Your senior SOC analyst who never sleeps, never complains, and has read every darknet forum |
| **SpyCloud KQL Plugin** | 🔌 Plugin (KQL) | 86+ skills running Kusto queries against Sentinel tables | The SQL wizard who memorized every table schema so you don't have to |
| **SpyCloud API Plugin** | 🔌 Plugin (API) | 12 skills calling SpyCloud REST APIs in real-time | The direct phone line to SpyCloud's 600B+ record darknet database |

**Together they give you:** 100+ skills, 17 sub-agents, coverage across 11 Microsoft security products, and the ability to investigate any identity, device, or credential exposure from dark web to endpoint. Not bad for a YAML file, right?

---

<a name="agents-vs-plugins"></a>
## 🤖 vs 🔌 Agents vs. Plugins — The Eternal Question

### What IS a Plugin?

A **Plugin** is a collection of **skills** — discrete, well-defined operations that Security Copilot can call. Think of each skill as a single tool in a toolbox:

- 🔧 "Look up this email in SpyCloud" (one skill)
- 🔧 "Show me password types across all exposures" (one skill)
- 🔧 "Get breach catalog details for RedLine" (one skill)

**Plugins are reactive.** You ask, they answer. One question, one answer. They don't have memory, personality, or the ability to chain actions together on their own.

#### Two Flavors of Plugins:

| Plugin Type | Data Source | Speed | Use Case |
|------------|------------|-------|----------|
| **KQL Plugin** | Queries data already in your Sentinel workspace | ⚡ Fast (data is local) | Historical analysis, trending, correlation with other Sentinel data |
| **API Plugin** | Calls SpyCloud REST API in real-time | 🌐 Real-time (hits SpyCloud servers) | Latest data, records not yet ingested, Compass deep investigations |

### What IS an Agent?

An **Agent** is a **conversational AI personality** that can:

- 🧠 **Remember context** across a conversation ("you asked about user X earlier — let me connect that to this new finding")
- 🔗 **Chain multiple skills** together ("let me check the user, then their device, then the malware, then the remediation status")
- 💡 **Make recommendations** ("Based on what I found, here's what I'd do...")
- 🎭 **Adapt its communication style** (brief for quick checks, thorough for deep dives)
- 🤔 **Interpret vague requests** ("show me stuff" → runs an org-wide exposure assessment)
- 🔄 **Orchestrate sub-agents** for specialized investigations

**Agents are proactive.** They don't just answer — they investigate, correlate, and advise.

### The Car Analogy 🚗

- **Plugin** = Individual car parts (engine, transmission, brakes)
- **Agent** = The fully assembled car with a GPS, a skilled driver, and a snarky co-pilot who knows every shortcut

You *can* use parts individually. But the car is a lot more fun.

### How They Relate

```
┌─────────────────────────────────────────────────┐
│              SECURITY COPILOT                     │
│                                                   │
│  ┌──────────────────────────────────────────┐    │
│  │     SpyCloud Investigation Agent 🤖       │    │
│  │                                            │    │
│  │  "Hey, investigate user@company.com"       │    │
│  │         │                                  │    │
│  │    ┌────┴────────────────────────┐         │    │
│  │    │  Orchestrates & Chains:     │         │    │
│  │    │                             │         │    │
│  │    │  ┌───────────┐  ┌────────┐  │         │    │
│  │    │  │KQL Plugin │  │API     │  │         │    │
│  │    │  │(86 skills)│  │Plugin  │  │         │    │
│  │    │  │           │  │(12     │  │         │    │
│  │    │  │ Sentinel  │  │skills) │  │         │    │
│  │    │  │ Data      │  │ Real-  │  │         │    │
│  │    │  │           │  │ time   │  │         │    │
│  │    │  └───────────┘  └────────┘  │         │    │
│  │    └─────────────────────────────┘         │    │
│  │                                            │    │
│  │  Returns: Rich narrative + data tables +    │    │
│  │  risk assessment + next steps + follow-ups  │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

---

<a name="the-three-amigos"></a>
## 🎬 The Three Amigos: Your Plugin Lineup

### 1. SpyCloud KQL Plugin (`SpyCloud_Plugin.yaml`)

**What it does:** Runs pre-built Kusto (KQL) queries against your Sentinel Log Analytics workspace.

**Why you need it:** Your SpyCloud data connector ingests data into 10 custom tables (233+ columns). This plugin has 90 hand-tuned KQL queries across 29 categories that extract exactly the right insights from those tables.

**Skill Categories:**

| Category | Skills | What You Get |
|----------|--------|-------------|
| User Investigation | 3 | Full user exposure, PII profile, account activity |
| Password Analysis | 4 | Exposed passwords, plaintext hunt, type breakdown, reuse detection |
| Severity & Exposure | 4 | By severity, domain, target sites, risk distribution |
| Sensitive PII | 2 | SSN/financial/health data, social media exposure |
| Device Forensics | 5 | Infected devices, forensics, user correlation, AV gaps, geo |
| Breach Catalog | 3 | Malware lookup, recent breaches, enriched exposures |
| Compass (Enterprise+) | 4 | Deep investigation, device fingerprints, applications, consumer exposure |
| UEBA & Behavior | 4 | Anomaly correlation, risk scoring, insider threat |
| Fusion & Multistage | 3 | ML-detected attack chains, multistage campaigns |
| Remediation Audit | 6 | MDE actions, CA changes, playbook health, SLA tracking |
| Threat Hunting | 8 | Session cookies, lateral movement, data exfil, supply chain |
| Cross-Connector | 10 | Entra/O365/Firewall/DNS/TI correlation |
| Risk Scoring | 4 | User risk, device risk, domain risk, trending |
| Executive Reporting | 4 | Dashboards, compliance, board summaries |
| Watchlist Ops | 3 | VIP monitoring, IOC management, approved domains |
| Data Health | 3 | Connector status, table stats, ingestion monitoring |

**When to use the KQL Plugin directly (without the Agent):**
- Quick single-question lookups
- Promptbook/automation chains
- When you want raw data without interpretation
- Building custom Security Copilot workflows

### 2. SpyCloud API Plugin (`SpyCloud_API_Plugin.yaml`)

**What it does:** Calls the SpyCloud REST API directly for real-time intelligence.

**Why you need it:** Sometimes you need data that hasn't been ingested yet, or you want to query SpyCloud's full 600B+ record database beyond what's in your Sentinel workspace.

**Skills:**

| Skill | API Endpoint | Use Case |
|-------|-------------|----------|
| GetBreachDataByEmail | Enterprise | "Is this email compromised RIGHT NOW?" |
| GetBreachDataByDomain | Enterprise | "Show me all breaches for contoso.com" |
| GetBreachDataByIp | Enterprise | "What's associated with this suspicious IP?" |
| CheckPasswordExposure | Enterprise | "Has this password been seen in breaches?" |
| GetBreachDataByUsername | Enterprise | "Look up this username across breaches" |
| GetBreachCatalog | Enterprise | "What breaches exist in SpyCloud's database?" |
| GetCompassDataByEmail | Compass | "Deep infostealer forensics for this email" |
| GetCompassDataByDomain | Compass | "Organization-wide Compass investigation" |
| GetCompassDataByIp | Compass | "Compass investigation by IP address" |
| GetIdentityExposures | Identity | "Identity exposure profile for this email" |
| GetWatchlistStatus | Identity | "What's on my monitored watchlist?" |

**Requires:** SpyCloud API key (configured in plugin settings)

**When to use the API Plugin directly:**
- Real-time lookups for incidents in progress
- Data not yet in Sentinel (freshly recaptured)
- Compass deep dives (Enterprise+ subscription)
- Password exposure validation
- Ad-hoc investigations outside your monitored domains

### 3. SpyCloud Investigation Agent (`SpyCloud_Agent.yaml`)

**What it does:** An interactive, conversational AI analyst named **SENTINEL** that orchestrates 17 specialized sub-agents.

**Why you need it:** Because typing KQL queries is so 2023. Ask SENTINEL anything in plain English (typos welcome) and it will figure out what you need, run the right queries, chain results together, and give you an analyst-grade report with recommendations.

**Sub-Agents:**

| Sub-Agent | Specialization |
|-----------|---------------|
| CoreInvestigationAgent | User credential & exposure analysis |
| PasswordAnalysisAgent | Credential types, reuse, crackability |
| DeviceForensicsAgent | Infected device investigation |
| BreachCatalogAgent | Malware family & breach source intel |
| PII_ComplianceAgent | Sensitive data & notification requirements |
| RemediationAuditAgent | Playbook execution & gap analysis |
| ThreatHuntingAgent | Proactive hunting across all data |
| UEBACorrelationAgent | Behavioral anomaly correlation |
| FusionMultistageAgent | ML-detected multi-stage attacks |
| RiskScoringAgent | Quantified risk assessment |
| ExecutiveReportingAgent | Board-level summaries & metrics |
| WatchlistManagementAgent | VIP/IOC/asset watchlist ops |
| DefenderXDREndpointAgent | Defender for Endpoint & XDR |
| IntuneDeviceComplianceAgent | Intune MDM & compliance |
| CASBCloudAppSecurityAgent | Cloud app security & shadow IT |
| CompassDeepInvestigationAgent | Deep infostealer forensics |
| CrossPlatformCorrelationAgent | Full-stack security narrative |

**Personality:** Confident, witty, thorough, empathetic. Handles typos gracefully. Never says "try again" — always provides value. Adds "Analyst's Take" interpretations. Uses severity emojis (🔴🟠🟡🟢). Ends every response with follow-up suggestions.

---

<a name="how-they-work-together"></a>
## 🤝 How They Work Together

Here's the magic: **you don't have to choose.** Upload all three and they complement each other:

```
User: "Investigate suspicious.user@company.com"
                    │
                    ▼
         ┌─────────────────────┐
         │  SENTINEL Agent     │  ← Understands intent
         │  "Got it — full     │
         │  investigation      │
         │  coming up!"        │
         └────────┬────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌─────────┐  ┌─────────┐  ┌─────────┐
│KQL Plugin│  │KQL Plugin│  │API Plugin│
│GetUser   │  │GetExposed│  │GetBreach │
│Exposures │  │Passwords │  │DataBy    │
│(Sentinel)│  │(Sentinel)│  │Email     │
│          │  │          │  │(Real-time│
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   ▼
         ┌─────────────────────┐
         │  SENTINEL Agent     │  ← Correlates & interprets
         │  combines all       │
         │  results into a     │
         │  rich narrative     │
         │  with risk rating,  │
         │  MITRE mapping,     │
         │  and next steps     │
         └─────────────────────┘
```

### The Workflow in Practice

1. **User asks a question** → Agent interprets intent
2. **Agent selects sub-agent(s)** → Routes to specialists
3. **Sub-agents invoke KQL and/or API skills** → Gets raw data
4. **Agent correlates results** → Connects the dots across sources
5. **Agent presents findings** → Rich narrative with tables, severity indicators, MITRE mapping
6. **Agent suggests next steps** → "Want me to check Defender XDR? Intune compliance? Build an attack timeline?"
7. **User follows up** → Agent remembers context and goes deeper

---

<a name="setup-guide"></a>
## 🛠️ Setup Guide: Step-by-Step

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

This deploys: Custom tables, data connector, analytics rules, playbooks, workbooks, watchlists, and automation rules.

### Step 2: Upload the KQL Plugin

1. Open **Microsoft Security Copilot** → **Settings** → **Plugins**
2. Click **Add Plugin** → **Custom Plugin** → **Upload File**
3. Upload `copilot/SpyCloud_Plugin.yaml`
4. Configure settings:
   - **TenantId**: Your Azure AD tenant ID
   - **SubscriptionId**: The subscription hosting Sentinel
   - **ResourceGroupName**: The resource group name
   - **WorkspaceName**: Your Log Analytics workspace name
5. Click **Save**

> 💡 **Pro Tip:** These four settings are the same across all three plugins. Copy-paste once, use everywhere.

### Step 3: Upload the API Plugin

1. Same path: **Settings** → **Plugins** → **Add Plugin** → **Upload File**
2. Upload `copilot/SpyCloud_API_Plugin.yaml`
3. Configure settings:
   - **API Key**: Your SpyCloud API key (get from SpyCloud portal)
   - **ApiBaseUrl**: Leave default (`https://api.spycloud.io`) unless directed otherwise
4. Click **Save**

> ⚠️ **Note:** The API Plugin requires a valid SpyCloud API key. Without it, API skills will return 401 errors. The KQL Plugin works without an API key since it queries local Sentinel data.

### Step 4: Upload the Investigation Agent

1. Same path: **Settings** → **Plugins** → **Add Plugin** → **Upload File**
2. Upload `copilot/SpyCloud_Agent.yaml`
3. Configure settings (same four as the KQL Plugin):
   - **TenantId**, **SubscriptionId**, **ResourceGroupName**, **WorkspaceName**
   - **SpyCloudApiKey** (optional — only needed if you want the agent to invoke API Plugin skills)
4. Click **Save**

### Step 5: Verify Everything Works

Open a new Copilot session and try:

```
"What can you help me investigate?"
```

SENTINEL should respond with its full capability menu. If it does — you're golden. 🎉

### Step 6: Enable Recommended Data Connectors

For maximum correlation power, enable these additional Sentinel data connectors:

| Connector | Why | Priority |
|-----------|-----|----------|
| **Microsoft Entra ID** | Sign-in logs, risky users, audit trail | 🔴 Critical |
| **Microsoft Defender for Endpoint** | Device telemetry, process/network/file events | 🔴 Critical |
| **Microsoft Defender for Identity** | AD attack detection (PtH, Golden Ticket) | 🟠 High |
| **Microsoft Defender for Office 365** | Email phishing & credential harvesting | 🟠 High |
| **Microsoft Defender for Cloud Apps** | Shadow IT, OAuth risk, DLP | 🟠 High |
| **Microsoft Intune** | Device compliance, enrollment, patch status | 🟡 Medium |
| **Azure Activity** | Resource management audit trail | 🟡 Medium |
| **Threat Intelligence** | TAXII feeds, MDTI, custom TI | 🟡 Medium |
| **DNS Analytics** | C2 beaconing detection | 🟡 Medium |
| **Common Event Format (CEF)** | Firewall logs (Fortinet, Palo Alto) | 🟡 Medium |

> 🧠 **SENTINEL will tell you what's missing.** Ask: *"What data sources am I missing?"* and it will analyze your environment and recommend connectors to enable.

---

<a name="connector-ecosystem"></a>
## 🔌 Connector Ecosystem & Recommendations

### What SENTINEL Can See (When Everything Is Connected)

```
                        ┌──────────────────────────────┐
                        │    SENTINEL Agent's Vision     │
                        └──────────────┬───────────────┘
                                       │
    ┌──────────────────────────────────┼──────────────────────────────────┐
    │                                  │                                  │
    ▼                                  ▼                                  ▼
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│DARK WEB  │                    │IDENTITY  │                    │ENDPOINT  │
│SpyCloud  │                    │Entra ID  │                    │Defender  │
│Breach    │                    │Sign-ins  │                    │for EP    │
│Records   │                    │Audit     │                    │Process   │
│Compass   │                    │Risky     │                    │Network   │
│Infosteal │                    │Users     │                    │File      │
│er Data   │                    │CA Eval   │                    │Alert     │
└──────────┘                    └──────────┘                    └──────────┘
    │                                  │                                  │
    │              ┌───────────────────┼───────────────────┐              │
    │              │                   │                   │              │
    ▼              ▼                   ▼                   ▼              ▼
┌──────────┐ ┌──────────┐      ┌──────────┐      ┌──────────┐ ┌──────────┐
│EMAIL     │ │CLOUD APP │      │MDM/DEVICE│      │IDENTITY  │ │NETWORK   │
│Defender  │ │CASB      │      │Intune    │      │ATTACKS   │ │Firewall  │
│for O365  │ │Defender  │      │Compliance│      │Defender  │ │DNS       │
│Phishing  │ │for Cloud │      │Enrollment│      │for ID    │ │CEF/Syslog│
│Harvest   │ │Apps      │      │Patching  │      │PtH, GT   │ │TI Feeds  │
└──────────┘ └──────────┘      └──────────┘      └──────────┘ └──────────┘
```

### Connector Maturity Model

**Level 1 — Foundation (Start Here)**
- ✅ SpyCloud Data Connector (CCF)
- ✅ SpyCloud KQL Plugin
- ✅ Microsoft Entra ID connector

**Level 2 — Core Security**
- ✅ SpyCloud API Plugin
- ✅ SpyCloud Investigation Agent
- ✅ Microsoft Defender for Endpoint
- ✅ Microsoft Defender for Identity

**Level 3 — Extended Detection**
- ✅ Microsoft Defender for Office 365
- ✅ Microsoft Defender for Cloud Apps
- ✅ Microsoft Intune
- ✅ UEBA enabled

**Level 4 — Full Ecosystem**
- ✅ DNS Analytics
- ✅ Firewall logs (CEF/Syslog)
- ✅ Threat Intelligence feeds
- ✅ Azure Activity logs
- ✅ Fusion enabled
- ✅ SpyCloud Compass (Enterprise+)

**Level 5 — Expert Mode (You're Basically a SOC Superhero)**
- ✅ Custom watchlists populated
- ✅ All 10 playbooks configured with permissions
- ✅ Automation rules enabled
- ✅ ServiceNow / Jira integration
- ✅ Teams / Slack notification channels
- ✅ Custom analytics rules tuned

---

<a name="openai-kusto-superpowers"></a>
## ⚡ OpenAI API, Kusto & Other Superpowers

### Kusto (KQL) — The Query Engine

**What it is:** Kusto Query Language (KQL) is the query language for Azure Data Explorer and Log Analytics. It's what makes Sentinel tick.

**How SpyCloud uses it:** The KQL Plugin has 90 pre-built queries covering every investigation scenario. You never need to write KQL — but if you want to, here's what's available:

**Your 10 Custom Tables:**

| Table | Columns | Purpose |
|-------|---------|---------|
| `SpyCloudBreachWatchlist_CL` | 73 | The motherload — credentials, PII, device forensics, passwords |
| `SpyCloudBreachCatalog_CL` | 13 | Breach metadata — what breach, when, how many records |
| `SpyCloudCompassData_CL` | 29 | Deep infostealer artifacts (Enterprise+ only) |
| `SpyCloudCompassDevices_CL` | 8 | Infected device fingerprints (Enterprise+ only) |
| `Spycloud_MDE_Logs_CL` | 19 | MDE isolation & remediation audit trail |
| `SpyCloud_ConditionalAccessLogs_CL` | 14 | Password reset & CA remediation audit |

**KQL Pro Tips:**
- `| top 25 by TimeGenerated desc` — Always get the freshest data first
- `| summarize count() by severity` — Quick severity breakdown
- `| where severity >= 20` — Filter to infostealers only (the scary stuff)
- `| where isnotempty(password_plaintext)` — Find the REALLY scary stuff
- `| mv-expand av_softwares` — Expand array fields for analysis

### OpenAI API Integration

**How it relates:** Microsoft Security Copilot is powered by OpenAI GPT-4 models under the hood. When you interact with the SpyCloud Agent, here's the chain:

```
You → Security Copilot (GPT-4) → SpyCloud Agent Instructions → KQL/API Skills → Results → GPT-4 Interpretation → You
```

**Optimization Tips for Better AI Responses:**
- Be specific: "Show me severity 25 exposures from the last 7 days" > "show me stuff"
- Use follow-ups: The Agent remembers context — build on previous answers
- Ask for analysis: "What does this mean?" after seeing raw data
- Request formats: "Show me this as a table" or "Give me a MITRE ATT&CK mapping"

### Additional Tool Integrations

| Tool | Integration Point | What It Adds |
|------|------------------|-------------|
| **VirusTotal** | TI Enrichment Playbook | File hash & URL reputation for infostealer malware |
| **AbuseIPDB** | TI Enrichment Playbook | IP reputation for C2 servers and infected device IPs |
| **Shodan** | Manual enrichment | Internet-facing device exposure for infected endpoints |
| **ServiceNow** | Playbook integration | Automated incident ticket creation |
| **Jira** | Playbook integration | Security task tracking and assignment |
| **Microsoft Teams** | SOC Notification Playbook | Adaptive Card alerts to security channels |
| **Slack** | Webhook integration | Alternative notification channel |
| **PagerDuty** | Webhook integration | On-call escalation for critical findings |
| **Fortinet FortiGate** | Firewall Playbook | Automated IP blocking at network edge |
| **Palo Alto Networks** | Firewall Playbook | Automated IP blocking at network edge |

### Want More Integrations? Here's What SENTINEL Recommends:

Ask SENTINEL: *"What other tools or connectors should I enable?"* and it will analyze your current setup and recommend additions based on gaps it detects.

**Top Recommendations:**

| Integration | Why | Effort |
|------------|-----|--------|
| **Have I Been Pwned API** | Cross-reference with SpyCloud for validation | Low |
| **CrowdStrike Falcon** | Additional endpoint telemetry if not pure Microsoft | Medium |
| **Okta / Ping Identity** | If you use non-Microsoft IdP | Medium |
| **Splunk SOAR** | If you're a Splunk shop wanting SpyCloud integration | High |
| **MISP** | Open-source threat intel sharing | Medium |
| **TheHive / Cortex** | Open-source SOAR alternative | Medium |
| **Recorded Future** | Additional dark web intelligence correlation | Medium |

---

<a name="use-cases-by-role"></a>
## 👥 Use Cases by Role

### 🔰 Helpdesk / IT Support

**Your scenario:** A user calls in saying their account got compromised. You need to check fast.

**What to ask SENTINEL:**
```
"Check if john.doe@company.com has been exposed"
"Was this user's password reset after the exposure?"
"Is this user's device managed and compliant in Intune?"
```

**What you get:** A clear yes/no with context, remediation status, and whether you need to escalate.

*Fun fact: SENTINEL handles your typos. Type "chek credentails for jon.doe@comany.com" and it'll figure it out. We've all been there.*

### 🛡️ SOC Analyst (Tier 1-2)

**Your scenarios:** Daily triage, incident investigation, threat hunting.

**What to ask SENTINEL:**
```
"Show me an overview of our dark web exposure"
"Which users have the most critical credential exposures?"
"Are any devices infected with infostealer malware?"
"Build a complete attack timeline for this user"
"What Defender XDR alerts correlate with SpyCloud exposures?"
```

**Power moves:**
```
"If you were an attacker with our exposed data, what would you do?"
"What's the single most dangerous finding right now?"
"Help me create a ServiceNow ticket for this finding"
```

### 🏢 SOC Manager / Team Lead

**Your scenarios:** Operational metrics, team workload, trend analysis.

**What to ask SENTINEL:**
```
"What's our mean time to remediate credential exposures?"
"How many playbook executions succeeded vs failed this week?"
"Compare our exposure this month vs last month"
"Show me remediation SLA compliance"
"What are the top 5 things to act on right now?"
```

### 🔒 CISO / Security Leadership

**Your scenarios:** Board reporting, risk posture, compliance, strategic decisions.

**What to ask SENTINEL:**
```
"Generate a compliance report for cyber insurance renewal"
"What would you present to the board right now?"
"Generate a board-level threat summary with recommendations"
"Show me exposure metrics formatted for SOC2 audit evidence"
"What PII exposures require GDPR/CCPA notification?"
"Predict our exposure trajectory — are things getting better or worse?"
```

### 📋 GRC / Compliance

**Your scenarios:** Audit evidence, breach notification assessment, framework compliance.

**What to ask SENTINEL:**
```
"Show me all SSN and financial data exposures"
"What exposures require breach notification under GDPR?"
"Show me SOC2 audit evidence for our credential exposure response"
"Map our findings to NIST CSF"
"How do our SpyCloud findings map to MITRE ATT&CK?"
```

### 🔧 Security Engineer / Architect

**Your scenarios:** Optimizing detection, tuning rules, building automations.

**What to ask SENTINEL:**
```
"What data sources am I missing?"
"Which analytics rules fired the most this week?"
"Show me the connector health and ingestion status"
"What antivirus products failed to prevent infections?"
"Design an incident response SOP for credential exposures"
"What security controls would you prioritize based on our data?"
```

---

<a name="optimization"></a>
## ⚡ Optimization Tips & Best Practices

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

### Accuracy Optimization

- **More connectors = better correlation.** SENTINEL can only connect dots it can see
- **Fresh data matters.** Configure the SpyCloud connector polling interval appropriately (hourly recommended)
- **Watchlist hygiene.** Keep VIP and IOC watchlists current for accurate alerting
- **Rule tuning.** Review analytics rule false positive rates monthly

---

<a name="missing-connectors"></a>
## 🔍 Missing Connectors? SENTINEL Will Tell You

One of SENTINEL's superpowers is **self-awareness about its own limitations.** Ask it:

```
"What data sources am I missing?"
"What connectors should I enable for better coverage?"
"What can't you see right now?"
"Are there blind spots in our detection?"
```

SENTINEL will:
1. Check which Sentinel tables have data vs. are empty
2. Identify which Microsoft connectors are not sending data
3. Recommend specific connectors to enable based on your security gaps
4. Suggest third-party integrations that would improve correlation
5. Prioritize recommendations by impact and effort

**It literally tells your admin what to buy/enable.** Forward the output to your admin or IT leadership. You're welcome.

---

<a name="admin-checklist"></a>
## ✅ Admin Recommendations Checklist

Send this to your Azure/Security admin:

### Immediate (Week 1)
- [ ] Deploy SpyCloud Sentinel solution via ARM template
- [ ] Configure SpyCloud API key in data connector
- [ ] Upload all 3 Copilot plugins (KQL, API, Agent)
- [ ] Enable Microsoft Entra ID connector (sign-in + audit logs)
- [ ] Enable Microsoft Defender for Endpoint connector
- [ ] Run `post-deploy-auto.sh` for permission configuration
- [ ] Verify data ingestion with: `SpyCloudBreachWatchlist_CL | count`

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
- [ ] Configure ServiceNow/Jira integration (if applicable)
- [ ] Tune analytics rule thresholds based on alert volume
- [ ] Review and optimize automation rules

### Ongoing
- [ ] Monthly: Review analytics rule false positive rates
- [ ] Monthly: Update VIP and IOC watchlists
- [ ] Quarterly: Review SpyCloud API usage and subscription tier
- [ ] Quarterly: Run SENTINEL's connector recommendation assessment
- [ ] Annually: Review and optimize playbook workflows

---

<a name="troubleshooting"></a>
## 🔧 Troubleshooting with Style

### "The Plugin Won't Upload!"
**Likely cause:** YAML formatting error.
**Fix:** Ensure you're uploading the `.yaml` file directly, not the `manifest.json`. The manifest is for OpenAI-compatible hosts only.

### "KQL Queries Return Empty Results"
**Likely cause:** Data connector not configured or API key invalid.
**Fix:** Run `SpyCloudBreachWatchlist_CL | count` in Log Analytics. If zero, check the SpyCloud data connector status.

### "API Plugin Returns 401 Unauthorized"
**Likely cause:** SpyCloud API key not configured or expired.
**Fix:** Verify API key in plugin settings. Test with `curl -H "X-API-Key: YOUR_KEY" https://api.spycloud.io/breach/data/emails/test@test.com`

### "Compass Data Is Empty"
**Likely cause:** You're on SpyCloud Enterprise (standard), not Enterprise+.
**Fix:** This is expected! Compass requires Enterprise+ subscription. Contact SpyCloud for upgrade.

### "Playbooks Aren't Running"
**Likely cause:** Missing managed identity permissions.
**Fix:** Run `scripts/post-deploy-auto.sh` or manually grant the required Graph API permissions listed in the Azure SP setup guide.

### "SENTINEL Says Something Weird"
**Likely cause:** You found an edge case!
**Fix:** Try rephrasing or provide more context. If it persists, report it — we actually want to know.

---

<a name="fun-stuff"></a>
## 🎉 Fun Stuff & Easter Eggs

### Things You Can Ask SENTINEL

- *"What are all the things you can help me with? Give me the full menu"* — Gets the complete capability overview
- *"If our CEO's credentials were exposed, walk me through the response"* — Gets a full IR walkthrough
- *"Tell me the story of the most interesting breach affecting us"* — Gets a narrative-style investigation
- *"What would a SOC maturity assessment say about our SpyCloud response?"* — Gets an honest self-assessment
- *"What questions should I be asking that I'm not thinking of?"* — Gets proactive recommendations

### SENTINEL's Personality

SENTINEL is designed to:
- Match your energy (brief question → brief answer, deep dive → full treatment)
- Never make you feel dumb for asking anything
- Celebrate wins ("That user was already remediated! 💪")
- Be brutally honest when things are bad ("47 users with plaintext passwords. We need to act NOW.")
- Handle typos gracefully (we know you're busy)
- Make security fun (or at least less painful)

### Password Puns SENTINEL Might Drop

> "Ah, `password123` — the gift that keeps on giving. To attackers."
>
> "Good news: this user changed their password. Bad news: they changed it from 'Summer2024!' to 'Winter2025!'. We need to talk about password policies."
>
> "This infostealer grabbed credentials from 47 apps. I'd say the device was compromised, but 'digitally eviscerated' might be more accurate."

---

<div align="center">

## 🚀 Ready to Get Started?

Upload the three plugins, ask SENTINEL what's going on, and let the dark web intelligence flow.

**Remember:** Every compromised credential you catch is an attack you prevented. Every infostealer you detect saves the organization. This work matters.

*Now go catch some bad guys.* 🎯

---

**Built with ❤️ (and a healthy dose of sarcasm) by the SpyCloud Sentinel team**

*"We swim through the darknet so you don't have to."*

</div>
