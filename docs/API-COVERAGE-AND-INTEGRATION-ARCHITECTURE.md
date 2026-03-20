# ═══════════════════════════════════════════════════════════════════════
# SpyCloud API Coverage Map + Logic App & MCP Integration Architecture
# ═══════════════════════════════════════════════════════════════════════
# Date: 2026-03-19
# ═══════════════════════════════════════════════════════════════════════

## COMPLETE SPYCLOUD API INVENTORY (from docs.spycloud.com)

### What Was Missing in v1.x vs What's Now Covered in v2.0

| API Product | v1.x Coverage | v2.0 Coverage | Endpoints Added |
|-------------|--------------|---------------|-----------------|
| **Enterprise ATO Prevention** | 6/11 endpoints | 11/11 ✅ | Watchlist CRUD (list/get/create/delete/verify), password lookup |
| **Compass** | 2/5 endpoints | 5/5 ✅ | Applications list, application records, device records |
| **SIP (Session Identity)** | 0/3 endpoints | 3/3 ✅ | Cookie domains, SIP breach catalog, SIP breach by ID |
| **CAP (Consumer ATO)** | 0/6 endpoints | 6/6 ✅ | Email, username, IP, phone, zero-knowledge, breach catalog |
| **NIST Password Check** | 0/1 endpoints | 1/1 ✅ | Password hash check |
| **Exposure Metrics** | 1/2 endpoints | 2/2 ✅ | Email stats, domain stats |
| **Investigations** | 0/17 endpoints | 17/17 ✅ | All 15 lookup types + 2 catalog |
| **IdLink** | 0/3 endpoints | 3/3 ✅ | Email, phone, username identity graph |
| **Compromised Credit Cards** | 0/2 endpoints | 2/2 ✅ | BIN lookup, card list |
| **Data Partnership** | 0/15 endpoints | 4/15 🟡 | Email, domain, SSN, phone (key endpoints) |
| **TOTAL** | **9/65** | **54/65** | **+45 endpoints** |

### v1.x Had: 9 endpoints (14% coverage)
### v2.0 Has: 54 endpoints (83% coverage)

The remaining 11 endpoints in Data Partnership are less common lookup types 
(drivers license, passport, national ID, health insurance, credit card, bank 
number, username, password, IP) that can be added on request.

---

## INTEGRATION ARCHITECTURE: THREE LAYERS

### Layer 1: KQL Plugin (Sentinel-Ingested Data)
**File:** `SpyCloud_Agent_v2.yaml` / `SpyCloud_Plugin.yaml`
**What:** 46 KQL skills querying SpyCloud data already in Sentinel tables
**When:** For investigation of historical/ingested data, trend analysis, cross-correlation
**Latency:** ~2-5 seconds
**Cost:** Zero API calls (data already in Sentinel)

### Layer 2: API Plugin (Live SpyCloud API Calls)
**File:** `SpyCloud_FullAPI_Plugin.yaml` + `spycloud-full-openapi-spec.yaml`
**What:** 54 API endpoints for real-time lookups
**When:** On-demand enrichment, data not yet in Sentinel, investigation-grade queries
**Latency:** ~1-3 seconds per call
**Cost:** SpyCloud API usage (varies by product/plan)

### Layer 3: Logic App Plugin (Orchestrated Actions)
**File:** `SpyCloud_LogicApp_Plugin_and_MCP_Design.yaml`
**What:** 8 Logic App skills for enrichment + remediation
**When:** Analyst-triggered response actions, automated incident enrichment
**Latency:** ~5-30 seconds (API call + write to Sentinel)
**Cost:** Logic App execution + API call + Copilot SCU

### Future Layer 4: MCP Server (Unified Protocol)
**File:** `SpyCloud_LogicApp_Plugin_and_MCP_Design.yaml` (design section)
**What:** 20+ MCP tools + resources + prompts
**When:** Multi-client access (Security Copilot, Claude, VS Code, Copilot Studio)
**Latency:** ~1-5 seconds
**Cost:** App Service hosting + API calls

---

## LOGIC APP INTEGRATION DETAILS

### How It Works in Security Copilot

Security Copilot has a **bidirectional Logic App integration**:

**Inbound (Logic App → Copilot):** Submit prompts/promptbooks to Security Copilot 
from a Logic App workflow. The Logic App connector action "Submit a Security Copilot 
prompt" sends a natural language prompt and receives the AI-generated response.

**Outbound (Copilot → Logic App):** Invoke Logic App workflows as skills from within 
Security Copilot. The `Format: LogicApp` skill type in the YAML manifest allows 
analysts to trigger remediation actions directly from the chat interface.

### SpyCloud Logic App Skills for Security Copilot

| Skill | Logic App | Trigger | Action | Inputs |
|-------|-----------|---------|--------|--------|
| EnrichEmailExposure | SpyCloud-Enrich-Email | HTTP | Call SpyCloud API → write incident comment | email, incidentId |
| EnrichDomainExposure | SpyCloud-Enrich-Domain | HTTP | Call SpyCloud API → write incident comment | domain, incidentId |
| EnrichIPExposure | SpyCloud-Enrich-IP | HTTP | Call SpyCloud API → write incident comment | ip, incidentId |
| EnrichCatalogContext | SpyCloud-Enrich-Catalog | HTTP | Call SpyCloud API → write incident comment | sourceId, incidentId |
| IsolateDeviceInMDE | SpyCloud-MDE-Remediation | HTTP | Isolate device + tag + submit IOC | deviceId, isolationType |
| ResetUserPasswordViaCA | SpyCloud-CA-Remediation | HTTP | Force password reset + revoke sessions | userEmail, disableAccount |
| SendSOCNotification | SpyCloud-CredResponse | HTTP | Send Teams/Slack alert | alertSummary, severity, entity |
| RunFullInvestigation | SpyCloud-FullInvestigation | HTTP | Multi-API + KQL comprehensive report | email, incidentId |

### Automated Incident Triage Pattern

```
Sentinel Incident Created (analytics rule fires)
  │
  ▼
Automation Rule → Trigger SpyCloud Triage Playbook
  │
  ├─→ Logic App: Extract entities (email, IP, host)
  │
  ├─→ Logic App: Call Security Copilot "Submit prompt"
  │     Prompt: "Investigate {email} for SpyCloud exposures,
  │              assess severity, and recommend remediation"
  │     Plugin: SpyCloud.HolisticIdentityThreat.SentinelAgent
  │     Direct Skill: SpyCloudInvestigationAgent
  │
  ├─→ Logic App: Parse Copilot response
  │
  ├─→ Logic App: Write investigation as incident comment
  │
  ├─→ Logic App: Classify severity (from Copilot response)
  │
  ├─→ Logic App: Auto-tag incident based on findings
  │
  └─→ Logic App: If severity = Critical → trigger remediation
        ├─→ IsolateDeviceInMDE
        ├─→ ResetUserPasswordViaCA
        └─→ SendSOCNotification
```

### Key Logic App Best Practices for Security Copilot

1. **Use Direct Skill Name** — bypass the planner for faster, cheaper execution
2. **Maintain Session ID** — chain multiple prompts in one investigation session
3. **Scope plugins** — list specific plugins to avoid skill collision
4. **Parse structured output** — ask Copilot to output JSON for Logic App parsing
5. **Cost optimization** — minimum 3 SCUs for production Logic App flows

---

## MCP SERVER DESIGN

### Why MCP?

Model Context Protocol enables **one server, many clients**. A SpyCloud MCP 
server would be accessible from:

- **Security Copilot** — as an MCP plugin with tools auto-discovered
- **Claude** (Anthropic) — as a connected MCP server
- **VS Code** (GitHub Copilot) — for developer security workflows
- **Copilot Studio** — for custom agents and Power Automate flows
- **Any MCP client** — universal protocol

### MCP Tool Inventory (20 tools)

| # | Tool Name | API Backend | Description |
|---|-----------|------------|-------------|
| 1 | lookup_email_exposure | Enterprise API | Look up breach records by email |
| 2 | lookup_domain_exposure | Enterprise API | Look up breach records by domain |
| 3 | lookup_ip_exposure | Enterprise API | Look up breach records by IP |
| 4 | lookup_username_exposure | Enterprise API | Look up breach records by username |
| 5 | check_password_nist | NIST API | Check password hash against breaches |
| 6 | get_watchlist_records | Enterprise API | Get all watchlist exposure records |
| 7 | manage_watchlist | Enterprise API | Add/remove/list watchlist identifiers |
| 8 | get_breach_catalog | Enterprise API | List/search breach source metadata |
| 9 | get_breach_details | Enterprise API | Get full details for a breach ID |
| 10 | get_compass_devices | Compass API | List compromised devices |
| 11 | get_compass_applications | Compass API | List compromised applications |
| 12 | get_sip_cookies | SIP API | Get stolen cookies for a domain |
| 13 | get_exposure_stats | Exposure API | Get aggregate exposure statistics |
| 14 | investigate_deep | Investigations API | Deep OSINT investigation |
| 15 | get_identity_graph | IdLink API | Map linked identities |
| 16 | check_consumer_exposure | CAP API | Consumer ATO protection check |
| 17 | query_sentinel_kql | Sentinel API | Run KQL query against Sentinel |
| 18 | trigger_remediation | Logic App | Trigger MDE/CA remediation |
| 19 | get_health_status | Sentinel API | Check data pipeline health |
| 20 | generate_report | GPT + All | Generate investigation report |

### MCP Resources (always-available context)

| Resource URI | Content | Purpose |
|-------------|---------|---------|
| spycloud://severity-model | Severity 2/5/20/25 definitions + SLAs | Always available for interpretation |
| spycloud://password-risk-model | Hash type → crackability mapping | Password assessment reference |
| spycloud://mitre-mapping | SpyCloud → MITRE ATT&CK technique map | Threat modeling reference |
| spycloud://breach-catalog | Cached breach catalog (refreshed hourly) | Quick catalog lookups |
| spycloud://watchlist-identifiers | Current monitored identifiers | Scope awareness |

### MCP Prompts (pre-built investigation templates)

| Prompt Name | Description | Arguments |
|-------------|-------------|-----------|
| investigate-user | Full user investigation workflow | email |
| investigate-device | Full device forensics workflow | machine_id |
| org-exposure-overview | Organization-wide exposure summary | (none) |
| threat-hunt | Proactive threat hunting workflow | (none) |
| compliance-assessment | Breach notification analysis | (none) |
| executive-brief | C-suite exposure summary | domain |

### Security Copilot MCP Plugin Registration

```yaml
# Upload this to Security Copilot → Sources → Custom → Add Plugin → MCP
Descriptor:
  Name: SpyCloud.MCP.ThreatIntelligence
  DisplayName: SpyCloud MCP — Identity Threat Intelligence
  Description: >-
    SpyCloud threat intelligence via Model Context Protocol. Provides 
    20 tools for breach lookup, device forensics, identity graph mapping, 
    remediation actions, and investigation workflows.
SkillGroups:
  - Format: MCP
    Settings:
      Url: https://spycloud-mcp.azurewebsites.net/sse
      TransportType: SSE
```

### Implementation Roadmap

| Phase | Content | Timeline | Effort |
|-------|---------|----------|--------|
| Phase 1 | Core read-only tools (lookup, catalog, stats) | 2 weeks | Medium |
| Phase 2 | Compass + SIP + Investigations tools | 1 week | Low |
| Phase 3 | Action tools (watchlist mgmt, remediation) | 2 weeks | Medium |
| Phase 4 | Sentinel KQL integration + reporting | 1 week | Low |
| Phase 5 | Security Store publication | 2 weeks | Medium |

---

## SPYCLOUD 2026 IDENTITY EXPOSURE REPORT — KEY FINDINGS

Per SpyCloud's just-released 2026 report (published March 19, 2026):

- **65.7 billion** total identity records in SpyCloud's datalake (+23% YoY)
- **18.1 million** exposed API keys and tokens (NHI explosion)
- **6.2 million** credentials tied to AI tools (new attack surface)
- **5.3 billion** credential pairs recaptured
- **80%** of corporate credentials had plaintext passwords
- **642.4 million** credentials from 13.2 million infostealer infections
- **50 credentials per malware infection** average
- **8.6 billion** stolen cookies and session artifacts
- **28.6 million** phished identity records (+400% YoY)
- **51%** of combolist records overlap with infostealer logs
- **Tycoon 2FA** phishing-as-a-service seized by Europol (March 4, 2026)

### What This Means for SCORCH Agent:

The agent should reference these stats in org-wide assessments and benchmarking. 
When analysts ask "how do we compare," SCORCH can contextualize with industry data.
The NHI (non-human identity) explosion means we should add skills for API key 
and token exposure detection in future iterations.
