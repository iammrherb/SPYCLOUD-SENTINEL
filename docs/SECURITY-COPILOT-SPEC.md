# SpyCloud Security Copilot Integration — Complete Specification

<p align="center">
  <img src="images/SpyCloud-Logo-white.png" alt="SpyCloud Logo" width="300"/>
</p>

<p align="center">
  <strong>SpyCloud Darknet & Identity Threat Exposure Intelligence</strong><br/>
  Microsoft Security Copilot Integration v8.0.0
</p>

---

## Table of Contents

1. [Executive Overview](#executive-overview)
2. [Architecture](#architecture)
3. [Plugin Inventory](#plugin-inventory)
4. [Agent — Autonomous Investigation](#agent--autonomous-investigation)
5. [KQL Plugin — 90 Promptbook Skills](#kql-plugin--90-promptbook-skills)
6. [API Plugin — 20 REST API Skills](#api-plugin--20-rest-api-skills)
7. [Sub-Agent Specifications](#sub-agent-specifications)
8. [Data Sources & Schema](#data-sources--schema)
9. [Sentinel Resources](#sentinel-resources)
10. [Branding & Customization](#branding--customization)
11. [Deployment Guide](#deployment-guide)
12. [Compatibility Matrix](#compatibility-matrix)
13. [Security & Compliance](#security--compliance)
14. [Appendix: Complete Skill Reference](#appendix-complete-skill-reference)

---

## Executive Overview

The SpyCloud Security Copilot Integration is the most comprehensive dark web threat intelligence solution available for Microsoft Security Copilot. It provides three complementary plugins that together deliver **168 skills**, **17 specialized sub-agents**, and seamless access to **155+ deployed Sentinel resources** — enabling SOC teams to investigate compromised credentials, infostealer infections, exposed PII, device forensics, session cookie theft, identity exposure, and automated remediation status through natural-language conversation.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Total Skills** | 168 (90 KQL + 20 API + 58 Agent-internal) |
| **Sub-Agents** | 17 specialized investigation agents |
| **Sentinel Tables** | 10 custom SpyCloud tables |
| **Total Columns** | 233+ across all SpyCloud tables |
| **SpyCloud APIs** | 6 (Enterprise, Catalog, Compass, SIP, Identity Exposure, Investigations) |
| **REST API Pollers** | 9 independent CCF pollers |
| **Analytics Rules** | 49 (38 scheduled, 1 Fusion, 5 NRT, 5 MSIC) |
| **Hunting Queries** | 28 proactive threat hunting queries |
| **Playbooks** | 10 Logic App automated response workflows |
| **Watchlists** | 4 (VIP, IOC Blocklist, Approved Domains, High-Value Assets) |
| **Workbooks** | 3 (Executive Dashboard, SOC Operations, Threat Intel) |
| **Notebooks** | 3 (Incident Triage, Threat Hunting, Threat Landscape) |
| **Notification Channels** | 6 (Slack, Teams, Email, ServiceNow, Jira, Azure DevOps) |
| **Deployment Methods** | 3 (ARM Template, Terraform, Azure Cloud Shell) |

### Solution Components

```
┌──────────────────────────────────────────────────────────────────┐
│                   Microsoft Security Copilot                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │  Investigation   │  │   KQL Plugin     │  │   API Plugin    │  │
│  │     Agent        │  │  (90 Skills)     │  │  (20 Skills)    │  │
│  │  (17 Sub-Agents) │  │                  │  │                 │  │
│  │  (58 Int Skills) │  │  Sentinel KQL    │  │  SpyCloud REST  │  │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬────────┘  │
│           │                     │                      │           │
├───────────┴─────────────────────┴──────────────────────┴──────────┤
│                     Microsoft Sentinel                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ 49 Rules │ │28 Hunting│ │10 Play-  │ │4 Watch-  │            │
│  │          │ │ Queries  │ │  books   │ │  lists   │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │3 Work-   │ │3 Note-   │ │10 Custom │ │UEBA/     │            │
│  │  books   │ │  books   │ │ Tables   │ │Fusion/TI │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
├──────────────────────────────────────────────────────────────────┤
│                     SpyCloud APIs                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │
│  │  Enterprise   │ │   Compass    │ │   SIP        │              │
│  │  Breach API   │ │Investigation │ │Session Cookie│              │
│  │  + Catalog    │ │     API      │ │    API       │              │
│  └──────────────┘ └──────────────┘ └──────────────┘              │
│  ┌──────────────┐ ┌──────────────┐                                │
│  │  Identity     │ │Investigations│                                │
│  │  Exposure API │ │     API      │                                │
│  └──────────────┘ └──────────────┘                                │
└──────────────────────────────────────────────────────────────────┘
```

---

## Architecture

### Data Flow

1. **Ingestion**: SpyCloud 6 APIs → 9 CCF REST pollers → Data Collection Rules (DCR) with KQL transforms → 10 custom Sentinel tables
2. **Detection**: 49 analytics rules continuously evaluate ingested data → Sentinel incidents
3. **Response**: 10 Logic App playbooks auto-remediate (password reset, session revoke, MFA enforce, device isolate, firewall block, user/SOC notify, incident enrich, full orchestration)
4. **Investigation**: Security Copilot agent + plugins provide natural-language access to all data and actions
5. **Reporting**: 3 workbooks + 3 notebooks + executive summary agent for dashboarding and compliance

### Plugin Interaction Model

| Scenario | Best Plugin | Why |
|----------|-------------|-----|
| Interactive investigation | **Agent** | Autonomous multi-step orchestration with personality |
| Quick KQL query | **KQL Plugin** | Direct promptbook skill invocation |
| Real-time API lookup | **API Plugin** | Live SpyCloud API for freshest data |
| Deep Compass analysis | **API Plugin** | Compass API endpoints not available via KQL |
| Executive reporting | **Agent** | Executive Summary sub-agent with GPT analysis |
| Automated triage | **Agent** | Identity Risk Scoring sub-agent |

All three plugins are **fully compatible** and can be used simultaneously. The Agent references skills from both the KQL and API plugins for comprehensive investigations.

---

## Plugin Inventory

### File Structure

```
copilot/
├── manifest.json                      # Unified manifest for all plugins
├── SpyCloud_Agent.yaml                # Autonomous investigation agent (17 sub-agents)
├── SpyCloud_Plugin.yaml               # KQL plugin (90 promptbook skills)
├── SpyCloud_API_Plugin.yaml           # API plugin (20 REST API skills)
└── SpyCloud_API_Plugin_OpenAPI.yaml   # OpenAPI 3.0.3 specification for API Plugin
```

### Authentication Requirements

| Plugin | Auth Type | Credentials Required |
|--------|-----------|---------------------|
| Agent | None | Azure Sentinel workspace access (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName) |
| KQL Plugin | None | Same Sentinel workspace access |
| API Plugin | API Key | SpyCloud API key (X-API-Key header) |

---

## Agent — Autonomous Investigation

### Overview

The SpyCloud Investigation Agent (`SpyCloud.ThreatIntelligence.SentinelAgent`) is an autonomous, conversational security analyst that provides interactive dark web threat investigation through Microsoft Security Copilot.

### Identity: SENTINEL

The agent operates as **SENTINEL** — a battle-hardened security analyst with:
- Confident, direct communication backed by 600B+ recaptured darknet records
- Strategic use of humor and engaging personality
- Persistent, thorough investigation with automatic pivoting
- Empathetic support for SOC analysts
- Brutal honesty about risk exposure

### Capabilities

| Capability | Description |
|------------|-------------|
| **User Investigation** | Full credential, PII, password, and account activity investigation for any email |
| **Device Forensics** | Infostealer infection analysis, malware path, AV coverage, OS, IPs, keyboard |
| **Malware Hunting** | Track malware families (RedLine, LummaC2, Vidar, Raccoon, StealC, etc.) |
| **Org-Wide Assessment** | Bird's-eye view of total exposure, top risks, remediation gaps |
| **UEBA Correlation** | Cross-reference exposed credentials with behavioral anomalies |
| **Fusion Analysis** | ML-detected multistage attack chain investigation |
| **Password Audit** | Plaintext, hash type breakdown, crackability assessment, reuse detection |
| **Compliance Reporting** | GDPR, HIPAA, PCI-DSS, SOX compliance mapping and notification requirements |
| **Playbook Status** | MDE isolations, password resets, TI enrichment, automation effectiveness |
| **Watchlist Management** | VIP accounts, IOC blocklists, approved domains, high-value assets |
| **Ransomware Assessment** | Precursor malware detection, pre-encryption containment recommendations |
| **Identity Risk Scoring** | Multi-dimensional risk scoring across 7 factors (0-105 scale) |
| **Supply Chain Analysis** | Third-party vendor credential exposure and shared account risk |
| **Dark Web Monitoring** | Ingestion velocity tracking, fresh infection alerts, intelligence briefings |

### Suggested Prompts (Starter)

| Prompt | Category |
|--------|----------|
| "What can you help me investigate?" | Getting Started |
| "Show me an overview of our dark web exposure" | Exposure Overview |
| "Which users have the most critical credential exposures?" | Critical Exposures |
| "Are any devices infected with infostealer malware?" | Infected Devices |
| "Show me users with plaintext passwords exposed" | Password Audit |
| "Do we have sensitive PII exposed requiring breach notification?" | Compliance Check |
| "What's the single most dangerous finding right now?" | Top Risk |

### Internal Skills (58 Total)

The Agent orchestrates 58 internal skills (35 KQL + 6 GPT-4o analysis + 17 sub-agents):

| # | Skill Name | Type | Description |
|---|-----------|------|-------------|
| 1 | GetUserExposures | KQL | All exposures for a specific email |
| 2 | GetUserFullPIIProfile | KQL | Complete PII/identity profile |
| 3 | GetUserAccountActivity | KQL | Account activity timeline |
| 4 | GetExposedPasswords | KQL | Password data for a user |
| 5 | GetPlaintextPasswordExposures | KQL | All plaintext password exposures |
| 6 | GetPasswordTypeBreakdown | KQL | Password type distribution |
| 7 | GetHighSeverityExposures | KQL | Severity 20+ infostealer exposures |
| 8 | GetExposureSummaryBySeverity | KQL | Exposure breakdown by severity |
| 9 | GetExposureSummaryByDomain | KQL | Exposure breakdown by domain |
| 10 | GetTargetedDomains | KQL | Most targeted websites |
| 11 | GetSensitivePIIExposures | KQL | SSN, financial, health data |
| 12 | GetSocialMediaExposures | KQL | LinkedIn, Twitter, social profiles |
| 13 | GetInfectedDevices | KQL | Infected device summary |
| 14 | GetDeviceForensics | KQL | Full device forensics |
| 15 | GetDeviceToUserCorrelation | KQL | Users affected by a device |
| 16 | GetAVCoverageGaps | KQL | AV products that failed |
| 17 | GetMalwareInfo | KQL | Breach catalog malware lookup |
| 18 | GetRecentBreaches | KQL | Recently added breaches |
| 19 | GetEnrichedExposures | KQL | Exposures joined with catalog |
| 20 | GetMDERemediationActions | KQL | MDE isolation/tagging actions |
| 21 | GetMDERemediationForDevice | KQL | MDE actions for a device |
| 22 | GetMDERemediationStats | KQL | MDE effectiveness summary |
| 23 | GetConditionalAccessActions | KQL | CA remediation actions |
| 24 | GetConditionalAccessForUser | KQL | CA actions for a user |
| 25 | GetConditionalAccessStats | KQL | CA effectiveness summary |
| 26 | GetFullUserInvestigation | KQL | Cross-table user investigation |
| 27 | GetGeographicAnalysis | KQL | Geographic infection distribution |
| 28 | GetSpyCloudHealthStatus | KQL | Data ingestion health check |
| 29 | InvestigateFullExposureChain | KQL | Multi-table exposure chain |
| 30 | GenerateIncidentSummary | KQL | Structured incident summary |
| 31 | DetectPermissionGaps | KQL | Playbook permission gap detection |
| 32 | AnalyzeAndSummarize | GPT | GPT-4.1 analysis and reporting |

---

## Sub-Agent Specifications

### 1. UEBA & Behavioral Analysis Agent

**Purpose**: Correlates credential exposure with UEBA behavioral anomalies

**Data Sources**: SpyCloudBreachWatchlist_CL, BehaviorAnalytics, IdentityInfo, SigninLogs

**Investigation Flow**:
1. Identify exposed users with severity >= 20
2. Cross-reference with BehaviorAnalytics for anomalous activity
3. Check SigninLogs for unusual sign-in patterns post-exposure
4. Score risk: exposure severity + anomaly count + investigation priority

**Key Output**: Correlation table of users with BOTH credential exposure AND behavioral anomalies

---

### 2. Fusion & Multistage Attack Agent

**Purpose**: Investigates Fusion-detected multistage attacks for credential theft correlation

**Data Sources**: SpyCloudBreachWatchlist_CL, SecurityAlert, SecurityIncident, SpyCloudBreachCatalog_CL

**Investigation Flow**:
1. Query Fusion alerts from SecurityAlert
2. Extract entities (accounts, IPs, hosts)
3. Cross-reference with SpyCloud exposures
4. Map kill chain timeline: SpyCloud exposure date vs. Fusion detection
5. Assess whether stolen credentials enabled the attack chain

**Key Output**: Attack chain visualization with MITRE ATT&CK mapping

---

### 3. TI Enrichment & IOC Analysis Agent

**Purpose**: Threat intelligence enrichment and IOC blocklist management

**Data Sources**: SpyCloudBreachWatchlist_CL, ThreatIntelligenceIndicator, IOC Blocklist watchlist, Spycloud_MDE_Logs_CL

**Investigation Flow**:
1. Extract IOCs from SpyCloud exposures (IPs, domains, URLs)
2. Query ThreatIntelligenceIndicator for matches
3. Check IOC Blocklist for coverage
4. Identify gaps and score IOC confidence
5. Recommend blocking actions

**Key Output**: IOC coverage gap analysis with prioritized blocking recommendations

---

### 4. Session Cookie & MFA Bypass Agent

**Purpose**: Detects stolen session tokens and MFA bypass attempts

**Data Sources**: SpyCloudBreachWatchlist_CL (severity 25), SigninLogs, AADNonInteractiveUserSignInLogs, CloudAppEvents

**Investigation Flow**:
1. Find severity 25 exposures (stolen session cookies)
2. Check SigninLogs for single-factor authentication events
3. Detect impossible travel (different countries within hours)
4. Detect token replay (multiple IPs for same session)
5. Check CloudAppEvents for OAuth consent abuse

**Key Output**: Session theft risk assessment with MFA gap analysis

---

### 5. Lateral Movement Investigation Agent

**Purpose**: Tracks device-to-device movement from compromised accounts

**Data Sources**: SpyCloudBreachWatchlist_CL, IdentityLogonEvents, DeviceLogonEvents, Spycloud_MDE_Logs_CL

**Investigation Flow**:
1. Identify compromised users with severity >= 20
2. Query IdentityLogonEvents for RDP/SMB/NTLM logons
3. Map source-to-target device pairs
4. Flag outliers (>3 unique targets in 24h)
5. Verify containment status

**Key Output**: Movement map with device isolation status

---

### 6. Data Exfiltration Detection Agent

**Purpose**: Detects data theft patterns from compromised accounts

**Data Sources**: SpyCloudBreachWatchlist_CL, CloudAppEvents, OfficeActivity, SpyCloud_ConditionalAccessLogs_CL

**Investigation Flow**:
1. Determine exposure window (publish date to remediation)
2. Query CloudAppEvents for mass file operations
3. Check OfficeActivity for mailbox forwarding rules
4. Flag suspicious patterns (>50 files/day, external forwarding)
5. Estimate data volume at risk

**Key Output**: Exfiltration risk assessment with containment recommendations

---

### 7. Executive Summary & Compliance Agent

**Purpose**: Executive reporting and compliance framework mapping

**Data Sources**: All SpyCloud tables, MDE logs, CA logs

**Report Types**:
- Executive Dashboard: high-level metrics, trends, risk posture
- Compliance Assessment: GDPR, HIPAA, PCI-DSS, SOX mapping
- Malware Trend Report: top families, infection rates, AV evasion
- Third-Party Impact: external breach sources
- Automation Effectiveness: playbook metrics and ROI

**Key Output**: Business-impact-focused executive reports with strategic recommendations

---

### 8. Watchlist & Asset Management Agent

**Purpose**: VIP monitoring, IOC blocklist, and asset risk correlation

**Data Sources**: SpyCloudBreachWatchlist_CL, 4 Sentinel watchlists

**Capabilities**:
- VIP/Executive exposure monitoring (always HIGH priority)
- IOC Blocklist coverage gap analysis
- Approved Domains validation
- High-Value Asset risk correlation

**Key Output**: VIP exposure alerts and IOC coverage reports

---

### 9. Ransomware Impact Assessment Agent (NEW)

**Purpose**: Ransomware precursor detection and pre-encryption containment

**Data Sources**: SpyCloudBreachWatchlist_CL, SpyCloudBreachCatalog_CL, IdentityLogonEvents, DeviceLogonEvents, High-Value Assets watchlist

**Risk Model**: Malware family risk × lateral movement × asset criticality × containment gaps

**Tracked Malware Families**: RedLine, LummaC2, Vidar, Raccoon, StealC, Aurora, Mars, META, Mystic, RisePro, Titan

**Key Output**: Ransomware risk score with MITRE ATT&CK mapping and containment playbook

---

### 10. Identity Risk Scoring Agent (NEW)

**Purpose**: Dynamic multi-dimensional identity risk scoring

**Risk Dimensions** (0-15 points each, max 105):

| Dimension | Scoring |
|-----------|---------|
| Credential Severity | sev25=15, sev20=12, sev5=6, sev2=3 |
| Password Crackability | plaintext=15, MD5/SHA1=12, SHA256=8, bcrypt=3 |
| PII Exposure Depth | SSN/financial=15, DOB+addr=10, name+phone=5 |
| Device Infection | active=15, historical=8, none=0 |
| Remediation Timeliness | unremediated>7d=15, 1-7d=10, <24h=0 |
| Behavioral Anomalies | UEBA anomalies=15, suspicious sign-ins=10 |
| VIP/Asset Criticality | C-suite=15, admin=10, high-value access=8 |

**Risk Tiers**: Critical (75-105), High (50-74), Medium (25-49), Low (0-24)

**Key Output**: Risk-ranked user lists with composite scores for SOC triage

---

### 11. Supply Chain & Third-Party Exposure Agent (NEW)

**Purpose**: Third-party vendor and supply chain credential risk assessment

**Data Sources**: SpyCloudBreachWatchlist_CL (target_domain analysis), SpyCloudBreachCatalog_CL, Approved Domains watchlist

**Capabilities**:
- Partner/vendor domain credential exposure tracking
- Shared service account compromise detection
- Vendor risk scoring: breach count × affected users × max severity
- SSO/IdP credential monitoring (Okta, Azure AD, OneLogin)

**Key Output**: Vendor risk tiering with supply chain risk score

---

### 12. Dark Web Monitoring & Alert Agent (NEW)

**Purpose**: Real-time dark web monitoring and intelligence briefings

**Monitoring Workflows**:
- New exposure ingestion tracking (records per hour/day/week)
- Ingestion velocity anomaly detection (>2x baseline = alert)
- New breach source identification
- Fresh infostealer detection (infected_time < 72h = CRITICAL)
- Response gap monitoring

**Key Output**: Daily/weekly dark web intelligence briefings with trending threats

---

## KQL Plugin — 90 Promptbook Skills

### Skill Categories (29 Categories)

| # | Category | Skills | Description |
|---|----------|--------|-------------|
| 1 | User Credential Investigation | 3 | Email-based exposure, PII profile, account activity |
| 2 | Password & Credential Analysis | 5 | Passwords, plaintext, types, reuse, crackability |
| 3 | Severity & Breach Category | 4 | High severity, by severity, by domain, by category |
| 4 | Sensitive PII & Financial | 3 | SSN, financial, health data, social media |
| 5 | Device & Malware Forensics | 5 | Infected devices, forensics, user correlation, AV gaps, malware |
| 6 | Breach Catalog Intelligence | 3 | Recent breaches, catalog search, enriched exposures |
| 7 | MDE Remediation Audit | 3 | MDE actions, per-device, stats |
| 8 | Conditional Access Remediation | 3 | CA actions, per-user, stats |
| 9 | Cross-Table Investigation | 3 | Full user investigation, exposure chain, health status |
| 10 | UEBA Correlation | 4 | Behavioral anomalies, sign-in patterns, risk intersection |
| 11 | Fusion Multistage | 3 | Fusion alerts, entity correlation, kill chain mapping |
| 12 | TI Enrichment | 3 | IOC analysis, blocklist coverage, TI matches |
| 13 | Session Cookie & Lateral Movement | 4 | Cookie theft, MFA bypass, lateral movement, token replay |
| 14 | Data Exfiltration | 3 | File operations, mailbox rules, volume estimation |
| 15 | Campaign Intelligence | 4 | Malware campaigns, threat actors, campaign timeline |
| 16 | Executive Reporting | 5 | Trends, metrics comparison, recommendations, compliance |
| 17 | Network & Infrastructure | 4 | Firewall events, DNS C2, VPN, geographic distribution |
| 18 | Compass Consumer Identity | 4 | Consumer exposures, device fingerprints |
| 19 | Watchlist & Asset Management | 4 | VIP check, IOC blocklist, approved domains, asset risk |
| 20 | Operational Health | 3 | Ingestion health, automation metrics, incident summary |
| 21 | Risk Scoring | 4 | User risk score, org risk posture, trend analysis |
| 22 | SIP Session Cookie Analysis | 3 | Cookie domain exposure, session hijack risk, SIP summary |
| 23 | Identity Exposure Profiling | 3 | Identity risk profiles, exposure timeline, corporate impact |
| 24 | Investigations Deep Dive | 3 | Full database search results, investigation timeline, evidence chain |
| 25 | Compass Applications | 2 | Application credential exposure, SaaS risk mapping |
| 26 | Cross-API Correlation | 2 | Multi-table join investigations, API-to-table mapping |
| 27 | Infostealer Malware Families | 2 | Family-specific detection, infection pattern analysis |
| 28 | Remediation Gap Analysis | 2 | Unremediated exposure tracking, SLA compliance |
| 29 | Supply Chain & Third-Party | 2 | Vendor credential exposure, shared account risk |

---

## API Plugin — 20 REST API Skills

### Enterprise Breach API (7 Skills)

| Skill | Endpoint | Description |
|-------|----------|-------------|
| GetBreachDataByEmail | `GET /breach/data/emails/{email}` | Breach records by email address |
| GetBreachDataByDomain | `GET /breach/data/domains/{domain}` | Breach records by corporate domain |
| GetBreachDataByIp | `GET /breach/data/ips/{ip}` | Breach records by IP address |
| CheckPasswordExposure | `GET /breach/data/passwords/{password}` | Password exposure check |
| GetBreachDataByUsername | `GET /breach/data/usernames/{username}` | Breach records by username |
| ListBreachCatalog | `GET /breach/catalog` | Browse breach catalog |
| GetBreachCatalogEntry | `GET /breach/catalog/{id}` | Specific breach details |

### Compass Investigation API (5 Skills)

| Skill | Endpoint | Description |
|-------|----------|-------------|
| CompassInvestigateEmail | `GET /compass/data/emails/{email}` | Deep Compass investigation by email |
| CompassInvestigateDomain | `GET /compass/data/domains/{domain}` | Deep Compass investigation by domain |
| CompassInvestigateIp | `GET /compass/data/ips/{ip}` | Deep Compass investigation by IP |
| CompassGetDevices | `GET /compass/devices` | Infected device fingerprints and malware artifacts |
| CompassGetApplications | `GET /compass/applications` | Application credential exposure data |

### SIP Session Identity Protection API (3 Skills)

| Skill | Endpoint | Description |
|-------|----------|-------------|
| GetSipCookiesByDomain | `GET /sip/cookies/{domain}` | Stolen session cookies by domain |
| GetSipCookiesByEmail | `GET /sip/cookies/emails/{email}` | Stolen session cookies by email |
| GetSipSessionSummary | `GET /sip/summary` | SIP session exposure summary |

### Identity Exposure API (3 Skills)

| Skill | Endpoint | Description |
|-------|----------|-------------|
| GetIdentityExposure | `GET /identity/exposure/{email}` | Identity exposure risk profile |
| GetIdentityExposureByDomain | `GET /identity/exposure/domains/{domain}` | Corporate identity exposure |
| GetIdentityWatchlist | `GET /identity/watchlist` | Monitored identity watchlist |

### Investigations API (2 Skills)

| Skill | Endpoint | Description |
|-------|----------|-------------|
| InvestigationsSearch | `GET /investigations/search` | Full database search across all SpyCloud data |
| InvestigationsGetDetails | `GET /investigations/{id}` | Detailed investigation record |

### Common API Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | date | Records published on or after (YYYY-MM-DD) |
| `until` | date | Records published on or before |
| `severity` | int | Minimum severity threshold (1-25) |
| `password_type` | string | Filter: plaintext, hashed, cracked, unknown |
| `type` | string | Category: corporate or infected |
| `limit` | int | Max records per page (1-10000, default 100) |
| `cursor` | string | Pagination cursor for large result sets |

---

## Data Sources & Schema

### SpyCloud Custom Tables

#### SpyCloudBreachWatchlist_CL (73 columns)

Primary table for credential exposures and infostealer data.

| Column Group | Key Fields |
|-------------|------------|
| **Identity** | email, username, full_name, first_name, last_name, email_domain |
| **Credentials** | password, password_plaintext, password_type, salt, sighting |
| **Target** | target_domain, target_url, target_subdomain |
| **PII** | phone, dob, birth_year, age, gender, address_1, city, state, country |
| **Financial** | ssn_last_four, social_security_number, bank_number, taxid, health_insurance_id |
| **Social** | social_linkedin, social_twitter, social_crunchbase, homepage |
| **Employment** | job_title, company_name, company_website, industry |
| **Device** | infected_machine_id, user_hostname, user_os, infected_path, device_name |
| **Infection** | infected_time, ip_addresses, country_code, keyboard_languages, av_softwares |
| **Metadata** | severity, source_id, document_id, spycloud_publish_date, log_id |

#### SpyCloudBreachCatalog_CL (13 columns)

Breach source metadata and malware family context.

| Field | Description |
|-------|-------------|
| source_id | Unique breach identifier |
| breach_title | Breach/malware family name |
| description | Breach description |
| status | Breach processing status |

#### SpyCloudCompassData_CL (29 columns)

Consumer/partner identity exposures (Enterprise+ only).

#### SpyCloudCompassDevices_CL (8 columns)

Infected device fingerprints and malware artifacts (Enterprise+ only).

#### Spycloud_MDE_Logs_CL (19 columns)

MDE device isolation, tagging, and IOC submission audit trail.

| Field | Description |
|-------|-------------|
| IncidentId | Sentinel incident ID |
| HostName / NormalizedHostName | Device hostname |
| DeviceId | MDE device identifier |
| IsolationRequested / IsolationStatus | Isolation request and result |
| MachineTagAdded / MachineTagName | Device tagging |
| AddedIOCsToDefender | IOC submission status |
| PlaybookName | Triggering playbook |

#### SpyCloudCompassApplications_CL (15 columns)

Application credential exposure from Compass deep investigation (Enterprise+ only).

| Column Group | Key Fields |
|-------------|------------|
| **Application** | app_name, app_domain, app_url, app_category |
| **Credential** | email, username, password_type |
| **Metadata** | source_id, severity, spycloud_publish_date |

#### SpyCloudSIPCookies_CL (18 columns)

Stolen session cookies and tokens from infostealer infections (SIP license required).

| Column Group | Key Fields |
|-------------|------------|
| **Session** | cookie_domain, cookie_name, cookie_value, session_token |
| **Identity** | email, target_domain, target_url |
| **Device** | infected_machine_id, user_hostname, infected_path |
| **Metadata** | severity, infected_time, spycloud_publish_date |

#### SpyCloudIdentityExposure_CL (23 columns)

Identity risk profiles and exposure scoring across corporate identities.

| Column Group | Key Fields |
|-------------|------------|
| **Identity** | email, full_name, username, email_domain |
| **Exposure** | exposure_count, severity_max, exposure_types |
| **Risk** | identity_risk_score, risk_tier, first_seen, last_seen |
| **Corporate** | company_name, job_title, department |
| **Metadata** | spycloud_publish_date, document_id |

#### SpyCloudInvestigations_CL (28 columns)

Full database search results from Investigations API (Enterprise+ with Investigations add-on).

| Column Group | Key Fields |
|-------------|------------|
| **Identity** | email, username, full_name, phone, dob |
| **Credential** | password, password_type, password_plaintext |
| **Target** | target_domain, target_url, target_subdomain |
| **Device** | infected_machine_id, user_hostname, user_os, infected_path |
| **Source** | source_id, breach_title, severity |
| **Metadata** | spycloud_publish_date, document_id, investigation_id |

#### SpyCloud_ConditionalAccessLogs_CL (14 columns)

Identity remediation audit trail.

| Field | Description |
|-------|-------------|
| Username / UserEmail | User identifier |
| ForcedPasswordResetOnNextSignIn | Password reset status |
| UserSessionsRevoked | Session revocation status |
| CAgroup | Conditional Access group assignment |
| UserDisabled | Account disable status |
| PlaybookName | Triggering playbook |

### Severity Model

| Score | Label | Risk Level | Description |
|-------|-------|------------|-------------|
| 2 | Breach Credential | Medium | Basic credential from a breach |
| 5 | Breach + PII | High | Credential with personal information |
| 20 | Infostealer | Urgent | Credential stolen by infostealer malware |
| 25 | Infostealer + App Data | Critical | Stolen cookies, sessions, autofill (MFA bypass risk) |

### Password Crackability

| Type | Time to Crack | Risk |
|------|--------------|------|
| Plaintext | Immediate | Critical |
| MD5 / SHA1 / NTLM | Minutes | Critical |
| SHA256 | Hours | High |
| bcrypt / scrypt / argon2 | Secure | Low |

---

## Sentinel Resources

### Analytics Rules (49 Total)

| Type | Count | Description |
|------|-------|-------------|
| Scheduled | 38 | Time-based detection rules across 8 categories |
| Fusion | 1 | ML-powered multistage attack detection |
| NRT (Near-Real-Time) | 5 | Low-latency detection for critical events |
| MSIC | 5 | Microsoft Security Incident Creation rules |

**Rule Categories**: Core detection, O365/Entra ID correlation, UEBA/firewall/network correlation, infostealer-specific, credential compromise, device infection, remediation monitoring, compliance alerts.

### Playbooks (10 Total)

| Playbook | Category | Action |
|----------|----------|--------|
| SpyCloud-ForcePasswordReset | Identity | Force password change + require MFA |
| SpyCloud-RevokeSessions | Identity | Revoke all active sign-in sessions |
| SpyCloud-EnforceMFA | Identity | Delete MFA methods, force re-registration |
| SpyCloud-BlockConditionalAccess | Access | Assign user to CA policy blocking group |
| SpyCloud-BlockFirewall | Network | Push block rules to Fortinet/Palo Alto |
| SpyCloud-IsolateDevice | Device | MDE isolation (full or selective) |
| SpyCloud-NotifyUser | Notify | Email user with breach details and guidance |
| SpyCloud-NotifySOC | Notify | Teams Adaptive Card alert to SOC channel |
| SpyCloud-EnrichIncident | Enrich | Add SpyCloud context to Sentinel incident |
| SpyCloud-FullRemediation | Orchestration | Chain all playbooks in 3 phases |

### Workbooks (3 Total)

| Workbook | Audience | Key Metrics |
|----------|----------|-------------|
| Executive Dashboard | Leadership/CISO | Risk posture, trends, ROI, compliance |
| SOC Operations | SOC Analysts | Active incidents, triage queues, remediation |
| Threat Intelligence | Threat Intel Team | Malware families, campaigns, IOCs, geography |

### Hunting Queries (28 Total)

Categories: session cookies, lateral movement, data exfiltration, mailbox compromise, privilege escalation, malware trends, breach impact, password reuse, risk scoring, supply chain, ransomware indicators, identity correlation.

---

## Branding & Customization

### Logo Assets

| Asset | Path | Usage |
|-------|------|-------|
| Icon (Color) | `docs/images/SpyCloud-icon-SC_2.png` | Plugin/agent icon in Copilot |
| Logo (White) | `docs/images/SpyCloud-Logo-white.png` | Dark backgrounds |
| Wordmark (Black) | `docs/images/SpyCloud_wordmark-black.png` | Light backgrounds |

### Brand Colors

| Color | Hex | Usage |
|-------|-----|-------|
| Primary (Teal) | `#00D4AA` | Accent, highlights, positive indicators |
| Secondary (Dark) | `#1a1a2e` | Backgrounds, headers |
| Accent (Orange) | `#FF6B35` | Alerts, warnings, CTAs |

### Agent Branding

The Investigation Agent uses consistent branding in its responses:
- **Name**: SENTINEL
- **Severity Indicators**: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- **Status Indicators**: ✅ Remediated, ⚠️ Partial, ❌ Unremediated
- **Analyst's Take**: Expert interpretation callouts after data presentations

### Plugin Icon URLs

All plugins reference the same SpyCloud icon for consistent brand presence in the Security Copilot interface:
```
https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/SpyCloud-icon-SC_2.png
```

---

## Deployment Guide

### Prerequisites

1. Microsoft Sentinel workspace (Log Analytics)
2. Security Copilot license
3. SpyCloud API key (for API Plugin and data ingestion)
4. Azure permissions: Contributor on resource group, Microsoft Sentinel Contributor

### Step 1: Deploy Sentinel Resources

Choose one deployment method:

**ARM Template (Recommended)**:
```bash
az deployment group create \
  --resource-group <rg-name> \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json
```

**Terraform**:
```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init && terraform plan && terraform apply
```

**Interactive Wizard**:
```bash
chmod +x scripts/deploy-wizard.sh
./scripts/deploy-wizard.sh
```

### Step 2: Install Copilot Plugins

1. Open Microsoft Security Copilot
2. Navigate to **Settings** → **Plugins** → **Custom plugins**
3. Upload each plugin file:
   - `SpyCloud_Agent.yaml` — Investigation Agent
   - `SpyCloud_Plugin.yaml` — KQL Plugin
   - `SpyCloud_API_Plugin.yaml` — API Plugin (requires API key)
4. Configure required settings (TenantId, SubscriptionId, etc.)

### Step 3: Verify

Run the post-deployment verification:
```bash
./scripts/verify-deployment.sh
```

In Security Copilot, test with:
- "What can you help me investigate?" (Agent)
- "Check SpyCloud for exposures on user@company.com" (KQL Plugin)
- "Look up SpyCloud breach data for user@company.com" (API Plugin)

---

## Compatibility Matrix

| Platform | Version | Status |
|----------|---------|--------|
| Microsoft Sentinel | 2024.x+ | ✅ Full Support |
| Security Copilot | 2024.x+ | ✅ Full Support |
| Defender XDR | 2024.x+ | ✅ Full Support |
| Entra ID | 2024.x+ | ✅ Full Support |
| Azure Commercial | All regions | ✅ Full Support |
| Azure Government | USGov, USGovDoD | ✅ Full Support |
| Defender for Endpoint | P2 | ✅ Required for MDE playbooks |
| Defender for Identity | Latest | ✅ Required for lateral movement |
| Fortinet FortiGate | 6.x+ | ✅ Required for firewall playbook |
| Palo Alto NGFW | PAN-OS 10+ | ✅ Required for firewall playbook |

### Plugin Cross-Compatibility

All three plugins are designed to work together seamlessly:

| Combination | Use Case |
|-------------|----------|
| Agent + KQL | Agent uses KQL skills for Sentinel data queries |
| Agent + API | Agent references API skills for real-time lookups |
| KQL + API | Analyst uses KQL for historical data, API for live data |
| All Three | Maximum coverage: autonomous investigation + KQL + live API |

---

## Security & Compliance

### Data Handling

- **No password display**: Agent never displays actual password values in responses
- **PII masking**: Sensitive PII (SSN, financial) is handled per compliance requirements
- **Audit trail**: All remediation actions logged to Spycloud_MDE_Logs_CL and SpyCloud_ConditionalAccessLogs_CL
- **RBAC**: Sentinel RBAC controls access to data and playbook execution

### Compliance Frameworks Supported

| Framework | Coverage |
|-----------|----------|
| GDPR | Breach notification assessment, PII exposure mapping |
| HIPAA | Health data exposure detection (health_insurance_id) |
| PCI-DSS | Financial credential monitoring (bank_number, card data) |
| SOX | Access control monitoring, remediation audit trail |
| SOC 2 | Security monitoring effectiveness metrics |
| CCPA | California consumer data exposure assessment |
| NIST CSF | Identify, Protect, Detect, Respond, Recover mapping |

### MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|--------------------|
| Initial Access | T1078 Valid Accounts, T1566 Phishing |
| Credential Access | T1555 Credentials from Password Stores, T1539 Steal Web Session Cookie |
| Lateral Movement | T1021 Remote Services, T1550 Use Alternate Authentication |
| Collection | T1114 Email Collection, T1213 Data from Information Repositories |
| Exfiltration | T1567 Exfiltration Over Web Service |
| Impact | T1486 Data Encrypted for Impact (Ransomware) |

---

## Appendix: Complete Skill Reference

### Quick Reference — All 168 Skills

**Agent Internal Skills (58)**: 35 KQL investigation skills + 6 GPT-4o analysis skills + 17 specialized sub-agents. See SpyCloud_Agent.yaml for complete definitions.

**KQL Plugin Skills (90)**: 90 promptbook skills across 29 categories querying 10 custom SpyCloud tables. See SpyCloud_Plugin.yaml for full skill definitions.

**API Plugin Skills (20)**: GetBreachDataByEmail, GetBreachDataByDomain, GetBreachDataByIp, CheckPasswordExposure, GetBreachDataByUsername, ListBreachCatalog, GetBreachCatalogEntry, CompassInvestigateEmail, CompassInvestigateDomain, CompassInvestigateIp, CompassGetDevices, CompassGetApplications, GetSipCookiesByDomain, GetSipCookiesByEmail, GetSipSessionSummary, GetIdentityExposure, GetIdentityExposureByDomain, GetIdentityWatchlist, InvestigationsSearch, InvestigationsGetDetails

### Custom Table Summary

| Table | Columns | API Source | Tier |
|-------|---------|------------|------|
| SpyCloudBreachWatchlist_CL | 73 | Enterprise Breach | Enterprise |
| SpyCloudBreachCatalog_CL | 13 | Breach Catalog | Enterprise |
| SpyCloudCompassData_CL | 29 | Compass Data | Enterprise+ |
| SpyCloudCompassDevices_CL | 8 | Compass Devices | Enterprise+ |
| SpyCloudCompassApplications_CL | 15 | Compass Applications | Enterprise+ |
| SpyCloudSIPCookies_CL | 18 | SIP Cookies | SIP License |
| SpyCloudIdentityExposure_CL | 23 | Identity Exposure | Enterprise |
| SpyCloudInvestigations_CL | 28 | Investigations | Enterprise+ |
| SpyCloud_ConditionalAccessLogs_CL | 14 | Playbook Output | All |
| Spycloud_MDE_Logs_CL | 19 | Playbook Output | All |
| **Total** | **233+** | **6 APIs + 2 playbook logs** | |

---

*SpyCloud Sentinel v8.0.0 — Darknet & Identity Threat Exposure Intelligence*
*Copyright (c) 2024-2026 SpyCloud, Inc. All rights reserved.*
