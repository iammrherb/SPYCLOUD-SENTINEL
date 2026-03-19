# SpyCloud Sentinel Supreme — Enrichment Architecture & Integration Blueprint

**Version:** 1.0 Draft  
**Date:** March 18, 2026  
**Status:** Architecture Planning — Pre-Implementation  
**Purpose:** Define the complete enrichment, automation, and integration architecture before building ARM template resources

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [SpyCloud Product & API Mapping](#2-spycloud-product--api-mapping)
3. [Current Deployment Gap Analysis](#3-current-deployment-gap-analysis)
4. [Enrichment Playbook Architecture](#4-enrichment-playbook-architecture)
5. [Cross-Platform Integration Matrix](#5-cross-platform-integration-matrix)
6. [Analytics Rules & Automation Catalog](#6-analytics-rules--automation-catalog)
7. [Table Architecture](#7-table-architecture)
8. [API Key Strategy & Cost Considerations](#8-api-key-strategy--cost-considerations)
9. [Rate Limits & Quota Management](#9-rate-limits--quota-management)
10. [Licensing & Prerequisites Matrix](#10-licensing--prerequisites-matrix)
11. [Configuration Flexibility Design](#11-configuration-flexibility-design)
12. [Deployment Decision Tree](#12-deployment-decision-tree)
13. [Open Questions & Decisions Needed](#13-open-questions--decisions-needed)

---

## 1. Executive Summary

Our current deployment excels at **data ingestion** (13 CCF pollers, 14 tables, 38+ analytics rules) and **response actions** (MDE isolation, CA password reset, Teams/Slack/ServiceNow/Jira/DevOps notifications, VirusTotal/AbuseIPDB enrichment). However, we are missing a critical layer: **real-time SpyCloud API enrichment at incident time**.

The official SpyCloud Sentinel solution from Content Hub uses 6 incident-triggered playbooks that call the SpyCloud API to enrich incidents with entity-specific data (email, domain, IP, username, password, malware). Our deployment has NONE of these — our Logic Apps call Microsoft Graph, MDE, VirusTotal, and AbuseIPDB, but never the SpyCloud API itself.

This document defines the architecture to close that gap while extending far beyond the official solution with advanced cross-platform correlations, multi-product SpyCloud API coverage, and configurable deployment based on which SpyCloud products and third-party tools the customer has.

---

## 2. SpyCloud Product & API Mapping

### 2.1 SpyCloud Products by License Tier

| Product | API Family | License Tier | Key Capabilities | Typical Customer |
|---------|-----------|-------------|-----------------|-----------------|
| **Enterprise Protection** | Enterprise v2 | Base | Breach watchlist, breach catalog, credential monitoring | All customers |
| **Compass (Endpoint Threat Protection)** | Compass | Enterprise+ / Add-on | Consumer exposure, device forensics, application-level theft | Customers with BYOD/unmanaged devices |
| **SIP (Session Identity Protection)** | SIP | Add-on | Stolen session cookies, token theft, MFA bypass data | Customers with web apps / SSO |
| **Investigations** | Investigations v2 | Separate product | Full database search, pivot on any data point, link analysis | Threat intel / IR teams |
| **IdLink** | IdLink | Add-on | Identity correlation across breaches, persona mapping | Advanced threat hunting |
| **CAP (Credential Access Protection)** | CAP | Add-on | Real-time credential check against active breach data | IAM integration use case |
| **Exposure Stats** | Exposure | Enterprise | Domain-level exposure statistics, trend data | Executive reporting |
| **Data Partnership** | Data Partnership | Partner tier | Partner data sharing, syndication | MSSP / partner use case |

### 2.2 Complete API Endpoint Inventory

#### Enterprise v2 (Base — All Customers)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/enterprise-v2/breach/data/watchlist` | GET | Bulk polling of monitored assets | ✅ CCF Poller (new) | — |
| `/enterprise-v2/breach/data/watchlist` | GET | Modified records re-check | ✅ CCF Poller (modified) | — |
| `/enterprise-v2/breach/data/emails/{email}` | GET | Get all exposures for a specific email | ❌ MISSING | **Yes — Tier 1** |
| `/enterprise-v2/breach/data/domains/{domain}` | GET | Get all exposures for a domain | ❌ MISSING | **Yes — Tier 1** |
| `/enterprise-v2/breach/data/ips/{ip}` | GET | Get exposures originating from an IP | ❌ MISSING | **Yes — Tier 1** |
| `/enterprise-v2/breach/data/usernames/{username}` | GET | Get exposures by username | ❌ MISSING | **Yes — Tier 1** |
| `/enterprise-v2/breach/data/passwords` | POST | Check if a password hash exists in breaches | ❌ MISSING | **Yes — Tier 1 (sensitive)** |
| `/enterprise-v2/breach/catalog` | GET | Bulk polling of breach metadata | ✅ CCF Poller | — |
| `/enterprise-v2/breach/catalog/{id}` | GET | Get specific breach source details | ❌ MISSING | **Yes — Tier 2** |
| `/enterprise-v2/watchlist/identifiers` | GET | Bulk polling of watchlist identifiers | ✅ CCF Poller | — |

#### Compass (Enterprise+ / Add-on)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/enterprise-v2/compass/data` | GET | Bulk polling of consumer exposures | ✅ CCF Poller | — |
| `/enterprise-v2/compass/devices` | GET | Bulk polling of infected device fingerprints | ✅ CCF Poller | — |
| `/enterprise-v2/compass/applications` | GET | Bulk polling of application-level theft | ✅ CCF Poller | — |
| `/enterprise-v2/compass/data/emails/{email}` | GET | Get compass data for a specific email | ❌ MISSING | **Yes — Tier 2** |
| `/enterprise-v2/compass/devices/{machine_id}` | GET | Get compass data for a specific device | ❌ MISSING | **Yes — Tier 2** |

#### SIP — Session Identity Protection (Add-on)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/enterprise-v2/sip/cookies/domains/{domain}` | GET | Bulk polling of stolen cookies | ✅ CCF Poller | — |
| `/enterprise-v2/sip/cookies/emails/{email}` | GET | Get stolen cookies for a specific user | ❌ MISSING | **Yes — Tier 2** |

#### Investigations v2 (Separate Product)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/investigations-v2/records/domains/{domain}` | GET | Full database search by domain | ✅ CCF Poller | — |
| `/investigations-v2/records/emails/{email}` | GET | Full database search by email | ❌ MISSING | **Yes — Tier 3** |
| `/investigations-v2/records/ips/{ip}` | GET | Full database search by IP | ❌ MISSING | **Yes — Tier 3** |
| `/investigations-v2/records/usernames/{username}` | GET | Full database search by username | ❌ MISSING | **Yes — Tier 3** |
| `/investigations-v2/records/passwords` | POST | Full database password search | ❌ MISSING | **Yes — Tier 3 (sensitive)** |

#### IdLink (Add-on)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/idlink/records/emails/{domain}` | GET | Bulk polling of identity links | ✅ CCF Poller | — |
| `/idlink/records/emails/{email}` | GET | Identity correlation for specific email | ❌ MISSING | **Yes — Tier 3** |

#### CAP — Credential Access Protection (Add-on)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/cap/records/domains/{domain}` | GET | Bulk polling of CAP records | ✅ CCF Poller | — |
| `/cap/check/emails/{email}` | GET | Real-time credential check for a user | ❌ MISSING | **Yes — Tier 2** |

#### Exposure Stats (Enterprise)

| Endpoint | Method | Use Case | Current Status | Enrichment Candidate |
|----------|--------|----------|---------------|---------------------|
| `/exposure/stats/domains/{domain}` | GET | Bulk polling of exposure stats | ✅ CCF Poller | — |

---

## 3. Current Deployment Gap Analysis

### 3.1 What We Have (Strengths)

| Category | Count | Details |
|----------|-------|---------|
| CCF Pollers | 13 | Covers all bulk ingestion endpoints |
| Custom Tables | 14 | Full schema with DCR transforms |
| Analytics Rules (ARM) | 38 | Core + IdP + cross-platform + UEBA + firewall |
| Analytics Rules (Extended) | 49 | Additional library for manual import |
| Hunting Queries | 28 | Comprehensive coverage |
| Response Playbooks | 5 | MDE isolation, CA reset, credential response, MDE blocklist, TI enrichment |
| Standalone Playbooks | 19 | Additional response templates |
| Automation Rules | 4 | Auto-response, auto-escalate, auto-triage, auto-close |
| Workbooks | 4 + 13 templates | Executive, SOC, Threat Intel, Defender/CA |
| Copilot | 267 skills | 138 plugin + 129 agent |
| Notebooks | 3 | Triage, hunting, landscape |

### 3.2 What We're Missing (Gaps)

| Gap | Impact | Priority |
|-----|--------|----------|
| **SpyCloud Custom API Connector** | No Logic App can call SpyCloud API | **P0 — Blocker** |
| **SpyCloud API Connection** | No pre-authenticated API connection for playbooks | **P0 — Blocker** |
| **Incident Enrichment Playbooks** | Incidents lack SpyCloud context at investigation time | **P0 — Critical** |
| **Enrichment Audit Table** | No visibility into what enrichment occurred | **P1 — High** |
| **Auto-Enrichment Automation Rules** | Enrichment requires manual trigger | **P1 — High** |
| **Entity-specific API lookups** | Can't look up email/IP/domain/username at incident time | **P0 — Critical** |
| **Breach catalog enrichment** | Can't get source details when investigating | **P2 — Medium** |
| **SIP cookie enrichment** | Can't check stolen cookies per-user | **P2 — Medium** |
| **Compass per-user enrichment** | Can't get consumer data per-user | **P2 — Medium** |
| **Investigation deep-dive** | Can't do full database search from Sentinel | **P3 — Nice to have** |

---

## 4. Enrichment Playbook Architecture

### 4.1 Design Principles

1. **Every playbook is optional** — toggled via ARM parameter with sensible defaults
2. **API key entered once** — ARM deployment parameter feeds the custom connector; same key works for all playbooks
3. **Product-aware** — playbooks that require Compass/SIP/Investigations only deploy when those products are enabled
4. **Rate-limit safe** — built-in throttling, severity-gated triggers, configurable cooldowns
5. **Audit everything** — every API call logged to SpyCloudEnrichmentAudit_CL
6. **Incident comments are structured** — formatted markdown with severity indicators, actionable recommendations, and links to relevant Sentinel entities

### 4.2 Playbook Catalog

#### Tier 1: Core Enrichment (Enterprise API — All Customers)

These playbooks use only the base Enterprise v2 API key that every SpyCloud customer has.

##### PB-E1: SpyCloud-Enrich-Email

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | Account (email from UPN, mailbox, or custom field) |
| **SpyCloud Endpoint** | `GET /enterprise-v2/breach/data/emails/{email}` |
| **What it returns** | All exposures for this email: severity, source IDs, password types, target domains, timestamps, infected machine IDs |
| **Incident Comment** | Formatted report: exposure count, max severity, plaintext passwords found (Y/N), most recent exposure date, top target domains, device infection status |
| **Audit Log** | Writes to SpyCloudEnrichmentAudit_CL: timestamp, incident ID, email (hashed), endpoint, records_found, max_severity, duration_ms |
| **Cross-platform value** | Correlate with SigninLogs (was this user active?), AuditLogs (any recent changes?), MDE DeviceInfo (is their device healthy?), Okta/Duo/Ping sign-in logs |
| **Auto-trigger** | Automation rule fires on any incident with Account entity from SpyCloud analytics rules |
| **ARM Parameter** | `enableEnrichEmail` (bool, default: true) |
| **Prerequisite** | SpyCloud Enterprise API key, Sentinel Responder role |
| **API calls per incident** | 1 (+ optional 1 for breach catalog lookup if source_id found) |

**Use cases this enables:**
- SOC analyst opens incident → immediately sees full SpyCloud exposure history in comments
- Automation can escalate severity if enrichment reveals plaintext passwords or severity 25
- Correlate with Entra ID sign-in logs: "This user had a successful sign-in 2 hours after exposure was published"
- Feed exposed email into CA playbook for automatic password reset
- Cross-reference with Okta/Duo: "This email authenticated via Okta 30 min after infostealer infection"

##### PB-E2: SpyCloud-Enrich-Domain

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | DNS Domain (from URL entity, target_domain field, or custom field) |
| **SpyCloud Endpoint** | `GET /enterprise-v2/breach/data/domains/{domain}` |
| **What it returns** | All exposures for the domain: affected user count, severity distribution, exposure timeline, password types, source IDs |
| **Incident Comment** | Domain exposure summary: total users affected, severity breakdown, most-exposed users (top 10), plaintext password ratio, newest exposure date |
| **Auto-trigger** | Automation rule fires on incidents with DNS entity |
| **ARM Parameter** | `enableEnrichDomain` (bool, default: true) |
| **API calls per incident** | 1 per domain entity (typically 1-3 per incident) |

**Use cases this enables:**
- Assess blast radius: "How many employees are exposed on this breached domain?"
- Identify credential reuse: domain X has 500 exposures but domain Y (internal SSO) has 50 — are they the same users?
- Feed into executive dashboard: "These are our most-targeted domains this month"
- Cross-reference with firewall logs: "Traffic to this domain from our network after breach date"

##### PB-E3: SpyCloud-Enrich-IP

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | IP Address (from network entity or infected IP field) |
| **SpyCloud Endpoint** | `GET /enterprise-v2/breach/data/ips/{ip}` |
| **What it returns** | All exposures associated with this IP: infected users, device details, malware artifacts, infection timestamps |
| **Incident Comment** | IP exposure report: associated users, devices, malware families, AV software present, infection timeline |
| **Auto-trigger** | Automation rule fires on incidents with IP entity |
| **ARM Parameter** | `enableEnrichIP` (bool, default: true) |
| **API calls per incident** | 1 per IP entity |

**Use cases this enables:**
- Network forensics: "This IP was an infection source — what credentials were stolen from it?"
- Firewall correlation: "Block this IP at Fortinet/Palo Alto/Checkpoint if it's an active infection source"
- VPN correlation: "This VPN IP was used by an infected device — revoke VPN certificate"
- Cross-reference with VirusTotal/AbuseIPDB (already in TI Enrichment playbook) for combined TI report

##### PB-E4: SpyCloud-Enrich-Username

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | Account (username — SAMAccountName, UPN prefix, or custom field) |
| **SpyCloud Endpoint** | `GET /enterprise-v2/breach/data/usernames/{username}` |
| **What it returns** | All exposures for this username across all breached sites |
| **Incident Comment** | Username exposure report: domains where this username was found, password types, cross-site reuse indicator |
| **ARM Parameter** | `enableEnrichUsername` (bool, default: true) |
| **API calls per incident** | 1 per username entity |

**Use cases this enables:**
- Detect credential stuffing risk: "This username+password pair exists on 12 different sites"
- Active Directory correlation: "This AD username was found in 3 breaches — force password change"
- ITSM ticket enrichment: "Include username exposure data in ServiceNow/Jira ticket"

##### PB-E5: SpyCloud-Enrich-Password

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) — **manual trigger only recommended** |
| **Entity** | Password hash (from SpyCloud watchlist data, NOT cleartext) |
| **SpyCloud Endpoint** | `POST /enterprise-v2/breach/data/passwords` |
| **What it returns** | All breaches where this password hash appears, indicating reuse across sites |
| **Incident Comment** | Password reuse report: number of sites, breach sources, earliest/latest appearance |
| **ARM Parameter** | `enableEnrichPassword` (bool, default: **false** — sensitive, requires explicit opt-in) |
| **Security consideration** | Never logs or transmits cleartext passwords. Only sends SHA256 hash. Audit log records hash prefix only. |
| **API calls per incident** | 1 |

**Why default OFF:** This playbook transmits password hashes to the SpyCloud API. While this is the intended use of the API and hashes are one-way, some security policies prohibit any password-related data transmission. Customers should explicitly opt in after reviewing their data handling policies.

**Use cases this enables:**
- Password reuse detection: "This password hash appears in 47 breaches across 12 sites"
- Risk scoring: "This is a known-compromised password — immediate reset required"
- Compliance: "Evidence that we detected and acted on password reuse per NIST 800-63B"

#### Tier 2: Advanced Enrichment (Requires Additional SpyCloud Products)

##### PB-E6: SpyCloud-Enrich-Malware (Enterprise API)

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | Host (infected_machine_id from SpyCloud data, or hostname from MDE/Intune) |
| **SpyCloud Endpoints** | `GET /breach/catalog/{source_id}` + entity extraction from existing watchlist data |
| **What it does** | When an incident involves a host entity, queries existing SpyCloud data for that host AND enriches with breach catalog metadata for the malware source |
| **Incident Comment** | Malware investigation report: malware family name, infection path, AV that was present, OS details, all credentials stolen from this device, all users affected, timeline, breach catalog context |
| **ARM Parameter** | `enableEnrichMalware` (bool, default: true) |
| **Prerequisite** | Only Enterprise API key needed (uses KQL against existing tables + catalog API) |

**Use cases this enables:**
- Immediate malware triage: "This device was infected with RedLine Stealer, which stole 47 credentials including SSO tokens"
- MDE correlation: "The infected machine_id maps to this MDE device — initiate isolation"
- AV gap analysis: "McAfee was installed but failed to prevent the infostealer"
- Timeline reconstruction: "Infection occurred 3 days before our EDR detected it"

##### PB-E7: SpyCloud-Enrich-Compass (Requires Compass License)

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | Account (email) or Host (device) |
| **SpyCloud Endpoints** | `GET /compass/data/emails/{email}` or `GET /compass/devices/{machine_id}` |
| **What it returns** | Consumer-side exposure data: personal accounts, non-corporate devices, application-level stolen credentials, device fingerprints |
| **Incident Comment** | Compass enrichment: personal account exposures, applications with stolen credentials (banking, social media, email), device history, consumer identity risk score |
| **ARM Parameter** | `enableEnrichCompass` (bool, default: false — requires Compass license) |
| **API key** | Uses same Enterprise API key (Compass is a feature flag, not a separate key) |

**Use cases this enables:**
- BYOD risk: "This employee's personal device has stolen credentials for 15 banking and social media apps"
- Supply chain: "This contractor's device has stolen SSO tokens for 3 client organizations"
- Unmanaged device visibility: "Devices not in MDE but appearing in Compass data"

##### PB-E8: SpyCloud-Enrich-SIP-Cookies (Requires SIP License)

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident (ApiConnectionWebhook) |
| **Entity** | Account (email) |
| **SpyCloud Endpoint** | `GET /sip/cookies/emails/{email}` |
| **What it returns** | Stolen session cookies and tokens for this user: application, cookie name, domain, expiry, theft timestamp |
| **Incident Comment** | Session hijack risk report: applications with stolen cookies, which are still valid (within expiry), recommended immediate session revocation targets |
| **ARM Parameter** | `enableEnrichSipCookies` (bool, default: false — requires SIP license) |
| **API key** | Requires separate SIP API key (`sipApiKey`) |

**Use cases this enables:**
- MFA bypass detection: "Stolen Okta session cookie is still within its validity period — revoke NOW"
- Application-specific response: "Stolen cookies for O365, Salesforce, and AWS Console — revoke each"
- Priority scoring: "Session cookies are more urgent than password-only exposures because they bypass MFA"
- Cross-reference with CloudAppEvents: "Was this stolen cookie used to access any cloud apps?"

##### PB-E9: SpyCloud-Enrich-CAP-Check (Requires CAP License)

| Property | Value |
|----------|-------|
| **Trigger** | Sentinel Incident OR Entra ID sign-in event |
| **Entity** | Account (email) |
| **SpyCloud Endpoint** | `GET /cap/check/emails/{email}` |
| **What it returns** | Real-time credential exposure status: is this user currently exposed in active breach data? |
| **Incident Comment** | CAP status: currently exposed (Y/N), active breach count, most recent exposure, recommended action |
| **ARM Parameter** | `enableEnrichCAP` (bool, default: false — requires CAP license) |

**Use cases this enables:**
- Real-time sign-in risk: "This user just signed in — check if their credentials are actively compromised"
- Conditional Access integration: "Block or require MFA step-up if CAP returns exposed status"
- Zero Trust validation: "Verify credential status before granting access to sensitive resources"

#### Tier 3: Investigation & Advanced Correlation

##### PB-E10: SpyCloud-Enrich-Investigation (Requires Investigations License)

| Property | Value |
|----------|-------|
| **Trigger** | Manual or high-severity incident only |
| **Entity** | Any (email, IP, username, domain) |
| **SpyCloud Endpoints** | `/investigations-v2/records/emails/{email}` or `/records/ips/{ip}` etc. |
| **What it returns** | Full database search across ALL SpyCloud data (not just customer watchlist) — includes data from breaches the customer's domain isn't in |
| **Incident Comment** | Deep investigation report: all known exposures globally, persona mapping, linked identities |
| **ARM Parameter** | `enableEnrichInvestigation` (bool, default: false — requires Investigations license, high API consumption) |
| **API key** | Requires separate Investigations API key (`investigationsApiKey`) |
| **Rate limit consideration** | These queries search the entire SpyCloud database and are more expensive — use only for targeted investigations |

**Use cases this enables:**
- Threat actor attribution: "This email address appears in 200+ breaches across the entire darknet"
- Insider threat: "This employee's credentials are being sold on 3 different dark web forums"
- Incident response: "Full history of this identity across all known data sources"

##### PB-E11: SpyCloud-Enrich-IdLink (Requires IdLink License)

| Property | Value |
|----------|-------|
| **Trigger** | Manual or high-severity incident |
| **Entity** | Account (email) |
| **SpyCloud Endpoint** | `/idlink/records/emails/{email}` |
| **What it returns** | Identity correlation: other emails/usernames/accounts linked to this identity across breaches |
| **ARM Parameter** | `enableEnrichIdLink` (bool, default: false — requires IdLink license) |

**Use cases this enables:**
- Persona mapping: "This corporate email is linked to 5 personal accounts with the same password"
- Shadow IT detection: "This employee has accounts on unauthorized services discovered via identity linking"
- Lateral movement prediction: "If this identity is compromised, these other accounts are also at risk"

##### PB-E12: SpyCloud-Enrich-FullInvestigation (Orchestrator)

| Property | Value |
|----------|-------|
| **Trigger** | Manual or automation rule (severity = High/Critical only) |
| **Design** | Parent Logic App that calls child enrichment playbooks in sequence |
| **Flow** | 1) Enrich-Email → 2) If malware severity, Enrich-Malware → 3) If Compass enabled, Enrich-Compass → 4) If SIP enabled, Enrich-SIP-Cookies → 5) If Investigation enabled, Enrich-Investigation → 6) Compile final report as incident comment |
| **ARM Parameter** | `enableEnrichFullInvestigation` (bool, default: true) |
| **Smart routing** | Only calls APIs the customer is licensed for — checks enable flags before each child call |
| **Cost protection** | Built-in severity gate: only fires on severity >= configurable threshold (default: 20) |
| **API calls per incident** | 2-8 depending on which products are enabled and severity routing |

**Why this should be a parent/child design:**
- Each child playbook is independently useful AND callable from the orchestrator
- If one API call fails, others still complete
- Customers who add SpyCloud products later just enable the flag — the orchestrator automatically includes the new enrichment
- Cost-effective: only calls APIs the customer has

---

## 5. Cross-Platform Integration Matrix

### 5.1 Microsoft Security Services

| Service | Data Source Table | SpyCloud Correlation | Enrichment Playbook Use | Required License |
|---------|-----------------|---------------------|------------------------|-----------------|
| **Entra ID** | SigninLogs, AuditLogs | Match exposed email → sign-in activity | Enrich-Email: "Was this exposed user active?" | Entra ID P1 (sign-in logs) |
| **Entra ID Protection** | AADRiskyUsers, AADUserRiskEvents | Match exposed email → risk events | Enrich-Email + CAP: "Is this risky user also exposed?" | Entra ID P2 |
| **Defender for Endpoint** | DeviceInfo, DeviceEvents, DeviceNetworkEvents, DeviceProcessEvents | Match infected_machine_id → MDE device | Enrich-Malware: "Is this infected device in MDE?" | MDE P2 |
| **Defender for Cloud Apps** | CloudAppEvents | Match stolen cookies → cloud app access | Enrich-SIP-Cookies: "Was stolen cookie used in cloud app?" | Defender for Cloud Apps |
| **Defender for Office 365** | EmailEvents, UrlClickEvents | Match exposed email → phishing targets | Enrich-Email: "Was this exposed user targeted by phishing?" | Defender for O365 P1/P2 |
| **Microsoft 365** | OfficeActivity | Match exposed email → file/mail access | Enrich-Email: "Did exposed user access SharePoint after exposure?" | M365 E3/E5 |
| **Azure Activity** | AzureActivity | Match exposed identity → cloud resource changes | Enrich-Email: "Did compromised identity modify Azure resources?" | Azure subscription |
| **Intune** | IntuneDevices | Match infected device → managed device status | Enrich-Malware: "Is infected device Intune-managed?" | Intune P1 |
| **UEBA** | BehaviorAnalytics, IdentityInfo | Match exposed user → behavioral anomalies | All enrichment: "Does this user have UEBA anomalies post-exposure?" | Sentinel UEBA (free with Sentinel) |

### 5.2 Identity Providers (Third-Party)

| IdP | Data Source Table | SpyCloud Correlation | Enrichment Use | Required Connector |
|-----|-----------------|---------------------|---------------|-------------------|
| **Okta** | OktaSSO / Okta_CL | Match email → Okta sign-in events | "Exposed credential used in Okta auth?" | Okta SSO connector (Content Hub) |
| **Duo** | Duo_CL / CiscoISE | Match email → Duo MFA events | "Exposed user authenticated via Duo?" | Cisco Duo connector |
| **Ping Identity** | PingFederate_CL | Match email → PingOne/PingFed events | "Exposed credential in Ping auth?" | Ping Identity connector |
| **CyberArk** | CyberArk_CL | Match username → privileged session | "Exposed credential has PAM access?" | CyberArk connector |
| **OneLogin** | OneLogin_CL | Match email → OneLogin events | "Exposed credential in OneLogin auth?" | Custom connector |
| **Auth0** | Auth0_CL | Match email → Auth0 events | "Exposed credential in Auth0 auth?" | Custom connector |

### 5.3 Firewalls & Network Security

| Vendor | Data Source Table | SpyCloud Correlation | Enrichment Use | Required Connector |
|--------|-----------------|---------------------|---------------|-------------------|
| **Fortinet** | CommonSecurityLog (DeviceVendor=Fortinet) | Match infected IP → firewall sessions | "Infected IP passed through firewall?" | Fortinet connector |
| **Palo Alto** | CommonSecurityLog (DeviceVendor=PaloAlto) | Match infected IP → PAN sessions | "Block infected IP at PAN firewall" | Palo Alto connector |
| **Checkpoint** | CommonSecurityLog (DeviceVendor=CheckPoint) | Match infected IP → CP sessions | "Infected IP in Checkpoint logs?" | Checkpoint connector |
| **Cisco ASA/FTD** | CommonSecurityLog (DeviceVendor=Cisco) | Match infected IP → ASA sessions | "Infected IP traversed ASA?" | Cisco ASA connector |
| **Zscaler** | ZscalerNSS_CL | Match infected IP/user → Zscaler sessions | "Infected user bypassing Zscaler?" | Zscaler connector |

### 5.4 DNS & Proxy

| Service | Data Source Table | SpyCloud Correlation | Use Case |
|---------|-----------------|---------------------|----------|
| **Azure DNS** | DnsEvents | Match infected device → DNS queries to C2 | "Infected device resolving malware C2 domains" |
| **Infoblox** | Infoblox_CL | Match infected IP → DNS resolution | "DNS queries from infected source" |
| **Cisco Umbrella** | CiscoUmbrella_CL | Match infected user → blocked domains | "Umbrella blocked C2 from infected device?" |

### 5.5 EDR / AV (Third-Party)

| Vendor | Data Source Table | SpyCloud Correlation | Use Case |
|--------|-----------------|---------------------|----------|
| **CrowdStrike** | CrowdStrike_CL / CommonSecurityLog | Match infected device → CrowdStrike detection | "Did CrowdStrike detect the infostealer?" |
| **SentinelOne** | SentinelOne_CL | Match infected device → S1 detection | "S1 missed this infostealer — gap analysis" |
| **Carbon Black** | CarbonBlack_CL | Match infected device → CB detection | "CB alert correlation with SpyCloud infection" |
| **Trend Micro** | TrendMicro_CL | Match AV software → infection bypass | "Trend Micro was present but infection succeeded" |
| **Symantec / Broadcom** | Symantec_CL | Match AV software → infection bypass | "Symantec endpoint was bypassed" |

### 5.6 ITSM & Ticketing

| Service | Integration Method | Use Case | Required |
|---------|-------------------|----------|----------|
| **ServiceNow** | Logic App HTTP action | Auto-create incident ticket with SpyCloud enrichment data | ServiceNow instance + credentials |
| **Jira** | Logic App HTTP action | Auto-create Jira issue for exposed credential remediation | Jira instance + API token |
| **Azure DevOps** | Logic App HTTP action | Create work item for security team tracking | Azure DevOps project |
| **PagerDuty** | Logic App HTTP webhook | Page on-call for critical (sev 25) exposures | PagerDuty API key |
| **Slack** | Logic App HTTP webhook | SOC channel notification with enrichment summary | Slack webhook URL |
| **Teams** | Logic App HTTP webhook | Teams channel adaptive card with enrichment details | Teams webhook URL |

### 5.7 Threat Intelligence Platforms

| Service | Integration | Use Case |
|---------|------------|----------|
| **VirusTotal** | Already in TI-Enrichment playbook | IP reputation check on infection source IPs |
| **AbuseIPDB** | Already in TI-Enrichment playbook | IP abuse confidence score |
| **GreyNoise** | Can be added to TI-Enrichment | Distinguish targeted vs. opportunistic scanning |
| **Shodan** | Logic App HTTP action | Check if infected IP has exposed services |
| **MISP** | Logic App HTTP action | Feed SpyCloud IOCs into MISP for sharing |
| **ThreatConnect** | Logic App HTTP action | Enrich SpyCloud data with TC threat intelligence |
| **Recorded Future** | Logic App HTTP action | Cross-reference SpyCloud IOCs with RF intelligence |
| **Sentinel TI** | ThreatIntelligenceIndicator table | Match SpyCloud IOCs against Sentinel TI feed |

---

## 6. Analytics Rules & Automation Catalog

### 6.1 Enrichment-Triggered Analytics Rules (NEW — Require Enrichment Playbooks)

These rules query the SpyCloudEnrichmentAudit_CL table to detect patterns across enrichment results.

| # | Rule Name | Severity | Trigger | Use Case | Prerequisites |
|---|-----------|----------|---------|----------|--------------|
| E1 | Enrichment Revealed Plaintext Password | High | Enrichment audit shows plaintext_found=true | Escalate incident when enrichment discovers plaintext credentials | Enrich-Email playbook |
| E2 | Enrichment Revealed Multi-Domain Reuse | Medium | Enrichment shows same user on 5+ domains | Password reuse risk escalation | Enrich-Email playbook |
| E3 | Enrichment Gap — No Enrichment After 1 Hour | Medium | Incident exists but no enrichment audit record | SLA monitoring: enrichment playbook may have failed | SpyCloudEnrichmentAudit_CL |
| E4 | User Re-Exposed After Remediation | High | Enrichment on a user who was previously remediated (CA logs) | Remediation failure: user was reset but got re-exposed | Enrich-Email + CA playbook |
| E5 | High-Value Target with Stolen Cookies | Critical | SIP enrichment reveals valid session cookies for VIP | Immediate session revocation required | Enrich-SIP + VIP watchlist |
| E6 | Compass Reveals Unmanaged Device Infection | High | Compass enrichment finds device not in MDE inventory | Shadow IT / BYOD infection outside corporate visibility | Enrich-Compass + MDE |
| E7 | Investigation Reveals Threat Actor Pattern | High | Investigation enrichment finds 50+ linked identities | Possible targeted attack or credential stuffing campaign | Enrich-Investigation |

### 6.2 Automation Rules for Enrichment (NEW)

| Rule | Trigger Condition | Action | Severity Gate | Product Required |
|------|------------------|--------|--------------|-----------------|
| AutoEnrich-Email | Incident created with Account entity + provider contains "SpyCloud" | Run SpyCloud-Enrich-Email | All severities | Enterprise (base) |
| AutoEnrich-Host | Incident created with Host entity + title contains "Malware" or "Infection" | Run SpyCloud-Enrich-Malware | Severity >= Medium | Enterprise (base) |
| AutoEnrich-IP | Incident created with IP entity + provider contains "SpyCloud" | Run SpyCloud-Enrich-IP | Severity >= Medium | Enterprise (base) |
| AutoEnrich-Domain | Incident created with DNS entity + provider contains "SpyCloud" | Run SpyCloud-Enrich-Domain | Severity >= Medium | Enterprise (base) |
| AutoEnrich-Full | Incident severity = High or Critical + provider contains "SpyCloud" | Run SpyCloud-Enrich-FullInvestigation | Severity >= High | Enterprise (base) + any enabled products |
| AutoEnrich-SIP | Incident title contains "Session" or "Cookie" or "MFA Bypass" | Run SpyCloud-Enrich-SIP-Cookies | Severity >= High | SIP |
| AutoEnrich-CAP | Entra ID sign-in from new location or new device | Run SpyCloud-Enrich-CAP-Check | N/A (proactive) | CAP |

---

## 7. Table Architecture

### 7.1 New Table: SpyCloudEnrichmentAudit_CL

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | When the enrichment occurred |
| IncidentId | string | Sentinel incident ID or ARM resource ID |
| IncidentTitle | string | Incident display name |
| PlaybookName | string | Which enrichment playbook ran |
| EntityType | string | email, domain, ip, username, password_hash, host, cookie |
| EntityValue | string | The entity that was looked up (email masked: j***@company.com) |
| EntityValueHash | string | SHA256 of the entity for correlation without exposing PII |
| SpyCloudEndpoint | string | API endpoint called |
| SpyCloudProduct | string | Enterprise, Compass, SIP, Investigations, IdLink, CAP |
| RecordsFound | int | Number of records returned |
| MaxSeverity | int | Highest severity in results (2, 5, 20, 25) |
| PlaintextFound | bool | Whether plaintext passwords were in results |
| CookiesFound | bool | Whether stolen session cookies were in results |
| SourceIds | dynamic | Array of breach source IDs found |
| MalwareFamilies | dynamic | Array of malware family names found |
| ActionTaken | string | What happened after enrichment (escalated, commented, triggered_response, no_action) |
| DurationMs | int | API call duration in milliseconds |
| ApiResponseCode | int | HTTP response code from SpyCloud API |
| ErrorMessage | string | Error details if API call failed |

**Why this table matters:**
- Enables "enrichment gap" analytics rules
- Provides SOC metrics: "How many incidents were enriched? Average time? Success rate?"
- Compliance evidence: "We enriched and acted on 100% of high-severity incidents"
- Workbook visualization: enrichment activity over time, top enriched entities, API performance

### 7.2 Existing Tables — No Changes Needed

The 14 existing tables cover all bulk ingestion needs. The enrichment playbooks write to **incident comments** (not new tables) for the enrichment results themselves. The audit table above is the only new table needed.

**Rationale for NOT creating per-enrichment tables:**
- Enrichment data is transient and incident-specific — it belongs as incident context, not standalone records
- Creating separate tables for each enrichment type would add 8-12 more tables, significantly increasing cost and complexity
- The SpyCloudEnrichmentAudit_CL table provides queryable metadata WITHOUT duplicating the SpyCloud data (which is already in the watchlist/catalog/compass tables from CCF polling)
- If a customer needs the raw enrichment data in a table (not just incident comments), they can enable the "write enrichment to table" option which would write to SpyCloudBreachWatchlist_CL using the same schema

---

## 8. API Key Strategy & Cost Considerations

### 8.1 API Key Architecture

| API Key Parameter | ARM Param Name | Products It Covers | Where It's Used |
|------------------|---------------|-------------------|----------------|
| SpyCloud Enterprise | `apiKey` | Breach Watchlist, Breach Catalog, Identity Exposure, Compass (if enabled), Exposure Stats | CCF pollers (connector page) + ALL enrichment playbooks + Logic App custom connector |
| SIP | `sipApiKey` | SIP Cookies | CCF SIP poller + Enrich-SIP-Cookies playbook |
| Investigations | `investigationsApiKey` | Investigations v2 | CCF Investigations poller + Enrich-Investigation playbook |
| IdLink | `idlinkApiKey` | IdLink | CCF IdLink poller + Enrich-IdLink playbook |
| CAP | `capApiKey` | CAP | CCF CAP poller + Enrich-CAP-Check playbook |
| Data Partnership | `dataPartnershipApiKey` | Data Partnership | CCF Data Partnership poller only |
| Exposure | `exposureApiKey` | Exposure Stats | CCF Exposure poller only |
| VirusTotal | `virusTotalApiKey` | VirusTotal | TI Enrichment playbook only |

**Key sharing design:** The `apiKey` parameter is entered ONCE during ARM deployment and automatically feeds into:
1. The SpyCloud Custom API Connector (Microsoft.Web/customApis)
2. The SpyCloud API Connection (Microsoft.Web/connections)
3. All enrichment Logic Apps via the connection reference

The user must ALSO enter it on the Sentinel connector page for CCF pollers (this is unavoidable due to CCF's `[[parameters()]]` architecture). The createUiDefinition.json and connector page will clearly state "use the same API key you entered during deployment."

### 8.2 Sentinel Cost Considerations

| Cost Factor | Impact | Mitigation |
|-------------|--------|------------|
| **Log Analytics ingestion** | ~$2.76/GB ingested. Enrichment audit table adds minimal data (~1KB per enrichment) | 100 enrichments/day = ~3MB/month = negligible cost |
| **Logic App executions** | ~$0.000025/action. Enrichment playbook ~10-15 actions per run | 100 enrichments/day × 15 actions = $0.0375/day = ~$1.14/month |
| **Sentinel incidents** | No per-incident cost, but high incident volume increases analyst workload | Severity gating on automation rules prevents over-enrichment |
| **Data retention** | SpyCloudEnrichmentAudit_CL uses workspace retention setting (default 90 days) | Configurable 30-730 days |

**Bottom line: Enrichment adds negligible cost** — typically under $5/month for most organizations. The value (automated triage, faster MTTR, compliance evidence) far outweighs the cost.

### 8.3 SpyCloud API Cost Considerations

| Scenario | API Calls/Day | Within Standard Limits? | Recommendation |
|----------|--------------|------------------------|----------------|
| Small org (10 incidents/day) | ~10-70 calls | ✅ Yes (limit: 864,000/day at 10 QPS) | Enable all Tier 1 + auto-enrichment |
| Medium org (100 incidents/day) | ~100-700 calls | ✅ Yes | Enable all Tier 1-2 + selective Tier 3 |
| Large org (1000+ incidents/day) | ~1,000-7,000 calls | ✅ Yes | Enable all tiers, consider severity gating on Tier 3 |
| Over-subscription risk | >50,000 calls/day | ⚠️ Possible at extreme volume | Implement cooldown, dedup, severity gate |

**Built-in protections:**
- Severity gating: Auto-enrichment only fires above configurable severity threshold
- Deduplication: Don't re-enrich the same entity within a configurable cooldown period (default: 24 hours)
- Rate limiting: Logic App retry policy with exponential backoff, max 3 retries
- Batch optimization: For domain enrichment, aggregate all domains from a single incident into one API call where possible

---

## 9. Rate Limits & Quota Management

### 9.1 SpyCloud API Rate Limits

| API | Rate Limit | Burst | Daily Quota | Our Usage Pattern |
|-----|-----------|-------|------------|-------------------|
| Enterprise v2 | 10 req/sec | 10 | Unlimited (fair use) | CCF: ~2 QPS sustained. Enrichment: burst of 1-5 per incident |
| Compass | 10 req/sec | 10 | Unlimited | CCF: ~2 QPS. Enrichment: 1-2 per incident |
| SIP | 10 req/sec | 10 | Unlimited | CCF: ~2 QPS. Enrichment: 1 per incident |
| Investigations | 10 req/sec | 10 | May be metered | CCF: ~2 QPS. Enrichment: 1 per incident (manual only) |
| IdLink | 10 req/sec | 10 | May be metered | CCF: ~2 QPS. Enrichment: 1 per incident (manual only) |
| CAP | 10 req/sec | 10 | Unlimited | CCF: ~2 QPS. Enrichment: 1 per sign-in event |

### 9.2 Quota Protection Design

```
Enrichment Playbook Execution Flow:

1. Incident triggers automation rule
2. Check severity gate (configurable threshold)
   → Below threshold? Skip enrichment, log "skipped_low_severity"
3. Check entity dedup cache (KQL query against audit table)
   → Same entity enriched within cooldown? Skip, log "skipped_dedup"
4. Check rate limit counter (Azure Table Storage or variable)
   → Approaching daily limit? Log "skipped_rate_limit", alert SOC
5. Call SpyCloud API with retry policy (3 retries, exponential backoff)
6. Parse response, format incident comment
7. Write to SpyCloudEnrichmentAudit_CL
8. If results indicate high risk → trigger downstream response playbook
```

---

## 10. Licensing & Prerequisites Matrix

### 10.1 Per-Playbook Prerequisites

| Playbook | SpyCloud License | SpyCloud API Key | Azure/Sentinel License | External Connectors | Data Sources |
|----------|-----------------|-----------------|----------------------|-------------------|-------------|
| **Enrich-Email** | Enterprise (base) | `apiKey` | Sentinel | None required | SpyCloudBreachWatchlist_CL |
| **Enrich-Domain** | Enterprise (base) | `apiKey` | Sentinel | None required | SpyCloudBreachWatchlist_CL |
| **Enrich-IP** | Enterprise (base) | `apiKey` | Sentinel | None required | SpyCloudBreachWatchlist_CL |
| **Enrich-Username** | Enterprise (base) | `apiKey` | Sentinel | None required | SpyCloudBreachWatchlist_CL |
| **Enrich-Password** | Enterprise (base) | `apiKey` | Sentinel | None required | SpyCloudBreachWatchlist_CL |
| **Enrich-Malware** | Enterprise (base) | `apiKey` | Sentinel | None (uses existing data) | SpyCloudBreachWatchlist_CL + SpyCloudBreachCatalog_CL |
| **Enrich-Compass** | Compass (add-on) | `apiKey` (same) | Sentinel | None required | SpyCloudCompassData_CL |
| **Enrich-SIP-Cookies** | SIP (add-on) | `sipApiKey` | Sentinel | None required | SpyCloudSipCookies_CL |
| **Enrich-CAP-Check** | CAP (add-on) | `capApiKey` | Sentinel | None required | SpyCloudCAP_CL |
| **Enrich-Investigation** | Investigations (separate) | `investigationsApiKey` | Sentinel | None required | SpyCloudInvestigations_CL |
| **Enrich-IdLink** | IdLink (add-on) | `idlinkApiKey` | Sentinel | None required | SpyCloudIdLink_CL |
| **Enrich-FullInvestigation** | Enterprise (base) + any enabled | `apiKey` + enabled product keys | Sentinel | None required | All enabled tables |
| **MDE Remediation** | None (response only) | None | Sentinel + MDE P2 | MDE API permissions | DeviceInfo |
| **CA Remediation** | None (response only) | None | Sentinel + Entra ID P1+ | Graph API permissions | SigninLogs, AuditLogs |
| **TI Enrichment** | None | `virusTotalApiKey` (optional) | Sentinel | None | SecurityIncident |

### 10.2 Cross-Platform Analytics Rules Prerequisites

| Rule Category | Rules | Required Data Source | Required Connector | Required License |
|--------------|-------|---------------------|-------------------|-----------------|
| Core SpyCloud Detection | 14 | SpyCloudBreachWatchlist_CL only | None (CCF built-in) | SpyCloud Enterprise |
| IdP Correlation (Okta) | 2 | OktaSSO or Okta_CL | Okta SSO (Content Hub) | Okta + SpyCloud Enterprise |
| IdP Correlation (Duo) | 2 | Duo_CL or CiscoISE | Cisco Duo (Content Hub) | Duo + SpyCloud Enterprise |
| IdP Correlation (Ping) | 2 | PingFederate_CL | Ping Identity (Content Hub) | Ping + SpyCloud Enterprise |
| IdP Correlation (Entra) | 2 | SigninLogs | Entra ID Diagnostics | Entra ID P1 + SpyCloud Enterprise |
| O365/Entra Advanced | 6 | SigninLogs, AuditLogs, OfficeActivity | M365 + Entra ID Diagnostics | M365 E3+ + Entra P1+ |
| UEBA Correlation | 4 | BehaviorAnalytics | UEBA enabled in Sentinel | Sentinel (UEBA is free) |
| Firewall Correlation | 4 | CommonSecurityLog | Fortinet/PAN/Checkpoint | Firewall vendor license |
| DNS Correlation | 2 | DnsEvents, Syslog | DNS connector | DNS logging enabled |
| MDE Correlation | 4 | DeviceInfo, DeviceEvents, AlertEvidence | Microsoft Defender XDR | MDE P2 |
| Cloud Apps | 2 | CloudAppEvents | Defender for Cloud Apps | MDCA license |
| Email | 2 | EmailEvents, UrlClickEvents | Defender for O365 | MDO P1/P2 |
| Azure Activity | 2 | AzureActivity | Azure Activity connector | Azure subscription |
| Enrichment-Based | 7 | SpyCloudEnrichmentAudit_CL | Enrichment playbooks deployed | SpyCloud Enterprise + enrichment |

---

## 11. Configuration Flexibility Design

### 11.1 ARM Parameter Groups for Enrichment

```
Group: Enrichment Configuration
├── enableEnrichmentPlaybooks (bool, default: true)     ← Master toggle
│   ├── enableEnrichEmail (bool, default: true)          ← Tier 1
│   ├── enableEnrichDomain (bool, default: true)         ← Tier 1
│   ├── enableEnrichIP (bool, default: true)             ← Tier 1
│   ├── enableEnrichUsername (bool, default: true)        ← Tier 1
│   ├── enableEnrichPassword (bool, default: false)      ← Tier 1 (sensitive)
│   ├── enableEnrichMalware (bool, default: true)        ← Tier 2 (uses base key)
│   ├── enableEnrichCompass (bool, default: false)       ← Tier 2 (requires Compass)
│   ├── enableEnrichSipCookies (bool, default: false)    ← Tier 2 (requires SIP)
│   ├── enableEnrichCAP (bool, default: false)           ← Tier 2 (requires CAP)
│   ├── enableEnrichInvestigation (bool, default: false) ← Tier 3 (requires Investigations)
│   ├── enableEnrichIdLink (bool, default: false)        ← Tier 3 (requires IdLink)
│   └── enableEnrichFullInvestigation (bool, default: true) ← Orchestrator
│
├── enrichmentSeverityThreshold (int, default: 5)        ← Min severity for auto-enrichment
├── enrichmentCooldownHours (int, default: 24)           ← Dedup window
├── enrichmentMaxCallsPerHour (int, default: 100)        ← Rate limit protection
└── enableEnrichmentAuditTable (bool, default: true)     ← Audit logging
```

### 11.2 createUiDefinition.json Wizard Step

The enrichment configuration would be a dedicated wizard step with:
- InfoBox explaining what enrichment is and why it matters
- Product selection: checkboxes for which SpyCloud products the customer has
- Based on selection, auto-enable/disable the appropriate enrichment playbooks
- API key entry fields that appear only for selected products
- Severity threshold slider with explanation of API consumption implications
- Cost estimate display based on expected incident volume

---

## 12. Deployment Decision Tree

```
Customer Deployment Flow:

Q1: Do you have a SpyCloud Enterprise API key?
  → No: Cannot deploy. Contact SpyCloud.
  → Yes: Deploy Tier 1 foundation (CCF + tables + core rules)

Q2: Do you want automated enrichment? (Recommended)
  → No: Skip enrichment playbooks. Manual investigation via Copilot.
  → Yes: Deploy custom connector + API connection + Tier 1 enrichment playbooks

Q3: Which SpyCloud products do you have? (Select all that apply)
  → Compass: Enable Compass pollers + Enrich-Compass playbook
  → SIP: Enable SIP pollers + Enrich-SIP-Cookies playbook (enter SIP API key)
  → Investigations: Enable Investigations pollers + Enrich-Investigation (enter key)
  → IdLink: Enable IdLink pollers + Enrich-IdLink (enter key)
  → CAP: Enable CAP pollers + Enrich-CAP-Check (enter key)

Q4: Which Microsoft security products do you have?
  → MDE P2: Enable MDE playbook + MDE correlation rules
  → Entra ID P1/P2: Enable CA playbook + Entra correlation rules
  → Defender for Cloud Apps: Enable cloud app correlation rules
  → M365 E3/E5: Enable O365 correlation rules

Q5: Which third-party tools do you use?
  → Okta/Duo/Ping/CyberArk: Enable IdP correlation rules
  → Fortinet/PAN/Checkpoint: Enable firewall correlation rules
  → ServiceNow/Jira: Enable ITSM ticket creation in playbooks
  → Teams/Slack: Enable notification webhooks
  → VirusTotal: Enable TI enrichment playbook
```

---

## 13. Open Questions & Decisions Needed

### Architecture Decisions

1. **Custom Connector vs. HTTP Actions:** Should we build a full Microsoft.Web/customApis resource (more complex ARM, but provides a reusable connector in the Logic App designer) or use direct HTTP actions in each playbook (simpler ARM, but duplicates API config across playbooks)? **Recommendation: Custom Connector** — it's what the official solution uses and it means the API key is stored once in the connection, not in every playbook.

2. **Enrichment data storage:** Should enrichment results write to incident comments only, or also to a queryable table? **Recommendation: Both** — incident comments for analyst UX, audit table for analytics rules and workbook visualization. But the enrichment detail goes to comments; only metadata goes to the audit table.

3. **Scheduled proactive enrichment:** Should we add playbooks that proactively enrich NEW watchlist records before an analytics rule fires? This would mean enrichment data is available BEFORE the SOC analyst opens the incident. **Trade-off:** More API consumption, but better analyst experience. **Recommendation: Optional, default off** — the CCF pollers + analytics rules + auto-enrichment on incident creation is fast enough (typically under 2 minutes from exposure to enriched incident).

### Implementation Sequencing

**Phase 1 (Immediate — This PR):**
- SpyCloud Custom API Connector
- SpyCloud API Connection (using `apiKey` parameter)
- SpyCloudEnrichmentAudit_CL table + DCR stream
- Tier 1 enrichment playbooks (Email, Domain, IP, Username, Password)
- Enrich-Malware playbook
- Auto-enrichment automation rules
- Updated createUiDefinition.json wizard step

**Phase 2 (Next PR):**
- Tier 2 enrichment playbooks (Compass, SIP, CAP)
- Enrich-FullInvestigation orchestrator
- Enrichment-based analytics rules
- Updated workbook with enrichment dashboard tab

**Phase 3 (Following PR):**
- Tier 3 enrichment playbooks (Investigation, IdLink)
- Advanced cross-platform correlation rules
- Proactive enrichment playbook (optional)
- Comprehensive documentation update

---

*This document is the architectural blueprint. No code should be written until the decisions in Section 13 are confirmed and the scope is locked.*
