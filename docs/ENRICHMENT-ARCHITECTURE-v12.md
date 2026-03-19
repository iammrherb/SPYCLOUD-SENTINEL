# SpyCloud Sentinel Supreme — Complete Enrichment Architecture & Use Case Reference

**Version:** 12.0 Planning Draft
**Date:** March 18, 2026
**Status:** Architecture Review — Pre-Implementation

---

## Table of Contents

1. Executive Summary
2. SpyCloud Product & API Landscape
3. Licensing Tiers & API Key Strategy
4. Complete Use Case Catalog
5. Enrichment Playbook Architecture
6. Cross-Platform Integration Matrix
7. Analytics Rules & Automation Design
8. Tables & Data Model
9. Rate Limiting, Quotas & Cost Considerations
10. Prerequisites & Data Source Requirements
11. Deployment Configuration Options
12. Best Practices & Recommendations

---

## 1. Executive Summary

This document defines the complete architecture for SpyCloud Sentinel Supreme v12.0, expanding from a CCF polling-only deployment to a full enrichment, investigation, and automated response platform. The key additions are:

- **SpyCloud Custom API Connector** — enables all Logic Apps to call SpyCloud API at incident time
- **10+ enrichment playbooks** — real-time entity-specific lookups when incidents fire
- **Enrichment audit table** — queryable trail of all API enrichment actions
- **Enhanced automation rules** — auto-trigger enrichment on every SpyCloud incident
- **Cross-platform correlation** — enrichment data correlated with MDE, Entra ID, firewalls, DNS, IdPs, and ITSM tools
- **API rate limiting** — built-in throttling to stay within SpyCloud quotas
- **Flexible deployment** — every component toggled by ARM parameter, gated by SpyCloud license tier

### Architecture Principle: Layered Intelligence

```
LAYER 1: BULK INGESTION (CCF Pollers)
  → 13 pollers ingest data on schedule into 14 tables
  → Analytics rules detect patterns → Create incidents

LAYER 2: REAL-TIME ENRICHMENT (New Logic App Playbooks)
  → Incidents trigger enrichment playbooks
  → Playbooks call SpyCloud API for fresh, entity-specific data
  → Results written to incident comments + enrichment audit table

LAYER 3: AUTOMATED RESPONSE (Existing + Enhanced Playbooks)
  → MDE device isolation, CA password reset, session revocation
  → TI enrichment (VirusTotal/AbuseIPDB/GreyNoise)
  → ITSM ticket creation (Jira/ServiceNow/Azure DevOps)
  → SOC notification (Teams/Slack/Email)

LAYER 4: INVESTIGATION (Copilot + Notebooks)
  → 267 Copilot skills for interactive investigation
  → 3 Jupyter notebooks for deep analysis
  → 28 hunting queries for proactive threat hunting
```

---

## 2. SpyCloud Product & API Landscape

### 2.1 SpyCloud Products & Their API Tiers

| Product | API Tier | Key Capabilities | Typical Customer |
|---------|----------|-----------------|------------------|
| **Enterprise Protection** | Enterprise v2 | Breach watchlist, breach catalog, breach data lookups by email/domain/IP/username/password | All customers (base product) |
| **Compass (Endpoint Threat Protection)** | Enterprise v2 (Compass endpoints) | Consumer identity monitoring, infected device fingerprints, application-level stolen cred data, device-to-user correlation | Customers with Compass add-on |
| **SIP (Session Identity Protection)** | Enterprise v2 (SIP endpoints) | Stolen session cookies, authentication tokens, cookie domain mapping | Customers with SIP add-on |
| **Investigations** | Investigations v2 | Full database access for threat hunting, pivot on any data point, attribution research | Customers with Investigations license |
| **IdLink** | IdLink API | Identity correlation across personas, link analysis, identity graph | Customers with IdLink license |
| **CAP (Compromised Account Protection)** | CAP API | Consumer-facing compromised account checks | Consumer-facing businesses |
| **Exposure Stats** | Exposure API | Domain-level exposure statistics and trending | All Enterprise customers |
| **Data Partnership** | Data Partnership API | Partner data sharing and ingestion | Data partnership customers |

### 2.2 Complete API Endpoint Catalog

#### Enterprise Breach Data (Base — All Customers)

| Endpoint | Method | Use | Entity Type | Rate Limit Concern |
|----------|--------|-----|-------------|-------------------|
| `/enterprise-v2/breach/data/watchlist` | GET | Bulk polling — new records | Watchlist | Medium (scheduled) |
| `/enterprise-v2/breach/data/watchlist` (modified) | GET | Bulk polling — re-sighted records | Watchlist | Medium (scheduled) |
| `/enterprise-v2/breach/data/emails/{email}` | GET | Enrichment — lookup by email | Account | Low (per-incident) |
| `/enterprise-v2/breach/data/domains/{domain}` | GET | Enrichment — lookup by domain | DNS Domain | Low-Medium |
| `/enterprise-v2/breach/data/ips/{ip}` | GET | Enrichment — lookup by IP | IP Address | Low (per-incident) |
| `/enterprise-v2/breach/data/usernames/{username}` | GET | Enrichment — lookup by username | Account | Low (per-incident) |
| `/enterprise-v2/breach/data/passwords` | POST | Enrichment — check password hash | Password | Low (sensitive) |

#### Breach Catalog (Base — All Customers)

| Endpoint | Method | Use | Rate Limit Concern |
|----------|--------|-----|--------------------|
| `/enterprise-v2/breach/catalog` | GET | Bulk polling — all breach sources | Low (scheduled) |
| `/enterprise-v2/breach/catalog/{id}` | GET | Enrichment — single breach context | Very Low |

#### Compass (Requires Compass License)

| Endpoint | Method | Use | Entity Type |
|----------|--------|-----|-------------|
| `/enterprise-v2/compass/data` | GET | Bulk polling — consumer exposures | Watchlist |
| `/enterprise-v2/compass/data/emails/{email}` | GET | Enrichment — consumer exposure by email | Account |
| `/enterprise-v2/compass/devices` | GET | Bulk polling — infected devices | Device |
| `/enterprise-v2/compass/devices/{machine_id}` | GET | Enrichment — device details | Host |
| `/enterprise-v2/compass/applications` | GET | Bulk polling — application data | Application |

#### SIP — Session Identity Protection (Requires SIP License)

| Endpoint | Method | Use | Entity Type |
|----------|--------|-----|-------------|
| `/enterprise-v2/sip/cookies/domains/{domain}` | GET | Bulk polling + enrichment — stolen cookies | DNS Domain |
| `/enterprise-v2/sip/cookies/emails/{email}` | GET | Enrichment — stolen cookies by email | Account |

#### Investigations (Requires Investigations License)

| Endpoint | Method | Use | Entity Type |
|----------|--------|-----|-------------|
| `/investigations-v2/records/domains/{domain}` | GET | Deep investigation by domain | DNS Domain |
| `/investigations-v2/records/emails/{email}` | GET | Deep investigation by email | Account |
| `/investigations-v2/records/ips/{ip}` | GET | Deep investigation by IP | IP Address |
| `/investigations-v2/records/usernames/{username}` | GET | Deep investigation by username | Account |
| `/investigations-v2/records/passwords` | POST | Deep investigation by password | Password |

#### IdLink (Requires IdLink License)

| Endpoint | Method | Use | Entity Type |
|----------|--------|-----|-------------|
| `/idlink/records/emails/{domain}` | GET | Identity correlation by domain | Identity Graph |

#### Other APIs

| Endpoint | Method | License | Use |
|----------|--------|---------|-----|
| `/exposure/stats/domains/{domain}` | GET | Enterprise | Domain exposure statistics |
| `/cap/records/domains/{domain}` | GET | CAP | Consumer compromised account checks |
| `/data-partnership/records/domains/{domain}` | GET | Partnership | Partner data sharing |

---

## 3. Licensing Tiers & API Key Strategy

### 3.1 API Key Configuration Model

```
DEPLOYMENT TIME (ARM Template):
  apiKey (required)           → Used by: Custom Connector, all enrichment Logic Apps
  compassApiKey (optional)    → Used by: Compass pollers + Compass enrichment
  sipApiKey (optional)        → Used by: SIP pollers + SIP enrichment
  investigationsApiKey (opt)  → Used by: Investigations pollers + Investigation enrichment
  idlinkApiKey (optional)     → Used by: IdLink poller
  capApiKey (optional)        → Used by: CAP poller
  dataPartnershipApiKey (opt) → Used by: Data Partnership poller
  exposureApiKey (optional)   → Used by: Exposure poller

CONNECT TIME (Sentinel Connector Page):
  Same apiKey entered again   → Used by: CCF pollers (mandatory double-entry due to CCF framework)
  Same optional keys          → Used by: Optional CCF pollers
```

### 3.2 Value by License Tier

| Tier | What You Get in Sentinel | Pollers | Enrichment Playbooks | Analytics Rules | Estimated Value |
|------|-------------------------|---------|---------------------|----------------|----------------|
| **Enterprise (Base)** | Breach watchlist + catalog + email/domain/IP/username enrichment | 3 (watchlist new, modified, catalog) | 6 (email, domain, IP, username, password, catalog) | 38 embedded + 49 extended | High — covers 80% of use cases |
| **+ Compass** | Consumer identity + device forensics + application data | +3 (data, devices, apps) | +2 (compass email, compass device) | +2 (compass cross-reference, device reinfection) | High for orgs with BYOD/consumer exposure |
| **+ SIP** | Stolen session cookies and tokens | +1 (cookies by domain) | +1 (cookies by email) | +1 (stolen cookie alert) | Critical for MFA bypass defense |
| **+ Investigations** | Full database access for hunting | +1 (domain records) | +3 (email, IP, username deep investigation) | +2 (investigation enrichment) | High for IR teams and threat hunters |
| **+ IdLink** | Identity correlation graph | +1 (email domain) | +1 (identity graph enrichment) | +1 (multi-persona detection) | Medium-High for identity-focused orgs |
| **Enterprise + All** | Everything above | 13 pollers | 14+ playbooks | Full rule library | Maximum coverage |

### 3.3 Single Key vs Multiple Keys — Pros and Cons

| Approach | Pros | Cons | Recommendation |
|----------|------|------|----------------|
| **Single API key for everything** | Simple, one entry point, less configuration | Some endpoints may require separate keys by product, may hit per-key rate limits faster | Good for Enterprise-only customers |
| **Separate keys per product** | Better rate limit isolation, clearer API usage tracking, matches SpyCloud billing model | More configuration, more connection resources | Recommended for customers with multiple SpyCloud products |
| **Shared key with fallback** | Logic: try enterprise key first, fall back to product-specific key if provided | Best flexibility but more complex Logic App logic | What we should implement |

**Recommendation:** Implement the shared-with-fallback model. The ARM template accepts all keys. Enrichment playbooks use `if(not(empty(parameters('specificKey'))), parameters('specificKey'), parameters('apiKey'))` — same pattern already used by the SIP and Investigations pollers.

---

## 4. Complete Use Case Catalog

### 4.1 Use Cases by Category

#### CATEGORY A: Credential Exposure Detection & Response

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| A1 | Employee credential exposed in breach | Analytics rule detects new breach record | BreachWatchlist_CL (email, severity, source_id) | Entra ID SigninLogs, Okta/Duo/Ping logs | Force password reset, revoke sessions, notify user | Enterprise |
| A2 | Plaintext password available to attackers | Analytics rule detects password_plaintext != null | BreachWatchlist_CL (password_plaintext, email) | Entra ID PasswordChangeEvents | Force immediate reset, add to CA policy, block sign-in | Enterprise |
| A3 | Password reused across multiple domains | Analytics rule detects same hash 3+ domains | BreachWatchlist_CL (password hash, target_domain) | None (self-contained) | Notify user of reuse, force reset on corporate domain | Enterprise |
| A4 | Executive/VIP account exposed | Analytics rule with VIP watchlist join | BreachWatchlist_CL + SpyCloudVIP watchlist | Entra ID AuditLogs for admin actions | Immediate reset, disable account pending verification, SOC alert, executive notification | Enterprise |
| A5 | Credential exposure followed by successful sign-in | Analytics rule correlating exposure + sign-in | BreachWatchlist_CL + SigninLogs | Entra ID ConditionalAccessPolicies | Revoke sessions, force MFA re-registration, investigate sign-in source | Enterprise |
| A6 | Exposed credential used in OAuth app consent | Analytics rule correlating exposure + OAuth consent | BreachWatchlist_CL + AuditLogs | Entra ID Application Consent | Revoke OAuth consent, investigate app permissions | Enterprise |

#### CATEGORY B: Infostealer / Device Infection Response

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| B1 | Infostealer infection detected (sev 20+) | Analytics rule on severity >= 20 | BreachWatchlist_CL (infected_machine_id, infected_path, user_os) | MDE DeviceInfo, DeviceNetworkEvents | Isolate device in MDE, tag, investigate infection path | Enterprise |
| B2 | Device re-infection (same machine_id, multiple sources) | Analytics rule detecting repeat infections | BreachWatchlist_CL (infected_machine_id count) | MDE DeviceAlerts | Isolate + reimage recommendation, investigate root cause | Enterprise |
| B3 | Infostealer with stolen cookies/sessions (sev 25) | Analytics rule on severity = 25 | BreachWatchlist_CL (cookie data, auth tokens) | Entra ID SigninLogs, CloudAppEvents | Revoke ALL sessions, force MFA re-registration, isolate device | Enterprise + SIP |
| B4 | AV present but failed to prevent infection | Analytics rule on av_softwares != null AND severity >= 20 | BreachWatchlist_CL (av_softwares) | MDE AntivirusDetections | Alert SOC to AV bypass, investigate AV configuration | Enterprise |
| B5 | Infected device accessing corporate network | Analytics rule correlating infection + network events | BreachWatchlist_CL (ip_addresses) + firewall logs | Fortinet/PaloAlto/Cisco firewall, DNS logs | Block at firewall, isolate device, alert NOC | Enterprise |
| B6 | Multiple users compromised from same device | Analytics rule on machine_id with dcount(email) > 1 | BreachWatchlist_CL (infected_machine_id, email) | Entra ID for all affected users | Reset ALL affected users, investigate shared device | Enterprise |
| B7 | Stolen application credentials (OAuth tokens, API keys) | SIP cookie detection + application correlation | SipCookies_CL, CompassApplications_CL | CloudAppEvents, AADServicePrincipalSignInLogs | Revoke tokens, rotate API keys, notify app owners | SIP + Compass |

#### CATEGORY C: Identity & Access Management

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| C1 | Exposed user signs in from new location | Exposure + impossible travel detection | BreachWatchlist_CL + SigninLogs | Entra ID NamedLocations, ConditionalAccess | Block sign-in, require MFA, investigate | Enterprise |
| C2 | Exposed user changes MFA method | Exposure + MFA registration change | BreachWatchlist_CL + AuditLogs | Entra ID AuthenticationMethods | Alert SOC, verify with user, revert if unauthorized | Enterprise |
| C3 | Exposed user grants admin role | Exposure + privilege escalation | BreachWatchlist_CL + AuditLogs | Entra ID PIM logs | Revoke role, investigate, alert security team | Enterprise |
| C4 | Compromised credential in IdP sign-in (Okta) | Exposure + Okta sign-in correlation | BreachWatchlist_CL + Okta_CL | Okta SSO connector | Force Okta password reset, revoke Okta sessions | Enterprise |
| C5 | Compromised credential in IdP sign-in (Duo) | Exposure + Duo auth correlation | BreachWatchlist_CL + CiscoSecureEndpoint_CL | Duo MFA connector | Lock Duo account, investigate bypass attempts | Enterprise |
| C6 | Compromised credential in IdP sign-in (Ping) | Exposure + Ping auth correlation | BreachWatchlist_CL + PingFederate logs | Ping Identity connector | Force Ping password reset | Enterprise |
| C7 | Identity linkage across multiple personas | IdLink correlation identifies same person with multiple accounts | IdLink_CL (identity graph) | Entra ID, Okta, Duo | Investigate all linked accounts, reset all | IdLink |

#### CATEGORY D: Network & Perimeter Security

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| D1 | Infected device IP in firewall allow logs | IP correlation across exposure + firewall | BreachWatchlist_CL (ip_addresses) + firewall logs | Fortinet FortiGate, Palo Alto PAN-OS, Cisco ASA/Meraki, Zscaler | Block IP at perimeter, investigate allowed traffic | Enterprise |
| D2 | Infected device IP in VPN connections | IP correlation with VPN logs | BreachWatchlist_CL (ip_addresses) + VPN logs | GlobalProtect, AnyConnect, Zscaler ZPA, Netskope | Terminate VPN session, block reconnection | Enterprise |
| D3 | DNS queries to malware C2 domains | Infected host resolving known bad domains | BreachWatchlist_CL (infected_machine_id) + DNS logs | Infoblox, Cisco Umbrella, Azure DNS, Windows DNS | Sinkhole C2 domain, isolate device | Enterprise |
| D4 | Infected device IP in proxy/web gateway logs | IP correlation with web proxy | BreachWatchlist_CL (ip_addresses) + proxy logs | Zscaler ZIA, Netskope, Symantec WSS | Block at proxy, investigate browsing activity | Enterprise |

#### CATEGORY E: Cloud & SaaS Security

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| E1 | Compromised user accessing SharePoint/OneDrive | Exposure + M365 file access | BreachWatchlist_CL + OfficeActivity | M365 connector | Audit file access, check for mass download, alert DLP team | Enterprise |
| E2 | Compromised user modifying Azure resources | Exposure + Azure activity | BreachWatchlist_CL + AzureActivity | Azure Activity connector | Investigate resource changes, revert if suspicious | Enterprise |
| E3 | Compromised user in AWS/GCP (cross-cloud) | Exposure + cloud provider logs | BreachWatchlist_CL + AWSCloudTrail/GCPAuditLogs | AWS/GCP connectors | Alert cloud security team, investigate cross-cloud impact | Enterprise |
| E4 | Stolen SaaS session cookies being used | SIP cookie data + CloudAppEvents | SipCookies_CL + CloudAppEvents | Microsoft Defender for Cloud Apps | Revoke SaaS sessions, force re-authentication | SIP |
| E5 | Compromised user creating mail forwarding rules | Exposure + Exchange audit | BreachWatchlist_CL + OfficeActivity (Exchange) | M365 connector | Remove forwarding rule, alert user, investigate exfiltration | Enterprise |

#### CATEGORY F: Compliance & Governance

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| F1 | PII exposure requiring breach notification | SSN, financial, health data in exposure | BreachWatchlist_CL (social_security_number, bank_number, etc.) | Compliance watchlist | Alert legal/compliance, initiate breach notification workflow | Enterprise |
| F2 | GDPR/CCPA data subject exposure | EU/CA resident PII in exposure | BreachWatchlist_CL + geo data | DPA records | Initiate data subject notification, log for compliance audit | Enterprise |
| F3 | Remediation SLA breach | Exposure without remediation action within threshold | BreachWatchlist_CL + ConditionalAccessLogs_CL + MDE_Logs_CL | None (self-contained) | Escalate to security manager, create compliance incident | Enterprise |
| F4 | Enrichment audit for compliance evidence | All enrichment API calls logged | SpyCloudEnrichmentAudit_CL | None | Demonstrate due diligence in incident response | Enterprise |

#### CATEGORY G: Threat Intelligence & Hunting

| # | Use Case | Trigger | SpyCloud Data | Correlated With | Response Actions | Required License |
|---|----------|---------|---------------|----------------|-----------------|-----------------|
| G1 | New malware family targeting organization | New breach source_id in catalog | BreachCatalog_CL (new entries) | ThreatIntelligenceIndicators | Alert threat intel team, update MITRE mapping | Enterprise |
| G2 | Malware family attribution and tracking | Catalog enrichment on incident | BreachCatalog_CL + BreachWatchlist_CL | MITRE ATT&CK framework | Build threat actor profile, update detection rules | Enterprise |
| G3 | Cross-org infection campaign (same malware, multiple domains) | Analytics rule on source_id with dcount(email_domain) > 1 | BreachWatchlist_CL (source_id, email_domain) | ThreatIntelligenceIndicators | Investigate campaign scope, notify affected business units | Enterprise |
| G4 | Investigations API deep dive on threat actor | Manual or automated investigation | Investigations_CL (full database access) | Multiple data sources | Build complete threat actor profile, support law enforcement | Investigations |
| G5 | Identity graph traversal for threat hunting | IdLink correlation across personas | IdLink_CL (identity graph) | All identity sources | Uncover hidden threat actor personas | IdLink |

---

## 5. Enrichment Playbook Architecture

### 5.1 Custom Connector Design

The SpyCloud Custom API Connector (`Microsoft.Web/customApis`) exposes the following actions to Logic Apps:

| Action Name | Endpoint | Method | Input | Output | License |
|-------------|----------|--------|-------|--------|---------|
| GetBreachDataByEmail | `/breach/data/emails/{email}` | GET | email, since, severity, source_id | Breach records array | Enterprise |
| GetBreachDataByDomain | `/breach/data/domains/{domain}` | GET | domain, since, severity | Breach records array | Enterprise |
| GetBreachDataByIP | `/breach/data/ips/{ip}` | GET | ip, since, severity | Breach records array | Enterprise |
| GetBreachDataByUsername | `/breach/data/usernames/{username}` | GET | username, since, severity | Breach records array | Enterprise |
| CheckPasswordExposure | `/breach/data/passwords` | POST | password_hash, hash_type | Breach records array | Enterprise |
| GetBreachCatalogEntry | `/breach/catalog/{id}` | GET | source_id | Breach metadata | Enterprise |
| GetCompassDataByEmail | `/compass/data/emails/{email}` | GET | email | Compass records | Compass |
| GetCompassDeviceById | `/compass/devices/{machine_id}` | GET | machine_id | Device details | Compass |
| GetStolenCookiesByEmail | `/sip/cookies/emails/{email}` | GET | email | Cookie records | SIP |
| GetInvestigationByEmail | `/investigations-v2/records/emails/{email}` | GET | email | Investigation records | Investigations |
| GetInvestigationByIP | `/investigations-v2/records/ips/{ip}` | GET | ip | Investigation records | Investigations |
| GetExposureStatsByDomain | `/exposure/stats/domains/{domain}` | GET | domain | Exposure statistics | Enterprise |

### 5.2 Enrichment Playbook Inventory

#### Tier 1: Core Entity Enrichment (Enterprise License)

| Playbook | Trigger | Entity | API Endpoint | What It Does | Output |
|----------|---------|--------|-------------|-------------|--------|
| SpyCloud-Enrich-Email | Incident (Account entity) | Email address | GetBreachDataByEmail | Looks up all breach records for the email. Summarizes: total exposures, max severity, plaintext passwords, domains affected, last exposure date, device count. | Incident comment (formatted) + EnrichmentAudit_CL |
| SpyCloud-Enrich-Domain | Incident (DNS entity) | Domain | GetBreachDataByDomain | Looks up all breach records for the domain. Summarizes: total exposed users, severity distribution, breach sources, plaintext password count, top exposed users. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-IP | Incident (IP entity) | IP address | GetBreachDataByIP | Looks up all breach records associated with this IP. Summarizes: infected devices at this IP, users affected, malware families, infection dates. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-Username | Incident (Account entity) | Username | GetBreachDataByUsername | Looks up breach records by username (for non-email identifiers). Summarizes: exposure count, domains, severity. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-Password | Incident (manual trigger) | Password hash | CheckPasswordExposure | Checks if a specific password hash appears in breach data. Reports: exposure count, domains where used, breach sources. **Note:** Sensitive — disabled by default. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-Catalog | Incident (any with source_id) | Source ID | GetBreachCatalogEntry | Enriches incident with breach source context: breach title, description, acquisition date, record count, confidence score, type (public/private). | Incident comment + EnrichmentAudit_CL |

#### Tier 2: Advanced Enrichment (Product-Specific Licenses)

| Playbook | Trigger | License | API Endpoints | What It Does | Output |
|----------|---------|---------|--------------|-------------|--------|
| SpyCloud-Enrich-Compass | Incident (Account entity) | Compass | GetCompassDataByEmail + GetCompassDeviceById | Looks up consumer exposure data: application-level stolen credentials, device fingerprints, infection artifacts. Cross-references with corporate exposure to find shared devices. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-StolenCookies | Incident (Account entity) | SIP | GetStolenCookiesByEmail | Looks up stolen session cookies for the user. Reports: affected applications/domains, cookie types, expiration status, MFA bypass risk assessment. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-Investigation | Incident (any entity) | Investigations | GetInvestigationByEmail or GetInvestigationByIP | Deep investigation using full SpyCloud database. Returns all available data including historical exposures, linked identities, full PII profile. | Incident comment + EnrichmentAudit_CL |
| SpyCloud-Enrich-Identity | Incident (Account entity) | IdLink | IdLink API | Identity graph traversal: finds all linked personas, email addresses, usernames, and accounts for the subject. Maps the full identity attack surface. | Incident comment + EnrichmentAudit_CL |

#### Tier 3: Orchestrated Investigation

| Playbook | Trigger | License | What It Does | Cost Impact |
|----------|---------|---------|-------------|-------------|
| SpyCloud-FullInvestigation | Incident (High/Critical severity) | Enterprise (minimum) | Orchestration playbook that chains: (1) Email enrichment → (2) Catalog enrichment on source_id → (3) Compass device lookup if machine_id found → (4) SIP cookie check if available → (5) Correlation with MDE device status → (6) Correlation with Entra sign-in activity → (7) Builds comprehensive investigation report as incident comment. Each step is **conditionally executed** — if Compass/SIP/Investigations keys aren't provided, those steps are gracefully skipped. | Medium — makes 3-7 API calls per incident depending on available licenses. Rate limited to 1 full investigation per minute. |

### 5.3 Full Investigation Playbook — Detailed Flow

```
TRIGGER: Incident created with severity High or Critical
         AND incident title contains "SpyCloud"

STEP 1: Extract Entities
  → Get all Account, Host, IP, DNS entities from incident
  → Prioritize: email first, then hostname, then IP

STEP 2: Email Enrichment (always runs)
  → Call GetBreachDataByEmail
  → Parse response: count, max severity, plaintext passwords, domains
  → Extract source_id(s) for catalog enrichment
  → Extract infected_machine_id(s) for device enrichment
  IF no results → log "no enrichment data" and continue

STEP 3: Catalog Enrichment (always runs if source_ids found)
  → For each unique source_id (max 5):
    → Call GetBreachCatalogEntry
    → Get breach title, type, description, confidence
  → Build breach source context section

STEP 4: Compass Device Lookup (runs IF compassApiKey provided)
  → For each infected_machine_id (max 3):
    → Call GetCompassDeviceById
    → Get device fingerprint, malware details, other affected users
  IF compassApiKey empty → skip with note "Compass data not available — enable Compass for device forensics"

STEP 5: SIP Cookie Check (runs IF sipApiKey provided)
  → Call GetStolenCookiesByEmail for primary email
  → Report stolen cookies, affected applications, MFA bypass risk
  IF sipApiKey empty → skip with note "SIP data not available — enable SIP for stolen cookie detection"

STEP 6: MDE Correlation (runs IF MDE connector available)
  → Query DeviceInfo for infected_machine_id or user_hostname
  → Check if device is managed, compliant, isolated
  → Check recent MDE alerts for the device
  IF MDE not available → skip

STEP 7: Entra ID Correlation (always runs)
  → Query SigninLogs for the exposed email in last 48h
  → Check: successful sign-ins, locations, apps, risk level
  → Query AuditLogs for password changes, MFA changes, role changes

STEP 8: Build Investigation Report
  → Compile all findings into structured Adaptive Card or HTML
  → Add to incident as comment
  → Log all API calls to EnrichmentAudit_CL
  → Update incident severity if warranted
  → Update incident tags with enrichment metadata

STEP 9: Recommend Actions
  → Based on findings, add recommended actions as comment:
    - If plaintext password → "IMMEDIATE: Force password reset"
    - If active sign-ins → "URGENT: Revoke all sessions"
    - If stolen cookies → "CRITICAL: Revoke sessions + re-register MFA"
    - If device infected → "IMPORTANT: Isolate device in MDE"
    - If AV bypass → "INVESTIGATE: Review endpoint protection"
```

### 5.4 Pros & Cons of Full Investigation Playbook

| Aspect | Pros | Cons |
|--------|------|------|
| **Comprehensiveness** | Single playbook provides complete picture; SOC gets everything in one incident comment | Higher API call count per incident; more complex Logic App logic |
| **Flexibility** | Gracefully handles missing licenses; each step is conditional | More parameters to configure; more testing needed |
| **Cost** | 3-7 API calls per incident (minimal for per-incident triggers) | Could be expensive if incidents are very high volume (>100/day) |
| **SOC Efficiency** | Analyst gets investigation-ready report immediately | Report can be overwhelming for low-severity incidents |
| **Maintainability** | Single playbook to update when API changes | More complex to debug; parent+child pattern would be simpler |

**Recommendation:** Implement as a single playbook with conditional steps rather than parent-child. The conditional pattern is more reliable in Logic Apps (child workflows add latency and complexity), and the total API call count is manageable. Add a rate limiter: max 1 full investigation per minute, max 50 per day. For incidents exceeding this, queue for batch processing.

---

## 6. Cross-Platform Integration Matrix

### 6.1 Microsoft Services

| Service | Data Source / Connector | How SpyCloud Enrichment Helps | Required License (Microsoft) |
|---------|----------------------|------------------------------|------------------------------|
| **Entra ID (Azure AD)** | SigninLogs, AuditLogs, AADRiskyUsers, AADRiskySignIns | Correlate exposed credentials with sign-in activity; detect compromise-then-access patterns | Entra ID P1 (sign-in logs) or P2 (risky users/sign-ins) |
| **Microsoft Defender for Endpoint** | DeviceInfo, DeviceNetworkEvents, DeviceAlertEvents, DeviceLogonEvents | Correlate infected machine IDs with MDE device inventory; auto-isolate infected devices | MDE P2 |
| **Microsoft Defender XDR** | AlertEvidence, IdentityLogonEvents, IdentityQueryEvents | Cross-correlate SpyCloud exposures with Defender XDR alert timelines | Microsoft 365 E5 or Defender XDR license |
| **Microsoft Defender for Cloud Apps** | CloudAppEvents, McasShadowItReporting | Detect compromised users accessing SaaS applications; stolen cookie usage | Defender for Cloud Apps license |
| **Microsoft Defender for Cloud** | SecurityAlert, SecurityRecommendation | Correlate exposed credentials with cloud resource access | Defender for Cloud enabled |
| **Microsoft 365** | OfficeActivity (Exchange, SharePoint, Teams) | Detect mail forwarding rules, mass file downloads, lateral movement after exposure | M365 E3+ |
| **Entra ID Protection** | AADRiskyUsers, AADRiskySignIns | Combine SpyCloud severity with Entra risk score for composite risk assessment | Entra ID P2 |
| **Microsoft Intune** | IntuneDevices | Correlate infected devices with compliance status; trigger compliance policy enforcement | Intune license |
| **Azure Activity** | AzureActivity | Detect exposed users modifying cloud resources (VMs, storage, networking) | Azure subscription |

### 6.2 Third-Party Identity Providers

| IdP | Sentinel Connector | Correlation Use Cases | Required for Rules |
|-----|-------------------|----------------------|-------------------|
| **Okta** | Okta SSO (Content Hub) | SC-013: Compromised credential used in Okta sign-in; Okta session hijack after exposure | Okta_CL table |
| **Cisco Duo** | Cisco Duo / Secure Endpoint | SC-014: Compromised credential in Duo authentication; MFA bypass detection | CiscoDuo_CL table |
| **Ping Identity** | PingFederate connector | SC-015: Compromised credential in PingOne authentication | PingFederate_CL table |
| **CyberArk** | CyberArk EPM/PAM | Privileged account exposure detection; vault credential compromise | CyberArk_CL table |
| **OneLogin** | OneLogin connector | SSO session hijack; credential exposure in OneLogin auth events | OneLogin_CL table |
| **Auth0** | Auth0 connector | Consumer identity exposure correlation; account takeover detection | Auth0_CL table |
| **ForgeRock** | Custom connector | Identity exposure in ForgeRock-managed identities | Custom table |

### 6.3 Firewalls & Network Security

| Vendor | Sentinel Connector | Correlation Use Cases | Data Table |
|--------|-------------------|----------------------|------------|
| **Fortinet FortiGate** | Fortinet connector (CEF) | Infected device IP in FSSO sessions, firewall allow/deny logs | CommonSecurityLog |
| **Palo Alto PAN-OS** | Palo Alto connector (CEF) | Infected device IP in User-ID traffic, GlobalProtect VPN sessions | CommonSecurityLog |
| **Cisco ASA/Meraki** | Cisco connector (CEF/Syslog) | Infected device IP in VPN/firewall logs | CommonSecurityLog |
| **Zscaler ZIA/ZPA** | Zscaler connector | Compromised user accessing cloud apps via Zscaler; infected device web traffic | Zscaler_CL |
| **Netskope** | Netskope connector | CASB correlation with stolen cookies; data exfiltration detection | Netskope_CL |
| **Check Point** | Check Point connector | Firewall correlation with infected IPs | CommonSecurityLog |

### 6.4 EDR / AV / Endpoint Security

| Vendor | Sentinel Connector | Correlation Use Cases |
|--------|-------------------|----------------------|
| **CrowdStrike Falcon** | CrowdStrike connector | Cross-reference SpyCloud infections with CrowdStrike detections; validate AV bypass | 
| **SentinelOne** | SentinelOne connector | Endpoint detection correlation; infection validation |
| **Carbon Black** | VMware Carbon Black connector | Process execution correlation on infected devices |
| **Trend Micro** | Trend Micro connector | Endpoint protection gap analysis |
| **Sophos** | Sophos connector | AV coverage gap detection on infected devices |
| **Symantec/Broadcom** | Symantec connector | Endpoint detection correlation |

### 6.5 ITSM & Collaboration

| Platform | Integration Method | Use Cases |
|----------|-------------------|-----------|
| **ServiceNow** | Logic App HTTP action | Auto-create incidents for high-severity exposures; link to SpyCloud enrichment data |
| **Jira** | Logic App HTTP action | Create security tickets for remediation tracking; link to enrichment |
| **Azure DevOps** | Logic App HTTP action | Create work items for security engineering follow-up |
| **Microsoft Teams** | Logic App webhook | Real-time SOC alerts with enrichment context; interactive Adaptive Cards |
| **Slack** | Logic App webhook | SOC channel notifications with formatted enrichment summaries |
| **PagerDuty** | Logic App HTTP action | Critical alert escalation for severity 25 infostealer incidents |
| **Email (O365/SMTP)** | Logic App email action | User notification of credential exposure; manager escalation |

### 6.6 DNS & Threat Intelligence

| Service | Sentinel Connector | Use Cases |
|---------|-------------------|-----------|
| **Infoblox** | Infoblox connector | DNS query correlation with infected host IPs |
| **Cisco Umbrella** | Umbrella connector | DNS sinkhole correlation; C2 communication detection |
| **Azure DNS** | Azure DNS Analytics | Internal DNS resolution from infected hosts |
| **Microsoft Defender TI** | ThreatIntelligenceIndicators | Cross-reference SpyCloud malware families with MDTI IOCs |
| **MISP** | MISP connector | IOC sharing from SpyCloud infection data |
| **VirusTotal** | TI Enrichment playbook (existing) | IP/hash reputation for infected device artifacts |
| **AbuseIPDB** | TI Enrichment playbook (existing) | IP reputation for infection source IPs |

---

## 7. Analytics Rules & Automation Design

### 7.1 Analytics Rule Categories (Current + Proposed)

| Category | Current Rules | Proposed Additions | Total |
|----------|--------------|-------------------|-------|
| Core Detection | 14 | +2 (SIP cookie, application credential theft) | 16 |
| IdP Correlation | 4 (Okta, Duo, Ping, Entra) | +3 (CyberArk, OneLogin, Auth0) | 7 |
| Cross-Platform | 12 (DNS, Network, MDE, Cloud, O365, UEBA) | +4 (Intune compliance, CASB, DLP, Conditional Access) | 16 |
| O365/Entra | 4 | +2 (eDiscovery, PowerBI access) | 6 |
| UEBA/Firewall | 4 | +2 (Proxy logs, VPN anomaly) | 6 |
| Compliance | 1 (health) | +3 (SLA breach, PII notification, enrichment gap) | 4 |
| SIP-Specific | 0 | +3 (cookie theft alert, app session hijack, MFA bypass) | 3 |
| Compass-Specific | 2 | +2 (application exposure spike, consumer+corporate overlap) | 4 |
| Investigations-Specific | 0 | +2 (investigation enrichment, threat actor correlation) | 2 |
| **Total** | **38+** | **+23** | **~64** |

### 7.2 Automation Rules Design

| Rule Name | Trigger | Condition | Action | Priority |
|-----------|---------|-----------|--------|----------|
| SpyCloud-AutoEnrich-Account | Incident created | Has Account entity AND title contains "SpyCloud" | Run SpyCloud-Enrich-Email | 1 (highest) |
| SpyCloud-AutoEnrich-Host | Incident created | Has Host entity AND title contains "SpyCloud" | Run SpyCloud-Enrich-Malware (if Compass key available) | 2 |
| SpyCloud-AutoEnrich-IP | Incident created | Has IP entity AND title contains "SpyCloud" | Run SpyCloud-Enrich-IP | 3 |
| SpyCloud-AutoEnrich-Domain | Incident created | Has DNS entity AND title contains "SpyCloud" | Run SpyCloud-Enrich-Domain | 4 |
| SpyCloud-AutoInvestigate | Incident created | Severity = High/Critical AND title contains "SpyCloud" | Run SpyCloud-FullInvestigation | 5 |
| SpyCloud-AutoResponse-MDE | Incident created | Severity >= High AND has Host entity AND MDE enabled | Run SpyCloud-MDE-Remediation | 6 |
| SpyCloud-AutoResponse-CA | Incident created | Has Account entity AND plaintext password detected | Run SpyCloud-CA-Remediation | 7 |
| SpyCloud-AutoEscalate-VIP | Incident created | Account entity matches VIP watchlist | Change severity to Critical + Run SOC notification | 8 |
| SpyCloud-AutoClose-Remediated | Incident updated | All entities remediated (CA + MDE actions complete) | Close incident with "True Positive - resolved" | 9 |
| SpyCloud-AutoEnrich-TI | Incident created | Has IP entity AND TI enrichment enabled | Run SpyCloud-TI-Enrichment (VirusTotal/AbuseIPDB) | 10 |

---

## 8. Tables & Data Model

### 8.1 Complete Table Inventory

| # | Table | Columns | Source | Category | Purpose |
|---|-------|---------|--------|----------|---------|
| 1 | SpyCloudBreachWatchlist_CL | 73 | CCF Poller | Ingestion | Primary credential/PII/device exposure data |
| 2 | SpyCloudBreachCatalog_CL | 13 | CCF Poller | Ingestion | Breach source metadata |
| 3 | SpyCloudCompassData_CL | 29 | CCF Poller | Ingestion | Consumer identity exposures |
| 4 | SpyCloudCompassDevices_CL | 8 | CCF Poller | Ingestion | Infected device fingerprints |
| 5 | SpyCloudCompassApplications_CL | TBD | CCF Poller | Ingestion | Application-level stolen credentials |
| 6 | SpyCloudSipCookies_CL | TBD | CCF Poller | Ingestion | Stolen session cookies |
| 7 | SpyCloudIdentityExposure_CL | TBD | CCF Poller | Ingestion | Identity exposure profiles |
| 8 | SpyCloudInvestigations_CL | TBD | CCF Poller | Ingestion | Investigation records |
| 9 | SpyCloudIdLink_CL | TBD | CCF Poller | Ingestion | Identity correlation |
| 10 | SpyCloudDataPartnership_CL | TBD | CCF Poller | Ingestion | Partner data |
| 11 | SpyCloudExposure_CL | TBD | CCF Poller | Ingestion | Exposure statistics |
| 12 | SpyCloudCAP_CL | TBD | CCF Poller | Ingestion | Compromised account protection |
| 13 | Spycloud_MDE_Logs_CL | 19 | Playbook | Response Audit | MDE isolation/tagging actions |
| 14 | SpyCloud_ConditionalAccessLogs_CL | 14 | Playbook | Response Audit | CA password reset/revocation actions |
| 15 | **SpyCloudEnrichmentAudit_CL** | ~20 | **NEW — Enrichment Playbooks** | **Enrichment Audit** | **All API enrichment calls logged** |

### 8.2 SpyCloudEnrichmentAudit_CL Schema (NEW)

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | When the enrichment API call was made |
| IncidentId | string | Sentinel incident ID that triggered enrichment |
| IncidentTitle | string | Incident title for context |
| PlaybookName | string | Which enrichment playbook ran |
| EntityType | string | Entity type enriched (Account, Host, IP, DNS) |
| EntityValue | string | Entity value (email, hostname, IP) — PII masked for passwords |
| ApiEndpoint | string | SpyCloud API endpoint called |
| ApiResponseCode | int | HTTP response code (200, 404, 429, etc.) |
| RecordsFound | int | Number of breach records returned |
| MaxSeverity | int | Highest severity in returned records |
| PlaintextPasswordsFound | int | Count of plaintext passwords in results |
| StolenCookiesFound | int | Count of stolen cookies (SIP enrichment) |
| BreachSourceIds | dynamic | Array of source_ids found |
| InfectedMachineIds | dynamic | Array of infected_machine_ids found |
| EnrichmentDurationMs | int | API call duration in milliseconds |
| ApiKeyType | string | Which API key was used (enterprise, compass, sip, investigations) |
| ActionsTaken | dynamic | Array of response actions triggered by this enrichment |
| ErrorMessage | string | Error details if API call failed |

---

## 9. Rate Limiting, Quotas & Cost Considerations

### 9.1 SpyCloud API Rate Limits

| API Tier | Typical Rate Limit | Burst Limit | Daily Limit | Notes |
|----------|-------------------|-------------|-------------|-------|
| Enterprise | 2-10 QPS | 20 QPS | Varies by contract | Contact SpyCloud for exact limits |
| Compass | 2-5 QPS | 10 QPS | Varies by contract | Separate from Enterprise quota |
| SIP | 2-5 QPS | 10 QPS | Varies by contract | Separate quota |
| Investigations | 1-2 QPS | 5 QPS | Often lower limits | Expensive API — use judiciously |

### 9.2 Rate Limiting Strategy in Playbooks

```
BUILT-IN PROTECTIONS:
1. Per-playbook concurrency control (Logic App concurrency setting = 1-5)
2. Retry with exponential backoff on 429 responses (3 retries, 30s/60s/120s)
3. Daily execution cap per playbook (configurable ARM parameter)
4. Rate limit check before API call (query EnrichmentAudit_CL for recent calls)

RECOMMENDED SETTINGS:
- Email enrichment: max 100/day (handles ~100 incidents/day)
- Domain enrichment: max 50/day
- IP enrichment: max 100/day
- Full investigation: max 20/day (5-7 API calls each = 100-140 calls)
- Catalog lookup: max 200/day (lightweight)
- Password check: max 10/day (sensitive + expensive)
```

### 9.3 Microsoft Sentinel Cost Implications

| Component | Cost Driver | Estimated Impact | Mitigation |
|-----------|------------|-----------------|------------|
| EnrichmentAudit_CL ingestion | Log Analytics ingestion (per GB) | ~1-5 MB/day for typical incident volume | Use Analytics plan (not Sentinel plan) for audit table |
| Logic App executions | Per-action pricing | ~$0.000125/action × ~20 actions/enrichment × ~100 incidents/day = ~$0.25/day | Minimal cost |
| Sentinel incident storage | Part of Sentinel plan | No additional cost (incidents are free) | N/A |
| API connection | Free | No cost | N/A |
| Custom connector | Free | No cost | N/A |
| Additional analytics rules | No direct cost (included in Sentinel) | More rules = more compute for scheduled queries | Optimize rule frequency |

### 9.4 Cost Optimization Recommendations

1. **Use Analytics plan for audit tables**: SpyCloudEnrichmentAudit_CL, Spycloud_MDE_Logs_CL, and SpyCloud_ConditionalAccessLogs_CL can use the cheaper Analytics plan instead of the Sentinel plan
2. **Tune polling frequency**: Don't poll Compass/SIP endpoints if you don't have those licenses
3. **Disable unused pollers**: ARM parameters control which pollers deploy — don't deploy pollers for products you don't have
4. **Set retention wisely**: 90 days for operational data, 30 days for audit data (or longer for compliance)
5. **Throttle full investigations**: Limit to high/critical incidents only to control API usage

---

## 10. Prerequisites & Data Source Requirements

### 10.1 Required for Base Deployment

| Prerequisite | Purpose | How to Verify |
|-------------|---------|---------------|
| Azure Subscription | Host all resources | Azure Portal |
| Microsoft Sentinel workspace | SIEM platform | Sentinel → Overview |
| SpyCloud Enterprise API key | Authenticate to SpyCloud API | portal.spycloud.com → Settings → API Keys |
| Contributor role on Resource Group | Deploy ARM template | Azure IAM |
| Microsoft Sentinel Contributor role | Create connectors, rules, workbooks | Sentinel Settings → IAM |

### 10.2 Required for Specific Features

| Feature | Prerequisites | Verification |
|---------|--------------|-------------|
| MDE Device Isolation | MDE P2 license, Machine.Isolate permission | Defender portal → Settings |
| CA Password Reset | Entra ID P1+, User.ReadWrite.All Graph permission | Entra admin center |
| Entra Sign-In Correlation | Entra ID P1+ (sign-in logs enabled) | Entra → Monitoring → Diagnostic Settings |
| Entra Risk Correlation | Entra ID P2 (risky users/sign-ins) | Entra → Security → Risky Users |
| UEBA Correlation | Sentinel UEBA enabled | Sentinel → Settings → UEBA |
| Okta Correlation | Okta SSO connector installed | Sentinel → Content Hub → Okta |
| Duo Correlation | Cisco Duo connector installed | Sentinel → Content Hub → Cisco Duo |
| Ping Correlation | Ping Identity connector installed | Sentinel → Data Connectors |
| Firewall Correlation | Fortinet/PaloAlto/Cisco connector | Sentinel → Data Connectors |
| M365 Correlation | M365 connector enabled | Sentinel → Content Hub → Microsoft 365 |
| MDE XDR Correlation | Defender XDR connector | Sentinel → Content Hub → Microsoft Defender XDR |
| Compass Enrichment | Compass API key from SpyCloud | portal.spycloud.com |
| SIP Cookie Detection | SIP API key from SpyCloud | portal.spycloud.com |
| Investigation Deep Dive | Investigations API key from SpyCloud | portal.spycloud.com |
| IdLink Correlation | IdLink API key from SpyCloud | portal.spycloud.com |

### 10.3 Data Source Dependency Map for Analytics Rules

| Rule Category | Required Data Sources | Optional Enhancements |
|--------------|---------------------|----------------------|
| Core SpyCloud Detection | SpyCloudBreachWatchlist_CL only | None — self-contained |
| IdP Correlation | SpyCloudBreachWatchlist_CL + IdP logs (Okta_CL / CiscoDuo_CL / PingFederate_CL / SigninLogs) | Entra Risk data |
| Network Correlation | SpyCloudBreachWatchlist_CL + CommonSecurityLog or firewall-specific tables | DNS logs, proxy logs |
| Cloud/SaaS Correlation | SpyCloudBreachWatchlist_CL + OfficeActivity / CloudAppEvents / AzureActivity | Defender for Cloud Apps |
| UEBA Correlation | SpyCloudBreachWatchlist_CL + BehaviorAnalytics (UEBA) | IdentityInfo |
| MDE Correlation | SpyCloudBreachWatchlist_CL + DeviceInfo / DeviceNetworkEvents | DeviceAlertEvents |
| Compliance/SLA | SpyCloudBreachWatchlist_CL + ConditionalAccessLogs_CL + MDE_Logs_CL | EnrichmentAudit_CL |
| SIP Rules | SpyCloudSipCookies_CL + CloudAppEvents | SigninLogs |
| Compass Rules | SpyCloudCompassData_CL + SpyCloudCompassDevices_CL + SpyCloudBreachWatchlist_CL | MDE DeviceInfo |

---

## 11. Deployment Configuration Options

### 11.1 ARM Parameter Groups

```
GROUP 1: Core (Required)
  workspace, apiKey, deploymentRegion

GROUP 2: Data Sources (Toggle by license)
  enableCompass, enableSip, enableInvestigations, enableIdLink,
  enableCAP, enableExposure, enableDataPartnership
  compassApiKey, sipApiKey, investigationsApiKey, idlinkApiKey,
  capApiKey, exposureApiKey, dataPartnershipApiKey

GROUP 3: Enrichment Playbooks (Toggle individually)
  enableEnrichmentPlaybooks (master)
  enableEnrichEmail, enableEnrichDomain, enableEnrichIP,
  enableEnrichUsername, enableEnrichPassword, enableEnrichCatalog,
  enableEnrichCompass, enableEnrichStolenCookies,
  enableEnrichInvestigation, enableEnrichIdentity,
  enableFullInvestigation
  enrichmentDailyLimit (int, default: 200)

GROUP 4: Response Playbooks (Toggle individually)
  enableMdePlaybook, enableCaPlaybook, enableCredResponsePlaybook,
  enableMdeBlocklistPlaybook, enableTiEnrichmentPlaybook

GROUP 5: Detection (Toggle by category)
  enableCoreDetectionRules, enableIdpCorrelationRules,
  enableCrossPlatformRules, enableUebaFirewallRules,
  enableComplianceRules, enableSipRules, enableCompassRules

GROUP 6: Notifications
  enableTeamsNotifications, enableSlackNotifications,
  enableEmailNotifications, enableServiceNow, enableJira,
  enableAzureDevOps

GROUP 7: Advanced Settings
  pollingIntervalMin, rateLimitQPS, retentionInDays,
  spycloudSeverityThreshold, mdeIsolationType
```

---

## 12. Best Practices & Recommendations

### 12.1 Deployment Approach

1. **Start with Enterprise Base**: Deploy with just the Enterprise API key. This gives you 3 CCF pollers, 6 core enrichment playbooks, and 38+ analytics rules.
2. **Add Compass/SIP later**: Once base is validated, add Compass and SIP keys to unlock device forensics and stolen cookie detection.
3. **Enable Investigations for IR teams**: Only add Investigations API key if you have dedicated threat hunters or IR team members.
4. **Tune before enabling auto-response**: Run analytics rules in audit mode for 1-2 weeks before enabling MDE isolation or CA password reset automation.

### 12.2 API Key Management

- Use a single SpyCloud API key for Enterprise features
- Use separate keys for Compass, SIP, Investigations (matches SpyCloud billing)
- Never put API keys in plain text in playbook parameters — always use securestring
- Rotate keys quarterly via portal.spycloud.com

### 12.3 Enrichment Strategy

- **Always enrich High/Critical incidents** — the investigation report pays for itself in analyst time savings
- **Selectively enrich Medium incidents** — use automation rules to filter by entity type
- **Don't enrich Informational incidents** — waste of API quota
- **Monitor EnrichmentAudit_CL** — track API usage trends and adjust rate limits

### 12.4 Cross-Platform Integration Priority

| Priority | Integration | Value | Effort |
|----------|------------|-------|--------|
| 1 | Entra ID sign-in logs | Credential-to-access correlation | Low (built-in connector) |
| 2 | MDE | Device isolation + infection validation | Medium (requires P2 license) |
| 3 | M365 | Post-compromise activity detection | Low (built-in connector) |
| 4 | Okta/Duo/Ping (whichever you use) | IdP credential correlation | Medium (Content Hub connector) |
| 5 | Firewall (whichever you use) | Network containment | Medium (CEF/Syslog) |
| 6 | ServiceNow/Jira | Ticket automation | Low (HTTP webhook) |
| 7 | Teams/Slack | SOC notification | Very Low (webhook) |
| 8 | CrowdStrike/SentinelOne | EDR cross-reference | Medium (Content Hub connector) |
| 9 | DNS (Infoblox/Umbrella) | C2 detection | Medium (connector-dependent) |
| 10 | Azure/AWS/GCP activity | Cloud resource abuse | Low-Medium (built-in connectors) |

---

## Appendix A: SpyCloud Severity Reference

| Severity | Label | Risk | Typical Auto-Response | Enrichment Priority |
|----------|-------|------|----------------------|-------------------|
| **25** | Infostealer + App Data | CRITICAL — stolen cookies bypass MFA | Isolate device + revoke ALL sessions + force MFA re-register + SOC alert | Full Investigation |
| **20** | Infostealer Credential | URGENT — malware-stolen credentials | Force password reset + revoke sessions + investigate device | Full Investigation |
| **5** | Breach + PII | HIGH — name, phone, DOB, address exposed | Reset password + monitor sign-ins | Email Enrichment |
| **2** | Breach Credential | MEDIUM — email + password in breach | Notify user + check for reuse | Email Enrichment |

## Appendix B: MITRE ATT&CK Coverage

| Tactic | Techniques Covered | SpyCloud Detection |
|--------|-------------------|-------------------|
| Initial Access | T1078 (Valid Accounts), T1078.004 (Cloud Accounts) | Credential exposure + sign-in correlation |
| Credential Access | T1555 (Credentials from Password Stores), T1539 (Steal Web Session Cookie), T1552 (Unsecured Credentials), T1110 (Brute Force) | Infostealer detection, cookie theft, password exposure |
| Persistence | T1098 (Account Manipulation), T1556.006 (MFA Request Generation) | MFA change after exposure, OAuth consent |
| Defense Evasion | T1550 (Use Alternate Authentication Material), T1550.004 (Web Session Cookie) | Stolen cookie usage, session hijack |
| Lateral Movement | T1021 (Remote Services), T1534 (Internal Spearphishing) | Password reuse across domains, lateral access patterns |
| Collection | T1114 (Email Collection), T1213 (Data from Information Repositories) | Mail forwarding rules, SharePoint mass download |
| Exfiltration | T1048 (Exfiltration Over Alternative Protocol), T1530 (Data from Cloud Storage Object) | Post-compromise data access patterns |

---

*End of Architecture Document — SpyCloud Sentinel Supreme v12.0*
