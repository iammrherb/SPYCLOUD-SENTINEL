# SpyCloud Sentinel Supreme — Product-Grouped Architecture & Redeployment Strategy

**Version:** 12.0 Product Catalog
**Date:** March 18, 2026

---

## Redeployment Strategy: Progressive Product Enablement

### How It Works

ARM templates use **incremental mode** by default. This means:
- Redeploying with new parameters ADDS new resources (pollers, playbooks, tables, rules)
- Existing resources are UPDATED if their properties change, but NOT deleted
- Resources not in the template are LEFT UNTOUCHED

This means a customer can:
1. Deploy with Enterprise API key only → gets 3 pollers, 6 enrichment playbooks, 38 rules
2. Later, redeploy with `enableCompass=true` + `compassApiKey=xxx` → adds 3 Compass pollers, 2 Compass playbooks, 4 Compass rules. Enterprise resources remain intact.
3. Later, redeploy with `enableSip=true` + `sipApiKey=xxx` → adds SIP poller, SIP playbook, SIP rules. Enterprise + Compass remain intact.

### CCF Connector Page Behavior

The CCF connector page is separate from the ARM deployment. When you redeploy:
- The connector definition is updated to show new pollers
- The user must go to the connector page and click "Connect" again to activate new pollers
- Existing pollers continue running — they are not interrupted
- New pollers appear as additional connection instances

### createUiDefinition.json Wizard Design

The wizard should use **collapsible sections per product** with visibility conditions:

```
Step 1: Core Configuration (always visible)
  → Workspace, region, Enterprise API key, severity, polling interval

Step 2: SpyCloud Enterprise Protection (always visible, expanded by default)
  → Enterprise enrichment playbooks (email, domain, IP, username, password, catalog)
  → Enterprise analytics rules (38 rules, toggleable by category)
  → Enterprise workbooks
  → Enterprise automation rules

Step 3: SpyCloud Compass — Endpoint Threat Protection (collapsed, expands on toggle)
  → enableCompass checkbox → reveals:
    → Compass API key input
    → Compass pollers (data, devices, applications)
    → Compass enrichment playbooks
    → Compass analytics rules
    → Compass workbook panels

Step 4: SpyCloud SIP — Session Identity Protection (collapsed)
  → enableSip checkbox → reveals SIP configuration

Step 5: SpyCloud Investigations (collapsed)
  → enableInvestigations checkbox → reveals Investigations configuration

Step 6: SpyCloud IdLink (collapsed)
  → enableIdLink checkbox → reveals IdLink configuration

Step 7: SpyCloud Exposure & CAP (collapsed)
  → enableExposure checkbox → Exposure Stats
  → enableCAP checkbox → CAP configuration

Step 8: SpyCloud Data Partnership (collapsed)
  → enableDataPartnership checkbox → Data Partnership configuration

Step 9: Response & Notification Configuration (always visible)
  → MDE, CA, Credential Response, TI Enrichment, ITSM, notifications

Step 10: Review & Deploy
```

---

## Product 1: SpyCloud Enterprise Protection (Base)

**API Key Parameter:** `apiKey` (required)
**License:** SpyCloud Enterprise or Enterprise+

### Pollers (3)

| Poller | Endpoint | Table | Polling Window | Description |
|--------|----------|-------|---------------|-------------|
| Watchlist New | `/breach/data/watchlist` | SpyCloudBreachWatchlist_CL | 40 min | New credential/PII/device exposure records from monitored watchlist |
| Watchlist Modified | `/breach/data/watchlist` (since_modification_date) | SpyCloudBreachWatchlist_CL | 1440 min (daily) | Updated or re-sighted records — catches credentials appearing in new sources |
| Breach Catalog | `/breach/catalog` | SpyCloudBreachCatalog_CL | 40 min | Breach source metadata — title, description, type, confidence, record count |

### Enrichment Playbooks (7)

| Playbook | API Endpoint | Entity Type | What It Does | Auto-Trigger |
|----------|-------------|-------------|-------------|-------------|
| SpyCloud-Enrich-Email | `/breach/data/emails/{email}` | Account (email) | Queries all breach records for the email address. Returns: total exposures, severity distribution, plaintext passwords found, target domains affected, breach sources, infection timestamps, device IDs. Writes structured summary to incident comment. | Automation rule on Account entity |
| SpyCloud-Enrich-Domain | `/breach/data/domains/{domain}` | DNS Domain | Queries all breach records for the domain. Returns: total exposed users, severity breakdown, top exposed accounts, breach source list, plaintext password count, average severity. Useful for understanding organizational exposure scope. | Automation rule on DNS entity |
| SpyCloud-Enrich-IP | `/breach/data/ips/{ip}` | IP Address | Queries breach records associated with an IP. Returns: infected devices at this IP, affected users, malware families present, infection dates, hostnames. Particularly valuable for infostealer investigations where IP is the only known indicator. | Automation rule on IP entity |
| SpyCloud-Enrich-Username | `/breach/data/usernames/{username}` | Account (username) | Queries breach records by non-email username. Returns: exposure count, associated emails, domains where this username was used, severity levels. Useful for service account or non-email identity compromise. | Automation rule on Account entity (when no email) |
| SpyCloud-Enrich-Password | `/breach/data/passwords` (POST) | Password hash | Checks if a specific password hash appears in breach data. Returns: how many breaches contain this password, which domains it was used on, severity levels. Sensitive — disabled by default, requires explicit opt-in. Hash is never stored in logs. | Manual trigger only (security-sensitive) |
| SpyCloud-Enrich-Catalog | `/breach/catalog/{id}` | Source ID | Enriches incident with breach source context. Returns: breach title, description, acquisition date, record count, confidence score, type (public/private), affected assets breakdown. Adds critical "where did this come from" context to every incident. | Chained from email/domain enrichment (auto) |
| SpyCloud-Enrich-ExposureStats | `/exposure/stats/domains/{domain}` | Domain | Retrieves aggregate exposure statistics for the domain. Returns: total exposed records over time, severity trend, breach source count, most recent exposure date. Provides executive-level exposure posture assessment. | Triggered from domain enrichment |

### Analytics Rules — Enterprise (16 core)

| # | Rule Name | Severity | Detection Logic | Entity Mapping | Required Tables |
|---|-----------|----------|----------------|---------------|----------------|
| E01 | Infostealer Credential Exposure | High | severity >= 20 | Account (email), Host (machine_id) | BreachWatchlist_CL |
| E02 | Plaintext Password Exposure | High | password_plaintext != null | Account (email) | BreachWatchlist_CL |
| E03 | Stolen Session Cookies/Tokens | High | severity = 25 or password_type has "cookie" | Account (email), Host (machine_id) | BreachWatchlist_CL |
| E04 | PII/SSN/Financial Data Exposure | High | ssn or bank_number or taxid != null | Account (email) | BreachWatchlist_CL |
| E05 | Executive/VIP Account Exposure | High | email in VIP watchlist | Account (email) | BreachWatchlist_CL + VIP Watchlist |
| E06 | Multi-Domain Credential Reuse | Medium | dcount(target_domain) >= 3 per email+password | Account (email) | BreachWatchlist_CL |
| E07 | Device Re-Infection | High | same machine_id from multiple source_ids | Host (machine_id) | BreachWatchlist_CL |
| E08 | High-Sighting Credential | Medium | sighting >= 3 | Account (email) | BreachWatchlist_CL |
| E09 | Password Reuse Across Critical Systems | High | same password hash, 3+ domains | Account (email) | BreachWatchlist_CL |
| E10 | New Malware Family Detected | Medium | new source_id in catalog with type=malware | None | BreachCatalog_CL |
| E11 | Sensitive Source Breach | High | catalog confidence >= 4, type = PRIVATE | None | BreachCatalog_CL |
| E12 | Credential Volume Spike | Medium | count > 2x 7-day average for domain | DNS (email_domain) | BreachWatchlist_CL |
| E13 | First-Time Domain Exposure | Medium | email_domain not seen in prior 30 days | DNS (email_domain) | BreachWatchlist_CL |
| E14 | Stale Credential Without Remediation | High | exposure > 30 days, no CA/MDE action | Account (email) | BreachWatchlist_CL + CA_Logs + MDE_Logs |
| E15 | Corporate Email on Consumer Site | Medium | target_domain in high-risk consumer list | Account (email) | BreachWatchlist_CL |
| E16 | Data Ingestion Health Alert | Medium | no data for 3+ hours | None | BreachWatchlist_CL |

### Analytics Rules — Enterprise Cross-Platform (22 correlation rules)

| # | Rule Name | Correlates With | Required Connector | Severity |
|---|-----------|----------------|-------------------|----------|
| EX01 | Exposed Credential + Successful Sign-In | Entra ID SigninLogs | Entra ID Diagnostics | High |
| EX02 | Exposed User + Risky Sign-In | Entra ID AADRiskySignIns | Entra ID P2 | High |
| EX03 | Exposed User + Impossible Travel | Entra ID SigninLogs (location) | Entra ID Diagnostics | High |
| EX04 | Exposed User + MFA Registration Change | Entra ID AuditLogs | Entra ID Diagnostics | High |
| EX05 | Exposed User + Suspicious Mailbox Rule | M365 OfficeActivity (Exchange) | Microsoft 365 connector | High |
| EX06 | Exposed User + OAuth App Consent | Entra ID AuditLogs | Entra ID Diagnostics | High |
| EX07 | Exposed User + Admin Role Grant | Entra ID AuditLogs | Entra ID Diagnostics | High |
| EX08 | Exposed User + Self-Service Password Change | Entra ID AuditLogs | Entra ID Diagnostics | Medium |
| EX09 | Exposed User + eDiscovery/Content Search | M365 OfficeActivity | Microsoft 365 connector | High |
| EX10 | Exposed User + SharePoint Mass Download | M365 OfficeActivity (SharePoint) | Microsoft 365 connector | High |
| EX11 | Exposed User + UEBA Anomaly | BehaviorAnalytics | Sentinel UEBA | High |
| EX12 | Exposed User + First-Time Resource Access | BehaviorAnalytics | Sentinel UEBA | Medium |
| EX13 | Infected IP in Firewall Deny Logs | CommonSecurityLog | Fortinet/PaloAlto/Cisco/CheckPoint | High |
| EX14 | Infected IP via Fortinet FSSO | CommonSecurityLog (Fortinet) | Fortinet connector | High |
| EX15 | Infected IP via Palo Alto User-ID | CommonSecurityLog (PAN-OS) | Palo Alto connector | High |
| EX16 | Infected Host DNS to Malware C2 | DnsEvents or Infoblox_CL | DNS connector | High |
| EX17 | Exposed User VPN from New Location | VPN logs (varies) | VPN connector | High |
| EX18 | Firewall Allow from Exposed IP | CommonSecurityLog | Any firewall connector | High |
| EX19 | Exposed Credential in Okta Sign-In | Okta_CL | Okta SSO connector | High |
| EX20 | Exposed Credential in Duo Auth | CiscoDuo_CL | Cisco Duo connector | High |
| EX21 | Exposed Credential in Ping Auth | PingFederate_CL | Ping Identity connector | High |
| EX22 | Exposed Credential in Entra ID Sign-In | SigninLogs | Entra ID Diagnostics | High |

### Automation Rules — Enterprise (6)

| Rule | Trigger | Action | Notes |
|------|---------|--------|-------|
| Auto-Enrich-Account | Incident created with Account entity + "SpyCloud" in title | Run SpyCloud-Enrich-Email | Always active if enrichment enabled |
| Auto-Enrich-IP | Incident created with IP entity + "SpyCloud" in title | Run SpyCloud-Enrich-IP | Always active if enrichment enabled |
| Auto-Enrich-Domain | Incident created with DNS entity + "SpyCloud" in title | Run SpyCloud-Enrich-Domain | Always active if enrichment enabled |
| Auto-Investigate-Critical | Incident created with severity Critical + "SpyCloud" in title | Run SpyCloud-FullInvestigation | Only for Critical incidents |
| Auto-Escalate-VIP | Incident created where Account matches VIP watchlist | Set severity to Critical | Requires VIP watchlist configured |
| Auto-Close-Remediated | Incident updated where all entities have CA + MDE actions | Close as True Positive - Resolved | Checks both audit tables |

### Workbooks — Enterprise (2)

| Workbook | Panels | Description |
|----------|--------|-------------|
| SpyCloud Threat Intelligence Dashboard | 38 panels: exposure tiles, severity trends, top users, top devices, password types, domains, geo, remediation, catalog, health | Primary SOC operational dashboard |
| SpyCloud Executive Dashboard | Executive summary tiles, severity trend over 90d, breach source distribution, remediation effectiveness, SLA compliance | CISO/management reporting |

---

## Product 2: SpyCloud Compass — Endpoint Threat Protection

**API Key Parameter:** `compassApiKey` (optional, separate from Enterprise key)
**License:** SpyCloud Compass add-on
**Prerequisites:** Enterprise Protection (base)

### What Compass Adds

Compass provides **post-infection visibility** into exactly what data infostealers stole from devices — including credentials for applications, session tokens, browser-saved passwords, autofill data, and device fingerprints. This goes beyond the breach watchlist's credential-focused view to show the complete blast radius of an infostealer infection.

### Pollers (3)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| Compass Data | `/compass/data` | SpyCloudCompassData_CL | Consumer/employee identity exposures with application-level detail — shows every application that had credentials stolen, not just corporate email |
| Compass Devices | `/compass/devices` | SpyCloudCompassDevices_CL | Infected device fingerprints: machine_id, hostname, OS, malware path, AV installed, infection time, all users who logged in, IP history |
| Compass Applications | `/compass/applications` | SpyCloudCompassApplications_CL | Application-level stolen credential data: which apps had saved passwords/tokens stolen, login URLs, credential types, last use timestamps |

### Enrichment Playbooks (3)

| Playbook | API Endpoint | Entity | What It Does |
|----------|-------------|--------|-------------|
| SpyCloud-Enrich-CompassEmail | `/compass/data/emails/{email}` | Account | Looks up all consumer exposure data for the email across ALL applications (not just corporate). Returns: total apps compromised, credential types stolen (passwords, cookies, tokens, autofill), device fingerprints, infection timeline. This is the "what else did the malware steal?" enrichment. |
| SpyCloud-Enrich-CompassDevice | `/compass/devices/{machine_id}` | Host | Deep device forensics: complete infection profile including all users who used this device, all credentials stolen from it, all applications compromised, malware family, infection vector, AV that was installed but failed. This is the device blast radius assessment. |
| SpyCloud-Enrich-CompassApps | `/compass/applications` (filtered) | Application | Application exposure assessment: for a given domain, shows which corporate applications had credentials stolen via infostealers. Maps the application attack surface — critical for understanding if VPN, SSO, cloud console, or other high-value application credentials were compromised. |

### Analytics Rules — Compass (6)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| C01 | Compass — Consumer + Corporate Credential Overlap | High | Same email in both CompassData_CL and BreachWatchlist_CL with different target_domains | Detects when personal device infection exposed corporate credentials via password reuse on personal accounts |
| C02 | Compass — Device Reinfection Detected | High | Same machine_id in CompassDevices_CL from multiple source_ids within 90 days | Device was cleaned but got re-infected — indicates failed remediation or persistent risky behavior |
| C03 | Compass — High Application Exposure Count | High | dcount(application) > 10 per infected device | Single infection compromised many applications — high blast radius requiring comprehensive remediation |
| C04 | Compass — Stolen VPN/SSO Credentials | Critical | CompassApplications_CL where application matches VPN/SSO patterns (GlobalProtect, AnyConnect, Okta, Azure, AWS) | Stolen credentials for high-privilege access tools — immediate containment required |
| C05 | Compass — BYOD/Unmanaged Device Infection | High | CompassDevices_CL where machine_id NOT in MDE DeviceInfo | Infection on unmanaged device with corporate credentials — common BYOD risk scenario |
| C06 | Compass — Infected Device Still Active in MDE | High | CompassDevices_CL machine_id found in MDE DeviceInfo with onboardingStatus = "Onboarded" AND device not isolated | Infected device is still active on corporate network — immediate isolation needed |

### Automation Rules — Compass (2)

| Rule | Trigger | Action |
|------|---------|--------|
| Auto-Enrich-Compass-Host | Incident with Host entity from Compass rule | Run SpyCloud-Enrich-CompassDevice |
| Auto-Enrich-Compass-Account | Incident with Account entity from Compass rule | Run SpyCloud-Enrich-CompassEmail |

### Workbook — Compass (1)

| Workbook | Panels | Description |
|----------|--------|-------------|
| SpyCloud Compass Dashboard | Device infection map, application exposure breakdown, consumer vs corporate overlap, BYOD risk assessment, device reinfection timeline, top malware families, AV coverage gaps | Compass-specific endpoint threat protection dashboard |

### Cross-Platform Correlation Opportunities

| Correlation | Compass Data | Correlated With | Value |
|------------|-------------|----------------|-------|
| Infected device in MDE inventory | CompassDevices_CL (machine_id) | MDE DeviceInfo | Validate if infected device is managed; auto-isolate if found |
| Stolen app credentials in use | CompassApplications_CL (app, credential) | CloudAppEvents, SigninLogs | Detect if stolen credentials are actively being used |
| Unmanaged device with corporate creds | CompassDevices_CL NOT IN MDE | Intune IntuneDevices | Identify BYOD risk exposure |
| Compass infection + Defender alert | CompassDevices_CL (machine_id, infection_time) | MDE DeviceAlertEvents | Validate if Defender detected the malware or missed it |

---

## Product 3: SpyCloud SIP — Session Identity Protection

**API Key Parameter:** `sipApiKey` (optional, may share Enterprise key)
**License:** SpyCloud SIP add-on
**Prerequisites:** Enterprise Protection (base)

### What SIP Adds

SIP provides stolen **session cookies, authentication tokens, and browser-stored session data** that allow attackers to bypass MFA entirely. This is the most critical data type for MFA bypass defense — attackers don't need passwords if they have valid session cookies.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| SIP Cookies | `/sip/cookies/domains/{domain}` | SpyCloudSipCookies_CL | Stolen session cookies by monitored domain — includes cookie name, domain, path, expiration, associated user, malware source, infection timestamp |

### Enrichment Playbooks (1)

| Playbook | API Endpoint | Entity | What It Does |
|----------|-------------|--------|-------------|
| SpyCloud-Enrich-StolenCookies | `/sip/cookies/emails/{email}` | Account | Looks up all stolen cookies for the user. Returns: which applications/services had cookies stolen, cookie types (session, auth, persistent), expiration status (still valid?), affected domains, infection source. Critical for determining if MFA bypass is possible. If cookies are still valid → IMMEDIATE session revocation needed. |

### Analytics Rules — SIP (4)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| S01 | SIP — Stolen Session Cookies Detected | Critical | New records in SipCookies_CL for monitored domain | Stolen cookies enable MFA bypass — most critical alert type |
| S02 | SIP — Active Session Cookie (Not Expired) | Critical | SipCookies_CL where cookie_expiry > now() | Cookie is STILL VALID — attacker can use it RIGHT NOW to impersonate user |
| S03 | SIP — Stolen Cookies for High-Privilege Application | Critical | SipCookies_CL where domain matches SSO/admin/VPN/cloud console patterns | Stolen cookies for admin portals, SSO providers, or cloud consoles — highest risk |
| S04 | SIP — Multiple Users with Stolen Cookies from Same Device | High | SipCookies_CL where dcount(email) > 1 per machine_id | Shared device with multiple users' cookies stolen — blast radius assessment |

### Cross-Platform Correlation

| Correlation | SIP Data | Correlated With | Value |
|------------|---------|----------------|-------|
| Stolen cookie + active CloudApp session | SipCookies_CL (domain, email) | CloudAppEvents | Detect if stolen cookie is being used to access SaaS apps |
| Stolen SSO cookie + new sign-in | SipCookies_CL (SSO domain) | SigninLogs | Detect if SSO session hijack is occurring |
| Stolen cookie + Entra token refresh | SipCookies_CL | AADNonInteractiveUserSignInLogs | Detect token replay attacks using stolen cookies |

---

## Product 4: SpyCloud Investigations

**API Key Parameter:** `investigationsApiKey` (separate, dedicated key)
**License:** SpyCloud Investigations (separate product)
**Prerequisites:** None (standalone product, but most valuable with Enterprise)

### What Investigations Adds

Investigations provides **full database access** to SpyCloud's recaptured data for threat hunting, attribution research, and incident investigation. Unlike Enterprise (which is scoped to your watchlist), Investigations lets you search the ENTIRE SpyCloud database by any pivot point — email, IP, username, password, domain — regardless of whether it's on your watchlist.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| Investigations Domain | `/investigations-v2/records/domains/{domain}` | SpyCloudInvestigations_CL | Full investigation records for your monitored domain — includes ALL available data fields, not just watchlist-scoped data |

### Enrichment Playbooks (3)

| Playbook | API Endpoint | Entity | What It Does |
|----------|-------------|--------|-------------|
| SpyCloud-Investigate-Email | `/investigations-v2/records/emails/{email}` | Account | Deep investigation: returns ALL breach records for any email (not just your watchlist). Includes historical exposures going back years, full PII profile, linked accounts, device fingerprints. Used for: threat actor attribution, insider threat investigation, supply chain risk assessment. |
| SpyCloud-Investigate-IP | `/investigations-v2/records/ips/{ip}` | IP | Deep investigation by IP: returns all breach records from malware infections at this IP. Used for: C2 infrastructure mapping, botnet identification, geographic analysis of infection campaigns. |
| SpyCloud-Investigate-Username | `/investigations-v2/records/usernames/{username}` | Account | Deep investigation by username: pivots on non-email identifiers across the full database. Used for: dark web persona tracking, threat actor de-anonymization, credential stuffing source identification. |

### Analytics Rules — Investigations (2)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| I01 | Investigation — External Entity Cross-Reference | Medium | Investigations_CL record matching known threat actor indicator (TI watchlist) | Links SpyCloud investigation data to known threat intelligence indicators |
| I02 | Investigation — Supply Chain Third-Party Exposure | High | Investigations_CL where domain is in partner/supplier watchlist | Detects when third-party partner credentials are compromised — supply chain risk |

### Use Cases Unique to Investigations

| Use Case | How | Value | Rate Limit Concern |
|----------|-----|-------|-------------------|
| Threat actor attribution | Pivot from known email → find all usernames → find all IPs → map infrastructure | Supports law enforcement and IR teams | High — use judiciously, 1-2 QPS |
| Supply chain risk assessment | Search partner/supplier domains in full database | Proactive third-party risk management | Medium — batch during off-hours |
| Insider threat investigation | Search personal emails of suspected insider across full database | Determines if insider's personal accounts are compromised | Low — manual trigger only |
| Dark web persona tracking | Pivot from username across breaches | Uncover threat actor's full identity graph | High — use judiciously |

---

## Product 5: SpyCloud IdLink

**API Key Parameter:** `idlinkApiKey` (separate)
**License:** SpyCloud IdLink add-on
**Prerequisites:** Enterprise Protection

### What IdLink Adds

IdLink provides **identity correlation and linking** — it connects different usernames, email addresses, and accounts that belong to the same person. When an employee uses their work email, personal email, and various usernames across services, IdLink maps all these identities together. This means when one identity is compromised, you can immediately identify ALL identities at risk.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| IdLink Domain | `/idlink/records/emails/{domain}` | SpyCloudIdLink_CL | Identity correlation records — maps email addresses to all known linked identities including alternate emails, usernames, phone numbers, and associated devices |

### Enrichment Playbooks (1)

| Playbook | API Endpoint | Entity | What It Does |
|----------|-------------|--------|-------------|
| SpyCloud-Enrich-Identity | IdLink API | Account | Identity graph traversal: takes a single email and returns all linked identities — other email addresses, usernames, phone numbers, social accounts. Enables: "this one compromised email is actually connected to 5 other accounts that also need remediation." |

### Analytics Rules — IdLink (2)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| IL01 | IdLink — Multi-Persona Exposure (Same Person, Multiple Accounts) | High | IdLink_CL shows 3+ linked identities for one person, all with BreachWatchlist records | One person's entire digital identity is compromised across multiple accounts |
| IL02 | IdLink — Personal Email Linked to Corporate Account | Medium | IdLink_CL links personal email (gmail, yahoo, etc.) to corporate email, personal email has exposures | Personal email compromise creates risk path to corporate account via password reuse |

---

## Product 6: SpyCloud Exposure Stats

**API Key Parameter:** `exposureApiKey` (may share Enterprise key)
**License:** Enterprise (included)
**Prerequisites:** Enterprise Protection

### What Exposure Stats Adds

Domain-level aggregate statistics showing exposure trends over time. Not record-level data — this is the "how exposed is my organization?" metric that feeds executive dashboards and compliance reporting.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| Exposure Stats | `/exposure/stats/domains/{domain}` | SpyCloudExposure_CL | Aggregate exposure statistics by domain: total records, records by severity, records by type, trend data, first/last exposure dates |

### Analytics Rules — Exposure (2)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| XS01 | Exposure — Domain Exposure Spike (Week-over-Week) | Medium | SpyCloudExposure_CL total_records increased > 50% week-over-week | Unusual increase in organizational exposure — could indicate targeted campaign or large breach publication |
| XS02 | Exposure — High-Severity Exposure Ratio Increasing | High | SpyCloudExposure_CL ratio of severity 20+ records increasing over 30 days | More infostealers targeting your org — increasing risk trend |

### Workbook Panels (added to Executive Dashboard)

| Panel | Data | Description |
|-------|------|-------------|
| Exposure Trend Over Time | SpyCloudExposure_CL time series | Line chart showing total exposure count by severity over 90/180/365 days |
| Exposure Comparison by Domain | SpyCloudExposure_CL grouped by domain | Multi-domain organizations can compare exposure across business units |

---

## Product 7: SpyCloud CAP — Compromised Account Protection

**API Key Parameter:** `capApiKey` (separate)
**License:** SpyCloud CAP
**Prerequisites:** None (standalone consumer-facing product)

### What CAP Adds

CAP is designed for **consumer-facing businesses** that need to check if their customers' accounts are compromised. It's different from Enterprise Protection (which protects employees) — CAP protects your customers.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| CAP Domain | `/cap/records/domains/{domain}` | SpyCloudCAP_CL | Consumer compromised account records for your domain — customer email addresses found in breach data |

### Analytics Rules — CAP (2)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| CAP01 | CAP — Customer Account Compromised | Medium | New records in SpyCloudCAP_CL | Customer account credentials found in breach data — ATO risk |
| CAP02 | CAP — Customer Account with Plaintext Password | High | SpyCloudCAP_CL where password_plaintext != null | Customer password available in cleartext — immediate ATO risk |

---

## Product 8: SpyCloud Data Partnership

**API Key Parameter:** `dataPartnershipApiKey` (separate)
**License:** SpyCloud Data Partnership agreement
**Prerequisites:** Partnership agreement with SpyCloud

### What Data Partnership Adds

Data Partnership provides access to shared/partner data feeds that extend beyond SpyCloud's own recaptured data. This is typically used by organizations that have a data sharing agreement with SpyCloud and want to ingest partner-contributed intelligence.

### Pollers (1)

| Poller | Endpoint | Table | Description |
|--------|----------|-------|-------------|
| Data Partnership | `/data-partnership/records/domains/{domain}` | SpyCloudDataPartnership_CL | Partner-contributed breach and exposure data for your domain — extends coverage beyond SpyCloud's own collection |

### Analytics Rules — Data Partnership (1)

| # | Rule Name | Severity | Detection Logic | Value |
|---|-----------|----------|----------------|-------|
| DP01 | Data Partnership — New Partner Intelligence | Medium | New records in SpyCloudDataPartnership_CL | New threat intelligence from partner sources — review and correlate with existing exposure data |

---

## Multi-Product Combination Rules

These rules require data from multiple SpyCloud products:

| # | Rule Name | Products Required | Detection Logic | Severity | Value |
|---|-----------|------------------|----------------|----------|-------|
| MP01 | Enterprise + Compass — Infection with Application Blast Radius | Enterprise + Compass | BreachWatchlist_CL severity >= 20 joined with CompassApplications_CL for same machine_id showing 5+ compromised applications | Critical | Full picture: credential stolen + all apps compromised from same device |
| MP02 | Enterprise + SIP — Credential + Cookie Double Exposure | Enterprise + SIP | BreachWatchlist_CL email matches SipCookies_CL email with active cookies | Critical | Attacker has BOTH password AND session cookies — complete account takeover capability |
| MP03 | Enterprise + IdLink — Linked Identity Chain Exposure | Enterprise + IdLink | BreachWatchlist_CL email found in IdLink_CL with 3+ linked identities, all having exposures | High | Entire identity graph is compromised — all linked accounts need remediation |
| MP04 | Enterprise + Investigations — Threat Actor Tracking | Enterprise + Investigations | BreachWatchlist_CL source_id appears in Investigations_CL with known threat actor patterns | High | Links organizational exposure to known threat campaigns |
| MP05 | Compass + SIP — Device Infection with Stolen Sessions | Compass + SIP | CompassDevices_CL machine_id has corresponding SipCookies_CL records with valid cookies | Critical | Infected device had active session cookies stolen — immediate MFA bypass risk |
| MP06 | Enterprise + Exposure — Exposure Spike Correlated with New Breach | Enterprise + Exposure | SpyCloudExposure_CL spike correlates with new BreachCatalog_CL entry within 48 hours | High | New breach published that significantly impacts your organization |
| MP07 | Enterprise + CAP — Employee Credential Found in Customer Data | Enterprise + CAP | BreachWatchlist_CL email found in SpyCloudCAP_CL | High | Employee credential appearing in consumer breach data — possible insider risk or credential reuse |

---

## Full Investigation Playbook — Multi-Product Aware

The Full Investigation playbook adapts its behavior based on which API keys are available:

```
ENTERPRISE KEY ONLY (minimum):
  Step 1: Email enrichment (/breach/data/emails/{email})
  Step 2: Catalog enrichment (/breach/catalog/{source_id})
  Step 3: Exposure stats (/exposure/stats/domains/{domain})
  Step 4: Entra ID sign-in correlation
  Step 5: Build report (3 API calls + 1 KQL query)

ENTERPRISE + COMPASS:
  Steps 1-3 above, plus:
  Step 4: Compass device lookup (/compass/devices/{machine_id})
  Step 5: Compass application assessment (/compass/applications filtered)
  Step 6: MDE device correlation
  Step 7: Entra ID sign-in correlation
  Step 8: Build enhanced report (5 API calls + 2 KQL queries)

ENTERPRISE + COMPASS + SIP:
  Steps 1-5 above, plus:
  Step 6: Stolen cookie check (/sip/cookies/emails/{email})
  Step 7: MDE + CloudAppEvents correlation
  Step 8: Entra ID sign-in correlation
  Step 9: Build comprehensive report (6 API calls + 3 KQL queries)

ALL PRODUCTS:
  All steps above, plus:
  Step 10: IdLink identity graph (/idlink)
  Step 11: Investigation deep dive (/investigations-v2)
  Step 12: Build full investigation dossier (8-10 API calls + 4 KQL queries)

EACH STEP IS CONDITIONAL:
  if(empty(compassApiKey), skip step with note, execute step)
  This ensures graceful degradation — no errors for missing licenses
```

---

## Summary: Component Count by Product

| Product | Pollers | Enrichment Playbooks | Analytics Rules | Automation Rules | Workbook Panels | Tables |
|---------|---------|---------------------|----------------|-----------------|----------------|--------|
| **Enterprise (Base)** | 3 | 7 | 38 (16 core + 22 cross-platform) | 6 | 38+ (2 workbooks) | 2 (Watchlist, Catalog) |
| **Compass** | 3 | 3 | 6 | 2 | 8+ (1 workbook) | 3 (Data, Devices, Apps) |
| **SIP** | 1 | 1 | 4 | 1 | 4 | 1 (Cookies) |
| **Investigations** | 1 | 3 | 2 | 1 | 2 | 1 (Investigations) |
| **IdLink** | 1 | 1 | 2 | 1 | 2 | 1 (IdLink) |
| **Exposure Stats** | 1 | 0 (built into Enterprise enrichment) | 2 | 0 | 2 | 1 (Exposure) |
| **CAP** | 1 | 0 | 2 | 0 | 2 | 1 (CAP) |
| **Data Partnership** | 1 | 0 | 1 | 0 | 1 | 1 (Partnership) |
| **Multi-Product** | 0 | 1 (Full Investigation) | 7 | 0 | 4 | 1 (EnrichmentAudit) |
| **Response** | 0 | 5 (MDE, CA, Cred, Blocklist, TI) | 0 | 3 | 4 | 2 (MDE_Logs, CA_Logs) |
| **TOTAL** | **13** | **21** | **~64** | **14** | **67+** | **15** |
