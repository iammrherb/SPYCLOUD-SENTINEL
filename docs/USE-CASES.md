# SpyCloud Identity Exposure Intelligence for Sentinel — Use Cases

> **Version 2.0** | Complete use case catalog with pros, cons, and configuration

## Use Case Categories

### Category A: Credential Exposure Detection and Response

#### A1. Employee Credential Exposed in Data Breach

**Scenario:** An employee's email and password appear in a dark web breach database.

**Detection:** Analytics rule matches new records in `SpyCloudBreachWatchlist_CL` where `severity_d >= 2`.

**Response Chain:**
1. Incident created in Sentinel with Account entity mapping
2. Auto-enrichment playbook queries SpyCloud for full exposure history
3. If plaintext password found: Force password reset via Entra ID
4. If severity >= 20: Revoke all active sessions
5. Notify user via email with password change instructions
6. Log all actions to `SpyCloudEnrichmentAudit_CL`

**Pros:**
- Fully automated detection-to-remediation pipeline
- Reduces mean time to remediate (MTTR) from days to minutes
- Preserves evidence trail for compliance

**Cons:**
- High-volume environments may generate alert fatigue at low severity thresholds
- Password reset may disrupt user productivity

**Configuration:**
```
Minimum Severity: 2 (all breaches) or 5 (PII only) or 20 (infostealers only)
Automation Rule: Auto-Enrich-Account -> SpyCloud-EnrichIncident
Playbook Chain: SpyCloud-EnrichIncident -> SpyCloud-ForcePasswordReset -> SpyCloud-NotifyUser
```

---

#### A2. Infostealer Infection with Stolen Sessions (Severity 25)

**Scenario:** Malware on an employee's device stole browser cookies, session tokens, saved passwords, and autofill data.

**Detection:** Analytics rule on `severity_d == 25` in `SpyCloudBreachWatchlist_CL`.

**Response Chain:**
1. Critical incident created with Host + Account entity mapping
2. Device isolated via MDE API
3. All sessions revoked (including OAuth tokens)
4. Password forced reset across all linked accounts
5. MFA re-enrollment required
6. Mailbox rules audited and suspicious rules removed
7. SOC notified via Teams/Slack with full investigation report

**Pros:**
- Addresses the complete blast radius of infostealer infection
- Prevents MFA bypass via stolen session cookies
- Automatic device containment prevents lateral movement

**Cons:**
- Aggressive response may over-remediate for false positives
- Device isolation impacts user productivity immediately

**Configuration:**
```
Severity Threshold: 25 (stolen sessions)
Automation: Auto-FullRemediation -> SpyCloud-FullRemediation
Required: MDE onboarded devices, Entra ID P2 license
```

---

#### A3. Executive/VIP Account Exposure

**Scenario:** A C-suite executive's credentials appear in SpyCloud data.

**Detection:** Analytics rule joins `SpyCloudBreachWatchlist_CL` with a VIP watchlist.

**Response Chain:**
1. Incident immediately escalated to Critical severity
2. Account temporarily disabled pending verification
3. Executive personally notified by security team
4. AI Investigation Engine generates executive briefing
5. Full exposure history compiled for legal review

**Pros:**
- Prioritizes highest-value targets
- Provides executive-ready reports
- Legal/compliance documentation included

**Cons:**
- VIP watchlist requires manual maintenance
- Account disable may disrupt business-critical activities

---

### Category B: Cross-Platform Correlation

#### B1. Exposed Credential + Successful Sign-In

**Scenario:** Employee's credential found in SpyCloud data AND they successfully signed in to Entra ID within the exposure window.

**Detection:** KQL join between `SpyCloudBreachWatchlist_CL` and `SigninLogs`.

```kql
SpyCloudBreachWatchlist_CL
| where TimeGenerated >= ago(7d)
| where severity_d >= 5
| join kind=inner (
    SigninLogs
    | where TimeGenerated >= ago(7d)
    | where ResultType == 0
) on $left.email_s == $right.UserPrincipalName
| project email_s, severity_d, SignInTime=TimeGenerated1, IPAddress, Location
```

**Pros:**
- Dual-signal detection dramatically reduces false positives
- Proves credential is actively in use by potentially unauthorized party
- High-confidence indicator of compromise

**Cons:**
- Requires Entra ID Diagnostics connector enabled
- 7-day lookback may miss slower attack patterns

---

#### B2. Infected Device Accessing Corporate Network

**Scenario:** A device identified by SpyCloud as infostealer-infected is still connecting to the corporate network.

**Detection:** KQL correlation between `SpyCloudBreachWatchlist_CL` (infected_machine_id) and MDE `DeviceInfo`.

```kql
let InfectedDevices = SpyCloudBreachWatchlist_CL
| where severity_d >= 20
| where isnotempty(infected_machine_id_s)
| distinct infected_machine_id_s;
DeviceInfo
| where TimeGenerated >= ago(7d)
| where DeviceId in (InfectedDevices) or DeviceName in (InfectedDevices)
| project TimeGenerated, DeviceName, DeviceId, OSPlatform, LoggedOnUsers
```

**Pros:**
- Identifies immediate lateral movement risk
- Can auto-isolate device before attacker pivots
- Validates whether infected device is managed or BYOD

**Cons:**
- Requires MDE integration
- Machine ID correlation may not match across all platforms

---

#### B3. Stolen Cookie Bypassing MFA

**Scenario:** Attacker uses stolen session cookies to bypass MFA and access M365 services.

**Detection:** Correlate `SpyCloudSipCookies_CL` with `AADNonInteractiveUserSignInLogs`.

```kql
let StolenCookies = SpyCloudSipCookies_CL
| where TimeGenerated >= ago(7d)
| distinct email_s, target_domain_s;
AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(7d)
| where ResultType == 0
| where ResourceDisplayName has_any (StolenCookies)
| where AuthenticationRequirement == "singleFactorAuthentication"
| project TimeGenerated, UserPrincipalName, ResourceDisplayName, IPAddress
```

**Pros:**
- Detects the most dangerous infostealer outcome (MFA bypass)
- Session cookies are often overlooked in password-focused remediation
- High-confidence indicator of active compromise

**Cons:**
- Requires SpyCloud SIP API license
- Cookie domain matching may produce false positives

---

### Category C: Compliance and Governance

#### C1. GDPR Breach Notification Assessment

**Scenario:** PII exposure requires assessment against GDPR 72-hour notification requirement.

**Detection:** AI Compliance Assessment endpoint triggered when PII fields detected.

**Response Chain:**
1. PII classification engine maps exposed fields to regulatory frameworks
2. AI generates compliance assessment with notification timeline
3. Purview sensitivity labels applied to incident
4. DLP policies evaluated for gaps
5. Notification templates generated for supervisory authority

**Pros:**
- Automates complex regulatory mapping
- Provides legally defensible documentation
- Integrates with Microsoft Purview for label enforcement

**Cons:**
- AI analysis should be reviewed by legal counsel
- Regulatory mapping is advisory, not legal advice
- Requires OpenAI or Azure OpenAI for AI assessment

---

#### C2. PCI-DSS Payment Card Exposure

**Scenario:** Credit card numbers detected in SpyCloud breach data.

**Detection:** Analytics rule on `cc_number` field not null.

**Response:**
1. Incident immediately escalated to Critical
2. Card issuer notification process initiated
3. Purview "Highly Confidential" label applied
4. All access to related systems logged for forensic review

**Pros:**
- Immediate detection of financial data exposure
- Automated compliance tagging via Purview
- Full audit trail for PCI-DSS evidence

**Cons:**
- Credit card data in breach records may be partial/masked
- Requires PCI-DSS compliance program already in place

---

#### C3. HIPAA Protected Health Information

**Scenario:** Breach data contains network identifiers or device IDs from healthcare systems that constitute PHI under HIPAA.

**Detection:** PII classification engine identifies HIPAA-relevant fields (ip_addresses, infected_machine_id from healthcare context).

**Response:**
1. Incident labeled "Highly Confidential - PHI"
2. 60-day notification timeline initiated
3. HHS breach notification assessment generated
4. Purview DLP policies evaluated for healthcare data

---

### Category D: Proactive Threat Hunting

#### D1. Password Reuse Across Multiple Domains

**Scenario:** Proactively identify employees reusing passwords across corporate and personal sites.

**Hunting Query:**
```kql
SpyCloudBreachWatchlist_CL
| where TimeGenerated >= ago(90d)
| where isnotempty(password_plaintext_s) or isnotempty(password_type_s)
| summarize DomainCount = dcount(target_domain_s),
            Domains = make_set(target_domain_s, 10),
            MaxSeverity = max(severity_d)
  by email_s
| where DomainCount >= 3
| order by DomainCount desc
```

**Pros:**
- Identifies systemic password hygiene issues
- Prioritizes users for security awareness training
- Reduces blast radius of future breaches

---

#### D2. Malware C2 Domain Resolution

**Scenario:** Hunt for devices resolving known malware command-and-control domains.

**Hunting Query:**
```kql
let C2Domains = SpyCloudBreachWatchlist_CL
| where severity_d >= 20
| distinct target_domain_s;
DnsEvents
| where TimeGenerated >= ago(7d)
| where Name in (C2Domains)
| project TimeGenerated, Computer, Name, IPAddresses
```

---

#### D3. Lateral Movement via Shared Credentials

**Scenario:** Identify users whose credentials appear in multiple breach sources, indicating potential lateral movement paths.

**Hunting Query:**
```kql
SpyCloudBreachWatchlist_CL
| where TimeGenerated >= ago(30d)
| summarize
    BreachCount = dcount(source_id_d),
    Breaches = make_set(source_id_d, 20),
    MaxSeverity = max(severity_d),
    HasPlaintext = max(iff(isnotempty(password_plaintext_s), 1, 0)),
    Domains = make_set(target_domain_s, 10)
  by email_s
| where BreachCount >= 3
| order by MaxSeverity desc, BreachCount desc
```

---

### Category E: MSSP/MSP Multi-Tenant Operations

#### E1. Cross-Tenant Exposure Monitoring

**Scenario:** MSSP managing multiple client tenants needs unified exposure visibility.

**Configuration:**
- Deploy SpyCloud connector per tenant with tenant-specific API keys
- Use Azure Lighthouse for cross-tenant workspace access
- Configure workbooks with tenant selector parameter
- Set up per-tenant automation rules with client-specific playbooks

**Pros:**
- Single-pane-of-glass across all managed tenants
- Per-tenant severity thresholds and response policies
- Automated reporting per client

**Cons:**
- Requires Azure Lighthouse setup per tenant
- API key management across tenants adds complexity

---

## Use Case Decision Matrix

| Use Case | Severity | License Required | Complexity | Business Value |
|----------|----------|-----------------|-----------|---------------|
| Employee credential exposure | Any | Enterprise | Low | High |
| Infostealer full remediation | 20-25 | Enterprise | Medium | Very High |
| VIP account monitoring | Any | Enterprise | Low | Very High |
| Cross-platform sign-in correlation | 5+ | Enterprise + Entra P2 | Medium | Very High |
| Device infection + MDE isolation | 20+ | Enterprise + MDE | Medium | High |
| Stolen cookie/session detection | 25 | SIP | Medium | Critical |
| Compliance assessment | Any with PII | Enterprise + AI Engine | High | High |
| PCI-DSS card exposure | Any | Enterprise | Low | Critical |
| Identity graph analysis | Any | IdLink | High | Medium |
| Password reuse hunting | Any | Enterprise | Low | Medium |
| Malware C2 detection | 20+ | Enterprise + DNS logs | Medium | High |
| MSSP multi-tenant | Any | Enterprise per tenant | High | Very High |

## Deployment Complexity Guide

```
Low Complexity (< 1 hour):
  - Single-click ARM deployment
  - Enable analytics rules
  - Configure email notifications

Medium Complexity (1-4 hours):
  - Full playbook configuration with managed identities
  - MDE/Intune integration setup
  - Workbook customization

High Complexity (4+ hours):
  - AI Investigation Engine with OpenAI
  - Purview compliance integration
  - Custom graph materialization
  - Multi-tenant MSSP setup
  - Full CI/CD pipeline configuration
```
