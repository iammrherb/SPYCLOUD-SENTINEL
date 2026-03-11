# SpyCloud Security Copilot Integration -- Complete Guide

<p align="center">
  <img src="images/SpyCloud-Logo-white.png" alt="SpyCloud Logo" width="300"/>
</p>

<p align="center">
  <strong>SpyCloud Darknet & Identity Threat Exposure Intelligence</strong><br/>
  Microsoft Security Copilot Integration v8.0.0
</p>

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation Guide](#2-installation-guide)
3. [API Plugin Configuration](#3-api-plugin-configuration)
4. [KQL Plugin Skills Catalog](#4-kql-plugin-skills-catalog)
5. [API Plugin Skills Catalog](#5-api-plugin-skills-catalog)
6. [Investigation Agent](#6-investigation-agent)
7. [GPT-4o AI Analysis Skills](#7-gpt-4o-ai-analysis-skills)
8. [Agent Persona -- SENTINEL](#8-agent-persona--sentinel)
9. [Suggested Prompts](#9-suggested-prompts)
10. [Settings Reference](#10-settings-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Integration with Other Tools](#12-integration-with-other-tools)
13. [What to Expect](#13-what-to-expect)

---

## 1. Overview

The SpyCloud Security Copilot Integration delivers three complementary plugins that together provide **168 skills**, **17 specialized sub-agents**, and seamless access to **145+ deployed Sentinel resources** -- enabling SOC teams to investigate compromised credentials, infostealer infections, exposed PII, device forensics, and automated remediation status through natural-language conversation.

### Three Integrated Plugins

| Plugin | File | Skills | Purpose |
|--------|------|--------|---------|
| **KQL Plugin** | `SpyCloud_Plugin.yaml` | 90 | Query SpyCloud tables in Sentinel via natural-language KQL across 29 categories |
| **API Plugin** | `SpyCloud_API_Plugin.yaml` | 20 | Direct REST API access to SpyCloud for real-time darknet lookups across 6 APIs |
| **Investigation Agent** | `SpyCloud_Agent.yaml` | 58 total | Autonomous investigation: 17 sub-agents + 6 GPT-4o skills + 35 internal KQL skills |

### Key Metrics

| Metric | Value |
|--------|-------|
| **Total Skills** | 168 (90 KQL + 20 API + 58 Agent) |
| **Sub-Agents** | 17 specialized investigation agents |
| **GPT-4o Analysis Skills** | 6 AI-powered analysis and reporting skills |
| **Agent Internal KQL Skills** | 35 data retrieval skills for agent orchestration |
| **SpyCloud APIs Covered** | 6 (Enterprise, Catalog, Compass, SIP, Identity Exposure, Investigations) |
| **Sentinel Custom Tables** | 10 SpyCloud tables |
| **Analytics Rules** | 49 (38 scheduled, 1 Fusion, 5 NRT, 5 MSIC) |
| **Hunting Queries** | 28 proactive threat hunting queries |
| **Playbooks** | 10 Logic App automated response workflows |
| **Watchlists** | 4 (VIP, IOC Blocklist, Approved Domains, High-Value Assets) |
| **Workbooks** | 3 (Executive Dashboard, SOC Operations, Threat Intelligence) |
| **Notebooks** | 3 (Incident Triage, Threat Hunting, Threat Landscape) |
| **Deployment Methods** | 5 (ARM Template, Terraform, GitHub Actions, Cloud Shell, Azure Portal) |

### Plugin Architecture

```
+----------------------------------------------------------------------+
|                    Microsoft Security Copilot                         |
+----------------------------------------------------------------------+
|                                                                      |
|  +-------------------+  +------------------+  +-------------------+  |
|  |  Investigation    |  |   KQL Plugin     |  |   API Plugin      |  |
|  |     Agent         |  |  (90 Skills)     |  |  (20 Skills)      |  |
|  |  (17 Sub-Agents)  |  |                  |  |                   |  |
|  |  (6 GPT-4o)       |  |  Sentinel KQL    |  |  SpyCloud REST    |  |
|  |  (35 KQL)         |  |  queries across  |  |  across 6 APIs   |  |
|  |                   |  |  29 categories   |  |                   |  |
|  +--------+----------+  +--------+---------+  +--------+----------+  |
|           |                      |                      |            |
+-----------+----------------------+----------------------+------------+
|                      Microsoft Sentinel                              |
|  +----------+ +----------+ +----------+ +----------+ +----------+   |
|  | 49 Rules | |28 Hunting| |10 Play-  | |4 Watch-  | |3 Work-   |   |
|  |          | | Queries  | |  books   | |  lists   | |  books   |   |
|  +----------+ +----------+ +----------+ +----------+ +----------+   |
|  +----------+ +----------+ +----------+                              |
|  |3 Note-   | |10 Custom | |UEBA/     |                             |
|  |  books   | | Tables   | |Fusion/TI |                              |
|  +----------+ +----------+ +----------+                              |
+---------+--------+--------+--------+--------+-----------------------+
|                      SpyCloud APIs                                   |
|  +------------+ +----------+ +--------+ +-----+ +--------+ +------+ |
|  | Enterprise | | Catalog  | |Compass | | SIP | |Identity| |Invest| |
|  | Breach API | | API      | |  API   | | API | |Exposure| |  API | |
|  +------------+ +----------+ +--------+ +-----+ +--------+ +------+ |
+----------------------------------------------------------------------+
```

---

## 2. Installation Guide

### Prerequisites

1. Microsoft Sentinel workspace (Log Analytics) with SpyCloud data connector configured
2. Security Copilot license
3. SpyCloud API key (required for API Plugin and data ingestion)
4. Azure permissions: Contributor on resource group, Microsoft Sentinel Contributor

### Step 1: Deploy Sentinel Resources

Deploy the SpyCloud Sentinel solution first (ARM, Terraform, or Cloud Shell). This creates the 10 custom tables, 49 analytics rules, 10 playbooks, and all other Sentinel resources.

### Step 2: Install the KQL Plugin

1. Open Microsoft Security Copilot
2. Navigate to **Settings** > **Plugins** > **Custom plugins**
3. Click **Add plugin** > **Upload file**
4. Upload `copilot/SpyCloud_Plugin.yaml`
5. Configure the required settings:
   - **TenantId**: Your Azure Tenant ID
   - **SubscriptionId**: Your Azure Subscription ID
   - **ResourceGroupName**: Resource Group containing the Sentinel workspace
   - **WorkspaceName**: Sentinel Log Analytics workspace name
6. Click **Save**

### Step 3: Install the API Plugin

1. In **Settings** > **Plugins** > **Custom plugins**, click **Add plugin**
2. Upload `copilot/SpyCloud_API_Plugin.yaml`
3. For authentication, enter your SpyCloud API key
4. The API key is sent as the `X-API-Key` header on all requests
5. Configure optional settings:
   - **ApiBaseUrl**: Defaults to `https://api.spycloud.io` (override only for regional/on-prem)
6. Click **Save**

### Step 4: Install the Investigation Agent

1. In **Settings** > **Plugins** > **Custom plugins**, click **Add plugin**
2. Upload `copilot/SpyCloud_Agent.yaml`
3. Configure the required settings:
   - **TenantId**: Your Azure Tenant ID
   - **SubscriptionId**: Your Azure Subscription ID
   - **ResourceGroupName**: Resource Group containing the Sentinel workspace
   - **WorkspaceName**: Sentinel Log Analytics workspace name
4. Optionally configure:
   - **SpyCloudApiKey**: SpyCloud API key for API Plugin integration (not required if API Plugin is installed separately)
5. Click **Save**

### Step 5: Verify Installation

Test each plugin with these prompts:

| Plugin | Test Prompt |
|--------|------------|
| **Agent** | "What can you help me investigate?" |
| **KQL Plugin** | "Check SpyCloud for exposures on user@company.com" |
| **API Plugin** | "Look up SpyCloud breach data for user@company.com" |

---

## 3. API Plugin Configuration

### Authentication Details

The API Plugin authenticates to SpyCloud using an API key sent in the HTTP header.

| Setting | Value |
|---------|-------|
| **Auth Type** | APIKey |
| **Key Header Name** | `X-API-Key` |
| **AuthScheme** | *(empty string)* |
| **Location** | Header |
| **AuthorizationHeader** | `X-API-Key` |

### Security Copilot Settings Fields

When configuring the API Plugin in Security Copilot, enter the following in the authentication dialog:

| Field | What to Enter |
|-------|---------------|
| **API Key** | Your SpyCloud API key (e.g., `abc123def456...`) |
| **Key name** | `X-API-Key` |
| **Auth scheme** | Leave empty |
| **Location** | Select **Header** |

### Base URL

The default API base URL is `https://api.spycloud.io`. This is configured in the optional `ApiBaseUrl` setting and should only be changed if directed by SpyCloud support for regional or on-premises deployments.

### OpenAPI Specification

The API Plugin references the OpenAPI 3.0.3 specification at:
```
https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/copilot/SpyCloud_API_Plugin_OpenAPI.yaml
```

---

## 4. KQL Plugin Skills Catalog

The KQL Plugin provides **90 promptbook skills** organized into **29 categories**. All skills query SpyCloud custom tables in Microsoft Sentinel.

### Category 1: User Credential and Exposure Investigation (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetUserExposures** | All compromised credentials and infostealer infections for a specific email | `targetEmail` |
| **GetUserFullPIIProfile** | Complete identity profile including SSN, financial, employment, social media | `targetEmail` |
| **GetUserAccountActivity** | Account activity timeline -- signup, login, modification timestamps | `targetEmail` |

### Category 2: Password and Credential Analysis (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetExposedPasswords** | All password data including hashes, plaintext, types, salts, sightings | `targetEmail` |
| **GetPlaintextPasswordExposures** | Organization-wide plaintext password exposures (highest risk) | -- |
| **GetPasswordTypeBreakdown** | Breakdown by password type with crackability assessment | -- |

### Category 3: Severity, Exposure Type, and Breach Category (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetHighSeverityExposures** | Recent severity 20+ infostealer exposures with device context | -- |
| **GetExposureSummaryBySeverity** | Exposure breakdown by severity level (2, 5, 20, 25) | -- |
| **GetExposureSummaryByDomain** | Exposures aggregated by corporate email domain | -- |
| **GetTargetedDomains** | Most frequently targeted websites and applications | -- |

### Category 4: Sensitive PII and Financial Data (2 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetSensitivePIIExposures** | Records with SSN, bank accounts, tax IDs, health data | -- |
| **GetSocialMediaExposures** | LinkedIn, Twitter, social profiles for a user | `targetEmail` |

### Category 5: Device and Malware Forensics (5 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetInfectedDevices** | All infected devices grouped by machine ID and hostname | -- |
| **GetDeviceForensics** | Full forensic details for a specific infected device | `machineId` |
| **GetDeviceToUserCorrelation** | All users affected by a single infected device | `machineId` |
| **GetAVCoverageGaps** | AV products present on infected devices that failed to prevent infection | -- |
| **GetMalwareInfo** | Breach catalog lookup for a malware family or breach source | `threatName` |

### Category 6: Breach Catalog Intelligence (2 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetRecentBreaches** | Recently ingested breach and malware sources | -- |
| **GetEnrichedExposures** | Exposures joined with catalog for malware family names | -- |

### Category 7: MDE Device Remediation Audit (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetMDERemediationActions** | All MDE remediation actions triggered by SpyCloud | -- |
| **GetMDERemediationForDevice** | MDE actions for a specific hostname | `hostName` |
| **GetMDERemediationStats** | Aggregate MDE remediation effectiveness metrics | -- |

### Category 8: Conditional Access Remediation (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetConditionalAccessActions** | All Entra ID identity protection actions | -- |
| **GetConditionalAccessForUser** | Identity actions for a specific user | `userEmail` |
| **GetConditionalAccessStats** | Aggregate identity remediation effectiveness | -- |

### Category 9: Cross-Table Investigation (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetFullUserInvestigation** | Comprehensive cross-table investigation for a user | `investigateEmail` |
| **GetGeographicAnalysis** | Geographic distribution of infostealer infections | -- |
| **GetSpyCloudHealthStatus** | Data ingestion health check across all tables | -- |

### Category 10: Compass Consumer Identity (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetCompassExposures** | Consumer identity exposures from Compass | `SearchTerm` |
| **GetCompassDevices** | Compass infected devices with OS and infection timeline | -- |
| **GetCompassCorporateOverlap** | Users with both consumer and corporate credential exposure | -- |
| **GetDeviceReinfections** | Devices infected multiple times indicating failed remediation | -- |

### Category 11: Cross-Connector Threat Hunting (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **HuntExposedUserSignIns** | Correlate exposed users with Entra ID sign-in logs | `DaysBack` (optional) |
| **HuntExposedUserEmailActivity** | Office 365 email activity by exposed users | -- |
| **HuntExposedUserAzureActivity** | Azure resource changes by exposed users | -- |
| **HuntInfectedIPsInNetwork** | Search infected IPs across MDE, DNS, firewall, TI | -- |

### Category 12: Risk Scoring and Prioritization (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetUserRiskScore** | Composite risk score for a user based on multiple factors | `UserEmail` |
| **GetOrgRiskDashboard** | Organization-wide risk summary | -- |
| **GetTopPriorityActions** | Highest-priority remediation actions needed now | -- |

### Category 13: UEBA Correlation (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetUEBAAnomaliesForExposedUsers** | Cross-reference exposed users with UEBA anomalies | `Lookback`, `MinSeverity` (optional) |

### Category 14: Fusion Multistage (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetFusionMultistageIncidents** | Fusion-detected multistage attack incidents | `Lookback` (optional) |

### Category 15: TI Enrichment (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetTIEnrichmentResults** | TI enrichment results (VirusTotal, AbuseIPDB) for SpyCloud incidents | `Lookback` (optional) |

### Category 16: Automation Rule Effectiveness (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetAutomationRuleMetrics** | Automation rule execution statistics and success rates | `Lookback` (optional) |

### Category 17: Session Cookie Theft and Token Replay (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **HuntStolenSessionCookies** | Hunt stolen session cookies bypassing MFA via token replay | -- |

### Category 18: Lateral Movement Detection (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **HuntLateralMovementFromExposedAccounts** | Detect RDP/SMB/NTLM lateral movement from exposed accounts | -- |

### Category 19: Data Exfiltration Detection (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **HuntDataExfiltrationFromExposedUsers** | Detect mass file downloads from exposed users in cloud apps | -- |

### Category 20: Malware Family Tracking (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **TrackMalwareFamilyTrends** | Track infostealer malware family trends across the org | `Lookback` (optional) |

### Category 21: Watchlist Management (3 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetIOCBlocklistEntries** | Current IOC Blocklist watchlist entries | -- |
| **GetHighValueAssets** | High-value assets requiring elevated monitoring | -- |
| **GetApprovedDomains** | Corporate email domains configured for monitoring | -- |

### Category 22: MSIC Incident Correlation (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetMSICIncidentCorrelation** | Microsoft Security Incident Creation rule incidents correlated with SpyCloud | `Lookback` (optional) |

### Category 23: Executive Reporting (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GenerateExecutiveSummary** | Executive summary report with exposure metrics, incidents, and remediation | -- |

### Category 24: Campaign and Threat Actor Intelligence (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetMalwareCampaignSummary** | Full impact summary for a malware campaign or family | `malwareFamily` |
| **GetBreachCampaignTimeline** | Chronological timeline of breach catalog entries for a campaign | `campaignName` |
| **GetRelatedBreaches** | Find breaches sharing victims, IPs, or time windows | `sourceId` |
| **GetThreatActorProfile** | Comprehensive threat actor profile from SpyCloud data | `actorName` |

### Category 25: Campaign TTPs (1 skill)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetCampaignTTPs** | Enumerate MITRE ATT&CK TTPs for a malware campaign | `campaignName` |

### Category 26: Advanced User Analysis (5 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetUserAttackTimeline** | Complete attack timeline from exposure through data access | `targetEmail` |
| **GetUserPasswordHistory** | Password exposure patterns over time | `targetEmail` |
| **GetUserDeviceAssociations** | All devices a user signed in from with infection status | `targetEmail` |
| **GetUserRemediationHistory** | Full remediation trail across CA, MDE, and Entra audit | `targetEmail` |
| **GetUserRiskScoreBreakdown** | Composite risk score with detailed factor breakdown | `targetEmail` |

### Category 27: Network and Infrastructure (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetInfectedIPFirewallActivity** | Firewall events (allow/deny) for SpyCloud infection IPs | -- |
| **GetDNSQueriesFromInfectedHosts** | DNS queries from infected IPs for C2 detection | -- |
| **GetVPNConnectionsFromExposedUsers** | VPN/remote access from users with active exposures | -- |
| **GetNetworkLateralMovement** | Track lateral movement from compromised accounts | -- |

### Category 28: Compliance and Reporting (4 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetExposureComplianceReport** | Compliance audit metrics (SOC2, PCI DSS, HIPAA) | -- |
| **GetRemediationSLAReport** | Remediation SLA compliance (24h, 48h, 72h targets) | -- |
| **GetPIIExposureInventory** | Count exposed PII elements for regulatory notification | -- |
| **GetDataRetentionReport** | Table sizes, record counts, and retention spans | -- |

### Category 29: Incident, Alert Correlation, and Proactive Intelligence (10 skills)

| Skill | Description | Input |
|-------|-------------|-------|
| **GetIncidentCorrelation** | All correlated SpyCloud data for a Sentinel incident | `incidentId` |
| **GetFusionIncidentContext** | Fusion multistage incident details with SpyCloud alerts | `Lookback` (optional) |
| **GetAlertsByAnalyticsRule** | Rank SpyCloud analytics rules by alert volume | `Lookback` (optional) |
| **GetIncidentRemediationStatus** | Remediation action status for each SpyCloud incident | `Lookback` (optional) |
| **GetExposureForecast** | Trend analysis predicting exposure growth | -- |
| **GetHighRiskUserCohort** | Users with exposures, active sign-ins, and no remediation | -- |
| **GetStaleCredentialRisk** | Credentials exposed 30+ days with no password change | -- |
| **GetPasswordReuseRisk** | Password reuse risk detection | -- |
| **GetNewExposuresLastNHours** | New exposures ingested in recent hours | -- |
| **GetDeviceForensicProfile** | Complete device forensic profile | -- |

### Additional Operational Skills (10 skills)

| Skill | Description |
|-------|-------------|
| **GetDeviceReinfectionHistory** | Device reinfection tracking over time |
| **GetCompassDeviceInventory** | Compass device inventory summary |
| **GetMDEIsolationAudit** | MDE isolation audit trail |
| **GetExecutiveRiskGauge** | Executive-level risk gauge metric |
| **GetExposureTrendComparison** | Exposure trend comparison (month-over-month) |
| **GetTopRecommendations** | Top security recommendations based on data |
| **GetConnectorHealthAssessment** | Assessment of all data connectors and ingestion health |
| **GetMissingConnectorRecommendations** | Recommendations for missing connectors to enable |
| **GetPlaybookPermissionGaps** | Detect permission issues with playbooks |
| **GetCapabilityMatrix** | Full capability matrix of deployed resources |

---

## 5. API Plugin Skills Catalog

The API Plugin provides **20 direct REST API skills** for real-time SpyCloud lookups. All skills use API key authentication via the `X-API-Key` header.

### Enterprise API Skills (7 skills)

| Skill | Endpoint | Description | Required Input | Example Prompt |
|-------|----------|-------------|----------------|---------------|
| **GetBreachDataByEmail** | `GET /breach/data/emails/{email}` | Breach records by email address | `email` | "Look up SpyCloud breach data for user@company.com" |
| **GetBreachDataByDomain** | `GET /breach/data/domains/{domain}` | Breach records by corporate domain | `domain` | "Search SpyCloud for breaches affecting example.com" |
| **GetBreachDataByIp** | `GET /breach/data/ips/{ip}` | Breach records by IP address | `ip` | "Search SpyCloud for breach data linked to 10.0.0.1" |
| **CheckPasswordExposure** | `GET /breach/data/passwords/{password}` | Check if a password is exposed | `password` | "Has this password appeared in any SpyCloud breaches" |
| **GetBreachDataByUsername** | `GET /breach/data/usernames/{username}` | Breach records by username | `username` | "Search SpyCloud for breaches with this username" |
| **ListBreachCatalog** | `GET /breach/catalog` | Browse the full breach catalog | `query` (optional) | "Show me the SpyCloud breach catalog" |
| **GetBreachCatalogEntry** | `GET /breach/catalog/{id}` | Specific breach details by source ID | `id` | "Show me details for SpyCloud breach ID 12345" |

### Compass Investigation API Skills (3 skills)

| Skill | Endpoint | Description | Required Input | Example Prompt |
|-------|----------|-------------|----------------|---------------|
| **CompassInvestigateEmail** | `GET /compass/data/emails/{email}` | Deep Compass investigation by email | `email` | "Run a deep Compass investigation on user@company.com" |
| **CompassInvestigateDomain** | `GET /compass/data/domains/{domain}` | Deep Compass investigation by domain | `domain` | "Run a Compass investigation on example.com" |
| **CompassInvestigateIp** | `GET /compass/data/ips/{ip}` | Deep Compass investigation by IP | `ip` | "Run a Compass investigation on this IP address" |

### SIP API Skills (3 skills)

| Skill | Endpoint | Description | Required Input | Example Prompt |
|-------|----------|-------------|----------------|---------------|
| **SipGetCookiesByDomain** | `GET /sip/breach/data/cookies` | Stolen session cookies for a domain | `cookie_domain` | "Get stolen cookies for example.com from SpyCloud SIP" |
| **SipListBreachCatalog** | `GET /sip/breach/catalog` | SIP breach catalog entries | -- | "Show the SpyCloud SIP breach catalog" |
| **SipGetBreachCatalogEntry** | `GET /sip/breach/catalog/{id}` | Specific SIP breach details | `id` | "Show details for this SIP breach ID" |

### Investigations API Skills (5 skills)

| Skill | Endpoint | Description | Required Input | Example Prompt |
|-------|----------|-------------|----------------|---------------|
| **InvestigateByEmail** | `GET /investigations/data/emails/{email}` | Full database investigation by email | `email` | "Investigate this email across all SpyCloud data" |
| **InvestigateByDomain** | `GET /investigations/data/domains/{domain}` | Full database investigation by domain | `domain` | "Run a full investigation on this domain" |
| **InvestigateByIp** | `GET /investigations/data/ips/{ip}` | Full database investigation by IP | `ip` | "Investigate this IP across all SpyCloud data" |
| **InvestigateByUsername** | `GET /investigations/data/usernames/{username}` | Full database investigation by username | `username` | "Investigate this username across all SpyCloud data" |
| **InvestigateByPassword** | `GET /investigations/data/passwords/{password}` | Full database investigation by password | `password` | "Search SpyCloud Investigations for this password" |

### Identity API Skills (2 skills)

| Skill | Endpoint | Description | Required Input | Example Prompt |
|-------|----------|-------------|----------------|---------------|
| **GetIdentityExposure** | `GET /identity/exposure/{email}` | Aggregated identity exposure profile | `email` | "What is the identity exposure profile for user@company.com" |
| **GetIdentityWatchlist** | `GET /identity/watchlist` | Monitored identities on the watchlist | `type` (optional) | "Show the SpyCloud identity watchlist" |

### Common API Parameters

All API skills support these optional filter parameters:

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

## 6. Investigation Agent

### Overview

The SpyCloud Investigation Agent (`SpyCloud.ThreatIntelligence.SentinelAgent`) is an autonomous, conversational security analyst that orchestrates **17 specialized sub-agents** plus **6 GPT-4o analysis skills** and **35 internal KQL data retrieval skills** for a total of **58 capabilities**.

### 17 Sub-Agents

#### 1. UEBABehavioralAnalysisAgent
- **Display Name**: UEBA & Behavioral Analysis Agent
- **What it investigates**: Anomalous user behavior for accounts with credential exposure
- **Data sources**: SpyCloudBreachWatchlist_CL, BehaviorAnalytics, IdentityInfo, SigninLogs
- **Example prompts**: "Show UEBA anomalies for SpyCloud exposed users", "Which exposed users have anomalous behavior"
- **Expected output**: Correlation table of users with both credential exposure AND behavioral anomalies, risk intersection scoring, and prioritized action items

#### 2. FusionMultistageAttackAgent
- **Display Name**: Fusion & Multistage Attack Agent
- **What it investigates**: Fusion-detected multistage attacks for credential theft correlation
- **Data sources**: SpyCloudBreachWatchlist_CL, SecurityAlert, SecurityIncident, SpyCloudBreachCatalog_CL
- **Example prompts**: "What Fusion multistage attacks involve SpyCloud alerts", "Correlate Fusion incident with SpyCloud data"
- **Expected output**: Attack chain visualization with MITRE ATT&CK mapping, timeline of SpyCloud exposure vs Fusion detection

#### 3. TIEnrichmentIOCAnalysisAgent
- **Display Name**: TI Enrichment & IOC Analysis Agent
- **What it investigates**: Threat intelligence enrichment and IOC blocklist management
- **Data sources**: SpyCloudBreachWatchlist_CL, ThreatIntelligenceIndicator, IOC Blocklist watchlist, Spycloud_MDE_Logs_CL
- **Example prompts**: "Check SpyCloud IOCs against blocklists", "Show TI enrichment for SpyCloud incidents"
- **Expected output**: IOC coverage gap analysis with prioritized blocking recommendations

#### 4. SessionCookieMFABypassAgent
- **Display Name**: Session Cookie & MFA Bypass Agent
- **What it investigates**: Stolen session tokens and MFA bypass attempts
- **Data sources**: SpyCloudBreachWatchlist_CL (severity 25), SigninLogs, AADNonInteractiveUserSignInLogs, CloudAppEvents
- **Example prompts**: "Hunt for stolen session cookie abuse", "Find users bypassing MFA with stolen tokens"
- **Expected output**: Session theft risk assessment, token replay indicators, MFA gap analysis

#### 5. LateralMovementInvestigationAgent
- **Display Name**: Lateral Movement Investigation Agent
- **What it investigates**: Device-to-device movement from compromised accounts
- **Data sources**: SpyCloudBreachWatchlist_CL, IdentityLogonEvents, DeviceLogonEvents, Spycloud_MDE_Logs_CL
- **Example prompts**: "Detect lateral movement from SpyCloud exposed accounts", "Map device-to-device movement"
- **Expected output**: Movement map with source-to-target device chains, anomaly flags, containment status

#### 6. DataExfiltrationDetectionAgent
- **Display Name**: Data Exfiltration Detection Agent
- **What it investigates**: Data theft patterns from compromised accounts
- **Data sources**: SpyCloudBreachWatchlist_CL, CloudAppEvents, OfficeActivity, SpyCloud_ConditionalAccessLogs_CL
- **Example prompts**: "Hunt for data exfiltration from exposed users", "Check for suspicious mailbox forwarding"
- **Expected output**: Exfiltration risk assessment with data volume estimates and containment recommendations

#### 7. ExecutiveSummaryComplianceAgent
- **Display Name**: Executive Summary & Compliance Agent
- **What it investigates**: Executive reporting and compliance framework mapping
- **Data sources**: All SpyCloud tables, MDE logs, CA logs
- **Example prompts**: "Generate an executive summary", "Create a compliance assessment for GDPR"
- **Expected output**: Business-impact-focused reports with risk posture, trends, compliance mapping, and strategic recommendations

#### 8. WatchlistAssetManagementAgent
- **Display Name**: Watchlist & Asset Management Agent
- **What it investigates**: VIP monitoring, IOC blocklist coverage, and asset risk correlation
- **Data sources**: SpyCloudBreachWatchlist_CL, 4 Sentinel watchlists
- **Example prompts**: "Check VIP users for credential exposure", "Review IOC Blocklist coverage gaps"
- **Expected output**: VIP exposure alerts, IOC coverage reports, high-value asset risk matrix

#### 9. RansomwareImpactAssessmentAgent
- **Display Name**: Ransomware Impact Assessment Agent
- **What it investigates**: Ransomware precursor detection and pre-encryption containment
- **Data sources**: SpyCloudBreachWatchlist_CL, SpyCloudBreachCatalog_CL, IdentityLogonEvents, DeviceLogonEvents, High-Value Assets watchlist
- **Example prompts**: "Assess ransomware risk from current infections", "Identify ransomware-precursor malware"
- **Expected output**: Ransomware risk score with MITRE ATT&CK mapping and containment playbook
- **Tracked families**: RedLine, LummaC2, Vidar, Raccoon, StealC, Aurora, Mars, META, Mystic, RisePro, Titan

#### 10. IdentityRiskScoringAgent
- **Display Name**: Identity Risk Scoring Agent
- **What it investigates**: Dynamic multi-dimensional identity risk scoring
- **Data sources**: SpyCloudBreachWatchlist_CL, SpyCloud_ConditionalAccessLogs_CL, BehaviorAnalytics, VIP watchlist, SigninLogs
- **Example prompts**: "Generate risk scores for all exposed users", "Show top 10 highest-risk identities"
- **Expected output**: Risk-ranked user lists with composite scores (0-105 scale) across 7 dimensions
- **Risk tiers**: Critical (75-105), High (50-74), Medium (25-49), Low (0-24)

#### 11. SupplyChainExposureAgent
- **Display Name**: Supply Chain & Third-Party Exposure Agent
- **What it investigates**: Third-party vendor and supply chain credential risk
- **Data sources**: SpyCloudBreachWatchlist_CL (target_domain analysis), SpyCloudBreachCatalog_CL, Approved Domains watchlist
- **Example prompts**: "Assess third-party vendor credential risk", "Find partner domain exposures"
- **Expected output**: Vendor risk tiering with supply chain risk score

#### 12. DarkWebMonitoringAlertAgent
- **Display Name**: Dark Web Monitoring & Alert Agent
- **What it investigates**: Real-time dark web monitoring and intelligence briefings
- **Data sources**: SpyCloudBreachWatchlist_CL, SpyCloudBreachCatalog_CL, Spycloud_MDE_Logs_CL, SpyCloud_ConditionalAccessLogs_CL
- **Example prompts**: "Show new exposures ingested today", "Generate a dark web intelligence briefing"
- **Expected output**: Daily/weekly intelligence briefings with ingestion velocity, new breach sources, fresh infections

#### 13. DefenderXDREndpointAgent
- **Display Name**: Defender XDR & Endpoint Investigation Agent
- **What it investigates**: Deep endpoint investigation across the full Defender XDR suite
- **Data sources**: DeviceAlertEvents, DeviceInfo, DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents, DeviceLogonEvents, IdentityLogonEvents, IdentityQueryEvents, EmailEvents, CloudAppEvents, SecurityAlert, SecurityIncident
- **Example prompts**: "Check Defender alerts for this exposed user", "Show device timeline for this infected host"
- **Expected output**: Unified XDR threat summary with endpoint forensics, identity attacks, email threats, cloud app risk

#### 14. IntuneDeviceComplianceAgent
- **Display Name**: Intune Device Compliance & Posture Agent
- **What it investigates**: Device compliance posture for SpyCloud-infected endpoints
- **Data sources**: IntuneDevices, IntuneDeviceComplianceOrg, DeviceInfo, SpyCloudBreachWatchlist_CL, Spycloud_MDE_Logs_CL
- **Example prompts**: "Are infected devices Intune-managed", "Find unmanaged devices with infections"
- **Expected output**: Device compliance matrix, unmanaged device alerts, compliance gap analysis

#### 15. CASBCloudAppSecurityAgent
- **Display Name**: CASB & Cloud Application Security Agent
- **What it investigates**: Cloud app security risks from compromised credentials
- **Data sources**: CloudAppEvents, OfficeActivity, SigninLogs, AuditLogs, SpyCloudBreachWatchlist_CL
- **Example prompts**: "What shadow IT apps are accessed by compromised users", "Check OAuth consent grants"
- **Expected output**: Cloud app risk summary, OAuth consent table, SSO blast radius, shadow IT inventory

#### 16. CompassDeepInvestigationAgent
- **Display Name**: Compass Deep Infostealer Investigation Agent
- **What it investigates**: Deepest level infostealer forensics via SpyCloud Compass
- **Data sources**: SpyCloudCompassData_CL, SpyCloudCompassDevices_CL, SpyCloudCompassApplications_CL, SpyCloudBreachWatchlist_CL, SpyCloudBreachCatalog_CL
- **Example prompts**: "Run a deep Compass investigation on this email", "What stolen cookies exist for this user"
- **Expected output**: Complete infection profile with stolen artifact inventory, malware family attribution, C2 infrastructure, application credential map
- **Note**: Requires SpyCloud Enterprise+ subscription for Compass data

#### 17. SpyCloudInvestigationAgent (Primary Orchestrator)
- **Display Name**: SpyCloud Investigation Agent
- **What it investigates**: The primary entry point -- autonomously orchestrates all 16 other sub-agents plus internal skills based on the user's request
- **Data sources**: All available sources via child skills and sub-agents
- **Example prompts**: "What can you help me investigate?", "Show me an overview of our dark web exposure"
- **Expected output**: Rich, detailed reports with data tables, severity indicators, timelines, and actionable pivot suggestions

---

## 7. GPT-4o AI Analysis Skills

The Investigation Agent includes **6 GPT-4o analysis skills** that transform raw data into structured intelligence reports.

| # | Skill | Description |
|---|-------|-------------|
| 1 | **AnalyzeAndSummarize** | Takes raw SpyCloud data from KQL queries and produces structured investigation reports with threat assessment, risk scoring, remediation recommendations, and compliance impact analysis. |
| 2 | **BuildThreatNarrative** | Constructs chronological attack narratives from multi-source data (SpyCloud, Defender XDR, Intune, Entra ID, CASB). Maps findings to MITRE ATT&CK and generates complete incident timelines. |
| 3 | **GenerateComplianceAssessment** | Analyzes exposure data against GDPR, CCPA, HIPAA, PCI-DSS, SOX, and NIST frameworks. Determines breach notification obligations, regulatory exposure, and remediation timelines. Produces audit-ready documentation. |
| 4 | **GenerateExecutiveBriefing** | Transforms technical findings into board-level executive briefings with business impact analysis, risk quantification, trend assessment, strategic recommendations, and automation ROI metrics. |
| 5 | **CorrelateExternalThreatIntel** | Enriches SpyCloud indicators (IPs, domains, malware families, hashes) with threat intelligence context including VirusTotal reputation, AbuseIPDB confidence, MITRE ATT&CK mapping, and threat actor attribution. |
| 6 | **DesignResponsePlaybook** | Analyzes specific threat scenarios and designs custom incident response playbooks with step-by-step procedures, automation opportunities, decision trees, escalation criteria, and Logic App design guidance. |

---

## 8. Agent Persona -- SENTINEL

The Investigation Agent operates as **SENTINEL** -- a battle-hardened security analyst personality designed for engaging, productive conversations.

### Personality Traits

- **Confident and Direct**: Speaks with authority backed by 600B+ recaptured darknet records. Does not hedge -- tells it like it is.
- **Witty and Engaging**: Uses humor strategically. A well-placed observation about password reuse habits, a wry comment about "password123" showing up again.
- **Persistent and Thorough**: Never gives up on an investigation. If one angle does not work, pivots to another. Always has a "but let me also check..." follow-up.
- **Empathetic and Supportive**: Understands SOC analysts are overwhelmed. Makes their lives easier, celebrates wins, and prioritizes actionable findings.
- **Brutally Honest**: When the situation is bad, says so directly. "Look, 47 users have plaintext passwords on the dark web and 12 of them logged in yesterday. We need to act NOW."

### Communication Style

- Leads with the most important finding first
- Always ends with actionable next steps or pivot suggestions
- Uses severity indicators for quick scanning: Critical, High, Medium, Low
- Matches the user's energy -- brief question gets a brief answer, deep dive gets the full treatment
- Uses tables for data clarity but adds an "Analyst's Take" with expert interpretation
- Handles misspellings and typos gracefully without calling them out
- Interprets single-word inputs intelligently (e.g., "passwords" shows password exposure summary, an email address triggers full user investigation)

### When SENTINEL Uses Humor

- After delivering good news: "Nice -- this user was already remediated 2 hours after exposure. The automation is doing its job."
- When providing capabilities: "I've got 100+ skills, 17 sub-agents, and 600 billion darknet records. I'm basically the Avengers of threat intelligence, except I actually show up on time."
- When password hygiene is poor: Wry observations about password reuse habits (tastefully)
- Never uses humor when delivering critical threat findings or when the user is clearly stressed

### Status Indicators

- Severity: Critical, High, Medium, Low
- Remediation: Remediated, Partial, Unremediated
- "Analyst's Take": Expert interpretation callouts after data presentations

---

## 9. Suggested Prompts

### Getting Started (6 prompts)

| Prompt | What it does |
|--------|-------------|
| "What can you help me investigate?" | Shows full capability menu with categories |
| "Show me an overview of our dark web exposure" | Runs organization-wide assessment with severity breakdown |
| "Which users have the most critical credential exposures?" | Shows highest-severity exposed users |
| "Are any devices infected with infostealer malware?" | Lists infected devices with forensic context |
| "Show me users with plaintext passwords exposed" | Lists most dangerous credential exposures |
| "Do we have sensitive PII exposed requiring breach notification?" | Compliance-focused PII assessment |

### User Investigation (10 prompts)

| Prompt |
|--------|
| "Investigate user@company.com" |
| "Tell me more about this user's exposure" |
| "What passwords were stolen and are any plaintext?" |
| "Show the full PII profile including SSN and financial data" |
| "Show account activity and login history" |
| "Show social media and LinkedIn exposure for this user" |
| "Build a complete attack timeline for this compromised user" |
| "Calculate the risk score for this user" |
| "Show full remediation history for this user" |
| "Find users whose exposed password matches their current Active Directory password" |

### Device Forensics (7 prompts)

| Prompt |
|--------|
| "Show device forensics -- malware path, AV installed, IPs" |
| "What other users were compromised from this device?" |
| "Was this device isolated in Defender?" |
| "What antivirus products failed to prevent infections?" |
| "Walk me through a full forensic analysis of this infected device" |
| "Show the kill chain for this infostealer infection end to end" |
| "Are our SpyCloud-infected devices managed in Intune?" |

### Malware and Threat Hunting (8 prompts)

| Prompt |
|--------|
| "What malware campaigns are currently targeting our organization?" |
| "Analyze the RedLine infostealer campaign affecting our users" |
| "Show me related breaches from the same threat actor group" |
| "What are the TTPs associated with the infostealers targeting us?" |
| "Track this malware family's activity over time" |
| "Create a campaign intelligence report for the last 30 days" |
| "Which bad actor groups have targeted our domain the most?" |
| "What malware family was responsible?" |

### Remediation and Response (7 prompts)

| Prompt |
|--------|
| "What's our mean time to remediate credential exposures?" |
| "Show me the remediation gap -- who still needs to be fixed?" |
| "Which users were re-exposed AFTER their password was reset?" |
| "How many playbook executions succeeded vs failed this week?" |
| "Is there anything NOT automatically remediated?" |
| "How effective are our automated playbooks?" |
| "What are the top 5 things to act on right now?" |

### Defender XDR and Endpoint (6 prompts)

| Prompt |
|--------|
| "Show me Defender XDR alerts for users with SpyCloud credential exposure" |
| "Check the device timeline for this infected host in Defender for Endpoint" |
| "Are there any identity attacks (pass-the-hash, golden ticket) from compromised accounts?" |
| "Correlate Defender alerts with SpyCloud exposure data for a full XDR picture" |
| "Are there any active MDE alerts on devices with infostealer infections?" |
| "Build a complete Defender XDR incident summary with SpyCloud correlation" |

### Intune Compliance (4 prompts)

| Prompt |
|--------|
| "Show device compliance status for all infected endpoints" |
| "Find unmanaged devices with active infostealer infections -- shadow IT risk" |
| "What are the OS patch levels on our compromised devices?" |
| "Which compliance policies are most frequently violated on infected devices?" |

### CASB and Cloud App Security (4 prompts)

| Prompt |
|--------|
| "What shadow IT apps are being accessed by compromised users?" |
| "Check for OAuth consent grants from SpyCloud-exposed accounts" |
| "If this user's SSO credentials were stolen, which connected apps are at risk?" |
| "What's the blast radius if our Okta/Azure AD credentials are on the dark web?" |

### Compass Deep Investigation (5 prompts)

| Prompt |
|--------|
| "Run a deep Compass investigation on this email" |
| "What stolen cookies and session tokens exist in Compass for this user?" |
| "Map all application credentials stolen by the infostealer from Compass data" |
| "Were any cryptocurrency wallets stolen in this infostealer infection?" |
| "Build a complete Compass infostealer forensic timeline" |

### Compliance and Executive (5 prompts)

| Prompt |
|--------|
| "Generate a compliance report for cyber insurance renewal" |
| "What PII exposures require GDPR/CCPA notification?" |
| "What would you present to the CISO right now?" |
| "Generate a board-level threat summary with recommendations" |
| "Compare our exposure this month vs last month" |

### Connector Health and Onboarding (5 prompts)

| Prompt |
|--------|
| "What data sources am I missing and what should I enable?" |
| "Check all my connector health and tell me what's broken" |
| "Are my playbooks actually running or do they have permission issues?" |
| "What blind spots do we have in our detection coverage?" |
| "Walk me through onboarding -- what should I set up first?" |

---

## 10. Settings Reference

### KQL Plugin Settings

| Setting | Required | Type | Description |
|---------|----------|------|-------------|
| **TenantId** | Yes | string | Azure Tenant ID where the Sentinel workspace is located |
| **SubscriptionId** | Yes | string | Azure Subscription ID where the Sentinel workspace is provisioned |
| **ResourceGroupName** | Yes | string | Resource Group containing the Sentinel workspace |
| **WorkspaceName** | Yes | string | Name of the Sentinel Log Analytics workspace with SpyCloud tables |

### API Plugin Settings

| Setting | Required | Type | Default | Description |
|---------|----------|------|---------|-------------|
| **API Key** | Yes | API Key | -- | SpyCloud API key sent as `X-API-Key` header |
| **ApiBaseUrl** | No | string | `https://api.spycloud.io` | Override for regional or on-premises deployments |

### Investigation Agent Settings

| Setting | Required | Type | Description |
|---------|----------|------|-------------|
| **TenantId** | Yes | string | Azure Tenant ID |
| **SubscriptionId** | Yes | string | Azure Subscription ID |
| **ResourceGroupName** | Yes | string | Resource Group name |
| **WorkspaceName** | Yes | string | Sentinel workspace name |
| **SpyCloudApiKey** | No | string | SpyCloud API key for API Plugin integration (optional if API Plugin installed separately) |

### Authentication Summary

| Plugin | Auth Type | Credentials Required |
|--------|-----------|---------------------|
| Agent | None | Azure Sentinel workspace access (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName) |
| KQL Plugin | None | Same Sentinel workspace access |
| API Plugin | APIKey | SpyCloud API key (`X-API-Key` header) |

---

## 11. Troubleshooting

### Common Issues and Solutions

#### "No data returned" from KQL skills

| Table | Cause | Solution |
|-------|-------|----------|
| SpyCloudBreachWatchlist_CL | Connector not configured or API key invalid | Verify the SpyCloud data connector is running and the API key is valid |
| Spycloud_MDE_Logs_CL | Playbook has not triggered yet | This table populates when the SpyCloud-IsolateDevice playbook executes. Check that automation rules are enabled and the playbook has MDE permissions (Machine.Isolate, Machine.ReadWrite.All) |
| SpyCloud_ConditionalAccessLogs_CL | Playbook has not triggered yet | This table populates when password reset/session revocation playbooks execute. Verify the managed identity has User.ReadWrite.All and UserAuthenticationMethod.ReadWrite.All Graph API permissions |
| SpyCloudCompassData_CL | Enterprise+ subscription required | Compass endpoints require an Enterprise+ SpyCloud subscription. Contact SpyCloud sales to upgrade |

#### KQL query fails with "Failed to resolve column"

The table exists but the column has not been populated yet. This is expected if the relevant playbook or connector has not processed any events. The agent will automatically explain this and suggest alternatives.

#### API Plugin returns 401 Unauthorized

1. Verify the API key is correct and active
2. Confirm the key is entered in the `X-API-Key` header field (not Bearer token)
3. Confirm `AuthScheme` is empty (not "Bearer" or any other value)
4. Check that the key has the appropriate SpyCloud API tier for the endpoint being called

#### API Plugin returns 403 Forbidden

The API key does not have access to the requested endpoint. Common causes:
- Compass endpoints require Enterprise+ subscription
- SIP endpoints require SIP API entitlement
- Investigations endpoints require Investigations API entitlement

#### Agent does not respond or gives generic answers

1. Verify all four required settings are configured (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName)
2. Ensure the plugin is enabled in Security Copilot settings
3. Try "What can you help me investigate?" as a basic test
4. Check that the workspace has SpyCloud tables with data

#### Plugin not appearing in Security Copilot

1. Re-upload the YAML file
2. Check for YAML syntax errors (common with copy-paste)
3. Verify your Security Copilot license includes custom plugins
4. Try clearing browser cache and refreshing

#### Playbook permission errors

Run the post-deployment script to automatically grant all required permissions:
```bash
./scripts/post-deploy-auto.sh
```

Or manually verify:
- Graph API: User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, Directory.ReadWrite.All
- MDE API: Machine.Isolate, Machine.ReadWrite.All, Ti.ReadWrite.All

---

## 12. Integration with Other Tools

The SpyCloud Copilot integration correlates with the entire Microsoft security ecosystem:

### Microsoft Sentinel

- Queries all 10 SpyCloud custom tables and 20+ native Microsoft tables
- Cross-references 49 analytics rules, 28 hunting queries, 10 playbooks
- Accesses 4 watchlists for VIP monitoring, IOC management, and asset risk
- Monitors automation rule health and playbook effectiveness

### Microsoft Defender XDR

- **Defender for Endpoint (MDE)**: Correlates SpyCloud infections with device alerts, process execution, network connections, file activity. Triggers device isolation via playbook.
- **Defender for Identity**: Detects pass-the-hash, golden ticket, and LDAP reconnaissance from compromised credentials via IdentityLogonEvents and IdentityQueryEvents.
- **Defender for Office 365**: Identifies phishing campaigns and credential harvesting targeting SpyCloud-exposed users via EmailEvents and EmailUrlInfo.
- **Defender for Cloud Apps (CASB)**: Discovers shadow IT, assesses OAuth app risk, monitors DLP violations from compromised identities via CloudAppEvents.

### Microsoft Intune

- Checks device enrollment, compliance state, OS version, encryption status for infected endpoints
- Identifies unmanaged devices with active infections (shadow IT risk)
- Reviews Intune device actions (wipe, retire, sync) taken post-infection
- Correlates compliance policy violations with infection severity

### Microsoft Entra ID

- Cross-references credential exposure with sign-in logs for active compromise detection
- Monitors Conditional Access policy effectiveness for exposed users
- Tracks risky user and risky sign-in assessments from Identity Protection
- Audits password resets, session revocations, and MFA re-registrations

### CASB / Cloud App Security

- Maps SSO/IdP credential exposure to connected SaaS application blast radius
- Detects OAuth consent phishing from compromised accounts
- Identifies shadow IT access using stolen credentials
- Monitors DLP policy violations by exposed users across cloud apps

---

## 13. What to Expect

### Typical Response Times

| Query Type | Expected Time | Notes |
|-----------|--------------|-------|
| Single user KQL lookup | 3-8 seconds | Depends on table size |
| Organization-wide summary | 5-15 seconds | Multiple aggregate queries |
| API Plugin real-time lookup | 2-5 seconds | Direct SpyCloud API call |
| Full investigation (Agent) | 10-30 seconds | Multiple skills orchestrated sequentially |
| Executive summary generation | 15-45 seconds | Multiple queries + GPT-4o analysis |
| Cross-platform correlation | 15-60 seconds | Multiple sub-agents + multi-source queries |

### Data Freshness

| Source | Update Frequency | Notes |
|--------|-----------------|-------|
| SpyCloud CCF Connector | Configurable polling interval (default: hourly) | New breach data and watchlist updates |
| MDE Remediation Logs | Real-time (playbook-triggered) | Populated when isolation playbook executes |
| Conditional Access Logs | Real-time (playbook-triggered) | Populated when identity playbooks execute |
| API Plugin (real-time) | Live | Queries SpyCloud API directly for freshest data |
| Breach Catalog | Updated as SpyCloud acquires new breaches | New sources appear in catalog within hours of acquisition |

### Limitations

- **Password values**: The agent never displays actual password values in responses for security. It reports password types, crackability, and sighting counts.
- **Compass data**: Requires SpyCloud Enterprise+ subscription. With standard Enterprise, Compass deep investigation tables will be empty. The agent gracefully falls back to Enterprise data.
- **SIP data**: Requires SIP API entitlement. Stolen cookie lookups require a separate SIP subscription.
- **Investigations API**: Requires Investigations API entitlement for full-database searches.
- **KQL result limits**: Most KQL skills return top 20-25 results by default to keep responses manageable. Use the API Plugin for bulk data needs.
- **Native Microsoft tables**: Some cross-correlation features (Defender XDR, Intune, CASB) require the corresponding Microsoft data connectors to be enabled in Sentinel.
- **Historical data**: KQL queries are subject to Log Analytics data retention settings (default 90 days). Older data may not be available.

### Plugin Cross-Compatibility

All three plugins are fully compatible and can be used simultaneously:

| Combination | Use Case |
|-------------|----------|
| Agent + KQL | Agent uses KQL skills for Sentinel data queries (primary mode) |
| Agent + API | Agent references API skills for real-time lookups |
| KQL + API | Analyst uses KQL for historical data, API for live data |
| All Three | Maximum coverage: autonomous investigation + KQL + live API |

### When to Use Which Plugin

| Scenario | Best Plugin | Why |
|----------|-------------|-----|
| Interactive investigation | **Agent** | Autonomous multi-step orchestration with SENTINEL personality |
| Quick KQL query | **KQL Plugin** | Direct promptbook skill invocation, fastest for single queries |
| Real-time API lookup | **API Plugin** | Live SpyCloud API for freshest data |
| Deep Compass analysis | **API Plugin** | Compass API endpoints for deep infostealer forensics |
| Executive reporting | **Agent** | Executive Summary sub-agent with GPT-4o analysis |
| Automated triage | **Agent** | Identity Risk Scoring sub-agent |
| Cross-platform correlation | **Agent** | Orchestrates multiple sub-agents across Sentinel, Defender, Intune, Entra, CASB |
| Compliance assessment | **Agent** | GenerateComplianceAssessment GPT-4o skill with regulatory framework mapping |

---

*SpyCloud Sentinel v8.0.0 -- Darknet & Identity Threat Exposure Intelligence*
*Copyright (c) 2024-2026 SpyCloud, Inc. All rights reserved.*
