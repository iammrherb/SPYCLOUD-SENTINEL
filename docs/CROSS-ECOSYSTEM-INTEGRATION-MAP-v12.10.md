# SpyCloud Identity Exposure Intelligence for Sentinel — Cross-Ecosystem Integration Map v12.10

**Date:** March 19, 2026
**Purpose:** Exhaustive mapping of SpyCloud data to every security tool, service, and data source
that can benefit from darknet identity threat intelligence

---

## INTEGRATION PHILOSOPHY

SpyCloud answers ONE question better than anyone: **"Which of my users and devices
are compromised, and what exactly was stolen?"**

Every integration below connects that answer to an ACTION:
- **Detect** — correlate exposure with suspicious activity
- **Respond** — auto-remediate compromised identities/devices
- **Hunt** — proactively search for post-compromise indicators
- **Report** — measure exposure risk and remediation effectiveness

---

## SECTION 1: MICROSOFT DEFENDER SUITE (Full Coverage)

### 1.1 Microsoft Defender for Endpoint (MDE)

| Integration | SpyCloud Data | MDE Data | Rule/Playbook | Value |
|-------------|--------------|----------|--------------|-------|
| Infected Device Isolation | `infected_machine_id`, `severity >= 20` | DeviceInfo, DeviceNetworkInfo | **Playbook: SpyCloud-MDE-Isolate** | Auto-isolate devices where infostealer stole credentials |
| Infected Device Tagging | `infected_machine_id` | DeviceInfo | **Playbook: SpyCloud-MDE-Tag** | Tag devices "SpyCloud-Compromised" for hunting |
| IOC Submission | `target_url`, `infected_ip` | TI Indicators | **Playbook: SpyCloud-MDE-IOC** | Submit malware C2 URLs and infected IPs as custom IOCs |
| Device Risk Correlation | `severity`, `password_plaintext` | DeviceRiskScore | **Rule: Exposed Device + High Risk Score** | Compound risk: SpyCloud exposure + Defender risk = escalate |
| AV Bypass Detection | `av_softwares` (from breach data) | DeviceAntivirusStatus | **Rule: AV Present But Failed** | Identify endpoint protection gaps where AV was installed but infostealer succeeded |
| Vulnerability Correlation | `infected_machine_id`, `user_os` | DeviceTvmSoftwareVulnerabilities | **Rule: Infected Device + Unpatched Vulns** | Prioritize patching on devices already known compromised |
| Network Isolation Validation | Post-isolation status | DeviceNetworkEvents | **Rule: Isolated Device Still Communicating** | Verify isolation actually stopped network activity |
| Selective Isolation | `severity` threshold | DeviceInfo (onboarding status) | **Playbook: SpyCloud-MDE-SelectiveIsolate** | Full isolation for sev 25, selective for sev 20 |
| Login After Infection | `email`, `infected_time` | DeviceLogonEvents | **Rule: Login to Infected Device After Exposure** | Someone logged into a known-compromised device |
| USB/Removable Media | `infected_machine_id` | DeviceEvents (RemovableMedia) | **Rule: USB Activity on Infected Device** | Data exfiltration risk from compromised device |

### 1.2 Microsoft Defender for Cloud Apps (MDCA / Cloud App Security)

| Integration | SpyCloud Data | MDCA Data | Rule/Playbook | Value |
|-------------|--------------|-----------|--------------|-------|
| Stolen Cookie Session Hijack | SIP cookies (`domain`, `email`) | CloudAppEvents | **Rule: Active Cloud Session from Stolen Cookie** | Detect if stolen cookies are being used to access SaaS apps RIGHT NOW |
| OAuth App Abuse | `email` (compromised user) | CloudAppEvents (OAuthAppConsent) | **Rule: Compromised User Granted OAuth App** | Attacker using stolen creds to consent to malicious OAuth app |
| Mass Download | `email` (compromised user) | CloudAppEvents (FileDownloaded) | **Rule: Mass File Download by Compromised User** | Data exfil via cloud app after credential compromise |
| Shadow IT Correlation | `target_domain` (from breach data) | CloudAppDiscovery | **Rule: Exposed Credentials for Shadow IT App** | Credentials stolen for apps not sanctioned by IT |
| Impossible Travel | `email`, `infected_ip` | CloudAppEvents (location) | **Rule: Cloud Access from Infection Source IP** | Cloud app accessed from same IP where malware was running |
| Session Policy Enforcement | `email` (compromised user) | SessionPolicy | **Playbook: SpyCloud-MDCA-SessionPolicy** | Auto-apply Conditional Access App Control policy to compromised users |
| App Governance Alert | `email` | AppGovernanceAlerts | **Rule: Compromised User + App Governance Alert** | Compound signal: credential exposure + abnormal app behavior |

### 1.3 Microsoft Defender for Identity (MDI)

| Integration | SpyCloud Data | MDI Data | Rule/Playbook | Value |
|-------------|--------------|----------|--------------|-------|
| Lateral Movement Path | `email`, `infected_machine_id` | IdentityLogonEvents | **Rule: Compromised User Lateral Movement** | Track if compromised credentials are being used to move laterally |
| Pass-the-Hash/Ticket | `password_plaintext`, `ntlm_hash` | IdentityQueryEvents | **Rule: Hash Match in MDI Detection** | SpyCloud has the hash, MDI detects it in use |
| LDAP Reconnaissance | `email` (compromised user) | IdentityDirectoryEvents | **Rule: Compromised User LDAP Enumeration** | Attacker using stolen creds for AD reconnaissance |
| DCSync Detection | `email` (admin account) | IdentityDirectoryEvents (DCSync) | **Rule: Compromised Admin + DCSync Attempt** | Most critical: compromised admin credential + DCSync = domain takeover |
| Kerberoasting | `email` (service account) | IdentityQueryEvents | **Rule: Compromised Service Account + Kerberoast** | Service account credential in SpyCloud + Kerberoasting detected |
| Suspicious NTLM Auth | `email` | IdentityLogonEvents (NTLM) | **Rule: NTLM Auth by Compromised User** | Downgrade attack using compromised credentials |

### 1.4 Microsoft Entra ID (Azure AD)

| Integration | SpyCloud Data | Entra Data | Rule/Playbook | Value |
|-------------|--------------|------------|--------------|-------|
| Password Reset Enforcement | `email`, `password_plaintext` | AuditLogs | **Playbook: SpyCloud-CA-PasswordReset** | Force password change when plaintext password found |
| Session Revocation | `email`, SIP cookies | SigninLogs | **Playbook: SpyCloud-CA-RevokeSession** | Kill all active sessions when cookies are stolen |
| MFA Registration Monitoring | `email` (compromised user) | AuditLogs (MFA) | **Rule: Compromised User Changed MFA Method** | Attacker enrolling their own MFA device |
| Conditional Access Group | `email` | GroupMembership | **Playbook: SpyCloud-CA-GroupAdd** | Add compromised users to "High Risk" CA group |
| Account Disable (Critical) | `email` (sev 25 + plaintext) | AuditLogs | **Playbook: SpyCloud-CA-DisableAccount** | Last resort: disable account for critical exposures |
| Risky Sign-In Correlation | `email` | AADRiskySignIns | **Rule: SpyCloud Exposure + Entra Risky Sign-In** | Dual signal: SpyCloud says compromised + Entra says risky |
| Guest/B2B User Exposure | `email` (external domain) | SigninLogs (guest) | **Rule: Guest User Credential Exposed** | Third-party/vendor credentials compromised |
| Privileged Identity Mgmt | `email` (PIM-eligible) | AuditLogs (PIM) | **Rule: PIM-Eligible User Credential Exposed** | Compromised user can elevate to admin role |
| App Registration Abuse | `email` (compromised user) | AuditLogs (AppRegistration) | **Rule: Compromised User Created App Registration** | Attacker persisting via malicious app registration |
| Named Location Anomaly | `email`, `infected_ip` | SigninLogs (location) | **Rule: Sign-In from Infection Source Country** | Login from same country as the infostealer infection |

### 1.5 Microsoft Intune / Endpoint Manager

| Integration | SpyCloud Data | Intune Data | Rule/Playbook | Value |
|-------------|--------------|-------------|--------------|-------|
| Device Compliance Status | `infected_machine_id` | IntuneDevices | **Rule: Compromised Device Non-Compliant** | Device already flagged non-compliant + SpyCloud infection |
| Managed vs Unmanaged | `infected_machine_id` | IntuneDevices | **Rule: BYOD/Unmanaged Device Infection** | Infection on personal device with corporate credentials |
| Remote Wipe | `infected_machine_id` (sev 25) | IntuneDeviceActions | **Playbook: SpyCloud-Intune-Wipe** | Remote wipe device with severe infostealer infection |
| Compliance Policy Enforcement | `email` (compromised user) | IntuneDeviceCompliancePolicies | **Playbook: SpyCloud-Intune-Compliance** | Force compliance re-evaluation on compromised devices |
| App Protection Policy | `email` | IntuneMAMPolicies | **Rule: Compromised User + Unprotected App** | User with stolen creds using app without protection policy |

### 1.6 Microsoft 365 / Office 365

| Integration | SpyCloud Data | M365 Data | Rule/Playbook | Value |
|-------------|--------------|-----------|--------------|-------|
| Mailbox Rule Creation | `email` (compromised user) | OfficeActivity (Exchange) | **Rule: Compromised User Created Mailbox Rule** | #1 BEC indicator: auto-forward, delete, or move rules |
| Email Forwarding | `email` | OfficeActivity (Set-Mailbox) | **Rule: Compromised User Set External Forwarding** | External mail forwarding = active BEC |
| SharePoint/OneDrive Access | `email` | OfficeActivity (SharePoint) | **Rule: Mass File Access by Compromised User** | Data exfiltration via SharePoint/OneDrive |
| Teams Message Exfil | `email` | OfficeActivity (Teams) | **Rule: Compromised User Teams Data Export** | Chat/channel data exfiltration |
| eDiscovery/Content Search | `email` (compromised admin) | OfficeActivity (SecurityComplianceCenter) | **Rule: Compromised Admin Running eDiscovery** | Insider threat or attacker searching mailboxes |
| Power Automate Abuse | `email` | OfficeActivity (PowerAutomate) | **Rule: Compromised User Created Flow** | Attacker creating persistent automation |
| DLP Policy Trigger | `email` | DLP Alerts | **Rule: Compromised User Triggered DLP** | Data loss by compromised account |

---

## SECTION 2: THIRD-PARTY EDR / XDR

### 2.1 CrowdStrike Falcon

| Integration | SpyCloud Data | CrowdStrike Data | Rule | Value |
|-------------|--------------|-----------------|------|-------|
| Device Containment | `infected_machine_id` | FalconHost (DeviceInfo) | **Rule: SpyCloud Infection + Falcon Device** | Correlate SpyCloud infection with Falcon-managed device for containment |
| Threat Graph Enrichment | `email`, `infected_ip` | FalconDetection | **Rule: SpyCloud Exposure + Falcon Detection** | Dual-signal: credential stolen + endpoint detection |
| RTR Command | `infected_machine_id` | FalconRTR | **Playbook: SpyCloud-CrowdStrike-RTR** | Remote response on infected device via Falcon |
| IOC Push | `target_url`, `infected_ip` | FalconIOC | **Playbook: SpyCloud-CrowdStrike-IOC** | Push SpyCloud IOCs to Falcon for blocking |

### 2.2 SentinelOne

| Integration | SpyCloud Data | S1 Data | Rule | Value |
|-------------|--------------|---------|------|-------|
| Threat Correlation | `infected_machine_id` | SentinelOneThreats | **Rule: SpyCloud + SentinelOne Detection** | Compound signal |
| Network Quarantine | `infected_machine_id` | SentinelOneAgents | **Playbook: SpyCloud-S1-Quarantine** | Quarantine infected device |
| Deep Visibility Query | `email`, `infected_ip` | SentinelOneDeepVisibility | **Hunting Query: S1 Process Activity on SpyCloud Device** | Hunt for malware artifacts |

### 2.3 Carbon Black (VMware)

| Integration | SpyCloud Data | CB Data | Rule | Value |
|-------------|--------------|---------|------|-------|
| Device Quarantine | `infected_machine_id` | CarbonBlackEvents | **Rule: SpyCloud + Carbon Black Alert** | Dual signal correlation |
| Live Response | `infected_machine_id` | CarbonBlackLiveResponse | **Playbook: SpyCloud-CB-LiveResponse** | Remote investigation |

### 2.4 Palo Alto Cortex XDR

| Integration | SpyCloud Data | Cortex Data | Rule | Value |
|-------------|--------------|-------------|------|-------|
| Incident Correlation | `email`, `infected_ip` | CortexXDRIncidents | **Rule: SpyCloud + Cortex XDR Incident** | Cross-platform detection |
| Agent Isolation | `infected_machine_id` | CortexXDRAgents | **Playbook: SpyCloud-Cortex-Isolate** | Isolate via Cortex agent |

### 2.5 Rapid7 InsightIDR / Velociraptor

| Integration | SpyCloud Data | Rapid7 Data | Rule | Value |
|-------------|--------------|-------------|------|-------|
| Investigation Enrichment | `email` | InsightIDR_CL | **Rule: SpyCloud Exposure in Rapid7 Environment** | Cross-SIEM correlation |
| Contained Asset | `infected_machine_id` | InsightIDR (Contained) | **Playbook: SpyCloud-Rapid7-Contain** | Contain via InsightAgent |

---

## SECTION 3: FIREWALL / VPN / SDWAN / NETWORK

### 3.1 Palo Alto Networks (PAN-OS)

| Integration | SpyCloud Data | PAN Data | Rule | Value |
|-------------|--------------|----------|------|-------|
| User-ID Correlation | `email`, `infected_ip` | CommonSecurityLog (PAN) | **Rule: Compromised User in PAN User-ID** | Infected user's traffic visible in firewall |
| Threat Feed Push | `infected_ip` | PAN Threat Intelligence | **Playbook: SpyCloud-PAN-ThreatFeed** | Push infected IPs as EDL entries |
| GlobalProtect VPN | `email` | PAN GlobalProtect Logs | **Rule: Compromised User VPN Connection** | VPN access with stolen credentials |
| Zone-Based Blocking | `infected_ip` | PAN Traffic Logs | **Rule: Traffic from Infected Source IP** | Block/alert on traffic from known infection sources |

### 3.2 Fortinet FortiGate

| Integration | SpyCloud Data | Fortinet Data | Rule | Value |
|-------------|--------------|---------------|------|-------|
| FSSO Correlation | `email` | CommonSecurityLog (Fortinet) | **Rule: Compromised User in FortiGate FSSO** | Infected user authenticated via FSSO |
| SSL VPN Access | `email` | FortiGate VPN Logs | **Rule: Compromised User FortiGate VPN** | VPN access with stolen credentials |
| Threat Feed | `infected_ip` | FortiGate Address Objects | **Playbook: SpyCloud-Forti-ThreatFeed** | Push IPs as address objects for blocking |

### 3.3 Cisco (ASA / Firepower / Umbrella / AnyConnect)

| Integration | SpyCloud Data | Cisco Data | Rule | Value |
|-------------|--------------|------------|------|-------|
| AnyConnect VPN | `email` | CiscoASA / CiscoMeraki | **Rule: Compromised User AnyConnect Session** | VPN with stolen creds |
| Umbrella DNS | `target_url` (malware C2) | CiscoUmbrella_CL | **Rule: DNS Query to SpyCloud Malware Domain** | Device resolving known C2 |
| ISE/RADIUS Auth | `email` | CiscoISE_CL | **Rule: Compromised User RADIUS Auth** | Network access with stolen creds |
| Firepower IDS | `infected_ip` | CommonSecurityLog (Cisco) | **Rule: IDS Alert from Infected IP** | Known infection source triggering IDS |

### 3.4 Zscaler

| Integration | SpyCloud Data | Zscaler Data | Rule | Value |
|-------------|--------------|--------------|------|-------|
| ZPA Access | `email` | ZscalerZPA_CL | **Rule: Compromised User ZPA Access** | Zero trust access with stolen creds |
| ZIA Web Activity | `email` | ZscalerZIA_CL | **Rule: Compromised User Web Activity** | Web browsing behavior of compromised user |
| DLP Trigger | `email` | ZscalerDLP_CL | **Rule: Compromised User DLP Event** | Data loss from compromised account |

### 3.5 Other VPN / SDWAN

| Vendor | Integration | Rule |
|--------|-------------|------|
| **Cloudflare Access** | `email` in CF Access logs | Compromised User CF Zero Trust Access |
| **WireGuard/OpenVPN** | `email` in VPN auth logs | Compromised User Open-Source VPN |
| **VMware SD-WAN (VeloCloud)** | `email` in SDWAN logs | Compromised User SDWAN Access |
| **Netskope** | `email` in Netskope_CL | Compromised User Netskope CASB |

### 3.6 DNS Security

| Vendor | Integration | Rule |
|--------|-------------|------|
| **Infoblox** | `target_url`, `infected_ip` in Infoblox_CL | DNS Query to Malware C2 Domain |
| **Microsoft DNS** | `target_url` in DnsEvents | Infected Host C2 DNS Resolution |
| **Cloudflare Gateway** | `target_url` in CF Gateway logs | C2 Blocked by Gateway |

---

## SECTION 4: IDENTITY PROVIDERS (IdP)

### 4.1 Okta

| Integration | SpyCloud Data | Okta Data | Rule | Value |
|-------------|--------------|-----------|------|-------|
| Sign-In Correlation | `email` | Okta_CL (authentication) | **Rule: Compromised User Okta Sign-In** | Credential in SpyCloud + user logged into Okta |
| MFA Bypass | SIP cookies | Okta_CL (session) | **Rule: Stolen Cookie + Okta Session** | MFA bypass via stolen session |
| Admin Console Access | `email` (admin) | Okta_CL (admin events) | **Rule: Compromised Admin Okta Console** | Admin credential compromise |
| App Assignment Change | `email` | Okta_CL (app events) | **Rule: Compromised User App Change** | Attacker modifying app assignments |

### 4.2 Duo Security (Cisco)

| Integration | SpyCloud Data | Duo Data | Rule | Value |
|-------------|--------------|----------|------|-------|
| Auth Correlation | `email` | CiscoDuo_CL | **Rule: Compromised User Duo Auth** | MFA push accepted by compromised user |
| Push Fraud | `email` | CiscoDuo_CL (fraud) | **Rule: Compromised User + Duo Push Fraud** | MFA fatigue attack on compromised user |

### 4.3 Ping Identity

| Integration | SpyCloud Data | Ping Data | Rule | Value |
|-------------|--------------|-----------|------|-------|
| SSO Correlation | `email` | PingFederate_CL | **Rule: Compromised User Ping SSO** | SSO access with stolen credentials |

### 4.4 Google Workspace

| Integration | SpyCloud Data | Google Data | Rule | Value |
|-------------|--------------|-------------|------|-------|
| Workspace Sign-In | `email` | GoogleWorkspace_CL | **Rule: Compromised User Google Sign-In** | Google account accessed with stolen creds |
| Admin Console | `email` (admin) | GoogleWorkspace_CL | **Rule: Compromised Admin Google Admin** | Admin credential exposure |

---

## SECTION 5: ITSM / ASSET MANAGEMENT / RMM

### 5.1 ServiceNow

| Integration | Type | Rule/Playbook | Value |
|-------------|------|--------------|-------|
| Auto-Create Incident | Playbook | **SpyCloud-SNOW-CreateIncident** | Auto-create SNOW incident for sev 20+ exposures |
| CMDB Enrichment | Playbook | **SpyCloud-SNOW-CMDBEnrich** | Enrich CMDB CI with infection status |
| Change Request | Playbook | **SpyCloud-SNOW-ChangeRequest** | Auto-create change request for password reset |
| Asset Correlation | Rule | **Rule: Compromised Device in SNOW CMDB** | Correlate infected machine with CMDB asset |

### 5.2 Jira (Atlassian)

| Integration | Type | Rule/Playbook | Value |
|-------------|------|--------------|-------|
| Auto-Create Issue | Playbook | **SpyCloud-Jira-CreateIssue** | Create Jira ticket for IR team |
| Status Tracking | Playbook | **SpyCloud-Jira-UpdateStatus** | Update ticket as remediation progresses |

### 5.3 Azure DevOps

| Integration | Type | Rule/Playbook | Value |
|-------------|------|--------------|-------|
| Work Item Creation | Playbook | **SpyCloud-AzDO-WorkItem** | Auto-create work item for security bugs |

### 5.4 ConnectWise / Datto / Kaseya (RMM)

| Integration | SpyCloud Data | RMM Data | Rule | Value |
|-------------|--------------|----------|------|-------|
| Agent Correlation | `infected_machine_id`, `user_hostname` | RMM Agent Inventory | **Rule: Infected Device in RMM** | MSP can identify managed devices with infections |
| Remote Command | `infected_machine_id` | RMM Remote Control | **Playbook: SpyCloud-RMM-Remediate** | Push remediation script via RMM agent |
| Patch Status | `infected_machine_id` | RMM Patch Management | **Rule: Infected + Unpatched Device** | Prioritize patching compromised devices |

### 5.5 Jamf (macOS/iOS)

| Integration | SpyCloud Data | Jamf Data | Rule | Value |
|-------------|--------------|-----------|------|-------|
| macOS Device Correlation | `infected_machine_id`, `user_os` contains "Mac" | Jamf_CL | **Rule: macOS Infection in Jamf Fleet** | macOS infostealer infections (KeySteal, MacStealer) |
| MDM Lock/Wipe | `infected_machine_id` (sev 25) | Jamf MDM Actions | **Playbook: SpyCloud-Jamf-Lock** | Remote lock compromised macOS device |
| Compliance Enforcement | `email` | Jamf Compliance | **Playbook: SpyCloud-Jamf-Compliance** | Force compliance re-evaluation |

---

## SECTION 6: THREAT INTELLIGENCE ENRICHMENT

### 6.1 VirusTotal

| Integration | SpyCloud Data | VT Data | Rule | Value |
|-------------|--------------|---------|------|-------|
| Malware Hash Lookup | `infected_path` (malware path) | VT File Report | **Playbook: SpyCloud-VT-HashLookup** | Identify the exact malware family from stolen data |
| URL Reputation | `target_url` | VT URL Report | **Rule: SpyCloud Target URL Malicious in VT** | Credential stealing site also flagged by VT |
| Domain Reputation | `target_domain` | VT Domain Report | **Playbook: SpyCloud-VT-DomainEnrich** | Cross-reference breach domains with VT reputation |

### 6.2 AbuseIPDB

| Integration | SpyCloud Data | AbuseIPDB Data | Rule | Value |
|-------------|--------------|----------------|------|-------|
| IP Reputation | `infected_ip` | AbuseIPDB Score | **Rule: Infected IP High Abuse Score** | Infection source IP also reported for abuse |

### 6.3 GreyNoise

| Integration | SpyCloud Data | GreyNoise Data | Rule | Value |
|-------------|--------------|----------------|------|-------|
| IP Classification | `infected_ip` | GreyNoise classification | **Rule: Infected IP = Known Scanner** | Infection IP actively scanning the internet |

### 6.4 AlienVault OTX / MISP

| Integration | SpyCloud Data | TI Data | Rule | Value |
|-------------|--------------|---------|------|-------|
| IOC Cross-Reference | `infected_ip`, `target_url` | TI Indicators | **Rule: SpyCloud IOC in Threat Feed** | Infection indicators match known threat campaign |

### 6.5 Recorded Future / Mandiant / Intel471

| Integration | SpyCloud Data | TI Data | Rule | Value |
|-------------|--------------|---------|------|-------|
| Threat Actor Attribution | `source_id`, `breach_title` | RF/Mandiant Reports | **Hunting Query: SpyCloud Source + TI Actor** | Link breach source to known threat group |

---

## SECTION 7: OTHER SIEMS / SOAR / XDR (Cross-Platform)

### 7.1 Splunk

| Integration | Type | Value |
|-------------|------|-------|
| Data Export | Forward SpyCloud alerts from Sentinel to Splunk via Event Hub | Dual-SIEM environments |
| Correlation | Import Splunk notable events → correlate with SpyCloud | Cross-platform detection |

### 7.2 Rapid7 InsightConnect (SOAR)

| Integration | Type | Value |
|-------------|------|-------|
| Webhook Trigger | SpyCloud incident → webhook → InsightConnect workflow | SOAR orchestration |
| Enrichment Plugin | InsightConnect calls SpyCloud Function App for enrichment | Cross-platform enrichment |

### 7.3 Palo Alto XSOAR

| Integration | Type | Value |
|-------------|------|-------|
| Incident Sync | Bi-directional sync via Logic App + XSOAR API | Cross-SOAR coordination |
| Playbook Chaining | XSOAR calls SpyCloud Function App | External SOAR enrichment |

### 7.4 Google Chronicle / SecOps

| Integration | Type | Value |
|-------------|------|-------|
| Data Forward | Event Hub → Chronicle ingestion | Dual-SIEM support |
| YARA-L Rules | SpyCloud exposure data matched with Chronicle rules | Cross-platform detection |

---

## SECTION 8: RADIUS / NAC / ZERO TRUST

| Vendor | SpyCloud Data | Integration | Value |
|--------|--------------|-------------|-------|
| **Microsoft NPS (RADIUS)** | `email` | NPS accounting logs in Sentinel | Compromised user RADIUS auth for WiFi/VPN |
| **Cisco ISE** | `email` | ISE logs in Sentinel | NAC posture assessment + compromise status |
| **Aruba ClearPass** | `email` | ClearPass_CL | Network access with stolen creds |
| **Portnox** | `email` | Portnox_CL | Cloud NAC + compromise correlation |
| **Forescout** | `infected_machine_id` | Forescout_CL | Device visibility + infection status |
| **Zscaler ZPA** | `email` | ZPA_CL | Zero trust access with compromised identity |
| **Cloudflare Access** | `email` | CF Access logs | ZTNA session with stolen credentials |

---

## SECTION 9: NOTEBOOKS / INVESTIGATION TEMPLATES

### 9.1 Jupyter Notebooks (Sentinel Notebooks)

| Notebook | Purpose | Data Sources | Output |
|----------|---------|-------------|--------|
| **SpyCloud User Investigation** | Deep dive on a single compromised user | Watchlist, Catalog, SigninLogs, MDE | Full investigation report with timeline |
| **SpyCloud Device Forensics** | Analyze a single infected device | Watchlist, Compass, MDE DeviceInfo | Device infection profile with blast radius |
| **SpyCloud Exposure Trend Analysis** | 30/90/180/365 day exposure trends | Watchlist, Exposure Stats | Executive-ready trend charts with Matplotlib |
| **SpyCloud Malware Family Analysis** | Analyze which malware families target your org | Watchlist, Catalog | Malware landscape report |
| **SpyCloud Password Hygiene Audit** | Assess password reuse and strength across org | Watchlist (password types) | Password hygiene score and recommendations |
| **SpyCloud Third-Party Risk** | Assess vendor/supplier credential exposure | Watchlist (external domains) | Supply chain risk report |
| **SpyCloud Geo-Analysis** | Geographic distribution of infections | Watchlist (country codes, IPs) | Heat map of infection sources |
| **SpyCloud Remediation Effectiveness** | Measure MTTR and auto-remediation rates | MDE Logs, CA Logs, EnrichmentAudit | Remediation KPI dashboard |

### 9.2 Summary/Report Templates

| Template | Audience | Content | Format |
|----------|----------|---------|--------|
| **Daily SOC Brief** | SOC Team Lead | New exposures, critical alerts, remediation actions, health | Email/Teams notification |
| **Weekly Exposure Report** | Security Manager | Exposure trends, top users, top devices, new breaches | PDF via Logic App |
| **Monthly Executive Summary** | CISO / VP Security | Risk score, trend, benchmark, remediation KPIs | PowerPoint/PDF |
| **Quarterly Board Report** | Board / C-Suite | High-level risk posture, program effectiveness, ROI | Executive one-pager |
| **Incident Investigation Report** | IR Team | Full investigation timeline for specific incident | Markdown in incident |
| **Compliance Evidence Package** | Audit / GRC | Detection coverage, remediation evidence, SLA compliance | ZIP package |
| **Vendor Risk Assessment** | Third-Party Risk | Supplier credential exposure summary | CSV + narrative |

---

## SECTION 10: RECOMMENDED OPTIONAL TEMPLATES & PACKAGES

These are ALL optional — customer enables only what matches their environment:

### Package A: "Enterprise Core" (DEFAULT — always deployed)
- 3 CCF pollers (Watchlist, Catalog, Modified)
- 8 core analytics rules
- 5 response playbooks (MDE, CA, Cred Response, Blocklist, TI)
- 1 SOC workbook
- 8 hunting queries
- Enrichment Function App

### Package B: "Defender Suite" (if MDE + Entra)
- +10 MDE correlation rules
- +10 Entra ID correlation rules
- +4 MDCA correlation rules
- +4 MDI correlation rules
- +4 M365 correlation rules
- +4 Intune correlation rules
- MDE isolation + CA password reset playbooks

### Package C: "Identity Provider" (if Okta/Duo/Ping)
- +4 Okta correlation rules
- +2 Duo correlation rules
- +2 Ping correlation rules
- +2 Google Workspace rules
- IdP enrichment playbook

### Package D: "Network Security" (if firewall/VPN connectors)
- +4 Palo Alto correlation rules
- +4 Fortinet correlation rules
- +4 Cisco correlation rules
- +2 Zscaler correlation rules
- +2 DNS correlation rules
- Network threat feed playbook

### Package E: "Compass & SIP" (if Compass/SIP licensed)
- Compass pollers (Data, Devices, Applications)
- SIP Cookie poller
- +6 Compass rules
- +4 SIP rules
- +4 multi-product fusion rules
- Compass/SIP workbook

### Package F: "ITSM Integration" (if ServiceNow/Jira)
- ServiceNow incident creation playbook
- Jira issue creation playbook
- Azure DevOps work item playbook
- Bi-directional status sync

### Package G: "Threat Intelligence" (if VT/AbuseIPDB/GreyNoise)
- VirusTotal enrichment playbook
- AbuseIPDB enrichment playbook
- GreyNoise enrichment playbook
- TI cross-reference rules

### Package H: "Executive Reporting"
- Executive Risk Dashboard workbook
- Weekly/Monthly report generation Logic App
- Compliance evidence automation
- Board report template

---

## TOTAL CONTENT INVENTORY (ALL PACKAGES)

| Content Type | Count | Notes |
|-------------|-------|-------|
| **Analytics Rule Templates** | 60+ | Organized by category, all optional |
| **Hunting Queries** | 28+ | Cross-table and cross-connector |
| **Workbooks** | 3-4 | SOC, Executive, Compass/SIP, ITSM |
| **Playbooks (Logic Apps)** | 20+ | Enrichment, response, ITSM, reporting |
| **Azure Function App** | 1 | All enrichment endpoints + Key Vault |
| **Automation Rules** | 14+ | Auto-trigger playbooks on incidents |
| **Watchlists** | 4 | VIP, exclusions, severity mapping, domains |
| **Notebooks** | 8 | Investigation, forensics, analysis templates |
| **Report Templates** | 7 | Daily to quarterly at all audience levels |
| **Custom Tables** | 15 | All SpyCloud data streams + audit |
| **Parsers** | 2+ | ASIM-compliant normalization (future) |
| **Copilot Plugin** | 1 | 28+ KQL skills + AI agent |

---

## NEXT STEPS

### Immediate (This PR — v12.10)
1. Fix Content Package dependencies (all 38+ rules, hunting queries, workbooks)
2. Content-template the workbook for Content Hub visibility
3. Content-template hunting queries
4. Remove monitoredDomain from required fields
5. Add hidden-SentinelTemplateName tags to all Logic Apps
6. Clean up createUiDefinition to remove duplicate API key fields

### Next Sprint
7. Build Azure Function App with all enrichment endpoints
8. Create Key Vault resource for centralized API key management
9. Build SOC Operational Dashboard workbook (6 tabs)
10. Build Executive Risk Dashboard workbook (6 tabs)
11. Add 22+ new cross-connector correlation rules

### Following Sprint
12. Build ITSM integration playbooks (ServiceNow, Jira)
13. Build threat intel enrichment playbooks (VT, AbuseIPDB)
14. Create Jupyter notebook templates
15. Build report generation automation
16. Submit to Azure-Sentinel GitHub for marketplace review
