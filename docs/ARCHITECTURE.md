# SpyCloud Identity Exposure Intelligence for Sentinel — Architecture Reference

> **Version 2.0** | Last Updated: March 2026

## Solution Architecture Overview

```mermaid
graph TB
    subgraph "SpyCloud Darknet Intelligence"
        SC_API["SpyCloud API\napi.spycloud.io"]
        SC_PORTAL["SpyCloud Portal\nportal.spycloud.io"]
    end

    subgraph "Azure Sentinel Workspace"
        subgraph "Data Ingestion Layer"
            CCF["Codeless Connector\nFramework - CCF"]
            DCE["Data Collection\nEndpoint"]
            DCR["Data Collection\nRules"]
        end

        subgraph "Custom Log Tables - 14"
            T1["SpyCloudBreachWatchlist_CL"]
            T2["SpyCloudBreachCatalog_CL"]
            T3["SpyCloudCompassData_CL"]
            T4["SpyCloudCompassDevices_CL"]
            T5["SpyCloudCompassApps_CL"]
            T6["SpyCloudSipCookies_CL"]
            T7["SpyCloudInvestigations_CL"]
            T8["SpyCloudIdLink_CL"]
            T9["SpyCloudCAP_CL"]
            T10["SpyCloudExposure_CL"]
            T11["SpyCloudIdentityExposure_CL"]
            T12["SpyCloudEnrichmentAudit_CL"]
            T13["SpyCloud_ConditionalAccessLogs_CL"]
            T14["Spycloud_MDE_Logs_CL"]
        end

        subgraph "Detection Engine"
            AR["38 Analytics Rules"]
            HQ["28 Hunting Queries"]
            AUTO["4 Automation Rules"]
        end

        subgraph "Visualization"
            WB1["Executive Dashboard"]
            WB2["SOC Operations"]
            WB3["Threat Intel Dashboard"]
            WB4["Defender/CA Response"]
            WB5["Graph Analysis"]
        end

        subgraph "Jupyter Notebooks"
            NB1["Threat Hunting"]
            NB2["Incident Triage"]
            NB3["Threat Landscape"]
            NB4["Graph Investigation"]
            NB5["Simulated Scenarios"]
        end
    end

    subgraph "Response and Orchestration"
        subgraph "SOAR Playbooks - 22"
            PB_CORE["Core Remediation\nPassword Reset - Session Revoke\nDevice Isolate - Account Disable"]
            PB_NOTIFY["Notifications\nEmail - Slack - Teams - Webhook"]
            PB_ITSM["ITSM Integration\nJira - ServiceNow"]
            PB_ADV["Advanced Response\nMFA Enforce - CA Block\nFirewall Block - OAuth Revoke\nMailbox Rules - Security Group"]
            PB_PURVIEW["Purview Integration\nCompliance Check - Label Incident"]
        end

        subgraph "AI Investigation Engine"
            AI_FUNC["Azure Function App\nSpyCloudAIEngine"]
            AI_OPENAI["OpenAI / Azure OpenAI"]
        end
    end

    subgraph "Copilot Integration"
        SC_AGENT["SCORCH Agent\n27 Sub-Agents"]
        SC_PLUGIN["KQL Plugin\n93 Skills"]
        SC_API_P["API Plugin"]
        SC_MCP["MCP Plugin"]
        PB_COPILOT["5 Promptbooks"]
    end

    subgraph "Microsoft Security Stack"
        MDE["Defender for Endpoint"]
        ENTRA["Entra ID"]
        INTUNE["Intune"]
        M365["Microsoft 365"]
        PURVIEW["Microsoft Purview"]
        GRAPH_API["Microsoft Graph API"]
    end

    SC_API --> CCF
    CCF --> DCE --> DCR
    DCR --> T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 & T9 & T10
    T1 --> AR
    AR --> AUTO
    AUTO --> PB_CORE & PB_NOTIFY & PB_ITSM & PB_ADV & PB_PURVIEW
    PB_CORE --> ENTRA & MDE
    PB_PURVIEW --> PURVIEW
    AI_FUNC --> AI_OPENAI
    AI_FUNC --> SC_API
    SC_AGENT --> AI_FUNC
    SC_PLUGIN --> T1
    T1 --> WB1 & WB2 & WB3
    PB_ADV --> INTUNE & M365 & GRAPH_API

    style SC_API fill:#e74c3c,color:#fff
    style AI_FUNC fill:#3498db,color:#fff
    style SC_AGENT fill:#9b59b6,color:#fff
    style PURVIEW fill:#2ecc71,color:#fff
```

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant SC as SpyCloud API
    participant CCF as CCF Connector
    participant DCE as Data Collection Endpoint
    participant DCR as Data Collection Rule
    participant LA as Log Analytics Tables
    participant AR as Analytics Rules
    participant AUTO as Automation Rules
    participant PB as Playbooks
    participant AI as AI Engine
    participant ENTRA as Entra ID / MDE

    Note over SC,ENTRA: Layer 1 - Bulk Ingestion (Every 40 min)
    SC->>CCF: Poll /breach/data/watchlist
    CCF->>DCE: Raw JSON payload
    DCE->>DCR: Apply KQL transformation
    DCR->>LA: Insert into SpyCloudBreachWatchlist_CL

    Note over SC,ENTRA: Layer 2 - Detection
    LA->>AR: Evaluate analytics rules
    AR->>AR: Match severity >= 20 or plaintext password
    AR-->>AUTO: Create Sentinel Incident

    Note over SC,ENTRA: Layer 3 - Automated Response
    AUTO->>PB: Trigger playbook based on entity type
    PB->>SC: Enrich via GET /breach/data/emails/{email}
    PB->>ENTRA: Force password reset
    PB->>ENTRA: Revoke all sessions
    PB->>LA: Log to SpyCloudEnrichmentAudit_CL

    Note over SC,ENTRA: Layer 4 - AI Investigation
    AI->>SC: Deep lookup across all endpoints
    AI->>AI: OpenAI analysis + threat research
    AI-->>PB: Return investigation report
```

## Playbook Orchestration Flow

```mermaid
graph LR
    subgraph "Trigger"
        INC["Sentinel Incident\nCreated"]
    end

    subgraph "Triage"
        ENRICH["SpyCloud-EnrichIncident\nQuery SpyCloud API\nAdd exposure details"]
        COPILOT["SpyCloud-Copilot-Triage\nAI-powered analysis"]
    end

    subgraph "Core Response"
        PWD["SpyCloud-ForcePasswordReset\nEntra ID password change"]
        SESS["SpyCloud-RevokeSessions\nRevoke all tokens"]
        ISO["SpyCloud-IsolateDevice\nMDE device isolation"]
        DIS["SpyCloud-DisableAccount\nTemporary account lockout"]
    end

    subgraph "Advanced Response"
        MFA["SpyCloud-EnforceMFA\nRequire re-enrollment"]
        CA["SpyCloud-BlockConditionalAccess\nBlock risky sign-ins"]
        FW["SpyCloud-BlockFirewall\nBlock malicious IPs"]
        OAUTH["SpyCloud-RevokeOAuthConsent\nRemove app permissions"]
        MAIL["SpyCloud-RemoveMailboxRules\nClean suspicious rules"]
        GRP["SpyCloud-AddToSecurityGroup\nAdd to quarantine group"]
    end

    subgraph "Notification"
        EMAIL["SpyCloud-EmailNotify"]
        SLACK["SpyCloud-SlackNotify"]
        WEBHOOK["SpyCloud-WebhookNotify"]
        SOC["SpyCloud-NotifySOC"]
        USER["SpyCloud-NotifyUser"]
    end

    subgraph "ITSM"
        JIRA["SpyCloud-Jira\nCreate ticket"]
        SNOW["SpyCloud-ServiceNow\nCreate incident"]
    end

    subgraph "Compliance"
        PURVIEW_CHK["SpyCloud-PurviewComplianceCheck\nRegulatory assessment"]
        PURVIEW_LBL["SpyCloud-PurviewLabelIncident\nSensitivity labels"]
    end

    INC --> ENRICH
    INC --> COPILOT
    ENRICH --> PWD & SESS & ISO & DIS
    ENRICH --> MFA & CA & FW & OAUTH & MAIL & GRP
    ENRICH --> EMAIL & SLACK & WEBHOOK & SOC & USER
    ENRICH --> JIRA & SNOW
    ENRICH --> PURVIEW_CHK & PURVIEW_LBL

    style INC fill:#e74c3c,color:#fff
    style ENRICH fill:#3498db,color:#fff
    style PWD fill:#e67e22,color:#fff
    style ISO fill:#e67e22,color:#fff
    style PURVIEW_CHK fill:#2ecc71,color:#fff
```

## AI Investigation Engine Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        COPILOT["Security Copilot\nSCORCH Agent"]
        PLAYBOOK["Logic App\nPlaybooks"]
        API_CLIENT["Direct API\nClients"]
    end

    subgraph "AI Function App - SpyCloudAIEngine"
        INVESTIGATE["/ai/investigate\nFull AI investigation"]
        EXEC_REPORT["/ai/executive-report\nBoard-level reporting"]
        THREAT["/ai/threat-research\nThreat intelligence"]
        INCIDENT["/ai/incident-report\nSentinel incident analysis"]
        REMEDIATE["/ai/remediation-plan\nRemediation planning"]
        COMPLIANCE["/ai/compliance-assessment\nRegulatory assessment"]
        CLASSIFY["/ai/purview/classify\nPII classification"]
        DLP["/ai/purview/dlp-status\nDLP policy status"]
        HEALTH["/ai/health\nHealth check"]
    end

    subgraph "Intelligence Sources"
        SC_API2["SpyCloud API\nBreach + Compass + SIP"]
        SENTINEL["Sentinel Workspace\nKQL Queries"]
        GRAPH["Microsoft Graph\nEntra + MDE + Purview"]
    end

    subgraph "AI Providers"
        OPENAI["OpenAI\nGPT-4o / GPT-4-turbo"]
        AZURE_AI["Azure OpenAI\nGPT-4o deployment"]
    end

    COPILOT --> INVESTIGATE & EXEC_REPORT & THREAT
    PLAYBOOK --> INCIDENT & REMEDIATE & COMPLIANCE
    API_CLIENT --> CLASSIFY & DLP & HEALTH

    INVESTIGATE --> SC_API2 & SENTINEL & OPENAI
    EXEC_REPORT --> SC_API2 & SENTINEL & OPENAI
    COMPLIANCE --> SC_API2 & SENTINEL & GRAPH & OPENAI
    CLASSIFY --> SC_API2 & GRAPH
    DLP --> SENTINEL & GRAPH & OPENAI

    style INVESTIGATE fill:#3498db,color:#fff
    style COMPLIANCE fill:#2ecc71,color:#fff
    style OPENAI fill:#9b59b6,color:#fff
```

## Severity Model

SpyCloud uses a numeric severity model that drives all detection and response logic:

| Severity | Meaning | Example Data | Recommended Response |
|----------|---------|-------------|---------------------|
| **2** | Breach credential (hashed) | Email + hashed password from public breach | Monitor, notify user |
| **5** | Breach credential + PII | Email + password + name + phone + DOB | Force password reset, notify user |
| **20** | Infostealer credential | Email + plaintext password stolen by malware | Force reset, revoke sessions, investigate device |
| **25** | Infostealer + application data | Full browser data: passwords, cookies, tokens, autofill | Full remediation: reset, revoke, isolate device, MFA re-enrollment |

## Password Risk Model

| Password Type | Risk Level | Detection | Response |
|--------------|-----------|-----------|----------|
| `plaintext` | **Critical** | password_plaintext field populated | Immediate forced reset |
| `md5` / `sha1` | **High** | Easily crackable hashes | Forced reset within 24h |
| `sha256` / `sha512` | **Medium** | Computationally expensive but possible | Reset recommended |
| `bcrypt` / `scrypt` / `argon2` | **Low** | Resistant to cracking | Monitor, optional reset |

## Composite Risk Scoring

The solution calculates a composite risk score for each user identity:

```
Risk Score = (Severity x 4) + (Plaintext x 25) + (Sighting Count x 3)
           + (Recent Infection x 15) + (Multiple Domains x 10)
           + (No Remediation x 20)

Where:
  Severity: SpyCloud severity value (2-25)
  Plaintext: 1 if plaintext password available, 0 otherwise
  Sighting Count: Number of times credential observed
  Recent Infection: 1 if infected within 30 days
  Multiple Domains: 1 if same password used on 3+ domains
  No Remediation: 1 if no password reset within 7 days of exposure
```

| Score Range | Risk Level | Color | Auto-Response |
|------------|-----------|-------|--------------|
| 0-25 | Low | Green | Monitor only |
| 26-50 | Medium | Yellow | Notify user, recommend reset |
| 51-75 | High | Orange | Force reset, revoke sessions |
| 76-100 | Critical | Red | Full remediation + device isolation |

## Custom Log Tables Schema

### SpyCloudBreachWatchlist_CL (Primary Table)

| Column | Type | Description |
|--------|------|-------------|
| `email_s` | string | Exposed email address |
| `domain_s` | string | Email domain |
| `severity_d` | double | Severity level (2, 5, 20, 25) |
| `source_id_d` | double | Breach source identifier |
| `password_plaintext_s` | string | Plaintext password (if available) |
| `password_type_s` | string | Hash type or "plaintext" |
| `infected_machine_id_s` | string | Infostealer device ID |
| `infected_path_s` | string | Malware file path |
| `infected_time_t` | datetime | Time of infection |
| `ip_addresses_s` | string | Associated IP addresses |
| `target_url_s` | string | URL where credentials were used |
| `target_domain_s` | string | Domain of target service |
| `full_name_s` | string | Full name (PII) |
| `phone_s` | string | Phone number (PII) |
| `dob_s` | string | Date of birth (PII) |
| `ssn_s` | string | Social Security Number (PII) |
| `cc_number_s` | string | Credit card number (PII) |
| `user_browser_s` | string | Browser fingerprint |
| `user_os_s` | string | Operating system |
| `sighting_d` | double | Number of times credential observed |
| `TimeGenerated` | datetime | Ingestion timestamp |

## Network and Port Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|------------|------|----------|---------|
| Azure Sentinel | api.spycloud.io | 443 | HTTPS | SpyCloud API polling |
| Logic Apps | graph.microsoft.com | 443 | HTTPS | Entra ID, MDE, Purview operations |
| Logic Apps | management.azure.com | 443 | HTTPS | Azure Resource Manager |
| AI Engine | api.openai.com | 443 | HTTPS | OpenAI GPT-4 analysis |
| AI Engine | {resource}.openai.azure.com | 443 | HTTPS | Azure OpenAI (alternative) |
| MCP Server | Sentinel workspace | 443 | HTTPS | Graph queries and analysis |

## OAuth Token Scopes

| Scope | Used By | Purpose |
|-------|---------|---------|
| `User.ReadWrite.All` | Password Reset, Session Revoke | Modify user properties, revoke sessions |
| `Directory.ReadWrite.All` | Security Group, Account Disable | Group membership, account management |
| `SecurityEvents.ReadWrite.All` | Incident enrichment | Read/update Sentinel incidents |
| `Mail.ReadWrite` | Mailbox Rules removal | Remove suspicious mail rules |
| `Policy.ReadWrite.ConditionalAccess` | CA Block playbook | Modify Conditional Access policies |
| `DeviceManagementManagedDevices.ReadWrite.All` | Device Isolation | MDE device actions |
| `InformationProtection.Policy.Read.All` | Purview labels | Read sensitivity labels |
| `SecurityIncident.ReadWrite.All` | Purview label application | Tag incidents with labels |

## MITRE ATT&CK Mapping

| SpyCloud Detection | MITRE Technique | Tactic |
|-------------------|----------------|--------|
| Credential Exposure (Breach) | T1078 - Valid Accounts | Initial Access |
| Plaintext Password | T1552.001 - Credentials in Files | Credential Access |
| Infostealer Infection | T1555 - Credentials from Password Stores | Credential Access |
| Cookie/Session Theft | T1539 - Steal Web Session Cookie | Credential Access |
| Lateral Movement | T1021 - Remote Services | Lateral Movement |
| Mailbox Rule Creation | T1114.003 - Email Forwarding Rule | Collection |
| OAuth App Consent | T1098.003 - Additional Cloud Credentials | Persistence |
| MFA Registration Change | T1556.006 - Multi-Factor Authentication | Defense Evasion |
| Device Re-infection | T1204 - User Execution | Execution |
| Data Exfiltration | T1567 - Exfiltration Over Web Service | Exfiltration |

## Sentinel Graph Integration

```mermaid
graph TB
    subgraph "Graph Materialization"
        SCHED["Scheduled Jobs\nDaily materialization"]
        GQL["GQL Queries\nGraph Query Language"]
    end

    subgraph "Graph Nodes"
        USER_N["User Nodes\nemail, UPN"]
        DEVICE_N["Device Nodes\nmachine_id, hostname"]
        BREACH_N["Breach Nodes\nsource_id, title"]
        IP_N["IP Nodes\nip_addresses"]
        DOMAIN_N["Domain Nodes\ntarget_domain"]
    end

    subgraph "Graph Edges"
        EXPOSED["EXPOSED_IN\nUser -> Breach"]
        INFECTED["INFECTED_ON\nUser -> Device"]
        ACCESSED["ACCESSED_FROM\nUser -> IP"]
        TARGETED["TARGETED\nUser -> Domain"]
    end

    subgraph "MCP Graph Tools"
        BLAST["Blast Radius\nFind all connected entities"]
        PATH["Path Discovery\nShortest path between entities"]
        EXPOSURE["Exposure Perimeter\nAttack surface analysis"]
    end

    SCHED --> USER_N & DEVICE_N & BREACH_N & IP_N & DOMAIN_N
    USER_N --> EXPOSED & INFECTED & ACCESSED & TARGETED
    GQL --> BLAST & PATH & EXPOSURE

    style BLAST fill:#e74c3c,color:#fff
    style PATH fill:#3498db,color:#fff
    style EXPOSURE fill:#9b59b6,color:#fff
```

## Copilot Integration Architecture

```mermaid
graph TB
    subgraph "Microsoft Security Copilot"
        NAT_LANG["Natural Language\nQuery Interface"]
    end

    subgraph "Plugin Suite"
        KQL_P["KQL Plugin\n93 Skills\nDirect table queries"]
        API_P["API Plugin\nReal-time SpyCloud lookups\nOpenAPI 3.0 spec"]
        AGENT_P["SCORCH Agent\n27 Sub-Agents\nAutonomous investigation"]
        MCP_P["MCP Plugin\nGraph analysis\nAdvanced queries"]
    end

    subgraph "Promptbooks"
        PB_TRIAGE["Incident Triage\n5-step investigation"]
        PB_USER["User Investigation\nFull exposure history"]
        PB_HUNT["Threat Hunt\nProactive hunting"]
        PB_ORG["Org Exposure\nExecutive overview"]
        PB_COMPLY["Compliance\nRegulatory assessment"]
    end

    subgraph "SCORCH Sub-Agents"
        SA1["BreachAnalysis"]
        SA2["DeviceForensics"]
        SA3["IdentityCorrelation"]
        SA4["ThreatIntelligence"]
        SA5["ComplianceAssessment"]
        SA6["RemediationPlanner"]
        SA7["ExecutiveReporting"]
        SA_MORE["... 20 more"]
    end

    NAT_LANG --> KQL_P & API_P & AGENT_P & MCP_P
    NAT_LANG --> PB_TRIAGE & PB_USER & PB_HUNT & PB_ORG & PB_COMPLY
    AGENT_P --> SA1 & SA2 & SA3 & SA4 & SA5 & SA6 & SA7 & SA_MORE

    style NAT_LANG fill:#0078d4,color:#fff
    style AGENT_P fill:#9b59b6,color:#fff
    style KQL_P fill:#3498db,color:#fff
```

## PII Classification Framework

Maps 16 SpyCloud exposure field types to regulatory frameworks:

| Field | Category | GDPR | CCPA | HIPAA | PCI-DSS |
|-------|----------|------|------|-------|---------|
| `email` | Contact Info | Yes | Yes | No | No |
| `password` | Credential | Yes | Yes | No | Yes |
| `password_plaintext` | Plaintext Credential | Yes | Yes | No | Yes |
| `full_name` | Personal Identity | Yes | Yes | No | No |
| `phone` | Contact Info | Yes | Yes | No | No |
| `dob` | Sensitive PII | Yes | Yes | No | No |
| `ssn` | Government ID | Yes | Yes | No | No |
| `cc_number` | Financial | Yes | Yes | No | Yes |
| `cc_expiration` | Financial | Yes | Yes | No | Yes |
| `bank_number` | Financial | Yes | Yes | No | Yes |
| `ip_addresses` | Network Identity | Yes | Yes | Yes | No |
| `infected_machine_id` | Device Identity | Yes | Yes | Yes | No |
| `target_url` | Behavioral | Yes | Yes | No | No |
| `user_browser` | Device Fingerprint | Yes | Yes | No | No |
| `user_os` | Device Fingerprint | Yes | Yes | No | No |

### Sensitivity Label Mapping

| Classification | Sensitivity Level | Purview Label | Trigger |
|---------------|------------------|---------------|---------|
| Standard | Low | General | Email-only exposure |
| Confidential | Medium | Confidential | PII fields detected |
| Highly Confidential | High | Highly Confidential | Financial or sensitive PII |
| Highly Confidential - PHI | Critical | Highly Confidential - PHI | HIPAA-relevant fields (ip_addresses, infected_machine_id) |

## Deployment Architecture

```mermaid
flowchart TB
    subgraph "Deployment Options"
        direction TB
        AZ_PORTAL["Azure Portal\nDeploy to Azure Button"]
        AZ_GOV["Azure Government\nDeploy to Azure Gov Button"]
        AZ_SHELL["Azure Cloud Shell\nAutomated Script"]
        TERRAFORM["Terraform\nInfrastructure as Code"]
        GH_ACTIONS["GitHub Actions\nCI/CD Pipeline"]
    end

    subgraph "Pre-Deployment Validation"
        ARM_VAL["ARM Template\nValidation"]
        PERM_CHK["Permission\nVerification"]
        API_VAL["SpyCloud API Key\nValidation"]
        DOMAIN_VAL["Domain\nVerification"]
    end

    subgraph "Resource Deployment"
        RG["Resource Group"]
        LAW["Log Analytics\nWorkspace"]
        SENTINEL["Microsoft Sentinel\nSolution"]
        KV["Azure Key Vault\nAPI Key Storage"]
        FUNC["Function App\nAI Engine + Enrichment"]
        LA_APPS["Logic Apps\n20 Playbooks"]
        DCE_R["Data Collection\nEndpoint + Rules"]
        CCF_R["CCF Connector\nSpyCloud API Polling"]
    end

    subgraph "Post-Deployment"
        HEALTH["Health Check\nAll 14 Tables"]
        RULES_EN["Enable Analytics\nRules (49)"]
        AUTO_EN["Enable Automation\nRules (4)"]
        RBAC["Configure RBAC\nManaged Identity"]
        REPORT["Deployment\nReport"]
    end

    AZ_PORTAL & AZ_GOV & AZ_SHELL & TERRAFORM & GH_ACTIONS --> ARM_VAL
    ARM_VAL --> PERM_CHK --> API_VAL --> DOMAIN_VAL
    DOMAIN_VAL --> RG --> LAW --> SENTINEL
    RG --> KV & FUNC & LA_APPS
    LAW --> DCE_R --> CCF_R
    SENTINEL --> HEALTH --> RULES_EN --> AUTO_EN --> RBAC --> REPORT

    style AZ_PORTAL fill:#0078d4,color:#fff
    style AZ_GOV fill:#5c2d91,color:#fff
    style AZ_SHELL fill:#00a4ef,color:#fff
    style TERRAFORM fill:#7b42bc,color:#fff
    style GH_ACTIONS fill:#2088ff,color:#fff
    style HEALTH fill:#2ecc71,color:#fff
```

## Remediation Workflow

```mermaid
flowchart TD
    subgraph "Detection"
        ALERT["SpyCloud Alert\nSeverity 2-25"]
    end

    subgraph "Severity-Based Routing"
        SEV2["Severity 2\nBreach Credential"]
        SEV5["Severity 5\nBreach + PII"]
        SEV20["Severity 20\nInfostealer"]
        SEV25["Severity 25\nInfostealer + App Data"]
    end

    subgraph "Response Actions"
        NOTIFY["Notify User\nEmail / Teams / Slack"]
        PWD_RESET["Force Password\nReset via Entra ID"]
        REVOKE["Revoke All\nActive Sessions"]
        MFA_RE["MFA Re-enrollment\nRequired"]
        ISOLATE["Isolate Device\nvia MDE"]
        CA_BLOCK["Block via\nConditional Access"]
        OAUTH_REV["Revoke OAuth\nConsent Grants"]
        FULL_REM["Full Remediation\nAll Actions Combined"]
    end

    subgraph "Compliance"
        PURVIEW_CHK["Purview Compliance\nAssessment"]
        PURVIEW_LBL["Apply Sensitivity\nLabel"]
        ITSM["Create ITSM\nTicket (Jira/SNOW)"]
    end

    subgraph "Investigation"
        AI_INV["AI Investigation\nOpenAI / Azure AI"]
        EXEC_RPT["Executive Report\nGeneration"]
        THREAT_R["Threat Research\nForums, IOCs, APTs"]
    end

    ALERT --> SEV2 & SEV5 & SEV20 & SEV25

    SEV2 --> NOTIFY
    SEV5 --> NOTIFY & PWD_RESET
    SEV20 --> PWD_RESET & REVOKE & MFA_RE & AI_INV
    SEV25 --> FULL_REM & AI_INV

    FULL_REM --> PWD_RESET & REVOKE & MFA_RE & ISOLATE & CA_BLOCK & OAUTH_REV

    SEV5 & SEV20 & SEV25 --> PURVIEW_CHK --> PURVIEW_LBL
    SEV20 & SEV25 --> ITSM
    AI_INV --> THREAT_R --> EXEC_RPT

    style ALERT fill:#e74c3c,color:#fff
    style SEV25 fill:#c0392b,color:#fff
    style SEV20 fill:#e67e22,color:#fff
    style SEV5 fill:#f39c12,color:#fff
    style SEV2 fill:#27ae60,color:#fff
    style FULL_REM fill:#8e44ad,color:#fff
    style AI_INV fill:#3498db,color:#fff
```

## Threat Hunting Mind Map

```mermaid
mindmap
    root((SpyCloud
    Threat Hunting))
        Credential Exposure
            Plaintext Passwords
                Immediate Reset Required
                Password Reuse Check
            Hashed Passwords
                Crack Difficulty Assessment
                Salted vs Unsalted
            Password Patterns
                Common Passwords
                Credential Stuffing Risk
        Infostealer Analysis
            Malware Family
                RedLine Stealer
                Vidar
                Raccoon
                META
            Device Forensics
                Infection Timeline
                Browser Data Scope
                Installed Applications
            Session Cookies
                MFA Bypass Risk
                Active Session Hijack
                Cookie Expiry Check
        Identity Correlation
            Cross-Domain Exposure
                Same Password Multiple Sites
                Corporate vs Personal
            Device Clustering
                Shared Device Infections
                Lateral Movement Paths
            Timeline Analysis
                Exposure to Attack Window
                Re-infection Patterns
        Organizational Impact
            Executive Exposure
                VIP Account Monitoring
                Board Member Risk
            Department Analysis
                Most Exposed Teams
                Access Level Correlation
            Compliance Impact
                GDPR Notification
                CCPA Requirements
                HIPAA Breach Rules
```

## Data Ingestion Pipeline Detail

```mermaid
flowchart LR
    subgraph "SpyCloud API Endpoints"
        EP1["/breach/data/watchlist\nPrimary breach data"]
        EP2["/breach/catalog\nBreach metadata"]
        EP3["/compass/data\nDevice forensics"]
        EP4["/compass/devices\nDevice inventory"]
        EP5["/compass/applications\nApp telemetry"]
        EP6["/sip/cookies\nStolen sessions"]
        EP7["/investigations\nInvestigation data"]
        EP8["/idlink\nIdentity correlation"]
        EP9["/cap\nCredential access"]
        EP10["/exposure\nExposure events"]
    end

    subgraph "CCF Transformation"
        CCF_T["Codeless Connector\nKQL Transform\n+ Schema Mapping"]
    end

    subgraph "Custom Log Tables"
        T1["SpyCloudBreachWatchlist_CL"]
        T2["SpyCloudBreachCatalog_CL"]
        T3["SpyCloudCompassData_CL"]
        T4["SpyCloudCompassDevices_CL"]
        T5["SpyCloudCompassApps_CL"]
        T6["SpyCloudSipCookies_CL"]
        T7["SpyCloudInvestigations_CL"]
        T8["SpyCloudIdLink_CL"]
        T9["SpyCloudCAP_CL"]
        T10["SpyCloudExposure_CL"]
    end

    EP1 --> CCF_T --> T1
    EP2 --> CCF_T --> T2
    EP3 --> CCF_T --> T3
    EP4 --> CCF_T --> T4
    EP5 --> CCF_T --> T5
    EP6 --> CCF_T --> T6
    EP7 --> CCF_T --> T7
    EP8 --> CCF_T --> T8
    EP9 --> CCF_T --> T9
    EP10 --> CCF_T --> T10

    style CCF_T fill:#3498db,color:#fff
    style T1 fill:#2ecc71,color:#fff
```

## Purview Integration Flow

```mermaid
sequenceDiagram
    participant INC as Sentinel Incident
    participant PB as Playbook
    participant AI as AI Engine
    participant SC as SpyCloud API
    participant PV as Microsoft Purview
    participant GRAPH as Microsoft Graph

    Note over INC,GRAPH: PII Classification Flow
    INC->>PB: Incident with exposed PII
    PB->>AI: POST /ai/purview/classify
    AI->>SC: Fetch exposure details
    SC-->>AI: Exposure records with PII fields
    AI->>AI: Map fields to regulatory frameworks
    AI-->>PB: Classification result + sensitivity level

    Note over INC,GRAPH: Sensitivity Label Application
    PB->>GRAPH: GET /security/informationProtection/sensitivityLabels
    GRAPH-->>PB: Available label IDs
    PB->>GRAPH: PATCH /security/incidents/{id} with tags
    GRAPH-->>PB: Label applied

    Note over INC,GRAPH: Compliance Assessment
    PB->>AI: POST /ai/compliance-assessment
    AI->>SC: Fetch domain exposures
    AI->>AI: OpenAI regulatory analysis
    AI-->>PB: GDPR/CCPA/HIPAA requirements + timelines
    PB->>PV: Log compliance event
    PB->>INC: Update incident with compliance tags
```

## Microsoft Security Stack Integration

```mermaid
graph TB
    subgraph "SpyCloud Intelligence"
        SC["SpyCloud API\nDarknet Data"]
    end

    subgraph "Microsoft Sentinel"
        SENT["Sentinel\nWorkspace"]
        WB["Workbooks\n5 Dashboards"]
        NB["Notebooks\n5 Investigation Tools"]
        AR_R["Analytics Rules\n49 Detections"]
        HQ_R["Hunting Queries\n28 Proactive Hunts"]
    end

    subgraph "Microsoft Defender"
        MDE_D["Defender for Endpoint\nDevice Isolation + Forensics"]
        MDO["Defender for Office 365\nMailbox Rule Cleanup"]
        MDI["Defender for Identity\nLateral Movement Detection"]
    end

    subgraph "Microsoft Entra ID"
        ENTRA_D["Entra ID\nPassword Reset + Session Revoke"]
        CA_D["Conditional Access\nRisk-Based Policies"]
        PIM["Privileged Identity\nManagement"]
    end

    subgraph "Microsoft Purview"
        IP["Information Protection\nSensitivity Labels"]
        DLP_D["DLP Policies\nData Loss Prevention"]
        CM["Compliance Manager\nRegulatory Compliance"]
    end

    subgraph "Microsoft 365"
        TEAMS["Teams\nSOC Notifications"]
        SPO["SharePoint\nExfiltration Monitoring"]
        EXO["Exchange Online\nMailbox Protection"]
    end

    subgraph "AI & Copilot"
        COPILOT_D["Security Copilot\nNatural Language Investigation"]
        OPENAI_D["OpenAI / Azure AI\nThreat Analysis + Reports"]
        MCP_D["MCP Server\nGraph Analysis"]
    end

    SC --> SENT
    SENT --> WB & NB & AR_R & HQ_R
    AR_R --> MDE_D & ENTRA_D & IP
    SENT --> MDE_D & MDO & MDI
    SENT --> ENTRA_D & CA_D & PIM
    SENT --> IP & DLP_D & CM
    SENT --> TEAMS & SPO & EXO
    COPILOT_D --> SENT & SC
    OPENAI_D --> COPILOT_D
    MCP_D --> SENT

    style SC fill:#e74c3c,color:#fff
    style SENT fill:#0078d4,color:#fff
    style COPILOT_D fill:#9b59b6,color:#fff
    style IP fill:#2ecc71,color:#fff
```
