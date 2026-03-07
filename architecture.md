# SpyCloud Sentinel — Unified Deployment Architecture

## Single Template, Full Automation

This document describes the architecture for the unified ARM template that consolidates
the connector, playbooks, Key Vault, analytics rules, and all optional Microsoft service
integrations into a single deployment.

---

## What Gets Deployed

```
┌─────────────────────────────────────────────────────────────────────┐
│                    UNIFIED ARM TEMPLATE                             │
│                    spycloud_unified_deployment.json                 │
│                                                                     │
│  ┌─ TIER 1: FOUNDATION (Always deployed) ──────────────────────┐   │
│  │                                                              │   │
│  │  □ Log Analytics Workspace (optional — use existing)         │   │
│  │  □ Microsoft Sentinel (optional — enable on workspace)       │   │
│  │  □ Data Collection Endpoint (DCE)                            │   │
│  │  □ Data Collection Rule (DCR) — 4 stream transforms          │   │
│  │  □ 4 Custom Tables:                                          │   │
│  │     • SpyCloudBreachWatchlist_CL (73 columns)                │   │
│  │     • SpyCloudBreachCatalog_CL (13 columns)                  │   │
│  │     • Spycloud_MDE_Logs_CL (19 columns)                     │   │
│  │     • SpyCloud_ConditionalAccessLogs_CL (14 columns)         │   │
│  │  □ CCF Connector Definition + 3 REST API Pollers             │   │
│  │  □ Content Package                                           │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ TIER 2: SECURITY (Optional per toggle) ────────────────────┐   │
│  │                                                              │   │
│  │  □ Azure Key Vault (enableKeyVault=true)                     │   │
│  │     • Stores SpyCloud API key as a secret                    │   │
│  │     • Access policy for Logic App managed identities         │   │
│  │     • Access policy for DCE/connector                        │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ TIER 3: AUTOMATION (Optional per toggle) ──────────────────┐   │
│  │                                                              │   │
│  │  □ Sentinel API Connection (managed identity)                │   │
│  │  □ MDE Remediation Logic App (enableMdePlaybook=true)        │   │
│  │     • Device isolation via Defender API                       │   │
│  │     • Machine tagging                                        │   │
│  │     • IOC submission                                         │   │
│  │     • Audit logging to Spycloud_MDE_Logs_CL via DCE          │   │
│  │  □ CA Remediation Logic App (enableCaPlaybook=true)           │   │
│  │     • Force password reset via Graph API                      │   │
│  │     • Revoke all sessions                                    │   │
│  │     • Add to CA security group                               │   │
│  │     • Audit logging to SpyCloud_ConditionalAccessLogs_CL      │   │
│  │  □ Analytics Rule — Infostealer Detection (enableAnalytics)   │   │
│  │  □ Automation Rule — Auto-trigger playbooks (enableAutomation)│   │
│  │  □ RBAC Role Assignments for Logic App identities             │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ TIER 4: NOTIFICATIONS (Optional per toggle) ───────────────┐   │
│  │                                                              │   │
│  │  □ Action Group (enableNotifications=true)                    │   │
│  │     • Email notification for high-severity incidents          │   │
│  │     • Optional webhook for Teams/Slack                       │   │
│  │  □ Alert Rule — Data ingestion health monitor                │   │
│  │     • Fires when SpyCloud data stops flowing for >2 hours    │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ TIER 5: MICROSOFT SERVICE CONNECTORS (Optional) ───────────┐   │
│  │                                                              │   │
│  │  These enable CORRELATION between SpyCloud exposure data     │   │
│  │  and Microsoft security signals in your Sentinel workspace:  │   │
│  │                                                              │   │
│  │  □ Entra ID Sign-In Logs (enableEntraSignIn=true)            │   │
│  │     • Diagnostic setting: SignInLogs → workspace              │   │
│  │     • Correlate stolen credentials with actual sign-in        │   │
│  │       attempts from anomalous locations                      │   │
│  │                                                              │   │
│  │  □ Entra ID Audit Logs (enableEntraAudit=true)               │   │
│  │     • Diagnostic setting: AuditLogs → workspace               │   │
│  │     • Track password changes, MFA registration after          │   │
│  │       SpyCloud-triggered resets                              │   │
│  │                                                              │   │
│  │  □ Entra ID Risky Users/Sign-Ins (enableEntraRisk=true)      │   │
│  │     • Diagnostic setting: RiskyUsers, RiskySignIns            │   │
│  │     • Correlate SpyCloud severity with Entra risk scores     │   │
│  │                                                              │   │
│  │  NOTE: Defender XDR and Exchange/O365 connectors are          │   │
│  │  configured through Sentinel Content Hub, not ARM. The        │   │
│  │  template will output instructions for enabling these.       │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Parameter Groups

### Group 1: Workspace & Region
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| workspace | string | (required) | Log Analytics workspace name |
| deploymentRegion | string | [resourceGroup().location] | Primary deployment region |
| createNewWorkspace | bool | false | Create new workspace + enable Sentinel |
| subscription | string | [auto-detected] | Subscription ID |
| resourceGroupName | string | [auto-detected] | Resource group name |

### Group 2: SpyCloud API Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| spycloudApiKey | securestring | (required) | SpyCloud Enterprise API key |
| spycloudApiRegion | string | us | API region (us/eu) |
| severityFilter | array | [2,5,20,25] | Severity levels to ingest |
| watchlistType | array | [corporate,infected,compass] | Exposure types |
| showPlainPassword | string | False | Include cleartext passwords |
| queryWindowInMin | int | 40 | Polling frequency |
| rateLimitQPS | int | 2 | API rate limit |
| initialLookbackDays | int | 30 | Historical backfill days |

### Group 3: Key Vault
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enableKeyVault | bool | true | Create Key Vault for API key |
| keyVaultName | string | kv-spycloud-{workspace} | Key Vault name |

### Group 4: Automation & Playbooks
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enableMdePlaybook | bool | true | Deploy MDE device isolation playbook |
| enableCaPlaybook | bool | true | Deploy CA identity protection playbook |
| enableAnalyticsRule | bool | true | Deploy infostealer detection rule |
| enableAutomationRule | bool | true | Auto-trigger playbooks on incidents |
| mdeIsolationType | string | Full | Full or Selective isolation |
| mdeTagName | string | SpyCloud-Compromised | MDE device tag |
| caSecurityGroupId | string | (optional) | Entra ID security group for CA |
| spycloudSeverityThreshold | int | 20 | Min severity for analytics rule |
| analyticsRuleFrequency | string | PT1H | How often the rule runs |

### Group 5: Notifications
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enableNotifications | bool | true | Create action group for alerts |
| notificationEmail | string | (optional) | Email for alert notifications |
| teamsWebhookUrl | string | (optional) | Teams incoming webhook URL |

### Group 6: Microsoft Service Connectors
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enableEntraSignInLogs | bool | false | Stream Entra sign-in logs to workspace |
| enableEntraAuditLogs | bool | false | Stream Entra audit logs to workspace |
| enableEntraRiskLogs | bool | false | Stream risky users/sign-ins to workspace |

### Group 7: Data Retention & Compliance
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| retentionInDays | int | 90 | Data retention period |
| resourceTags | object | (defaults) | Tags for all resources |

---

## Data Flow Architecture

```
                    SpyCloud API
                    (api.spycloud.io)
                         │
                         │ Bearer token auth
                         │ (from Key Vault secret)
                         ▼
              ┌─────────────────────┐
              │  CCF REST API Poller│
              │  (3 pollers)        │
              │  • Watchlist New    │
              │  • Watchlist Mod    │
              │  • Breach Catalog   │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │  Data Collection    │
              │  Endpoint (DCE)     │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │  Data Collection    │
              │  Rule (DCR)         │
              │  KQL Transforms     │
              └────────┬────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │Watchlist │ │ Catalog  │ │ MDE/CA   │
   │  _CL     │ │  _CL     │ │ Logs _CL │
   └────┬─────┘ └──────────┘ └────┬─────┘
        │                          ▲
        ▼                          │
   ┌──────────┐              ┌──────────┐
   │ Analytics│──Incident──→│ Playbooks│
   │ Rule     │              │ MDE + CA │
   └────┬─────┘              └──────────┘
        │
        ▼
   ┌──────────┐    ┌──────────┐
   │Automation│───→│ Action   │
   │ Rule     │    │ Group    │
   └──────────┘    │ (email/  │
                   │  Teams)  │
                   └──────────┘
```

---

## Key Vault Integration

When enableKeyVault=true:
1. ARM creates an Azure Key Vault
2. Stores the SpyCloud API key as a secret named 'spycloud-api-key'
3. Grants access to the Logic App managed identities
4. Logic Apps retrieve the API key at runtime via Key Vault reference
5. The CCF connector still uses the securestring parameter directly
   (CCF doesn't support Key Vault references natively)

---

## Logic App Auth Flow

```
Logic App (System Managed Identity)
  │
  ├─→ Key Vault: GET secret 'spycloud-api-key'
  │     Auth: Managed Identity → vault access policy
  │
  ├─→ SpyCloud API: GET /enterprise-v2/breach/data/watchlist
  │     Auth: Authorization: Bearer {api-key-from-vault}
  │
  ├─→ Microsoft Graph API: PATCH /users/{id}
  │     Auth: Managed Identity → Graph API permissions
  │
  ├─→ Defender API: POST /machines/{id}/isolate
  │     Auth: Managed Identity → MDE API permissions
  │
  ├─→ DCE Ingestion: POST /dataCollectionRules/{id}/streams/...
  │     Auth: Managed Identity → Monitoring Metrics Publisher role
  │
  └─→ Sentinel API: POST /Incidents/Comment
        Auth: Managed Identity → Sentinel Responder role
```

---

## Post-Deployment Manual Steps

These CANNOT be automated via ARM and require PowerShell or Portal:

1. **MDE API Permissions** — Assign Machine.Isolate + Machine.ReadWrite.All
   to MDE playbook managed identity
2. **Graph API Permissions** — Assign User.ReadWrite.All + Directory.ReadWrite.All
   to CA playbook managed identity
3. **Sentinel Automation Contributor** — Assign to Microsoft Sentinel service
   principal on the resource group
4. **Defender XDR Connector** — Enable via Sentinel Content Hub (not ARM)
5. **O365/Exchange Connector** — Enable via Sentinel Content Hub (not ARM)
6. **Security Copilot Plugin** — Upload SpyCloud_Copilot_Plugin_Ultimate.yaml
7. **Security Copilot Agent** — Upload SpyCloud_Agent_Manifest.yaml via Build

---

## Resource Count

| Tier | Resources | Conditional |
|------|-----------|-------------|
| Foundation | 8 | Workspace + Sentinel optional |
| Security | 2 | Key Vault + secret |
| Automation | 7 | All conditional per toggle |
| Notifications | 2 | Action group + health alert |
| Entra Connectors | 3 | Diagnostic settings |
| **Total** | **up to 22** | |
