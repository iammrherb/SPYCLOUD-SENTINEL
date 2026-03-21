# Publishing SpyCloud Agent to the Microsoft Defender Portal

> **Version:** 2.0.0 | **Last Updated:** March 2026

## Overview

This guide covers publishing the SpyCloud Security Copilot Agent and plugins to the Microsoft Defender Portal,
making them available to all Security Copilot users in your organization.

## Prerequisites

| Requirement | Details |
|---|---|
| **Microsoft 365 E5 Security** or **Security Copilot standalone** | Required for Copilot access |
| **Security Administrator** or **Global Administrator** role | Required to publish plugins |
| **Defender Portal access** | [https://security.microsoft.com](https://security.microsoft.com) |
| **SpyCloud API key** | Enterprise-tier API access |

## Step 1: Prepare Plugin Files

The SpyCloud integration includes multiple plugin types:

| Plugin | File | Purpose |
|---|---|---|
| **KQL Plugin** | `copilot/SpyCloud_Plugin.yaml` | Query Sentinel custom tables via natural language |
| **API Plugin** | `copilot/SpyCloud_API_Plugin.yaml` | Real-time REST lookups against SpyCloud API |
| **Full API Plugin** | `copilot/SpyCloud_FullAPI_Plugin.yaml` | Extended API coverage (Compass, SIP, IdLink) |
| **Logic App Plugin** | `copilot/SpyCloud_LogicApp_Plugin.yaml` | Trigger automated remediation playbooks |
| **MCP Plugin** | `copilot/SpyCloud_MCP_Plugin.yaml` | Model Context Protocol integration |
| **SCORCH Agent** | `copilot/SpyCloud_Agent.yaml` | Autonomous investigation agent with 26 sub-agents |

## Step 2: Upload Plugins to Defender Portal

### 2a. Navigate to Security Copilot Settings

1. Open [Microsoft Defender Portal](https://security.microsoft.com)
2. Navigate to **Settings** > **Security Copilot** > **Custom plugins**
3. Click **Add plugin**

### 2b. Upload KQL Plugin (Primary)

1. Select **Upload a custom plugin**
2. Choose `copilot/SpyCloud_Plugin.yaml`
3. Review the skill list — you should see 28+ KQL-based skills
4. Click **Save**

### 2c. Upload API Plugin

1. Click **Add plugin** again
2. Select **Upload a custom plugin**
3. Choose `copilot/SpyCloud_API_Plugin.yaml`
4. When prompted for authentication:
   - Select **API Key** authentication
   - Enter your SpyCloud API key
   - Header name: `X-API-Key`
   - Header value: `<your-api-key>` (the raw key value, no prefix)
5. Click **Save**

### 2d. Upload OpenAPI Specification (Optional)

1. Click **Add plugin** > **Upload OpenAPI specification**
2. Choose `copilot/SpyCloud_API_Plugin_OpenAPI.yaml`
3. Configure the base URL: `https://api.spycloud.io`
4. Set authentication as above

## Step 3: Deploy the SCORCH Agent

The SCORCH (SpyCloud Orchestration) Agent is a comprehensive autonomous investigation agent.

### 3a. Agent Manifest

Upload the manifest file to register the agent:

1. Navigate to **Settings** > **Security Copilot** > **Custom agents**
2. Click **Create agent**
3. Upload `copilot/manifest.json`
4. Review the agent configuration:
   - **Name:** SpyCloud SCORCH Agent
   - **Version:** 2.0.0
   - **Skills:** 267+ investigation capabilities

### 3b. Agent YAML

Upload the agent descriptor:

1. In the agent configuration, click **Upload descriptor**
2. Choose `copilot/SpyCloud_Agent.yaml`
3. Review the 26 sub-agents and their capabilities
4. Click **Publish**

### 3c. Promptbooks (Optional)

Upload investigation promptbooks for guided workflows:

```
copilot/promptbooks/
├── credential-exposure-triage.md
├── infostealer-investigation.md
├── executive-briefing.md
└── sip-cookie-analysis.md
```

1. Navigate to **Promptbooks** in Security Copilot
2. Click **Create promptbook**
3. Import each promptbook file

## Step 4: Configure Permissions

### Required Graph API Permissions

The agent and plugins require the following Microsoft Graph permissions:

| Permission | Type | Purpose |
|---|---|---|
| `SecurityIncident.ReadWrite.All` | Application | Read/update Sentinel incidents |
| `ThreatIndicators.ReadWrite.OwnedBy` | Application | Submit threat indicators |
| `User.Read.All` | Delegated | Look up user details |
| `Device.Read.All` | Delegated | Query device information |
| `SecurityEvents.Read.All` | Delegated | Read security alerts |

### Sentinel Workspace Connection

Ensure Security Copilot is connected to your Sentinel workspace:

1. **Settings** > **Security Copilot** > **Data sources**
2. Enable **Microsoft Sentinel**
3. Select your workspace: `<your-workspace-name>`
4. Verify custom tables are accessible:
   ```
   SpyCloudBreachWatchlist_CL
   SpyCloudBreachCatalog_CL
   SpyCloudCompassData_CL
   SpyCloudSipCookies_CL
   ```

## Step 5: Verify Installation

### Test KQL Plugin

In Security Copilot, try:
```
Show me the latest SpyCloud breach exposures from the last 24 hours
```

Expected: The agent should query `SpyCloudBreachWatchlist_CL` and return recent exposures.

### Test API Plugin

```
Look up email user@example.com in SpyCloud breach database
```

Expected: Real-time API call to SpyCloud returning breach records.

### Test SCORCH Agent

```
Investigate the latest SpyCloud infostealer incident and recommend remediation
```

Expected: Multi-step investigation using sub-agents for data gathering, risk scoring, and remediation recommendations.

## Step 6: Post-Publishing Configuration

### Enable Auto-Investigation

Configure the agent to automatically investigate new SpyCloud incidents:

1. **Settings** > **Security Copilot** > **Automation**
2. Create automation rule:
   - **Trigger:** New incident with title containing "SpyCloud"
   - **Action:** Run SCORCH Agent investigation
   - **Output:** Add investigation summary as incident comment

### Configure Notification Channels

Set up notification routing for critical findings:

| Severity | Channel | Configuration |
|---|---|---|
| 25 (Infostealer + Sessions) | Teams + Email + Ticket | Immediate escalation |
| 20 (Infostealer Credentials) | Teams + Email | High priority |
| 5 (Combo Lists) | Email | Standard priority |
| 2 (All Breaches) | Dashboard only | Low priority |

## Troubleshooting

| Issue | Solution |
|---|---|
| Plugin not appearing | Verify you have Security Administrator role; clear browser cache |
| "No data found" responses | Check Sentinel workspace connection and custom table population |
| API authentication failures | Verify API key is valid; check `X-API-Key` header format (raw key, no Bearer prefix) |
| Agent timeout | Reduce concurrent sub-agent count; check network connectivity |
| Skills not loading | Re-upload the YAML file; verify YAML syntax with `yamllint` |

## Related Documentation

- [SCORCH Agent Evaluation](SCORCH-AGENT-EVALUATION-v13.md)
- [Security Copilot Specification](SECURITY-COPILOT-SPEC.md)
- [Agents and Plugins Guide](AGENTS-AND-PLUGINS-GUIDE.md)
- [API Setup Guide](API-SETUP-GUIDE.md)
