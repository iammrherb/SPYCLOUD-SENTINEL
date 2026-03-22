# SpyCloud Identity Exposure Intelligence for Sentinel
## Content Hub & Data Connector Deployment Readiness Assessment

**Date**: March 21, 2026
**Version**: 2.0.0
**Branch**: `main` (commit `7cf510f`)

---

## Executive Summary

The repository has **three distinct deployment paths**, each serving different purposes. Currently, only **Path 1 (Content Hub)** has a structurally complete template (`mainTemplate.json`), but the **Sentinel Repository CI/CD deployment (Path 3)** is critically broken due to missing configuration and improperly formatted files. The **Full ARM deployment (Path 2)** has a fatal case-sensitivity bug that crashes the deployment script.

### Deployment Scorecard

| Path | Template | Status | Blockers |
|------|----------|--------|----------|
| **1. Content Hub (Marketplace)** | `mainTemplate.json` | Structurally Ready | Needs ISV validation testing |
| **2. Full ARM ("Deploy to Azure")** | `azuredeploy.json` | **BROKEN** | Case mismatch crashes PowerShell |
| **3. Sentinel Repository CI/CD** | Individual files | **BROKEN** | 7 critical issues (see below) |

---

## Path 1: Content Hub / Marketplace Deployment

### What It Is
The `mainTemplate.json` + `createUiDefinition.json` package that gets submitted to Microsoft Partner Center for Content Hub listing. Customers install it from the Sentinel Content Hub blade.

### What's Included (71 resources)

| Content Type | Count | Status |
|-------------|-------|--------|
| Analytics Rules | 38 | Included as `contentTemplates` |
| Playbooks (Logic Apps) | 23 | Included as `contentTemplates` |
| Workbooks | 3 | Included as `contentTemplates` |
| Data Connector | 1 | Included as `contentTemplate` |
| Hunting Queries | 1 | Included as `contentTemplate` |
| Notebooks | 3 | Included as `contentTemplates` |
| Content Package (Solution) | 1 | Included |
| Metadata | 1 | Included |

### What's NOT Included (requires Path 2)

| Resource | Why Not |
|----------|---------|
| Key Vault | Infrastructure resource - rejected by Content Hub |
| Function App (SpyCloudEnrichment) | Infrastructure resource |
| Azure Functions (SpyCloudAIEngine) | Infrastructure resource |
| Data Collection Endpoint (DCE) | Infrastructure resource |
| Data Collection Rules (DCR) | Infrastructure resource |
| 11 Custom Log Tables | Infrastructure resource |
| Automation Rules | Not included in current mainTemplate |
| Post-Deployment Script | Infrastructure resource |
| App Service Plan | Infrastructure resource |
| Storage Account | Infrastructure resource |
| Managed Identity + RBAC | Infrastructure resource |

### Data Connector Assessment

**YES** - The data connector IS included in `mainTemplate.json` as a content template. It provides:
- API polling configuration for SpyCloud endpoints
- Connection instructions displayed in the Sentinel Data Connectors blade
- Configuration UI for API key and domain settings

**BUT** - The data connector template in Content Hub is a **configuration template only**. It does NOT:
- Create the custom log tables (those are in `azuredeploy.json`)
- Deploy the Function App that actually polls the API
- Set up the DCE/DCR pipeline for data ingestion

**Bottom line**: Installing from Content Hub gives you the connector UI and configuration, but you still need to deploy `azuredeploy.json` (Path 2) to get the actual data ingestion pipeline working.

### Log Tables Assessment

**NO** - The 11 custom log tables are **NOT** in `mainTemplate.json`. They are only in `azuredeploy.json`:

1. `SpyCloudBreachCatalog_CL`
2. `SpyCloudBreachWatchlist_CL`
3. `SpyCloudExposure_CL`
4. `SpyCloudIdentityExposure_CL`
5. `SpyCloudCompassData_CL`
6. `SpyCloudCompassDevices_CL`
7. `SpyCloudCompassApplications_CL`
8. `SpyCloudIdLink_CL`
9. `SpyCloudInvestigations_CL`
10. `SpyCloudSipCookies_CL`
11. `SpyCloud_ConditionalAccessLogs_CL`

### Content Hub Readiness Checklist

- [x] `mainTemplate.json` has proper `$schema` and `contentVersion`
- [x] All 69 content templates have `packageKind`, `packageVersion`, `packageName`, `packageId`
- [x] Content package resource with proper dependencies
- [x] Solution metadata resource
- [x] `createUiDefinition.json` exists with wizard steps
- [x] `solutionMetadata.json` exists with content listing
- [ ] **NEEDS TESTING**: Deploy to a test Sentinel workspace via Content Hub
- [ ] **NEEDS VALIDATION**: Submit to Microsoft Partner Center for ISV certification

---

## Path 2: Full ARM Deployment ("Deploy to Azure" Button)

### What It Is
The `azuredeploy.json` template deployed via the "Deploy to Azure" button or `az deployment group create`. Deploys ALL infrastructure and content.

### What's Included (~158 resources)
Everything in Path 1, PLUS:
- Key Vault with secrets
- Function App (SpyCloudEnrichment) with managed identity
- AI Engine Function App (SpyCloudAIEngine)
- App Service Plan
- Storage Account
- Data Collection Endpoint (DCE)
- Data Collection Rules (DCR) for all 11 tables
- 11 Custom Log Tables
- Automation Rules (4)
- RBAC Role Assignments (Key Vault Secrets User)
- Post-Deployment Script (ARM deployment script)
- All Logic Apps (23 playbooks)
- All Analytics Rules (38)
- All Workbooks (3)

### CRITICAL BUG: Case Mismatch

**`azuredeploy.json` has a fatal bug** that crashes the Sentinel deployment PowerShell script:

```
Line 514:  "enableMsicRules"   (lowercase 'sic')
Line 1338: "enableMSICRules"   (uppercase 'SIC')
```

PowerShell's `ConvertFrom-Json` treats these as duplicate keys and crashes with:
```
Cannot convert the JSON string because it contains keys with different casing.
The key that was attempted to be added to the existing key 'enableMsicRules' was 'enableMSICRules'.
```

**Fix**: Standardize to `enableMsicRules` everywhere.

---

## Path 3: Sentinel Repository CI/CD Deployment

### What It Is
Microsoft Sentinel's built-in "Repositories" feature that connects a GitHub repo to a Sentinel workspace. On every push to `main`, the auto-generated PowerShell script (`azure-sentinel-deploy-*.ps1`) scans the repo for ARM template files and deploys them individually.

### Current Status: CRITICALLY BROKEN

The deployment workflow (`sentinel-deploy-03a1d12c-90ae-4f21-87fd-f401dd2e4bbb.yml`) triggers on every push to `main` and runs the PowerShell script that scans ALL `.json` files in the repo. Without a `sentinel-deployment.config` file, **every JSON file is attempted as an ARM template deployment**.

### Error Summary from Live Deployment

| Category | Files | Error | Root Cause |
|----------|-------|-------|------------|
| Non-ARM JSON files | 10 | `Could not find member 'X' on object of type 'Template'` | No `sentinel-deployment.config` to exclude them |
| Playbooks (missing params) | 19/22 | `Missing mandatory parameters: subscriptionId, workspaceName, ...` | Parameter files have empty values for mandatory params |
| Playbooks (succeeded) | 3/22 | Deployed successfully | These have all defaults or only `workspace` param |
| Template playbooks (missing params) | 16/22 | Same as above | Same root cause |
| Template playbooks (succeeded) | 6/22 | Deployed successfully | These use `workspace` param only |
| Workbook files | 16 | `Could not find member 'version' on object of type 'Template'` | Raw workbook JSON, NOT ARM templates |
| analytics-rules.json | 1 | `Could not find member 'description' on object of type 'Template'` | Custom JSON format, NOT ARM template |
| test-data files | 13 | `Resource without type detected` | Sample data JSON, NOT ARM templates |
| Automation rules | 4 | `Resource type not selected for this connection` | Content type not enabled in Sentinel connection |
| azuredeploy.json | 1 | `Contains keys with different casing` | enableMsicRules/enableMSICRules case mismatch |

### Detailed Breakdown of Non-ARM Files Being Deployed

These files should NEVER be sent to the ARM deployment engine:

| File | Actual Content |
|------|---------------|
| `.vscode/extensions.json` | VS Code extension recommendations |
| `.vscode/launch.json` | VS Code debug configuration |
| `.vscode/settings.json` | VS Code workspace settings |
| `.vscode/tasks.json` | VS Code task definitions |
| `copilot/manifest.json` | Copilot agent manifest |
| `copilot/SecurityCopilotAgent.json` | Security Copilot agent definition |
| `functions/SpyCloudAIEngine/host.json` | Azure Functions host config |
| `functions/SpyCloudEnrichment/host.json` | Azure Functions host config |
| `mcp-server/package.json` | Node.js package manifest |
| `mcp-server/package-lock.json` | Node.js lock file |

### Playbook Deployment Results

**Succeeded (CI/CD compatible - all params have defaults)**:
1. `SpyCloud-Copilot-Triage.json` - no mandatory params
2. `templates/playbooks/SpyCloud-EmailNotify-Template.json` - only `workspace` mandatory
3. `templates/playbooks/SpyCloud-Jira-Template.json` - only `workspace` mandatory
4. `templates/playbooks/SpyCloud-ServiceNow-Template.json` - only `workspace` mandatory
5. `templates/playbooks/SpyCloud-SlackNotify-Template.json` - only `workspace` mandatory
6. `templates/playbooks/SpyCloud-WebhookNotify-Template.json` - only `workspace` mandatory

**Failed (mandatory params without defaults)**:
All other playbooks require `subscriptionId`, `resourceGroupName`, `workspaceName`, and often additional params like `spycloudApiKey`, group IDs, URLs, etc.

### Workbook Files: Wrong Format

ALL workbook files in both `workbooks/` and `templates/workbooks/` are **raw Azure Workbook Gallery JSON** (starting with `{"version": "Notebook/1.0", "items": [...]}`) instead of **ARM deployment templates** (which need `$schema`, `contentVersion`, `parameters`, `resources`).

The Sentinel CI/CD script expects ARM templates with `Microsoft.Insights/workbooks` resource type. The current files cannot be deployed via CI/CD.

---

## Repo Structure Issues

### Current Structure (Problematic)
```
SPYCLOUD-SENTINEL/
  .vscode/              # Non-ARM JSON files (causing deployment errors)
  analytics-rules/      # YAML rule definitions (not deployable)
  analytics-rules.json  # Custom JSON format (not ARM, causes errors)
  azuredeploy.json      # Full ARM template (has case bug)
  copilot/              # Agent configs (causing deployment errors)
  createUiDefinition.json
  functions/            # host.json files (causing deployment errors)
  hunting-queries.json  # Hunting query JSON
  mainTemplate.json     # Content Hub template
  mcp-server/           # package.json (causing deployment errors)
  package/              # Node.js package (causing deployment errors)
  playbooks/            # Standalone playbooks (most fail CI/CD)
  portal/               # Web portal (non-ARM)
  scripts/              # Shell scripts
  templates/
    analytics/          # YAML analytics templates
    automations/        # Automation rule templates (skipped - content type not enabled)
    playbooks/          # Template playbooks (duplicates of playbooks/)
    workbooks/          # Raw workbook JSON (wrong format)
  test-data/            # Sample data (causing deployment errors)
  workbooks/            # Raw workbook JSON (wrong format)
```

### Key Issues
1. **No `sentinel-deployment.config`** - Every JSON file gets picked up by CI/CD
2. **Duplicate playbooks** - `playbooks/` AND `templates/playbooks/` (same content, different names)
3. **Workbooks in wrong format** - Both `workbooks/` and `templates/workbooks/` are raw gallery JSON
4. **Non-Sentinel files mixed in** - `.vscode`, `copilot`, `functions`, `mcp-server`, `package` all have JSON files
5. **No `.gitignore` for node_modules** - `.gitignore` has `node_modules/` but they shouldn't be in the repo search path

---

## Recommended Fixes (Priority Order)

### P0 - Critical (Blocking All Deployments)

1. **Create `sentinel-deployment.config`** with `excludecontentfiles` to skip non-ARM directories
2. **Fix `azuredeploy.json` case mismatch** - standardize `enableMsicRules`/`enableMSICRules`
3. **Update `sentinel-deploy-*.yml` paths** to only trigger on Sentinel content directories

### P1 - High (Blocking CI/CD Playbook Deployment)

4. **Fix playbook parameter files** - add proper default values so CI/CD can deploy them
5. **Consolidate playbooks** - remove duplicate `playbooks/` vs `templates/playbooks/` structure
6. **Convert workbooks to ARM format** - wrap raw workbook JSON in ARM template structure

### P2 - Medium (Repo Organization)

7. **Restructure directories** to separate Sentinel content from non-Sentinel files
8. **Add proper README tags** for each directory explaining its purpose
9. **Update `.gitignore`** to prevent non-Sentinel files from being tracked

### P3 - Low (Documentation & Polish)

10. **Document the three deployment paths** clearly in README
11. **Add deployment validation script** that checks all templates before push
12. **Create ISV submission checklist** document

---

## Comparison Matrix: What Each Path Deploys

| Component | Content Hub | Full ARM | CI/CD Repo |
|-----------|:-----------:|:--------:|:----------:|
| Analytics Rules (38) | Content Templates | ARM Resources | Individual ARM |
| Playbooks (23) | Content Templates | ARM Resources | Individual ARM |
| Workbooks (3) | Content Templates | ARM Resources | **BROKEN** |
| Data Connector (1) | Content Template | ARM Resource | N/A |
| Hunting Queries (1) | Content Template | ARM Resource | Individual ARM |
| Notebooks (3) | Content Templates | N/A | N/A |
| Key Vault | N/A | ARM Resource | N/A |
| Function App | N/A | ARM Resource | N/A |
| Custom Log Tables (11) | N/A | ARM Resource | N/A |
| DCE/DCR | N/A | ARM Resource | N/A |
| Automation Rules (4) | N/A | ARM Resource | **SKIPPED** |
| Post-Deploy Script | N/A | ARM Resource | N/A |
| RBAC Assignments | N/A | ARM Resource | N/A |

---

## Answer to User's Key Question

> "Will this also deploy the data connector and all the log tables or does that have to be done using a different template?"

**Data Connector**: YES - included in `mainTemplate.json` (Content Hub). It deploys the connector configuration and UI. However, the actual data ingestion requires the Function App from `azuredeploy.json`.

**Log Tables**: NO - the 11 custom log tables are ONLY in `azuredeploy.json`. Content Hub does not support creating custom log tables.

**Recommended customer workflow**:
1. Install Content Hub package (gets analytics rules, playbooks, workbooks, connector config, hunting queries)
2. Deploy `azuredeploy.json` via "Deploy to Azure" button (gets infrastructure: Function App, Key Vault, tables, DCE/DCR)
3. Configure the data connector in Sentinel with API key
4. Authorize Logic App connections (managed identity or OAuth)
