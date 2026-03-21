# Sentinel Content

This directory contains all Microsoft Sentinel deployable content organized by type. These files are deployed via the **Sentinel Repository CI/CD** workflow.

## Directory Structure

| Directory | Content Type | Description |
|-----------|-------------|-------------|
| `analytics-rules/` | Analytics Rules | YAML rule definitions and ARM templates for threat detection |
| `playbooks/` | Playbooks (Logic Apps) | ARM templates for automated response workflows |
| `workbooks/` | Workbooks | ARM templates for visualization dashboards |
| `hunting-queries/` | Hunting Queries | KQL queries for proactive threat hunting |
| `automations/` | Automation Rules | ARM templates for automatic incident handling |

## Deployment

These files are automatically deployed by the Sentinel CI/CD workflow when pushed to `main`. The workflow is configured in `.github/workflows/sentinel-deploy-*.yml`.

Files excluded from CI/CD deployment are listed in `sentinel-deployment.config` at the repo root.

## Naming Convention

- **Playbooks**: `SpyCloud-<Action>-Template.json`
- **Workbooks**: `SpyCloud-<Name>-Workbook.json`
- **Analytics**: `spycloud-<category>-templates.yaml`
- **Automations**: `auto-<action>-template.json`
