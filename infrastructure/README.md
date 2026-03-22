# Infrastructure

This directory contains infrastructure components deployed by the **Full ARM Deployment** (`azuredeploy.json`).

## Directory Structure

| Directory | Description |
|-----------|-------------|
| `functions/` | Azure Function Apps (SpyCloudEnrichment, SpyCloudAIEngine) |
| `terraform/` | Terraform configuration for alternative IaC deployment |

## Deployment

These components are **NOT** deployed via Content Hub or Sentinel CI/CD. They require the full ARM deployment template (`azuredeploy.json`) or the Terraform configuration.

### Full ARM Deployment
Deploys all infrastructure including Key Vault, Function App, Logic Apps, DCE/DCR, custom log tables, and automation rules.

### Terraform
Alternative deployment method for teams using Terraform/OpenTofu.
