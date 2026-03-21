# Deploy to Azure - Full Infrastructure

This directory contains the complete infrastructure deployment for SpyCloud Identity Exposure Intelligence for Sentinel.

## What's Included

Unlike the Content Hub package (in `Solutions/`), this deployment includes **everything**:

| Resource | Description |
|---|---|
| **Key Vault** | Secure storage for SpyCloud API key and other secrets |
| **Function Apps** | SpyCloud Enrichment + AI Engine Azure Functions |
| **Logic Apps** | All automation playbooks |
| **Custom Log Tables** | All 13 custom log tables (DCE/DCR) |
| **Data Connector** | SpyCloud data connector with polling |
| **Analytics Rules** | All detection rules |
| **Workbooks** | All visualization workbooks |
| **Automation Rules** | Auto-triage, auto-enrich, auto-remediate |
| **RBAC Assignments** | Managed identity permissions |

## Deployment

### Option 1: Deploy to Azure Button

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fdeploy%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fdeploy%2Fazuredeploy.json)

### Option 2: Azure CLI

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json
```

### Option 3: Terraform

```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Post-Deployment

Run the post-deployment script to configure permissions and validate:

```bash
chmod +x post-deploy.sh
./post-deploy.sh
```

Or use the automated version:

```bash
chmod +x post-deploy-auto.sh
./post-deploy-auto.sh
```

## Files

| File | Description |
|---|---|
| `azuredeploy.json` | Main ARM template (158+ resources) |
| `azuredeploy.parameters.json` | Parameter file template |
| `createUiDefinition.json` | Azure portal deployment wizard |
| `post-deploy.sh` | Post-deployment configuration script |
| `post-deploy-auto.sh` | Automated post-deployment script |
| `functions/` | Azure Function App code |
| `terraform/` | Terraform alternative deployment |
