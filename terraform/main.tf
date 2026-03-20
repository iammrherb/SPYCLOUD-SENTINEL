# ═══════════════════════════════════════════════════════════════════════════════
# SpyCloud Sentinel — Terraform Deployment
# Deploys the SpyCloud Threat Intelligence solution via ARM template
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  environment     = var.cloud_environment == "AzureUSGovernment" ? "usgovernment" : "public"
}

# ─── Resource Group ────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "sentinel" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

data "azurerm_resource_group" "existing" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

locals {
  resource_group_name = var.create_resource_group ? azurerm_resource_group.sentinel[0].name : data.azurerm_resource_group.existing[0].name
  location            = var.create_resource_group ? azurerm_resource_group.sentinel[0].location : data.azurerm_resource_group.existing[0].location

  template_url = coalesce(
    var.arm_template_url,
    "https://raw.githubusercontent.com/${var.github_repo}/main/azuredeploy.json"
  )

  # Azure Gov portal URL differs from commercial
  portal_url = var.cloud_environment == "AzureUSGovernment" ? "https://portal.azure.us" : "https://portal.azure.com"
}

# ─── Fetch ARM template from URL when no local path provided ─────────────────
data "http" "arm_template" {
  count = var.arm_template_local_path == "" ? 1 : 0
  url   = local.template_url

  request_headers = {
    Accept = "application/json"
  }
}

# ─── Fetch ARM template from URL when no local path provided ─────────────────
data "http" "arm_template" {
  count = var.arm_template_local_path == "" ? 1 : 0
  url   = local.template_url

  request_headers = {
    Accept = "application/json"
  }
}

# ─── ARM Template Deployment ──────────────────────────────────────────────────
resource "azurerm_resource_group_template_deployment" "spycloud" {
  name                = "spycloud-sentinel-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  resource_group_name = local.resource_group_name
  deployment_mode     = "Incremental"

  template_content = var.arm_template_local_path != "" ? file(var.arm_template_local_path) : data.http.arm_template[0].response_body

  parameters_content = jsonencode({
    workspace = {
      value = var.workspace_name
    }
    createNewWorkspace = {
      value = var.create_new_workspace
    }
    spycloudApiKey = {
      value = var.spycloud_api_key
    }
    deploymentRegion = {
      value = local.location
    }
    resourceGroupName = {
      value = local.resource_group_name
    }
    enableMdePlaybook = {
      value = var.enable_mde_playbook
    }
    enableCaPlaybook = {
      value = var.enable_ca_playbook
    }
    enableKeyVault = {
      value = var.enable_key_vault
    }
    enableAnalyticsRule = {
      value = var.enable_analytics_rules
    }
    enableAutomationRule = {
      value = var.enable_automation_rule
    }
    enableInvestigations = {
      value = var.enable_investigations
    }
    investigationsApiKey = {
      value = var.investigations_api_key
    }
    compassApiKey = {
      value = var.compass_api_key
    }
    sipApiKey = {
      value = var.sip_api_key
    }
    sipCookieDomain = {
      value = var.sip_cookie_domain
    }
    enableSip = {
      value = var.enable_sip
    }
    enableCompass = {
      value = var.enable_compass
    }
    monitoredDomain = {
      value = var.monitored_domain
    }
    pollingInterval = {
      value = var.polling_interval
    }
    spycloudSeverityThreshold = {
      value = var.severity_threshold
    }
    enablePlaintextPasswords = {
      value = var.enable_plaintext_passwords
    }
  })

  tags = var.tags

  lifecycle {
    ignore_changes = [name]
  }

  timeouts {
    create = "60m"
    update = "60m"
    delete = "30m"
  }
}

# ─── Post-Deployment: DCE Resolution ──────────────────────────────────────────
data "azurerm_monitor_data_collection_endpoint" "spycloud" {
  depends_on          = [azurerm_resource_group_template_deployment.spycloud]
  name                = "dce-spycloud-${var.workspace_name}"
  resource_group_name = local.resource_group_name
}

data "azurerm_monitor_data_collection_rule" "spycloud" {
  depends_on          = [azurerm_resource_group_template_deployment.spycloud]
  name                = "dcr-spycloud-${var.workspace_name}"
  resource_group_name = local.resource_group_name
}
