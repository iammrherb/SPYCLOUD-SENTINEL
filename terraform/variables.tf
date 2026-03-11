# ═══════════════════════════════════════════════════════════════════════════════
# SpyCloud Sentinel — Terraform Variables
# ═══════════════════════════════════════════════════════════════════════════════

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group for SpyCloud Sentinel resources"
  type        = string
  default     = "rg-spycloud-sentinel"
}

variable "create_resource_group" {
  description = "Create a new resource group (true) or use existing (false)"
  type        = bool
  default     = true
}

variable "location" {
  description = "Azure region for deployment"
  type        = string
  default     = "eastus"
  validation {
    condition     = contains(["eastus", "eastus2", "westus2", "centralus", "northeurope", "westeurope", "uksouth", "australiaeast", "southeastasia", "japaneast"], var.location)
    error_message = "Location must be a supported Azure region with Sentinel and DCE/DCR availability."
  }
}

variable "workspace_name" {
  description = "Name of the Log Analytics workspace (created if create_new_workspace=true)"
  type        = string
  default     = "law-spycloud-sentinel"
}

variable "create_new_workspace" {
  description = "Create a new Log Analytics workspace with Sentinel enabled"
  type        = bool
  default     = true
}

variable "spycloud_api_key" {
  description = "SpyCloud Enterprise API key from portal.spycloud.com"
  type        = string
  sensitive   = true
}

# ─── Feature Toggles ──────────────────────────────────────────────────────────

variable "enable_mde_playbook" {
  description = "Deploy the MDE device isolation playbook (requires Defender for Endpoint P2)"
  type        = bool
  default     = true
}

variable "enable_ca_playbook" {
  description = "Deploy the Conditional Access identity protection playbook (requires Entra ID P1+)"
  type        = bool
  default     = true
}

variable "enable_key_vault" {
  description = "Create an Azure Key Vault to store the SpyCloud API key"
  type        = bool
  default     = true
}

variable "enable_analytics_rules" {
  description = "Deploy analytics rules (all deploy disabled by default)"
  type        = bool
  default     = true
}

variable "enable_automation_rule" {
  description = "Deploy automation rules for playbook orchestration"
  type        = bool
  default     = true
}

# ─── v8.0 Feature Toggles ───────────────────────────────────────────────────

variable "enable_investigations" {
  description = "Enable SpyCloud Investigations integration — deploys the Investigations data connector, custom log table, and associated analytics rules for deep-dive identity investigation workflows"
  type        = bool
  default     = false
}

variable "investigations_api_key" {
  description = "SpyCloud Investigations API key (required when enable_investigations is true). Obtain from portal.spycloud.com under Investigations API settings"
  type        = string
  sensitive   = true
  default     = ""
}

variable "compass_api_key" {
  description = "SpyCloud Compass API key for automated identity resolution and enrichment. Required when enable_compass is true. Obtain from portal.spycloud.com under Compass API settings"
  type        = string
  sensitive   = true
  default     = ""
}

variable "sip_api_key" {
  description = "SpyCloud SIP (Session Identity Protection) API key for stolen session and cookie monitoring. Required when enable_sip is true. Obtain from portal.spycloud.com under SIP API settings"
  type        = string
  sensitive   = true
  default     = ""
}

variable "sip_cookie_domain" {
  description = "The corporate cookie domain to monitor for stolen sessions via SIP (e.g., 'example.com'). Only used when enable_sip is true"
  type        = string
  default     = ""
}

variable "enable_sip" {
  description = "Enable SpyCloud Session Identity Protection (SIP) — deploys the SIP data connector and analytics rules for detecting stolen web sessions and hijacked cookies"
  type        = bool
  default     = false
}

variable "enable_compass" {
  description = "Enable SpyCloud Compass — deploys the Compass data connector and analytics rules for automated identity exposure monitoring and remediation recommendations"
  type        = bool
  default     = false
}

# ─── Template Source ──────────────────────────────────────────────────────────

variable "arm_template_url" {
  description = "URL to the ARM template (leave empty to use github_repo)"
  type        = string
  default     = ""
}

variable "arm_template_local_path" {
  description = "Local path to azuredeploy.json (leave empty to use URL)"
  type        = string
  default     = "../azuredeploy.json"
}

variable "github_repo" {
  description = "GitHub repository (owner/repo) for remote template URL"
  type        = string
  default     = "iammrherb/SPYCLOUD-SENTINEL"
}

# ─── Tags ──────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Solution    = "SpyCloud-Sentinel"
    ManagedBy   = "Terraform"
    Environment = "Production"
  }
}
