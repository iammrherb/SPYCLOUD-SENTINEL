# ═══════════════════════════════════════════════════════════════════════════════
# SpyCloud Sentinel — Terraform Outputs
# ═══════════════════════════════════════════════════════════════════════════════

output "resource_group_name" {
  description = "Name of the resource group"
  value       = local.resource_group_name
}

output "deployment_name" {
  description = "Name of the ARM template deployment"
  value       = azurerm_resource_group_template_deployment.spycloud.name
}

output "dce_endpoint" {
  description = "Data Collection Endpoint logs ingestion URL"
  value       = try(data.azurerm_monitor_data_collection_endpoint.spycloud.logs_ingestion_endpoint, "pending")
}

output "dcr_immutable_id" {
  description = "Data Collection Rule immutable ID"
  value       = try(data.azurerm_monitor_data_collection_rule.spycloud.immutable_id, "pending")
}

output "sentinel_url" {
  description = "Direct link to Microsoft Sentinel in Azure Portal"
  value       = "${local.portal_url}/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/${var.subscription_id}/resourceGroup/${local.resource_group_name}/workspaceName/${var.workspace_name}"
}

output "cloud_environment" {
  description = "Azure cloud environment (AzureCloud or AzureUSGovernment)"
  value       = var.cloud_environment
}

output "workspace_id" {
  description = "Log Analytics workspace name"
  value       = var.workspace_name
}

output "identity_exposure_table" {
  description = "Custom log table for SpyCloud identity exposure data"
  value       = "SpyCloud_IdentityExposure_CL"
}

output "investigations_table" {
  description = "Custom log table for SpyCloud Investigations data (only populated when enable_investigations is true)"
  value       = var.enable_investigations ? "SpyCloud_Investigations_CL" : "not_deployed"
}

output "compass_table" {
  description = "Custom log table for SpyCloud Compass data (only populated when enable_compass is true)"
  value       = var.enable_compass ? "SpyCloud_Compass_CL" : "not_deployed"
}

output "sip_table" {
  description = "Custom log table for SpyCloud SIP stolen session data (only populated when enable_sip is true)"
  value       = var.enable_sip ? "SpyCloud_SIP_CL" : "not_deployed"
}

output "post_deployment_steps" {
  description = "Required post-deployment steps"
  value = <<-EOT
    Post-Deployment Steps:
    1. Run: ./scripts/post-deploy.sh -g ${local.resource_group_name} -w ${var.workspace_name}
    2. Enable analytics rules: Sentinel > Analytics > filter 'SpyCloud'
    3. Verify data flow: Sentinel > Data connectors > SpyCloud > Connect
    4. Upload Copilot files: copilot/SpyCloud_Plugin.yaml + SpyCloud_Agent.yaml
    5. If Investigations enabled: verify SpyCloud_Investigations_CL table in Log Analytics
    6. If Compass enabled: verify SpyCloud_Compass_CL table in Log Analytics
    7. If SIP enabled: verify SpyCloud_SIP_CL table and confirm cookie domain setting
  EOT
}
