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
  value       = "https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/${var.subscription_id}/resourceGroup/${local.resource_group_name}/workspaceName/${var.workspace_name}"
}

output "post_deployment_steps" {
  description = "Required post-deployment steps"
  value = <<-EOT
    Post-Deployment Steps:
    1. Run: ./scripts/post-deploy.sh -g ${local.resource_group_name} -w ${var.workspace_name}
    2. Enable analytics rules: Sentinel > Analytics > filter 'SpyCloud'
    3. Verify data flow: Sentinel > Data connectors > SpyCloud > Connect
    4. Upload Copilot files: copilot/SpyCloud_Plugin.yaml + SpyCloud_Agent.yaml
  EOT
}
