#!/usr/bin/env python3
"""
Convert alertRules resources in azuredeploy.json to AlertRuleTemplates
wrapped in contentTemplates, so they appear in the Sentinel Analytics
Rule Templates gallery instead of deploying as active rules.

Scheduled rules -> contentTemplates wrapping AlertRuleTemplates
Fusion / MicrosoftSecurityIncidentCreation rules -> kept as-is (built-in types)
"""

import json
import hashlib
import sys
import copy

def make_content_id(display_name):
    """Generate a deterministic content ID from the display name."""
    return hashlib.md5(display_name.encode()).hexdigest()[:12]

def convert_scheduled_rule_to_template(rule, index):
    """Convert a Scheduled alertRule resource to a contentTemplate wrapping AlertRuleTemplates."""
    props = rule.get("properties", {})
    display_name = props.get("displayName", f"SpyCloud Rule {index}")
    content_id = f"spycloud-ar-{make_content_id(display_name)}"

    # Build the inner AlertRuleTemplate resource
    inner_props = copy.deepcopy(props)
    # Remove properties not valid for templates
    inner_props.pop("etag", None)
    inner_props.pop("suppressionDuration", None)
    inner_props.pop("suppressionEnabled", None)
    # Templates use "status" instead of "enabled"
    inner_props.pop("enabled", None)
    inner_props["status"] = "Available"

    inner_resource = {
        "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
        "name": f"[variables('analyticRuleContentId{index}')]",
        "apiVersion": "2023-02-01-preview",
        "kind": rule.get("kind", "Scheduled"),
        "location": "[parameters('deploymentRegion')]",
        "properties": inner_props
    }

    # Build the contentTemplate wrapper
    content_template = {
        "condition": "[parameters('enableAnalyticsRule')]",
        "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
        "apiVersion": "2023-04-01-preview",
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', variables('analyticRuleContentId{index}'))]",
        "dependsOn": [
            "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
            "[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/onboardingStates', 'default')]"
        ],
        "properties": {
            "contentId": f"[variables('analyticRuleContentId{index}')]",
            "displayName": display_name,
            "contentKind": "AnalyticsRule",
            "mainTemplate": {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "[variables('_solutionVersion')]",
                "parameters": {},
                "variables": {},
                "resources": [inner_resource]
            },
            "packageKind": "Solution",
            "packageVersion": "[variables('_solutionVersion')]",
            "packageName": "[variables('_solutionName')]",
            "contentProductId": f"[concat(take(variables('_solutionId'), 50), '-ar-', uniqueString(variables('analyticRuleContentId{index}')))]",
            "packageId": "[variables('_solutionId')]",
            "contentSchemaVersion": "3.0.0",
            "version": "[variables('_solutionVersion')]"
        }
    }

    return content_template, content_id

def main():
    with open("azuredeploy.json", "r") as f:
        template = json.load(f)

    resources = template.get("resources", [])
    variables = template.get("variables", {})

    new_resources = []
    converted_count = 0
    kept_count = 0
    other_count = 0
    content_id_vars = {}

    for resource in resources:
        rtype = resource.get("type", "")

        if "alertRules" in rtype:
            kind = resource.get("kind", "")

            if kind == "Scheduled":
                # Convert to AlertRuleTemplate
                converted_count += 1
                content_template, content_id = convert_scheduled_rule_to_template(resource, converted_count)
                new_resources.append(content_template)
                content_id_vars[f"analyticRuleContentId{converted_count}"] = content_id
            else:
                # Keep Fusion and MicrosoftSecurityIncidentCreation as-is
                kept_count += 1
                new_resources.append(resource)
        else:
            other_count += 1
            new_resources.append(resource)

    # Add the content ID variables
    for var_name, var_value in content_id_vars.items():
        variables[var_name] = var_value

    # Ensure solution-level variables exist
    if "_solutionVersion" not in variables:
        variables["_solutionVersion"] = "10.0.0"
    if "_solutionName" not in variables:
        variables["_solutionName"] = "SpyCloud Identity Threat Protection"
    if "_solutionId" not in variables:
        variables["_solutionId"] = "spycloud.spycloud-sentinel-solution"

    template["resources"] = new_resources
    template["variables"] = variables

    with open("azuredeploy.json", "w") as f:
        json.dump(template, f, indent=2)

    print(f"Conversion complete:")
    print(f"  Scheduled rules converted to AlertRuleTemplates: {converted_count}")
    print(f"  Non-scheduled rules kept as alertRules: {kept_count}")
    print(f"  Other resources unchanged: {other_count}")
    print(f"  Total resources: {len(new_resources)}")

if __name__ == "__main__":
    main()
