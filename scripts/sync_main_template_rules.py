#!/usr/bin/env python3
"""
Sync mainTemplate.json analytics rules with the 38 AlertRuleTemplates
from azuredeploy.json. Replaces the existing 6 rules with all 38.
"""

import json
import copy

def main():
    # Load both templates
    with open("azuredeploy.json") as f:
        deploy = json.load(f)
    with open("mainTemplate.json") as f:
        main_tpl = json.load(f)

    # Extract all AnalyticsRule contentTemplates from azuredeploy.json
    analytics_templates = []
    for r in deploy["resources"]:
        if (r.get("type", "") == "Microsoft.OperationalInsights/workspaces/providers/contentTemplates"
            and r.get("properties", {}).get("contentKind") == "AnalyticsRule"):
            analytics_templates.append(r)

    print(f"Found {len(analytics_templates)} analytics rule templates in azuredeploy.json")

    # Remove old analytics rule contentTemplates from mainTemplate.json
    old_resources = main_tpl["resources"]
    new_resources = []
    removed = 0
    insert_pos = None

    for i, r in enumerate(old_resources):
        if (r.get("type", "") == "Microsoft.OperationalInsights/workspaces/providers/contentTemplates"
            and r.get("properties", {}).get("contentKind") == "AnalyticsRule"):
            removed += 1
            if insert_pos is None:
                insert_pos = len(new_resources)
        else:
            new_resources.append(r)

    print(f"Removed {removed} old analytics rule templates from mainTemplate.json")

    if insert_pos is None:
        # Insert before HuntingQuery or at end
        for i, r in enumerate(new_resources):
            if (r.get("type", "") == "Microsoft.OperationalInsights/workspaces/providers/contentTemplates"
                and r.get("properties", {}).get("contentKind") == "HuntingQuery"):
                insert_pos = i
                break
        if insert_pos is None:
            insert_pos = len(new_resources)

    # Convert azuredeploy.json templates to mainTemplate.json format
    # mainTemplate.json uses slightly different variable references and structure
    main_analytics = []
    for idx, at in enumerate(analytics_templates, 1):
        props = at["properties"]
        inner_resources = props["mainTemplate"]["resources"]
        inner_rule = inner_resources[0] if inner_resources else {}
        display_name = props.get("displayName", f"SpyCloud Rule {idx}")

        # Create the mainTemplate.json format contentTemplate
        content_id_var = f"analyticRulecontentId{idx}"
        version_var = f"analyticRuleVersion{idx}"

        # Build inner template matching mainTemplate.json format
        inner_template_resource = {
            "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
            "name": f"[variables('{content_id_var}')]",
            "apiVersion": "2023-02-01-preview",
            "kind": inner_rule.get("kind", "Scheduled"),
            "location": "[parameters('workspace-location')]",
            "properties": inner_rule.get("properties", {})
        }

        # Metadata resource
        metadata_resource = {
            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
            "apiVersion": "2022-01-01-preview",
            "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',concat('AnalyticsRule-', last(split(variables('{content_id_var}'),'/'))))]",
            "properties": {
                "description": f"SpyCloud Identity Threat Protection Analytics Rule {idx}",
                "parentId": f"[variables('{content_id_var}')]",
                "contentId": f"[variables('_{content_id_var}')]",
                "kind": "AnalyticsRule",
                "version": f"[variables('{version_var}')]",
                "source": {
                    "kind": "Solution",
                    "name": "SpyCloud Identity Threat Protection",
                    "sourceId": "[variables('_solutionId')]"
                },
                "author": {
                    "name": "SpyCloud, Inc."
                },
                "support": {
                    "name": "SpyCloud, Inc.",
                    "email": "integrations@spycloud.com",
                    "tier": "Partner"
                }
            }
        }

        content_template = {
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('analyticRuleTemplateSpecName{idx}')]",
            "location": "[parameters('workspace-location')]",
            "dependsOn": [
                f"[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
            ],
            "properties": {
                "description": f"SpyCloud Analytics Rule {idx} with template version [variables('{version_var}')]",
                "mainTemplate": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": f"[variables('{version_var}')]",
                    "parameters": {},
                    "variables": {},
                    "resources": [inner_template_resource, metadata_resource]
                },
                "contentId": f"[variables('_{content_id_var}')]",
                "contentKind": "AnalyticsRule",
                "displayName": display_name,
                "contentProductId": f"[concat(take(variables('_solutionId'),50),'-','ar','-', uniqueString(concat(variables('_solutionId'),'-','AnalyticsRule','-',variables('_{content_id_var}'),'-', variables('{version_var}'))))]",
                "id": f"[concat(take(variables('_solutionId'),50),'-','ar','-', uniqueString(concat(variables('_solutionId'),'-','AnalyticsRule','-',variables('_{content_id_var}'),'-', variables('{version_var}'))))]",
                "version": f"[variables('{version_var}')]"
            }
        }

        main_analytics.append(content_template)

    print(f"Created {len(main_analytics)} new analytics rule templates for mainTemplate.json")

    # Insert at the right position
    for i, ma in enumerate(main_analytics):
        new_resources.insert(insert_pos + i, ma)

    main_tpl["resources"] = new_resources

    # Update variables - remove old, add new
    variables = main_tpl.get("variables", {})

    # Remove old analyticRule variables
    old_vars = [k for k in variables if k.startswith("analyticRule")]
    for k in old_vars:
        del variables[k]

    # Add new variables for all 38 rules
    deploy_vars = deploy.get("variables", {})
    for idx in range(1, len(analytics_templates) + 1):
        content_id_key = f"analyticRuleContentId{idx}"
        if content_id_key in deploy_vars:
            content_id = deploy_vars[content_id_key]
        else:
            content_id = f"spycloud-ar-{idx:03d}"

        variables[f"analyticRuleVersion{idx}"] = "10.0.0"
        variables[f"analyticRulecontentId{idx}"] = content_id
        variables[f"_analyticRulecontentId{idx}"] = f"[variables('analyticRulecontentId{idx}')]"
        variables[f"analyticRuleTemplateSpecName{idx}"] = f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',concat(variables('_solutionId'),'-ar-',variables('analyticRulecontentId{idx}')))]"

    main_tpl["variables"] = variables

    # Write back
    with open("mainTemplate.json", "w") as f:
        json.dump(main_tpl, f, indent=2)

    print(f"mainTemplate.json updated with {len(main_analytics)} analytics rule templates")
    print(f"Total resources: {len(new_resources)}")

if __name__ == "__main__":
    main()
