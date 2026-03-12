#!/usr/bin/env python3
"""
Add notebook content templates to mainTemplate.json.
Sentinel notebooks are deployed as savedSearches with notebook metadata,
referenced via contentTemplates in the Content Hub solution.
"""

import json
import base64

NOTEBOOKS = [
    {
        "file": "notebooks/SpyCloud-Incident-Triage.ipynb",
        "id": "SpyCloud-Incident-Triage",
        "name": "SpyCloud Incident Triage Notebook",
        "description": "Interactive Jupyter notebook for triaging SpyCloud credential exposure incidents. Queries all 14 SpyCloud tables, correlates with Entra ID and MDE data, and generates investigation timelines with severity scoring."
    },
    {
        "file": "notebooks/SpyCloud-Threat-Landscape.ipynb",
        "id": "SpyCloud-Threat-Landscape",
        "name": "SpyCloud Threat Landscape Analysis",
        "description": "Analytical notebook for assessing organizational threat landscape using SpyCloud darknet intelligence. Generates executive-level breach exposure summaries, trend analysis, and risk heat maps."
    },
    {
        "file": "notebooks/SpyCloud-ThreatHunting.ipynb",
        "id": "SpyCloud-ThreatHunting",
        "name": "SpyCloud Threat Hunting Notebook",
        "description": "Advanced threat hunting notebook leveraging SpyCloud data for proactive investigation. Includes credential reuse detection, infostealer infection tracking, and cross-source correlation hunts."
    }
]

def main():
    with open("mainTemplate.json") as f:
        tpl = json.load(f)

    variables = tpl.get("variables", {})
    resources = tpl["resources"]

    # Find insert position (before Solution resources)
    insert_pos = len(resources)
    for i, r in enumerate(resources):
        if r.get("properties", {}).get("contentKind") == "Solution":
            insert_pos = i
            break

    notebook_templates = []
    for idx, nb_info in enumerate(NOTEBOOKS, 1):
        var_prefix = f"notebook{idx}"
        content_id = nb_info["id"]

        # Add variables
        variables[f"notebookVersion{idx}"] = "10.0.0"
        variables[f"notebookContentId{idx}"] = content_id
        variables[f"_notebookContentId{idx}"] = f"[variables('notebookContentId{idx}')]"
        variables[f"notebookTemplateSpecName{idx}"] = f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',concat(variables('_solutionId'),'-nb-',variables('notebookContentId{idx}')))]"

        # Read the notebook file and base64-encode it
        with open(nb_info["file"], "r") as f:
            nb_content = f.read()

        # Create content template for the notebook
        content_template = {
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('notebookTemplateSpecName{idx}')]",
            "location": "[parameters('workspace-location')]",
            "dependsOn": [
                f"[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
            ],
            "properties": {
                "description": f"{nb_info['name']} Notebook with template",
                "mainTemplate": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": f"[variables('notebookVersion{idx}')]",
                    "parameters": {},
                    "variables": {},
                    "resources": [
                        {
                            "type": "Microsoft.SecurityInsights/notebookTemplates",
                            "name": f"[variables('notebookContentId{idx}')]",
                            "apiVersion": "2023-06-01-preview",
                            "location": "[parameters('workspace-location')]",
                            "properties": {
                                "displayName": nb_info["name"],
                                "description": nb_info["description"],
                                "notebookContent": json.loads(nb_content),
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
                                },
                                "mainFileName": nb_info["file"].split("/")[-1],
                                "isDefault": False
                            }
                        },
                        {
                            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                            "apiVersion": "2022-01-01-preview",
                            "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',concat('Notebook-', last(split(variables('notebookContentId{idx}'),'/'))))]",
                            "properties": {
                                "description": f"SpyCloud Identity Threat Protection Notebook {idx}",
                                "parentId": f"[variables('notebookContentId{idx}')]",
                                "contentId": f"[variables('_notebookContentId{idx}')]",
                                "kind": "Notebook",
                                "version": f"[variables('notebookVersion{idx}')]",
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
                    ]
                },
                "contentId": f"[variables('_notebookContentId{idx}')]",
                "contentKind": "Notebook",
                "displayName": nb_info["name"],
                "contentProductId": f"[concat(take(variables('_solutionId'),50),'-','nb','-', uniqueString(concat(variables('_solutionId'),'-','Notebook','-',variables('_notebookContentId{idx}'),'-', variables('notebookVersion{idx}'))))]",
                "id": f"[concat(take(variables('_solutionId'),50),'-','nb','-', uniqueString(concat(variables('_solutionId'),'-','Notebook','-',variables('_notebookContentId{idx}'),'-', variables('notebookVersion{idx}'))))]",
                "version": f"[variables('notebookVersion{idx}')]"
            }
        }

        notebook_templates.append(content_template)

    # Insert notebook templates
    for i, nt in enumerate(notebook_templates):
        resources.insert(insert_pos + i, nt)

    tpl["variables"] = variables
    tpl["resources"] = resources

    with open("mainTemplate.json", "w") as f:
        json.dump(tpl, f, indent=2)

    print(f"Added {len(notebook_templates)} notebook templates to mainTemplate.json")
    print(f"Total resources: {len(resources)}")

if __name__ == "__main__":
    main()
