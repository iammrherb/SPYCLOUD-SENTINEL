// ═══════════════════════════════════════════════════════════════════
// SENTINEL GRAPH MCP TOOLS
// Purpose-built tools for Microsoft Sentinel Graph analysis
// Blast Radius, Path Discovery, Exposure Perimeter, AI Investigation
//
// Microsoft Sentinel Graph (GA Dec 2025) enables graph-based security
// analysis using GQL queries over security entity relationships.
// ═══════════════════════════════════════════════════════════════════

import { z } from "zod";

/**
 * Register Sentinel Graph tools on an MCP server instance.
 *
 * @param {McpServer} server - The MCP server instance
 * @param {object} config - Configuration with sentinel credentials
 */
export function registerGraphTools(server, config) {
  const {
    tenantId,
    subscriptionId,
    resourceGroup,
    workspaceName,
  } = config.sentinel || {};

  /**
   * Acquire an OAuth token for a given scope using client credentials.
   * Uses AZURE_CLIENT_ID and AZURE_CLIENT_SECRET from environment.
   *
   * @param {string} scope - The OAuth scope to request (e.g., "https://management.azure.com/.default")
   * @returns {string|null} Access token or null on failure
   */
  async function getTokenForScope(scope) {
    const clientId = process.env.AZURE_CLIENT_ID || "";
    const clientSecret = process.env.AZURE_CLIENT_SECRET || "";

    if (!tenantId || !clientId || !clientSecret) {
      return null;
    }

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      scope,
    });

    try {
      const resp = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!resp.ok) {
        const errText = await resp.text();
        console.error(`Token request failed: ${resp.status} ${errText}`);
        return null;
      }
      const data = await resp.json();
      return data.access_token;
    } catch (err) {
      console.error(`Token request error: ${err.message}`);
      return null;
    }
  }

  /**
   * Execute a GQL query against the Sentinel Graph API.
   *
   * @param {string} gql - Graph Query Language query
   * @returns {object} Query results or error
   */
  async function queryGraph(gql) {
    const token = await getTokenForScope("https://management.azure.com/.default");
    if (!token) {
      return {
        error:
          "Authentication failed — configure AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, " +
          "and sentinel.tenantId in MCP config",
      };
    }

    if (!subscriptionId || !resourceGroup || !workspaceName) {
      return {
        error:
          "Sentinel workspace not configured — set sentinel.subscriptionId, " +
          "sentinel.resourceGroup, and sentinel.workspaceName in MCP config",
      };
    }

    const baseUrl =
      `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}` +
      `/resourceGroups/${encodeURIComponent(resourceGroup)}` +
      `/providers/Microsoft.OperationalInsights/workspaces/${encodeURIComponent(workspaceName)}` +
      `/providers/Microsoft.SecurityInsights/graph/query` +
      `?api-version=2024-10-01-preview`;

    try {
      const resp = await fetch(baseUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query: gql }),
      });
      if (!resp.ok) {
        const errText = await resp.text();
        return {
          error: `Sentinel Graph API returned ${resp.status}: ${errText.substring(0, 500)}`,
        };
      }
      return await resp.json();
    } catch (err) {
      return { error: `Graph query failed: ${err.message}` };
    }
  }

  /**
   * Execute a KQL query against the Log Analytics workspace.
   *
   * @param {string} kql - Kusto Query Language query
   * @returns {object} Query results or error
   */
  async function queryLogAnalytics(kql) {
    const token = await getTokenForScope("https://api.loganalytics.io/.default");
    if (!token) {
      return { error: "Authentication failed" };
    }

    const workspaceId = process.env.LOG_ANALYTICS_WORKSPACE_ID || "";
    if (!workspaceId) {
      return { error: "LOG_ANALYTICS_WORKSPACE_ID not configured" };
    }

    try {
      const resp = await fetch(
        `https://api.loganalytics.io/v1/workspaces/${encodeURIComponent(workspaceId)}/query`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ query: kql }),
        }
      );
      if (!resp.ok) {
        return { error: `Log Analytics returned ${resp.status}` };
      }
      const data = await resp.json();
      const tables = data.tables || [];
      if (!tables.length) return { results: [] };

      const columns = tables[0].columns.map((c) => c.name);
      const rows = tables[0].rows.map((row) =>
        Object.fromEntries(columns.map((col, i) => [col, row[i]]))
      );
      return { results: rows };
    } catch (err) {
      return { error: `Log Analytics query failed: ${err.message}` };
    }
  }

  // ─── Blast Radius Analysis ────────────────────────────────────

  server.tool(
    "find_blast_radius",
    "Analyze the blast radius from a compromised entity (user, device, IP). " +
      "Maps all directly and transitively connected entities that could be impacted " +
      "by the compromise. Uses Microsoft Sentinel Graph (GQL).",
    {
      entity: z
        .string()
        .describe("Entity to analyze — email, hostname, IP address, or UPN"),
      entity_type: z
        .enum(["user", "device", "ip"])
        .describe("Type of the entity"),
      depth: z
        .number()
        .min(1)
        .max(5)
        .default(3)
        .describe("Graph traversal depth (1-5, default 3)"),
    },
    async ({ entity, entity_type, depth }) => {
      // First try Sentinel Graph API
      const gql = `
        MATCH path = (source:${entity_type} {name: '${entity.replace(/'/g, "\\'")}'})-[*1..${depth}]->(target)
        RETURN path, target.name AS impacted_entity, target.type AS entity_type,
               length(path) AS distance
        ORDER BY distance ASC
        LIMIT 50
      `;
      const graphResult = await queryGraph(gql);

      // Fallback: use KQL to build blast radius from SpyCloud + SigninLogs
      if (graphResult.error) {
        const kqlQuery = entity_type === "user"
          ? `
            let targetUser = "${entity.replace(/"/g, '\\"')}";
            let exposedDevices = SpyCloudBreachWatchlist_CL
              | where email_s =~ targetUser
              | where isnotempty(infected_machine_id_s)
              | distinct infected_machine_id_s;
            let accessedApps = SigninLogs
              | where TimeGenerated >= ago(30d)
              | where UserPrincipalName =~ targetUser
              | distinct AppDisplayName;
            let accessedIPs = SigninLogs
              | where TimeGenerated >= ago(30d)
              | where UserPrincipalName =~ targetUser
              | distinct IPAddress;
            union
              (exposedDevices | project Entity=infected_machine_id_s, Type="device"),
              (accessedApps | project Entity=AppDisplayName, Type="application"),
              (accessedIPs | project Entity=IPAddress, Type="ip")
            | take 50
          `
          : `
            let targetEntity = "${entity.replace(/"/g, '\\"')}";
            SpyCloudBreachWatchlist_CL
            | where infected_machine_id_s == targetEntity or ip_address_s == targetEntity
            | summarize
                Users=make_set(email_s),
                Domains=make_set(target_domain_s)
            | mv-expand Users
            | project Entity=tostring(Users), Type="user"
            | take 50
          `;

        const kqlResult = await queryLogAnalytics(kqlQuery);
        if (kqlResult.error) {
          return {
            content: [
              {
                type: "text",
                text:
                  `## Blast Radius Analysis for ${entity}\n\n` +
                  `Sentinel Graph: ${graphResult.error}\n` +
                  `KQL Fallback: ${kqlResult.error}\n\n` +
                  `Configure Sentinel Graph or Log Analytics credentials to enable analysis.`,
              },
            ],
          };
        }

        const entities = kqlResult.results || [];
        let summary = `## Blast Radius Analysis for ${entity}\n\n`;
        summary += `*Source: KQL fallback (Sentinel Graph not available)*\n\n`;
        summary += `| Entity | Type |\n|--------|------|\n`;
        for (const e of entities) {
          summary += `| ${e.Entity} | ${e.Type} |\n`;
        }
        summary += `\n**Total impacted entities:** ${entities.length}\n`;
        return { content: [{ type: "text", text: summary }] };
      }

      // Format Sentinel Graph results
      const entities = graphResult.results || [];
      let summary = `## Blast Radius Analysis for ${entity}\n\n`;
      summary += `| Entity | Type | Distance |\n|--------|------|----------|\n`;
      for (const e of entities) {
        summary += `| ${e.impacted_entity} | ${e.entity_type} | ${e.distance} hops |\n`;
      }
      summary += `\n**Total impacted entities:** ${entities.length}\n`;
      const maxDist = entities.length
        ? Math.max(...entities.map((e) => e.distance))
        : 0;
      summary += `**Max depth reached:** ${maxDist}\n`;

      return { content: [{ type: "text", text: summary }] };
    }
  );

  // ─── Path Discovery ───────────────────────────────────────────

  server.tool(
    "find_walkable_paths",
    "Discover all attack paths between two entities in the Sentinel security graph. " +
      "Identifies how an attacker could move from a compromised asset to a high-value target. " +
      "Uses Microsoft Sentinel Graph (GQL) with KQL fallback.",
    {
      source: z
        .string()
        .describe("Source entity (e.g., compromised user email)"),
      target: z
        .string()
        .describe("Target entity (e.g., admin account, key vault)"),
      max_hops: z
        .number()
        .min(1)
        .max(6)
        .default(4)
        .describe("Maximum path length (1-6)"),
    },
    async ({ source, target, max_hops }) => {
      const gql = `
        MATCH path = (s {name: '${source.replace(/'/g, "\\'")}'})-[*1..${max_hops}]->(t {name: '${target.replace(/'/g, "\\'")}' })
        RETURN path, length(path) AS path_length,
               [node IN nodes(path) | node.name] AS path_nodes
        ORDER BY path_length ASC
        LIMIT 10
      `;
      const result = await queryGraph(gql);

      if (result.error) {
        // KQL fallback: find shared assets between source and target
        const kqlQuery = `
          let sourceUser = "${source.replace(/"/g, '\\"')}";
          let targetUser = "${target.replace(/"/g, '\\"')}";
          let sourceDevices = SpyCloudBreachWatchlist_CL
            | where email_s =~ sourceUser
            | distinct infected_machine_id_s;
          let targetDevices = SpyCloudBreachWatchlist_CL
            | where email_s =~ targetUser
            | distinct infected_machine_id_s;
          let sharedDevices = sourceDevices | join kind=inner targetDevices on infected_machine_id_s;
          let sourceApps = SigninLogs
            | where TimeGenerated >= ago(30d)
            | where UserPrincipalName =~ sourceUser
            | distinct AppDisplayName;
          let targetApps = SigninLogs
            | where TimeGenerated >= ago(30d)
            | where UserPrincipalName =~ targetUser
            | distinct AppDisplayName;
          let sharedApps = sourceApps | join kind=inner targetApps on AppDisplayName;
          union
            (sharedDevices | project SharedAsset=infected_machine_id_s, Type="device"),
            (sharedApps | project SharedAsset=AppDisplayName, Type="application")
        `;

        const kqlResult = await queryLogAnalytics(kqlQuery);
        let summary = `## Path Discovery: ${source} → ${target}\n\n`;
        summary += `*Source: KQL fallback (Sentinel Graph not available)*\n\n`;

        if (kqlResult.error) {
          summary += `Could not determine paths: ${kqlResult.error}\n`;
        } else {
          const shared = kqlResult.results || [];
          if (shared.length === 0) {
            summary += `No shared assets found between source and target.\n`;
          } else {
            summary += `Found **${shared.length}** shared assets (potential pivot points):\n\n`;
            summary += `| Shared Asset | Type |\n|-------------|------|\n`;
            for (const s of shared) {
              summary += `| ${s.SharedAsset} | ${s.Type} |\n`;
            }
          }
        }
        return { content: [{ type: "text", text: summary }] };
      }

      const paths = result.results || [];
      let summary = `## Path Discovery: ${source} → ${target}\n\n`;
      if (paths.length === 0) {
        summary += `No paths found within ${max_hops} hops.\n`;
      } else {
        summary += `Found **${paths.length}** paths:\n\n`;
        for (let i = 0; i < paths.length; i++) {
          const p = paths[i];
          summary += `### Path ${i + 1} (${p.path_length} hops)\n`;
          summary += `${(p.path_nodes || []).join(" → ")}\n\n`;
        }
      }

      return { content: [{ type: "text", text: summary }] };
    }
  );

  // ─── Exposure Perimeter ───────────────────────────────────────

  server.tool(
    "exposure_perimeter",
    "Map the exposure perimeter — all external-facing assets and entry points " +
      "connected to an entity. Identifies attack surface from the security graph. " +
      "Uses Microsoft Sentinel Graph (GQL) with KQL fallback.",
    {
      entity: z.string().describe("Entity to map exposure perimeter for"),
      include_external: z
        .boolean()
        .default(true)
        .describe("Include external IPs and domains"),
    },
    async ({ entity, include_external }) => {
      const externalFilter = include_external
        ? ""
        : "WHERE target.is_internal = true";

      const gql = `
        MATCH (source {name: '${entity.replace(/'/g, "\\'")}'})-[r]->(target)
        ${externalFilter}
        RETURN target.name AS asset, target.type AS asset_type,
               type(r) AS relationship, r.last_seen AS last_activity
        ORDER BY r.last_seen DESC
        LIMIT 100
      `;
      const result = await queryGraph(gql);

      if (result.error) {
        // KQL fallback: build exposure from SpyCloud + SigninLogs
        const kqlQuery = `
          let targetEntity = "${entity.replace(/"/g, '\\"')}";
          let spycloudAssets = SpyCloudBreachWatchlist_CL
            | where email_s =~ targetEntity
            | summarize
                TargetDomains=make_set(target_domain_s),
                InfectedDevices=make_set(infected_machine_id_s),
                IPs=make_set(ip_address_s)
            | mv-expand TargetDomains
            | project Asset=tostring(TargetDomains), Type="domain", Source="SpyCloud";
          let signinAssets = SigninLogs
            | where TimeGenerated >= ago(30d)
            | where UserPrincipalName =~ targetEntity
            | summarize LastSeen=max(TimeGenerated) by AppDisplayName, IPAddress
            | project Asset=AppDisplayName, Type="application", Source="SigninLogs";
          union spycloudAssets, signinAssets
          | take 100
        `;

        const kqlResult = await queryLogAnalytics(kqlQuery);
        let summary = `## Exposure Perimeter for ${entity}\n\n`;
        summary += `*Source: KQL fallback (Sentinel Graph not available)*\n\n`;

        if (kqlResult.error) {
          summary += `Could not map perimeter: ${kqlResult.error}\n`;
        } else {
          const assets = kqlResult.results || [];
          summary += `| Asset | Type | Source |\n|-------|------|--------|\n`;
          for (const a of assets) {
            summary += `| ${a.Asset} | ${a.Type} | ${a.Source} |\n`;
          }
          summary += `\n**Total exposed assets:** ${assets.length}\n`;
        }
        return { content: [{ type: "text", text: summary }] };
      }

      const assets = result.results || [];
      let summary = `## Exposure Perimeter for ${entity}\n\n`;
      summary += `| Asset | Type | Relationship | Last Activity |\n`;
      summary += `|-------|------|-------------|---------------|\n`;
      for (const a of assets) {
        summary += `| ${a.asset} | ${a.asset_type} | ${a.relationship} | ${a.last_activity || "N/A"} |\n`;
      }
      summary += `\n**Total exposed assets:** ${assets.length}\n`;

      return { content: [{ type: "text", text: summary }] };
    }
  );

  // ─── Graph Materialization Status ─────────────────────────────

  server.tool(
    "graph_materialization_status",
    "Check the status of Sentinel Graph materialization jobs. " +
      "Graph materialization builds the entity relationship graph from raw logs. " +
      "Required for blast radius, path discovery, and exposure perimeter tools.",
    {},
    async () => {
      if (!subscriptionId || !resourceGroup || !workspaceName) {
        return {
          content: [
            {
              type: "text",
              text:
                "## Graph Materialization Status\n\n" +
                "Sentinel workspace not configured. Set sentinel.subscriptionId, " +
                "sentinel.resourceGroup, and sentinel.workspaceName in MCP config.\n\n" +
                "### Setup Instructions\n" +
                "1. Enable Sentinel Graph in your workspace (Settings → Preview Features)\n" +
                "2. Create a materialization job via the Azure Portal or API\n" +
                "3. Configure the MCP server with your workspace details",
            },
          ],
        };
      }

      const token = await getTokenForScope("https://management.azure.com/.default");
      if (!token) {
        return {
          content: [
            {
              type: "text",
              text: "Authentication failed — configure Azure credentials.",
            },
          ],
        };
      }

      const url =
        `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}` +
        `/resourceGroups/${encodeURIComponent(resourceGroup)}` +
        `/providers/Microsoft.OperationalInsights/workspaces/${encodeURIComponent(workspaceName)}` +
        `/providers/Microsoft.SecurityInsights/graph/materializationJobs` +
        `?api-version=2024-10-01-preview`;

      try {
        const resp = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!resp.ok) {
          return {
            content: [
              {
                type: "text",
                text: `Graph API returned ${resp.status}. Ensure Sentinel Graph is enabled.`,
              },
            ],
          };
        }
        const data = await resp.json();
        const jobs = data.value || [];

        let summary = `## Graph Materialization Status\n\n`;
        if (jobs.length === 0) {
          summary +=
            "No materialization jobs found. Create one to enable graph queries.\n\n";
          summary += "### How to Create a Materialization Job\n";
          summary += "```bash\n";
          summary += "az rest --method POST \\\n";
          summary += `  --url "https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}/providers/Microsoft.SecurityInsights/graph/materializationJobs?api-version=2024-10-01-preview" \\\n`;
          summary += '  --body \'{"properties": {"schedule": {"frequency": "Daily"}}}\'\n';
          summary += "```\n";
        } else {
          summary += `| Job ID | Status | Last Run | Schedule |\n`;
          summary += `|--------|--------|----------|----------|\n`;
          for (const job of jobs) {
            const props = job.properties || {};
            summary += `| ${job.name || "N/A"} | ${props.provisioningState || "Unknown"} | ${props.lastRunTime || "Never"} | ${props.schedule?.frequency || "N/A"} |\n`;
          }
        }

        return { content: [{ type: "text", text: summary }] };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Failed to check materialization status: ${err.message}`,
            },
          ],
        };
      }
    }
  );

  // ─── AI-Powered Investigation via MCP ─────────────────────────

  server.tool(
    "ai_investigate_entity",
    "Trigger an AI-powered investigation through the SpyCloud AI Engine. " +
      "Combines SpyCloud breach data, Sentinel telemetry, and GPT-4o analysis " +
      "for a comprehensive investigation report.",
    {
      email: z.string().email().describe("Email address to investigate"),
    },
    async ({ email }) => {
      const aiEngineUrl = process.env.SPYCLOUD_AI_ENGINE_URL || "";
      const aiEngineKey = process.env.SPYCLOUD_AI_ENGINE_KEY || "";

      if (!aiEngineUrl) {
        return {
          content: [
            {
              type: "text",
              text:
                "## AI Investigation\n\n" +
                "AI Engine not configured. Set these environment variables:\n" +
                "- `SPYCLOUD_AI_ENGINE_URL` — URL of the SpyCloud AI Engine Function App\n" +
                "- `SPYCLOUD_AI_ENGINE_KEY` — Function key for authentication\n\n" +
                "Deploy the AI Engine from `functions/SpyCloudAIEngine/` first.",
            },
          ],
        };
      }

      try {
        const resp = await fetch(`${aiEngineUrl}/api/ai/investigate`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-functions-key": aiEngineKey,
          },
          body: JSON.stringify({ email }),
        });

        if (!resp.ok) {
          const errText = await resp.text();
          return {
            content: [
              {
                type: "text",
                text: `AI investigation failed: HTTP ${resp.status}\n${errText.substring(0, 500)}`,
              },
            ],
          };
        }

        const data = await resp.json();
        let output = data.aiReport || "";

        // Add metadata footer
        output += `\n\n---\n`;
        output += `*Investigation timestamp: ${data.timestamp || "N/A"}*\n`;
        output += `*Data sources: SpyCloud=${data.dataSourcesQueried?.spycloud}, `;
        output += `Sentinel=${data.dataSourcesQueried?.sentinel}, `;
        output += `Graph=${data.dataSourcesQueried?.graph}*\n`;

        return { content: [{ type: "text", text: output }] };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `AI investigation failed: ${err.message}`,
            },
          ],
        };
      }
    }
  );

  // ─── SpyCloud Exposure Summary (KQL) ──────────────────────────

  server.tool(
    "spycloud_exposure_summary",
    "Get a summary of SpyCloud exposure data from the Sentinel workspace. " +
      "Provides organization-level metrics including severity distribution, " +
      "affected users, infected devices, and breach sources.",
    {
      domain: z
        .string()
        .optional()
        .describe("Filter by domain (optional, shows all if omitted)"),
      days: z
        .number()
        .min(1)
        .max(365)
        .default(30)
        .describe("Lookback period in days"),
    },
    async ({ domain, days }) => {
      const domainFilter = domain
        ? `| where domain_s =~ "${domain.replace(/"/g, '\\"')}"`
        : "";

      const kql = `
        SpyCloudBreachWatchlist_CL
        | where TimeGenerated >= ago(${days}d)
        ${domainFilter}
        | summarize
            TotalExposures=count(),
            CriticalExposures=countif(severity_d >= 20),
            PlaintextCredentials=countif(isnotempty(password_plaintext_s)),
            UniqueUsers=dcount(email_s),
            UniqueDevices=dcount(infected_machine_id_s),
            BreachSources=dcount(source_id_d),
            Sev25=countif(severity_d == 25),
            Sev20=countif(severity_d == 20),
            Sev5=countif(severity_d == 5),
            Sev2=countif(severity_d == 2)
      `;

      const result = await queryLogAnalytics(kql);
      if (result.error) {
        return {
          content: [
            {
              type: "text",
              text: `Failed to query exposure data: ${result.error}`,
            },
          ],
        };
      }

      const data = (result.results || [])[0] || {};
      let summary = `## SpyCloud Exposure Summary`;
      if (domain) summary += ` — ${domain}`;
      summary += ` (${days} days)\n\n`;

      summary += `| Metric | Value |\n|--------|-------|\n`;
      summary += `| Total Exposures | **${data.TotalExposures || 0}** |\n`;
      summary += `| Critical (Sev >= 20) | **${data.CriticalExposures || 0}** |\n`;
      summary += `| Plaintext Passwords | **${data.PlaintextCredentials || 0}** |\n`;
      summary += `| Unique Users | **${data.UniqueUsers || 0}** |\n`;
      summary += `| Infected Devices | **${data.UniqueDevices || 0}** |\n`;
      summary += `| Breach Sources | **${data.BreachSources || 0}** |\n`;
      summary += `\n### Severity Distribution\n`;
      summary += `| Severity | Count | Description |\n|----------|-------|-------------|\n`;
      summary += `| 25 | ${data.Sev25 || 0} | Critical — Infostealer + session cookies |\n`;
      summary += `| 20 | ${data.Sev20 || 0} | High — Infostealer credential |\n`;
      summary += `| 5 | ${data.Sev5 || 0} | Standard — Breach + PII |\n`;
      summary += `| 2 | ${data.Sev2 || 0} | Low — Breach credential pair |\n`;

      return { content: [{ type: "text", text: summary }] };
    }
  );
}
