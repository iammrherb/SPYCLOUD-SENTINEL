# SpyCloud MCP Server — Identity Threat Intelligence

Model Context Protocol server exposing SpyCloud's 65.7B+ recaptured darknet records as tools, resources, and prompts for AI agents.

## Compatible Clients

| Client | Connection | Status |
|--------|-----------|--------|
| Microsoft Security Copilot | SSE plugin | ✅ Supported |
| Claude (Anthropic) | MCP connection | ✅ Supported |
| VS Code / GitHub Copilot | MCP extension | ✅ Supported |
| Copilot Studio | MCP connector | ✅ Supported |
| Any MCP client | SSE transport | ✅ Supported |

## Quick Start

```bash
# 1. Install dependencies
cd mcp-server
npm install

# 2. Set environment variables
export SPYCLOUD_API_KEY="your-enterprise-api-key"
export PORT=3001

# 3. Start server
npm start

# 4. Connect from any MCP client via SSE
# Endpoint: http://localhost:3001/sse
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SPYCLOUD_API_KEY` | Yes | SpyCloud Enterprise API key (from portal.spycloud.com) |
| `PORT` | No | Server port (default: 3001) |
| `SPYCLOUD_API_REGION` | No | `us` (default) or `eu` |
| `SPYCLOUD_INVESTIGATIONS_KEY` | No | Separate key for Investigations API (if different from enterprise) |
| `SPYCLOUD_SIP_KEY` | No | Separate key for SIP API |
| `SPYCLOUD_IDLINK_KEY` | No | Separate key for IdLink API |
| `SPYCLOUD_CAP_KEY` | No | Separate key for CAP API |

## Tools (20)

| # | Tool | API Product | Description |
|---|------|------------|-------------|
| 1 | `lookup_email_exposure` | Enterprise | Breach records by email |
| 2 | `lookup_domain_exposure` | Enterprise | Breach records by domain |
| 3 | `lookup_ip_exposure` | Enterprise | Breach records by IP |
| 4 | `lookup_username_exposure` | Enterprise | Breach records by username |
| 5 | `get_watchlist_records` | Enterprise | All watchlist exposures |
| 6 | `get_breach_catalog` | Enterprise | Breach source metadata |
| 7 | `get_breach_details` | Enterprise | Specific breach by ID |
| 8 | `list_watchlist_identifiers` | Enterprise | Monitored assets list |
| 9 | `get_compass_devices` | Compass | Compromised device inventory |
| 10 | `get_compass_device_detail` | Compass | Device forensics detail |
| 11 | `get_compass_applications` | Compass | Compromised app list |
| 12 | `get_stolen_cookies` | SIP | Stolen session cookies by domain |
| 13 | `investigate_email_deep` | Investigations | Deep OSINT by email |
| 14 | `investigate_machine` | Investigations | Deep device investigation |
| 15 | `investigate_social_handle` | Investigations | Social media OSINT |
| 16 | `get_identity_graph` | IdLink | Identity graph mapping |
| 17 | `get_exposure_stats` | Exposure Metrics | Aggregate statistics |
| 18 | `check_password_hash` | NIST | Password breach check |
| 19 | `check_consumer_exposure` | CAP | Consumer ATO check |
| 20 | (reserved) | -- | Future: remediation actions |

## Resources (3)

| URI | Description |
|-----|-------------|
| `spycloud://severity-model` | Severity 2/5/20/25 definitions and response SLAs |
| `spycloud://password-risk-model` | Hash type crackability assessment |
| `spycloud://mitre-mapping` | SpyCloud data → MITRE ATT&CK techniques |

## Prompts (6)

| Prompt | Description |
|--------|-------------|
| `investigate-user` | Full user investigation workflow |
| `investigate-device` | Device forensics workflow |
| `org-exposure-overview` | Organization-wide assessment |
| `threat-hunt` | Proactive threat hunting |
| `compliance-assessment` | Breach notification analysis |
| `executive-brief` | C-suite exposure summary |

## Deploy to Azure

### Option A: Azure App Service (Recommended)

```bash
# Create App Service
az webapp create --resource-group spycloud-sentinel \
  --plan spycloud-mcp-plan --name spycloud-mcp \
  --runtime "NODE:18-lts"

# Set API key from Key Vault
az webapp config appsettings set --resource-group spycloud-sentinel \
  --name spycloud-mcp \
  --settings SPYCLOUD_API_KEY=@Microsoft.KeyVault(SecretUri=https://kv-spycloud.vault.azure.net/secrets/spycloud-api-key)

# Deploy
az webapp deployment source config-local-git --resource-group spycloud-sentinel \
  --name spycloud-mcp
git remote add azure <deployment-url>
git push azure main
```

### Option B: Docker

```bash
docker build -t spycloud-mcp-server .
docker run -p 3001:3001 -e SPYCLOUD_API_KEY=your-key spycloud-mcp-server
```

## Connect to Security Copilot

1. Deploy the MCP server to Azure App Service
2. In Security Copilot → Sources → Custom → Add Plugin
3. Select **Security Copilot plugin** → Upload `copilot/SpyCloud_MCP_Plugin.yaml`
4. Or: Select **MCP** → Enter SSE endpoint URL: `https://spycloud-mcp.azurewebsites.net/sse`
5. Tools automatically appear as available skills
6. Add tools to the SCORCH agent via Agent Builder → Add Tool

## Connect to Claude Desktop

Add to your Claude MCP config (`~/.config/claude/mcp.json`):

```json
{
  "mcpServers": {
    "spycloud": {
      "url": "https://spycloud-mcp.azurewebsites.net/sse"
    }
  }
}
```

## License

MIT — See repository root LICENSE file.
