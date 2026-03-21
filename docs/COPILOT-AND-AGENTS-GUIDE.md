# SpyCloud Identity Exposure Intelligence for Sentinel — Copilot and Agents Guide

> **Version 2.0** | Complete guide to Security Copilot integration, SCORCH Agent, and MCP tools

## Overview

The SpyCloud Sentinel solution integrates with Microsoft Security Copilot through four complementary interfaces:

| Component | Type | Skills | Purpose |
|-----------|------|--------|---------|
| **KQL Plugin** | Copilot Plugin | 93 | Direct Sentinel table queries via natural language |
| **API Plugin** | Copilot Plugin | 13 | Real-time SpyCloud API lookups |
| **SCORCH Agent** | Autonomous Agent | 27 sub-agents | AI-powered investigation orchestration |
| **MCP Plugin** | MCP Server | 15 tools | Graph analysis, blast radius, path discovery |

## KQL Plugin (SpyCloud_Plugin.yaml)

### What It Does

Enables Security Copilot to query all 14 SpyCloud custom log tables using natural language. Copilot translates user questions into KQL queries automatically.

### Setup

1. Navigate to Security Copilot > Settings > Plugins
2. Click "Add Plugin" > "Upload from file"
3. Upload `copilot/SpyCloud_Plugin.yaml`
4. Configure the Sentinel workspace connection

### Example Prompts

```
"Show me all exposed credentials with severity 25 in the last 7 days"
"Which users have plaintext passwords in SpyCloud data?"
"What are the top 10 most-exposed email domains?"
"Show infostealer infections from the last 30 days with device details"
"How many unique users were affected by breach source 12345?"
```

### Skill Categories

| Category | Count | Description |
|----------|-------|-------------|
| Breach Watchlist | 15 | Query exposure records, severity filters |
| Breach Catalog | 8 | Search breach sources, metadata |
| Compass | 12 | Device forensics, malware attribution |
| SIP | 10 | Session cookies, token theft |
| Investigations | 8 | Deep threat hunting |
| IdLink | 10 | Identity correlation, graph analysis |
| CAP | 8 | Credential access monitoring |
| Enrichment Audit | 7 | Remediation history, action logs |
| Health Check | 5 | Ingestion status, connector health |
| Cross-Table | 10 | Multi-table correlation queries |

---

## API Plugin (SpyCloud_API_Plugin.yaml)

### What It Does

Performs real-time lookups against the SpyCloud API directly from Security Copilot. Unlike the KQL Plugin which queries ingested data, this queries the live SpyCloud darknet intelligence database.

### Setup

1. Upload `copilot/SpyCloud_API_Plugin.yaml` to Security Copilot
2. Upload `copilot/SpyCloud_API_Plugin_OpenAPI.yaml` as the OpenAPI spec
3. Configure the API key in plugin settings

### Available Operations

| Operation | Endpoint | Description |
|-----------|----------|-------------|
| Lookup Email | `/breach/data/emails/{email}` | Full exposure history for email |
| Lookup Domain | `/breach/data/watchlist` | All exposures for a domain |
| Breach Catalog | `/breach/catalog/{id}` | Breach source details |
| Compass Devices | `/compass/data/devices` | Infected device lookup |
| SIP Cookies | `/sip/data/cookies` | Stolen session cookies |
| Investigations | `/investigations/search` | Deep investigation queries |

---

## SCORCH Agent (SpyCloud_Agent.yaml)

### What It Does

The SCORCH (Security Orchestration, Response, and Comprehensive Handling) Agent is an autonomous AI-powered investigation engine. It receives a natural language investigation request and orchestrates 27 specialized sub-agents to produce comprehensive threat analysis.

### Setup

1. Upload `copilot/SpyCloud_Agent.yaml` to Security Copilot
2. Upload `copilot/SecurityCopilotAgent.json` as the agent manifest
3. Configure the AI Engine Function App URL in agent settings
4. Ensure the AI Engine Function App is deployed and healthy

### Sub-Agent Roster

| Sub-Agent | Purpose |
|-----------|---------|
| BreachAnalysis | Analyze breach records and exposure patterns |
| BreachCatalog | Research breach source metadata and timeline |
| CompassDevice | Investigate infected device forensics |
| CompassApplication | Analyze compromised applications and browsers |
| SipCookies | Investigate stolen session cookies and tokens |
| InvestigationDeep | Deep-dive investigation across all data sources |
| IdLinkCorrelation | Map identity relationships across exposures |
| CAPMonitor | Monitor credential access patterns |
| ExposureTimeline | Build chronological exposure timeline |
| SeverityAssessment | Evaluate risk based on severity model |
| PasswordAnalysis | Analyze password types and reuse patterns |
| MalwareAttribution | Identify malware families and TTPs |
| GeoAnalysis | Geographic analysis of infections and access |
| EntraCorrelation | Correlate with Entra ID sign-in data |
| DefenderCorrelation | Correlate with MDE device events |
| NetworkAnalysis | Analyze IP addresses and network indicators |
| DomainIntelligence | Research target domains and infrastructure |
| ThreatActorProfiling | Profile potential threat actors |
| BlastRadiusMapping | Map the full blast radius of exposure |
| RemediationPlanner | Generate prioritized remediation plan |
| ComplianceAssessor | Assess regulatory notification requirements |
| ExecutiveReporter | Generate board-level executive summary |
| IncidentResponder | Execute automated response actions |
| ThreatHunter | Proactive threat hunting across environment |
| ForensicCollector | Collect and preserve forensic evidence |
| PurviewClassifier | Classify PII and apply sensitivity labels |
| PurviewDLPAnalyzer | Analyze DLP policy status and gaps |

### Example Investigation Prompts

```
"Investigate user@company.com for credential exposure and recommend remediation"
"Generate an executive report on our organization's exposure over the last 90 days"
"Perform threat research on breach source 54321 including malware attribution"
"Assess our GDPR compliance posture for recent SpyCloud exposures"
"Map the blast radius for the infostealer infection on device DESKTOP-ABC123"
```

---

## MCP Plugin (mcp-server/)

### What It Does

The Model Context Protocol (MCP) server provides advanced graph analysis capabilities for investigating identity exposure relationships. It materializes SpyCloud data into a graph structure and provides tools for blast radius analysis, path discovery, and exposure perimeter mapping.

### Setup

1. Deploy the MCP server:
   ```bash
   cd mcp-server/
   docker build -t spycloud-mcp .
   docker run -p 3001:3001 --env-file .env spycloud-mcp
   ```

2. Configure environment variables:
   ```
   SENTINEL_WORKSPACE_ID=your-workspace-id
   SENTINEL_WORKSPACE_KEY=your-workspace-key
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   ```

3. Register in Security Copilot:
   - Upload `copilot/SpyCloud_MCP_Plugin.yaml`
   - Set the MCP server URL

### Graph Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| `blast_radius` | Find all entities connected to a compromised identity | "What is the blast radius of user@company.com?" |
| `path_discovery` | Find shortest path between two entities in the graph | "How is device A connected to breach B?" |
| `exposure_perimeter` | Map the attack surface for a domain or user group | "Show the exposure perimeter for company.com" |
| `identity_cluster` | Group related identities by shared attributes | "Which users share the same infected device?" |
| `temporal_analysis` | Analyze exposure patterns over time | "Show the infection timeline for the last 90 days" |

### Graph Query Language (GQL)

The MCP server supports GQL queries for advanced graph analysis:

```gql
// Find all users exposed in the same breach as a specific user
MATCH (u:User {email: "target@company.com"})-[:EXPOSED_IN]->(b:Breach)<-[:EXPOSED_IN]-(other:User)
RETURN other.email, b.title, b.severity

// Find lateral movement paths through shared devices
MATCH path = (u1:User)-[:INFECTED_ON]->(d:Device)<-[:INFECTED_ON]-(u2:User)
WHERE u1.email = "source@company.com" AND u1 <> u2
RETURN path

// Calculate exposure perimeter
MATCH (u:User {domain: "company.com"})-[r]->(target)
RETURN type(r) as relationship, count(target) as count, labels(target) as target_type
ORDER BY count DESC
```

---

## Publishing Agent to Defender Portal

After installing the SCORCH Agent in Security Copilot, it becomes available in the Microsoft Defender portal:

1. **Verify Installation:** Security Copilot > Settings > Agents > Verify "SCORCH" appears
2. **Defender Portal Access:** Go to security.microsoft.com > Copilot
3. **Agent Availability:** The SCORCH agent skills appear automatically in the Defender Copilot sidebar
4. **Custom Prompts:** Create saved prompts for common investigation workflows
5. **Automation:** Connect agent skills to automation rules for hands-free investigation

See [DEFENDER-PORTAL-PUBLISHING-GUIDE.md](DEFENDER-PORTAL-PUBLISHING-GUIDE.md) for detailed publishing instructions.

---

## Promptbooks

Pre-built investigation workflows for Security Copilot:

| Promptbook | File | Steps | Purpose |
|------------|------|-------|---------|
| Incident Triage | `SpyCloud_IncidentTriage.yaml` | 5 | Rapid incident classification and initial response |
| User Investigation | `SpyCloud_UserInvestigation.yaml` | 7 | Complete user exposure history and risk assessment |
| Threat Hunt | `SpyCloud_ThreatHunt.yaml` | 6 | Proactive hunting for unremediated exposures |
| Org Exposure | `SpyCloud_OrgExposureOverview.yaml` | 5 | Executive-level organization risk overview |
| Compliance | `SpyCloud_ComplianceAssessment.yaml` | 6 | Regulatory compliance assessment |

### Using Promptbooks

1. Navigate to Security Copilot > Promptbooks
2. Click "Import" and select the YAML file from `copilot/promptbooks/`
3. Run the promptbook and provide the required inputs (email, domain, incident ID)

---

## Jupyter Notebook Integration

### VSCode Configuration

The repository includes VSCode configuration for Jupyter notebook development:

- `.vscode/settings.json` - Python interpreter, Jupyter server settings
- `.vscode/extensions.json` - Recommended extensions (Jupyter, Python, Azure)

### Notebook Catalog

| Notebook | Purpose | Key Features |
|----------|---------|-------------|
| `SpyCloud-ThreatHunting.ipynb` | Proactive threat hunting | Multi-table correlation, anomaly detection |
| `SpyCloud-Incident-Triage.ipynb` | Incident investigation | Timeline visualization, entity mapping |
| `SpyCloud-Threat-Landscape.ipynb` | Threat landscape analysis | Trend analysis, breach source profiling |
| `SpyCloud-Graph-Investigation.ipynb` | Graph-based investigation | NetworkX visualization, path analysis |
| `SpyCloud-Simulated-Scenarios.ipynb` | Training and testing | Simulated breach scenarios, response validation |

### Setup Instructions

```bash
# Install notebook dependencies
pip install -r notebooks/requirements.txt

# Configure Azure authentication
az login
az account set --subscription "your-subscription-id"

# Launch Jupyter in VSCode
# Open any .ipynb file and select the Python kernel
```

### Connecting Notebooks to Copilot

Notebooks can invoke Security Copilot skills programmatically:

```python
from azure.identity import DefaultAzureCredential
import requests

credential = DefaultAzureCredential()
token = credential.get_token("https://securitycopilot.microsoft.com/.default")

# Invoke SCORCH agent skill
response = requests.post(
    "https://securitycopilot.microsoft.com/api/skills/invoke",
    headers={"Authorization": f"Bearer {token.token}"},
    json={
        "skillName": "SpyCloud-Investigate",
        "parameters": {"email": "user@company.com"}
    }
)
```
