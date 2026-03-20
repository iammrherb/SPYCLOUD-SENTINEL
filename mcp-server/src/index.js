/**
 * SpyCloud MCP Server — Identity Threat Intelligence
 * 
 * Model Context Protocol server exposing SpyCloud's dark web threat intelligence
 * as tools, resources, and prompts for AI agents including Microsoft Security
 * Copilot, Claude, VS Code GitHub Copilot, and Copilot Studio.
 * 
 * Covers all 8 SpyCloud API products with 20+ tools, 5 resources, and 6 prompts.
 * 
 * @version 1.0.0
 * @author SpyCloud
 * @see https://modelcontextprotocol.io/
 * @see https://docs.spycloud.com/public-sc/reference
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import cors from "cors";
import { z } from "zod";

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const CONFIG = {
  port: process.env.PORT || 3001,
  spycloud: {
    baseUrl: process.env.SPYCLOUD_API_REGION === "eu"
      ? "https://api.eu.spycloud.io"
      : "https://api.spycloud.io",
    apiKey: process.env.SPYCLOUD_API_KEY || "",
    // Optional product-specific keys
    investigationsKey: process.env.SPYCLOUD_INVESTIGATIONS_KEY || "",
    sipKey: process.env.SPYCLOUD_SIP_KEY || "",
    idlinkKey: process.env.SPYCLOUD_IDLINK_KEY || "",
    capKey: process.env.SPYCLOUD_CAP_KEY || "",
  },
  sentinel: {
    tenantId: process.env.AZURE_TENANT_ID || "",
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID || "",
    resourceGroup: process.env.AZURE_RESOURCE_GROUP || "",
    workspaceName: process.env.SENTINEL_WORKSPACE || "",
  }
};

// ═══════════════════════════════════════════════════════════════════
// SPYCLOUD API CLIENT
// ═══════════════════════════════════════════════════════════════════

class SpyCloudClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async request(path, params = {}, overrideKey = null) {
    const url = new URL(path, this.baseUrl);
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") {
        url.searchParams.set(k, v);
      }
    });

    const key = overrideKey || this.apiKey;
    if (!key) {
      return { error: "No API key configured for this endpoint. Set SPYCLOUD_API_KEY environment variable." };
    }

    try {
      const resp = await fetch(url.toString(), {
        headers: {
          "X-Api-Key": key,
          "Accept": "application/json"
        }
      });

      if (!resp.ok) {
        if (resp.status === 401) return { error: "Invalid API key or insufficient permissions for this endpoint." };
        if (resp.status === 403) return { error: "This endpoint requires a specific SpyCloud product license." };
        if (resp.status === 404) return { error: "No records found for this query." };
        if (resp.status === 429) return { error: "Rate limited. Please wait and retry." };
        return { error: `API error: ${resp.status} ${resp.statusText}` };
      }

      return await resp.json();
    } catch (err) {
      return { error: `Network error: ${err.message}` };
    }
  }

  // Enterprise ATO Prevention
  async lookupEmail(email, params = {}) {
    return this.request(`/enterprise-v2/breach/data/emails/${encodeURIComponent(email)}`, params);
  }

  async lookupDomain(domain, params = {}) {
    return this.request(`/enterprise-v2/breach/data/domains/${encodeURIComponent(domain)}`, params);
  }

  async lookupIP(ip, params = {}) {
    return this.request(`/enterprise-v2/breach/data/ips/${encodeURIComponent(ip)}`, params);
  }

  async lookupUsername(username, params = {}) {
    return this.request(`/enterprise-v2/breach/data/usernames/${encodeURIComponent(username)}`, params);
  }

  async getWatchlist(params = {}) {
    return this.request("/enterprise-v2/breach/data/watchlist", params);
  }

  async getBreachCatalog(params = {}) {
    return this.request("/enterprise-v2/breach/catalog", params);
  }

  async getBreachById(id) {
    return this.request(`/enterprise-v2/breach/catalog/${id}`);
  }

  // Watchlist Management
  async listWatchlistIdentifiers() {
    return this.request("/enterprise-v2/watchlist/identifiers");
  }

  // Compass
  async getCompassDevices(params = {}) {
    return this.request("/enterprise-v2/compass/devices", params);
  }

  async getCompassApplications() {
    return this.request("/enterprise-v2/compass/applications");
  }

  async getCompassDeviceById(deviceId) {
    return this.request(`/enterprise-v2/compass/devices/${encodeURIComponent(deviceId)}`);
  }

  // SIP
  async getSIPCookies(domain, params = {}) {
    const key = CONFIG.spycloud.sipKey || this.apiKey;
    return this.request(`/sip-v2/cookies/domains/${encodeURIComponent(domain)}`, params, key);
  }

  // Investigations
  async investigateEmail(email) {
    const key = CONFIG.spycloud.investigationsKey || this.apiKey;
    return this.request(`/investigations-v2/breach/data/emails/${encodeURIComponent(email)}`, {}, key);
  }

  async investigateMachineId(machineId) {
    const key = CONFIG.spycloud.investigationsKey || this.apiKey;
    return this.request(`/investigations-v2/breach/data/infected_machine_ids/${encodeURIComponent(machineId)}`, {}, key);
  }

  async investigateSocialHandle(handle) {
    const key = CONFIG.spycloud.investigationsKey || this.apiKey;
    return this.request(`/investigations-v2/breach/data/social_handles/${encodeURIComponent(handle)}`, {}, key);
  }

  // IdLink
  async getIdLinkByEmail(email) {
    const key = CONFIG.spycloud.idlinkKey || this.apiKey;
    return this.request(`/idlink-v2/breach/data/emails/${encodeURIComponent(email)}`, {}, key);
  }

  // Exposure Metrics
  async getExposureStatsDomain(domain) {
    return this.request(`/exposure/stats/domains/${encodeURIComponent(domain)}`);
  }

  async getExposureStatsEmail(email) {
    return this.request(`/exposure/stats/emails/${encodeURIComponent(email)}`);
  }

  // CAP
  async capLookupEmail(email) {
    const key = CONFIG.spycloud.capKey || this.apiKey;
    return this.request(`/cap-v2/breach/data/emails/${encodeURIComponent(email)}`, {}, key);
  }

  // NIST Password Check
  async checkPasswordHash(hash) {
    return this.request("/nist-v2/check", { hash });
  }
}

// ═══════════════════════════════════════════════════════════════════
// STATIC RESOURCES
// ═══════════════════════════════════════════════════════════════════

const SEVERITY_MODEL = `# SpyCloud Severity Model

| Severity | Priority | Category | Description | Response SLA |
|----------|----------|----------|-------------|-------------|
| 25 | 🔴 P1 CRITICAL | Infostealer + App Data | Stolen cookies, sessions, autofill, application data | 1 hour — revoke sessions, reset pw, isolate device |
| 20 | 🔴 P1 HIGH | Infostealer Credential | Credential stolen by malware from infected device | 4 hours — reset password, check device health |
| 5 | 🟠 P3 STANDARD | Breach + PII | Name, phone, DOB, address from third-party breach | 24 hours — monitor, review scope |
| 2 | ⚪ P4 LOW | Breach Credential | Email + password from third-party breach | 72 hours — check credential reuse |

## Key Principles
- Severity 20+ = INFOSTEALER = device was compromised = immediate response required
- Severity 25 = stolen cookies/sessions = can bypass MFA = most critical
- Severity 5 = PII exposure = compliance/notification implications
- Severity 2 = credential pair only = monitoring and reuse detection
`;

const PASSWORD_RISK_MODEL = `# Password Risk Model

| Type | Risk Level | Time-to-Crack | Action Required |
|------|-----------|---------------|-----------------|
| plaintext | 🔴 CRITICAL | 0 seconds | Immediate password reset |
| MD5 | 🔴 CRITICAL | < 1 minute | Immediate password reset |
| SHA1 | 🔴 HIGH | < 10 minutes | Urgent password reset |
| NTLM | 🔴 HIGH | < 30 minutes | Urgent password reset |
| SHA256 | 🟠 MEDIUM | Hours to days | Schedule password reset |
| SHA512 | 🟡 LOW-MED | Days to weeks | Monitor and recommend reset |
| bcrypt | 🟢 LOW | Months to years | Monitor only |
| scrypt/argon2 | 🟢 MINIMAL | Years+ | Acceptable — no action |
`;

const MITRE_MAPPING = `# SpyCloud Data → MITRE ATT&CK Mapping

| Technique | ID | SpyCloud Evidence | Detection Method |
|-----------|----|--------------------|------------------|
| Valid Accounts | T1078 | Stolen credentials at any severity | Cross-reference with sign-in logs |
| Brute Force / Credential Stuffing | T1110 | High-sighting credentials (3+ sources) | Monitor for automated login attempts |
| Steal Application Access Token | T1528 | Severity 25, stolen OAuth tokens | Check cloud app events |
| Steal Web Session Cookie | T1539 | SIP cookie data, autofill credentials | Monitor active sessions |
| Unsecured Credentials | T1552 | Plaintext passwords, password reuse | Password policy enforcement |
| Credentials from Password Stores | T1555 | Infostealer browser extraction | Endpoint detection |
| Gather Victim Identity Info | T1589 | PII exposure (name, DOB, SSN) | Pre-attack reconnaissance indicator |
| Boot/Logon Autostart Execution | T1547 | Infected path data showing persistence | Endpoint forensics |
| Use Alternate Auth Material | T1550 | NTLM hashes, Kerberos tickets | Identity protection monitoring |
| Impair Defenses | T1562 | AV bypass (AV installed but failed) | Endpoint health assessment |
`;

// ═══════════════════════════════════════════════════════════════════
// MCP SERVER SETUP
// ═══════════════════════════════════════════════════════════════════

const server = new McpServer({
  name: "spycloud-threat-intelligence",
  version: "1.0.0",
  description: "SpyCloud dark web identity threat intelligence — 65.7B recaptured records across breach credentials, infostealer infections, stolen cookies, PII, and device forensics."
});

const client = new SpyCloudClient(CONFIG.spycloud.baseUrl, CONFIG.spycloud.apiKey);

// Helper to format API results
function formatResults(data, maxRecords = 10) {
  if (data.error) return `Error: ${data.error}`;
  const hits = data.hits || data.results?.length || 0;
  const records = (data.results || []).slice(0, maxRecords);
  let output = `Found ${hits} records.\n\n`;
  if (records.length > 0) {
    output += JSON.stringify(records, null, 2);
  }
  if (hits > maxRecords) {
    output += `\n\n... and ${hits - maxRecords} more records (showing first ${maxRecords})`;
  }
  return output;
}

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Enterprise ATO Prevention
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "lookup_email_exposure",
  "Look up all breach exposures for an email address. Returns compromised credentials, PII, infostealer infections, severity, target domains, password types, device context. Primary investigation tool.",
  {
    email: z.string().email().describe("Email address to investigate"),
    severity: z.number().optional().describe("Filter by minimum severity (2, 5, 20, 25)"),
    since: z.string().optional().describe("Only records published after this date (YYYY-MM-DD)")
  },
  async ({ email, severity, since }) => {
    const data = await client.lookupEmail(email, { severity, since });
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "lookup_domain_exposure",
  "Look up all breach exposures for a corporate domain. Returns total exposed users, severity breakdown, top affected accounts. Organizational exposure assessment.",
  {
    domain: z.string().describe("Domain to investigate (e.g. company.com)"),
    severity: z.number().optional().describe("Filter by minimum severity"),
    type: z.string().optional().describe("Filter by type: corporate, infected, compass")
  },
  async ({ domain, severity, type }) => {
    const data = await client.lookupDomain(domain, { severity, type });
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "lookup_ip_exposure",
  "Look up breach exposures associated with an IP address. Valuable for infostealer infection investigation where IP is the primary indicator.",
  {
    ip: z.string().describe("IP address to investigate")
  },
  async ({ ip }) => {
    const data = await client.lookupIP(ip);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "lookup_username_exposure",
  "Look up breach exposures for a non-email username. Useful for service accounts, application accounts, and non-email identities.",
  {
    username: z.string().describe("Username to investigate")
  },
  async ({ username }) => {
    const data = await client.lookupUsername(username);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "get_watchlist_records",
  "Get all exposure records from the organization's monitored watchlist — corporate domains, IP ranges, executive accounts.",
  {
    severity: z.string().optional().describe("Filter by severity levels (comma-separated: 2,5,20,25)"),
    since: z.string().optional().describe("Records published after this epoch timestamp")
  },
  async ({ severity, since }) => {
    const data = await client.getWatchlist({ severity, since });
    return { content: [{ type: "text", text: formatResults(data, 20) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Breach Catalog
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "get_breach_catalog",
  "List breach source metadata — title, description, type, confidence, record count, acquisition date, malware family. Use to understand breach context.",
  {
    since: z.string().optional().describe("Only entries modified after this date")
  },
  async ({ since }) => {
    const data = await client.getBreachCatalog({ since });
    return { content: [{ type: "text", text: formatResults(data, 25) }] };
  }
);

server.tool(
  "get_breach_details",
  "Get full metadata for a specific breach source by ID. Returns title, description, confidence score, record count, malware family.",
  {
    breach_id: z.number().describe("SpyCloud breach source ID")
  },
  async ({ breach_id }) => {
    const data = await client.getBreachById(breach_id);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Watchlist Management
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "list_watchlist_identifiers",
  "List all monitored identifiers on the organization's watchlist — domains, emails, IPs being monitored for exposure.",
  {},
  async () => {
    const data = await client.listWatchlistIdentifiers();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Compass
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "get_compass_devices",
  "List all compromised devices from Compass endpoint data — OS, hostname, infection path, AV status, affected users. Requires Compass license.",
  {
    since: z.string().optional().describe("Devices reported after this date")
  },
  async ({ since }) => {
    const data = await client.getCompassDevices({ since });
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "get_compass_device_detail",
  "Get full details for a specific compromised device from Compass — all credentials, applications, infection context.",
  {
    device_id: z.string().describe("SpyCloud infected_machine_id or device identifier")
  },
  async ({ device_id }) => {
    const data = await client.getCompassDeviceById(device_id);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

server.tool(
  "get_compass_applications",
  "List all applications with compromised credentials from Compass. Application blast radius assessment.",
  {},
  async () => {
    const data = await client.getCompassApplications();
    return { content: [{ type: "text", text: formatResults(data, 25) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — SIP (Session Identity Protection)
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "get_stolen_cookies",
  "Get stolen session cookies for a domain. CRITICAL for detecting MFA bypass risk via session hijacking. Requires SIP license.",
  {
    domain: z.string().describe("Domain to check for stolen cookies (e.g. login.microsoft.com)"),
    since: z.string().optional().describe("Cookies stolen after this date")
  },
  async ({ domain, since }) => {
    const data = await client.getSIPCookies(domain, { since });
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Investigations (Deep OSINT)
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "investigate_email_deep",
  "Deep cybercrime investigation by email. Returns expanded data including linked identities and investigation-grade metadata. Requires Investigations license.",
  {
    email: z.string().describe("Email address for deep investigation")
  },
  async ({ email }) => {
    const data = await client.investigateEmail(email);
    return { content: [{ type: "text", text: formatResults(data, 25) }] };
  }
);

server.tool(
  "investigate_machine",
  "Deep investigation of an infected device — all users, all credentials, full infection context. Requires Investigations license.",
  {
    machine_id: z.string().describe("SpyCloud infected_machine_id")
  },
  async ({ machine_id }) => {
    const data = await client.investigateMachineId(machine_id);
    return { content: [{ type: "text", text: formatResults(data, 25) }] };
  }
);

server.tool(
  "investigate_social_handle",
  "Investigation by social media handle — LinkedIn, Twitter, Instagram. OSINT enrichment. Requires Investigations license.",
  {
    handle: z.string().describe("Social media handle to investigate")
  },
  async ({ handle }) => {
    const data = await client.investigateSocialHandle(handle);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — IdLink (Identity Graph)
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "get_identity_graph",
  "Resolve the identity graph for an email — all linked accounts, usernames, phone numbers, connected identities. Maps the full exposure blast radius. Requires IdLink license.",
  {
    email: z.string().describe("Email address to map identity graph for")
  },
  async ({ email }) => {
    const data = await client.getIdLinkByEmail(email);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — Exposure Metrics
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "get_exposure_stats",
  "Get aggregate exposure statistics for a domain or email — total records, severity distribution, breach source count, timeline. Executive-level posture assessment.",
  {
    entity: z.string().describe("Domain or email address to get stats for"),
    entity_type: z.enum(["domain", "email"]).describe("Whether the entity is a domain or email")
  },
  async ({ entity, entity_type }) => {
    const data = entity_type === "domain"
      ? await client.getExposureStatsDomain(entity)
      : await client.getExposureStatsEmail(entity);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — NIST Password Check
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "check_password_hash",
  "NIST SP 800-63B compliant password check. Verifies whether a password hash (SHA256) appears in SpyCloud's breach database. For password policy enforcement.",
  {
    hash: z.string().describe("SHA256 hash of the password to check")
  },
  async ({ hash }) => {
    const data = await client.checkPasswordHash(hash);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// TOOLS — CAP (Consumer ATO Protection)
// ═══════════════════════════════════════════════════════════════════

server.tool(
  "check_consumer_exposure",
  "Check consumer account exposure for customer-facing ATO protection. Requires CAP license.",
  {
    email: z.string().describe("Consumer email to check for exposure")
  },
  async ({ email }) => {
    const data = await client.capLookupEmail(email);
    return { content: [{ type: "text", text: formatResults(data) }] };
  }
);

// ═══════════════════════════════════════════════════════════════════
// RESOURCES
// ═══════════════════════════════════════════════════════════════════

server.resource(
  "severity-model",
  "spycloud://severity-model",
  "SpyCloud severity model — severity levels 2/5/20/25 with definitions, response SLAs, and key principles",
  async () => ({ contents: [{ uri: "spycloud://severity-model", mimeType: "text/markdown", text: SEVERITY_MODEL }] })
);

server.resource(
  "password-risk-model",
  "spycloud://password-risk-model",
  "Password hash type risk model — crackability assessment from plaintext to argon2",
  async () => ({ contents: [{ uri: "spycloud://password-risk-model", mimeType: "text/markdown", text: PASSWORD_RISK_MODEL }] })
);

server.resource(
  "mitre-mapping",
  "spycloud://mitre-mapping",
  "SpyCloud data to MITRE ATT&CK technique mapping — 10 techniques with evidence types",
  async () => ({ contents: [{ uri: "spycloud://mitre-mapping", mimeType: "text/markdown", text: MITRE_MAPPING }] })
);

// ═══════════════════════════════════════════════════════════════════
// PROMPTS
// ═══════════════════════════════════════════════════════════════════

server.prompt(
  "investigate-user",
  "Full user investigation — check all SpyCloud data sources for an email address and produce a comprehensive threat assessment",
  { email: z.string().describe("Email address to investigate") },
  ({ email }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Investigate ${email} for dark web exposure using SpyCloud data. Follow this workflow:

1. Call lookup_email_exposure to get all breach records
2. Call get_exposure_stats with entity_type=email to get aggregate statistics
3. Call get_identity_graph to map linked identities (if IdLink available)
4. Call investigate_email_deep for investigation-grade data (if Investigations available)
5. Reference the severity-model resource to classify risk
6. Reference the password-risk-model resource to assess password crackability
7. Reference the mitre-mapping resource to identify applicable ATT&CK techniques

Produce a comprehensive report with:
- 🔴🟠🟡🟢 Threat Level with justification
- Key metrics (total exposures, severity distribution, plaintext passwords, devices)
- Findings with WHAT happened, WHY it matters, WHAT an attacker could do
- MITRE ATT&CK technique mapping
- Remediation recommendations prioritized by urgency
- Compliance implications if PII is exposed
- 5 follow-up investigation questions`
      }
    }]
  })
);

server.prompt(
  "investigate-device",
  "Full device forensics — investigate an infected device across all SpyCloud data",
  { device_id: z.string().describe("Infected machine ID or hostname") },
  ({ device_id }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Investigate device ${device_id} for infostealer infection using SpyCloud data. Follow this workflow:

1. Call get_compass_device_detail for full device profile
2. Call investigate_machine for deep investigation data
3. For each affected user found, call lookup_email_exposure
4. Reference severity-model for risk classification
5. Reference mitre-mapping for ATT&CK techniques

Report should include: device forensics (OS, hostname, AV, infection path), all affected users, credential exposure per user, remediation status, and whether the device should be isolated.`
      }
    }]
  })
);

server.prompt(
  "org-exposure-overview",
  "Organization-wide dark web exposure assessment — aggregate statistics across all domains",
  { domain: z.string().describe("Primary corporate domain").optional() },
  ({ domain }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Generate an organization-wide dark web exposure overview${domain ? ` for ${domain}` : ""}. Follow this workflow:

1. Call get_watchlist_records to get all current exposures
2. ${domain ? `Call get_exposure_stats for domain ${domain}` : "Call list_watchlist_identifiers to see monitored assets"}
3. Call get_breach_catalog for recent breach sources
4. Call get_compass_devices for infected device inventory
5. Reference all three resource models

Produce an executive-ready report with: total exposure count, severity distribution, top affected users, infected devices, password analysis, geographic distribution, remediation KPIs, trend assessment, and top 5 recommended actions.`
      }
    }]
  })
);

server.prompt(
  "threat-hunt",
  "Proactive threat hunting across SpyCloud data — find undetected compromises and campaign patterns",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Run a proactive threat hunt across all SpyCloud data. Check for:

1. Call get_watchlist_records with severity=20,25 for high-priority exposures
2. Call get_compass_devices for infected endpoint inventory
3. Call get_breach_catalog for new/recent malware-type breach sources
4. Look for patterns: same infection path across devices, same source affecting multiple users, geographic anomalies
5. Reference mitre-mapping for technique identification

Report: campaign patterns detected, credential stuffing indicators (high-sighting creds), MFA bypass risk (stolen cookies), lateral movement potential (admin/service accounts), unpatched devices with infections, and prioritized hunt findings.`
      }
    }]
  })
);

server.prompt(
  "compliance-assessment",
  "Breach notification and compliance analysis — identify PII exposure requiring regulatory action",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Assess compliance obligations from SpyCloud exposure data. Workflow:

1. Call get_watchlist_records and filter for records with SSN, bank numbers, health data, financial information
2. Call get_exposure_stats for domain-level aggregate impact
3. Reference severity-model for classification

Map findings to applicable frameworks:
- GDPR: 72-hour notification requirement, data categories
- CCPA/CPRA: 30-day notification, AG filing requirements
- HIPAA: 60-day notification, HHS filing for health data
- PCI-DSS: Immediate if payment card data exposed
- State breach notification laws: per-state requirements

Produce a compliance evidence package with: affected individuals count, data categories exposed, applicable regulations, notification deadlines, remediation evidence, and recommended legal actions.`
      }
    }]
  })
);

server.prompt(
  "executive-brief",
  "C-suite ready exposure summary with risk score and business impact",
  { domain: z.string().describe("Corporate domain for the brief").optional() },
  ({ domain }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Generate an executive brief on dark web exposure${domain ? ` for ${domain}` : ""}. Workflow:

1. Call get_watchlist_records for current exposure data
2. ${domain ? `Call get_exposure_stats for ${domain}` : "Call list_watchlist_identifiers"}
3. Reference severity-model

Produce a board-ready summary with: overall risk score (1-10), key metrics dashboard, top 3 risks with business impact, exposure trend (improving/stable/degrading), remediation effectiveness rate, compliance status, and 3-5 strategic recommendations. Use business language, not technical jargon.`
      }
    }]
  })
);

// ═══════════════════════════════════════════════════════════════════
// HTTP SERVER WITH SSE TRANSPORT
// ═══════════════════════════════════════════════════════════════════

const app = express();

// Body parsing & CORS
app.use(express.json());
app.use(cors({
  origin: process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(",")
    : "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
}));

// API key authentication middleware for MCP endpoints
const MCP_API_KEY = process.env.MCP_API_KEY || "";
function requireAuth(req, res, next) {
  if (!MCP_API_KEY) return next(); // No key configured — open access
  const provided = req.headers["x-api-key"] || req.headers["authorization"]?.replace("Bearer ", "");
  if (provided === MCP_API_KEY) return next();
  return res.status(401).json({ error: "Unauthorized — provide X-API-Key header or Bearer token" });
}

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    server: "spycloud-mcp-server",
    version: "1.0.0",
    tools: 20,
    resources: 3,
    prompts: 6,
    api_configured: !!CONFIG.spycloud.apiKey
  });
});

// SSE endpoint for MCP connections
const transports = {};

// Session cleanup interval — evict stale sessions every 5 minutes
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, transport] of Object.entries(transports)) {
    if (transport._createdAt && now - transport._createdAt > SESSION_TTL_MS) {
      try { transport.close?.(); } catch { /* ignore */ }
      delete transports[id];
    }
  }
}, 5 * 60 * 1000);

app.get("/sse", requireAuth, async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  transport._createdAt = Date.now();
  transports[transport.sessionId] = transport;
  
  res.on("close", () => {
    delete transports[transport.sessionId];
  });
  
  await server.connect(transport);
});

app.post("/messages", requireAuth, async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (transport) {
    transport._createdAt = Date.now(); // refresh TTL on activity
    await transport.handlePostMessage(req, res);
  } else {
    res.status(404).json({ error: "Session not found" });
  }
});

app.listen(CONFIG.port, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  SpyCloud MCP Server — Identity Threat Intelligence         ║
║  Version: 1.0.0                                             ║
║  Port: ${String(CONFIG.port).padEnd(53)}║
║  API: ${CONFIG.spycloud.apiKey ? "Configured ✅" : "NOT SET ❌ (set SPYCLOUD_API_KEY)".padEnd(50)}       ║
║  Tools: 20 | Resources: 3 | Prompts: 6                     ║
║                                                             ║
║  SSE Endpoint: http://localhost:${CONFIG.port}/sse${" ".repeat(27)}║
║  Health Check: http://localhost:${CONFIG.port}/health${" ".repeat(24)}║
╚══════════════════════════════════════════════════════════════╝
  `);
});
