"""
SpyCloud AI Investigation Engine
=================================
Azure Function providing AI-powered security investigations using
OpenAI GPT-4o or Azure OpenAI Service. Generates detailed analyst
reports, executive summaries, threat research, and remediation plans.

Integrates with:
- SpyCloud APIs (breach, compass, SIP, investigations)
- Microsoft Sentinel (Log Analytics KQL)
- OpenAI / Azure OpenAI (GPT-4o for analysis)
- Microsoft Graph (user/device context)

All API keys stored in Azure Key Vault references.
"""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from azure.identity import DefaultAzureCredential

app_ai = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# ================================================================
# CONFIGURATION
# ================================================================

# AI Provider Configuration
AI_PROVIDER = os.environ.get("AI_PROVIDER", "openai")  # "openai" or "azure_openai"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_KEY = os.environ.get("AZURE_OPENAI_KEY", "")
AZURE_OPENAI_DEPLOYMENT = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
AZURE_OPENAI_API_VERSION = os.environ.get(
    "AZURE_OPENAI_API_VERSION", "2024-08-01-preview"
)

# SpyCloud API
SPYCLOUD_BASE_URL = "https://api.spycloud.io/enterprise-v2"
SPYCLOUD_API_KEY = os.environ.get("SPYCLOUD_ENTERPRISE_KEY", "")

# Log Analytics
LOG_ANALYTICS_WORKSPACE_ID = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID", "")

# Microsoft Graph
GRAPH_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
GRAPH_CLIENT_ID = os.environ.get("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET = os.environ.get("GRAPH_CLIENT_SECRET", "")


# ================================================================
# HELPER FUNCTIONS
# ================================================================


def _get_ai_headers() -> Optional[dict]:
    """Get headers for the configured AI provider."""
    if AI_PROVIDER == "azure_openai" and AZURE_OPENAI_KEY:
        return {
            "api-key": AZURE_OPENAI_KEY,
            "Content-Type": "application/json",
        }
    if OPENAI_API_KEY:
        return {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
    return None


def _get_ai_url() -> str:
    """Get the AI API endpoint URL."""
    if AI_PROVIDER == "azure_openai" and AZURE_OPENAI_ENDPOINT:
        return (
            f"{AZURE_OPENAI_ENDPOINT.rstrip('/')}/openai/deployments/"
            f"{AZURE_OPENAI_DEPLOYMENT}/chat/completions"
            f"?api-version={AZURE_OPENAI_API_VERSION}"
        )
    return "https://api.openai.com/v1/chat/completions"


def call_ai(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.3,
    max_tokens: int = 4096,
) -> str:
    """Call OpenAI or Azure OpenAI for AI-powered analysis."""
    headers = _get_ai_headers()
    if not headers:
        return (
            "[AI analysis unavailable — no API key configured. "
            "Set OPENAI_API_KEY or AZURE_OPENAI_KEY.]"
        )

    url = _get_ai_url()
    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    # Only add model for OpenAI (Azure uses deployment name in URL)
    if AI_PROVIDER != "azure_openai":
        payload["model"] = OPENAI_MODEL

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=120)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        logging.error("AI API error: %s %s", resp.status_code, resp.text[:500])
        return f"[AI analysis failed: HTTP {resp.status_code}]"
    except requests.exceptions.Timeout:
        logging.error("AI API call timed out after 120s")
        return "[AI analysis timed out — try a shorter query or increase timeout]"
    except Exception as exc:
        logging.error("AI call error: %s", exc)
        return f"[AI analysis error: {exc}]"


def call_spycloud_api(endpoint: str, params: Optional[dict] = None) -> dict:
    """Call SpyCloud API with proper authentication."""
    if not SPYCLOUD_API_KEY:
        return {"error": "No SpyCloud API key configured", "hits": 0, "results": []}
    url = f"{SPYCLOUD_BASE_URL}{endpoint}"
    try:
        resp = requests.get(
            url,
            headers={"X-API-Key": SPYCLOUD_API_KEY, "Accept": "application/json"},
            params=params,
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()
        return {
            "error": f"API returned {resp.status_code}",
            "hits": 0,
            "results": [],
        }
    except Exception as exc:
        return {"error": str(exc), "hits": 0, "results": []}


def query_log_analytics(query: str) -> list:
    """Execute KQL query against Log Analytics using managed identity."""
    if not LOG_ANALYTICS_WORKSPACE_ID:
        return []
    url = (
        f"https://api.loganalytics.io/v1/workspaces/"
        f"{LOG_ANALYTICS_WORKSPACE_ID}/query"
    )
    try:
        credential = DefaultAzureCredential()
        token = credential.get_token("https://api.loganalytics.io/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        }
        resp = requests.post(
            url, headers=headers, json={"query": query.strip()}, timeout=60
        )
        if resp.status_code != 200:
            return []
        body = resp.json()
        tables = body.get("tables", [])
        if not tables:
            return []
        columns = [col["name"] for col in tables[0].get("columns", [])]
        rows = tables[0].get("rows", [])
        return [dict(zip(columns, row)) for row in rows]
    except Exception as exc:
        logging.warning("Log Analytics query failed: %s", exc)
        return []


def get_graph_token() -> Optional[str]:
    """Get Microsoft Graph API token via client credentials."""
    if not all([GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET]):
        return None
    try:
        resp = requests.post(
            f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": GRAPH_CLIENT_ID,
                "client_secret": GRAPH_CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except Exception:
        pass
    return None


def call_graph(endpoint: str) -> dict:
    """Call Microsoft Graph API."""
    token = get_graph_token()
    if not token:
        return {"error": "Graph API token unavailable"}
    try:
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0{endpoint}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Graph API returned {resp.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


def _build_exposure_summary(exposures: list) -> dict:
    """Build a structured summary from SpyCloud exposure records."""
    summary = {
        "total_exposures": len(exposures),
        "severities": {},
        "password_types": {},
        "breach_sources": [],
        "has_plaintext": False,
        "infected_devices": [],
        "target_domains": [],
    }
    seen_sources = set()
    device_set = set()
    domain_set = set()

    for record in exposures[:100]:
        sev = record.get("severity", 0)
        summary["severities"][str(sev)] = (
            summary["severities"].get(str(sev), 0) + 1
        )
        pt = record.get("password_type", "unknown")
        summary["password_types"][pt] = summary["password_types"].get(pt, 0) + 1

        if record.get("password_plaintext"):
            summary["has_plaintext"] = True

        machine_id = record.get("infected_machine_id")
        if machine_id:
            device_set.add(machine_id)

        target = record.get("target_domain")
        if target:
            domain_set.add(target)

        src = record.get("source_id")
        if src and src not in seen_sources:
            seen_sources.add(src)
            summary["breach_sources"].append(
                {
                    "source_id": src,
                    "title": record.get("breach_title", "Unknown"),
                    "severity": sev,
                }
            )

    summary["infected_devices"] = list(device_set)
    summary["target_domains"] = list(domain_set)
    return summary


# ================================================================
# SYSTEM PROMPTS
# ================================================================

ANALYST_SYSTEM_PROMPT = """You are SCORCH — SpyCloud Compromised Operations Research & Credential Hunter.
You are an expert identity threat intelligence analyst specializing in:
- Dark web credential exposure analysis
- Infostealer malware forensics (RedLine, LummaC2, Vidar, Raccoon, StealC, RisePro, Mystic)
- MITRE ATT&CK mapping for identity-based attacks
- Microsoft Sentinel/Defender/Entra ID correlation
- Compliance frameworks (GDPR, CCPA, HIPAA, PCI-DSS, SOC2, NIST CSF)

Your analysis is: technically precise, data-driven with specific numbers/dates/entities,
actionable with prioritized remediation steps, and thorough enough for incident documentation.

When generating reports, use markdown formatting with:
- Clear section headers
- Data tables for structured findings
- Severity indicators: CRITICAL, HIGH, MEDIUM, LOW
- MITRE ATT&CK technique IDs where applicable (e.g., T1078, T1539, T1555)
- Specific, actionable remediation steps with SLAs
- Timeline context and kill chain mapping

SpyCloud Severity Model:
- Severity 25: P1 CRITICAL — Infostealer + stolen cookies/sessions (MFA bypass risk)
- Severity 20: P1 HIGH — Infostealer credential (device compromised by malware)
- Severity 5: P3 STANDARD — Third-party breach with PII exposure
- Severity 2: P4 LOW — Third-party breach credential pair only

Password Risk Model (weakest to strongest):
plaintext > md5 > sha1 > sha256 > bcrypt > scrypt > argon2"""

EXECUTIVE_SYSTEM_PROMPT = """You are a senior cybersecurity consultant preparing board-level reports.
Write in clear, business-oriented language. Avoid technical jargon unless necessary.
Focus on: business impact, risk quantification ($), trend analysis, ROI of security investments,
and strategic recommendations. Use data visualization descriptions and executive-ready formatting.

Always include:
- Overall risk score (1-10 with justification)
- Key metrics with period-over-period comparison
- Top 3 risks with estimated business/financial impact
- Trend direction (improving/stable/degrading) with evidence
- 3-5 strategic recommendations with investment estimates
- Regulatory/compliance implications
- Board-ready risk statement (1 paragraph)"""

THREAT_RESEARCH_PROMPT = """You are a threat intelligence researcher with deep expertise in:
- Dark web forums (XSS, BreachForums, Exploit.in), marketplaces, and paste sites
- Infostealer malware families and their C2 infrastructure
- APT groups and their TTPs (Tactics, Techniques, Procedures)
- CVE analysis, exploit chain mapping, and weaponization timelines
- IOC (Indicators of Compromise) enrichment and pivoting
- OSINT techniques for threat actor attribution and campaign tracking

Provide thorough, well-sourced analysis. Reference specific malware families,
threat actor groups, MITRE ATT&CK techniques, and CVEs by ID. Include IOCs where relevant.
Format findings as actionable threat intelligence reports with confidence levels.

Use TLP markings where appropriate:
- TLP:RED — restricted to specific recipients
- TLP:AMBER — limited to organization
- TLP:GREEN — community-shareable
- TLP:WHITE — unrestricted"""


# ================================================================
# AI INVESTIGATION ENDPOINTS
# ================================================================


@app_ai.route(route="ai/investigate", methods=["POST"])
def ai_investigate(req: func.HttpRequest) -> func.HttpResponse:
    """
    AI-powered full investigation.

    Combines SpyCloud breach data, Sentinel sign-in telemetry,
    and Microsoft Graph user context with GPT-4o analysis to produce
    a comprehensive investigation report.

    Request body:
        {"email": "user@domain.com"}

    Returns:
        Full investigation report with exposure summary, AI analysis,
        and data source status.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    email = body.get("email", "").strip()
    if not email or "@" not in email:
        return func.HttpResponse(
            json.dumps({"error": "Valid email address required"}),
            status_code=400,
            mimetype="application/json",
        )

    # Gather SpyCloud data
    encoded_email = requests.utils.quote(email, safe="")
    breach_data = call_spycloud_api(f"/breach/data/emails/{encoded_email}")
    exposures = breach_data.get("results", [])
    exposure_summary = _build_exposure_summary(exposures)
    exposure_summary["total_exposures"] = breach_data.get("hits", 0)

    # Query Sentinel for sign-in context
    sentinel_context = ""
    signin_data = query_log_analytics(
        f"""
        SigninLogs
        | where TimeGenerated >= ago(30d)
        | where UserPrincipalName =~ "{email}"
        | summarize
            TotalSignins=count(),
            FailedSignins=countif(ResultType != "0"),
            UniqueIPs=dcount(IPAddress),
            UniqueLocations=dcount(
                strcat(LocationDetails.city, LocationDetails.countryOrRegion)
            ),
            RiskySignins=countif(RiskLevelDuringSignIn in ("high", "medium")),
            MFAChallenges=countif(
                AuthenticationRequirement == "multiFactorAuthentication"
            )
        """
    )
    if signin_data:
        sentinel_context = (
            "\n\nSentinel Sign-in Activity (30 days):\n"
            + json.dumps(signin_data[0], indent=2)
        )

    # Get Graph user context
    graph_context = ""
    user_info = call_graph(
        f"/users/{encoded_email}"
        "?$select=displayName,jobTitle,department,accountEnabled"
    )
    if "error" not in user_info:
        graph_context = (
            "\n\nEntra ID User Profile:\n" + json.dumps(user_info, indent=2)
        )

    # Build AI prompt
    user_prompt = f"""Investigate the following user for dark web exposure and security risk:

**User:** {email}

**SpyCloud Exposure Data:**
{json.dumps(exposure_summary, indent=2)}

**Sample Breach Records (first 5):**
{json.dumps(exposures[:5], indent=2, default=str)}
{sentinel_context}
{graph_context}

Produce a comprehensive investigation report with:
1. Executive Summary (2-3 sentences, risk level with justification)
2. Exposure Analysis (severity breakdown, timeline, breach sources)
3. Credential Risk Assessment (password types, reuse indicators, crackability)
4. Device/Endpoint Analysis (infected devices, malware families if present)
5. Identity Correlation (linked accounts, blast radius estimation)
6. MITRE ATT&CK Mapping (applicable techniques with evidence)
7. Remediation Plan (prioritized actions with SLAs)
8. Compliance Implications (GDPR, CCPA, HIPAA if applicable)
9. Recommended Follow-up Investigations"""

    ai_report = call_ai(ANALYST_SYSTEM_PROMPT, user_prompt, max_tokens=4096)

    return func.HttpResponse(
        json.dumps(
            {
                "email": email,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "exposureSummary": exposure_summary,
                "aiReport": ai_report,
                "dataSourcesQueried": {
                    "spycloud": True,
                    "sentinel": bool(signin_data),
                    "graph": "error" not in user_info,
                },
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/executive-report", methods=["POST"])
def ai_executive_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate AI-powered executive report for leadership/board.

    Request body:
        {"domain": "company.com", "periodDays": 30}

    Returns:
        Executive report with org-level metrics and AI analysis.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    domain = body.get("domain", "").strip()
    period_days = min(max(body.get("periodDays", 30), 1), 365)

    if not domain:
        return func.HttpResponse(
            json.dumps({"error": "domain required"}),
            status_code=400,
            mimetype="application/json",
        )

    encoded_domain = requests.utils.quote(domain, safe="")
    domain_data = call_spycloud_api(
        f"/breach/data/domains/{encoded_domain}", params={"limit": 1000}
    )
    exposures = domain_data.get("results", [])

    # Aggregate metrics
    severity_dist = {}
    password_dist = {}
    user_counts = {}
    device_ids = set()
    plaintext_count = 0

    for record in exposures:
        sev = record.get("severity", 0)
        severity_dist[str(sev)] = severity_dist.get(str(sev), 0) + 1

        pt = record.get("password_type", "unknown")
        password_dist[pt] = password_dist.get(pt, 0) + 1

        em = record.get("email", "unknown")
        user_counts[em] = user_counts.get(em, 0) + 1

        if record.get("infected_machine_id"):
            device_ids.add(record["infected_machine_id"])

        if record.get("password_plaintext"):
            plaintext_count += 1

    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    metrics = {
        "total_exposures": domain_data.get("hits", 0),
        "unique_users": len(set(r.get("email", "") for r in exposures)),
        "severity_distribution": severity_dist,
        "password_type_distribution": password_dist,
        "top_affected_users": [
            {"email": e, "exposures": c} for e, c in top_users
        ],
        "infected_devices": len(device_ids),
        "plaintext_credentials": plaintext_count,
    }

    # Query Sentinel trend data
    trend_data = query_log_analytics(
        f"""
        SpyCloudBreachWatchlist_CL
        | where TimeGenerated >= ago({period_days}d)
        | summarize
            DailyExposures=count(),
            CriticalCount=countif(severity_d >= 20),
            PlaintextCount=countif(isnotempty(password_plaintext_s))
            by bin(TimeGenerated, 1d)
        | order by TimeGenerated asc
        """
    )

    user_prompt = f"""Generate a board-level executive report on dark web exposure for {domain}.

**Organization Metrics ({period_days}-day period):**
{json.dumps(metrics, indent=2, default=str)}

**Daily Trend Data (from Sentinel):**
{json.dumps(trend_data[:30], indent=2, default=str) if trend_data else "Trend data unavailable — Log Analytics not connected."}

Generate an executive report with:
1. Executive Summary (overall risk score 1-10, key headline)
2. Key Metrics Dashboard (total exposures, critical %, affected users, infected devices)
3. Top 3 Business Risks (with estimated financial impact)
4. Trend Analysis (improving/stable/degrading with evidence)
5. Remediation Effectiveness (what's been done, what gaps remain)
6. Compliance Status (regulatory implications)
7. Strategic Recommendations (3-5 prioritized investments)
8. Board-Ready Risk Statement (1 paragraph)"""

    ai_report = call_ai(EXECUTIVE_SYSTEM_PROMPT, user_prompt, max_tokens=4096)

    return func.HttpResponse(
        json.dumps(
            {
                "domain": domain,
                "periodDays": period_days,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": metrics,
                "aiReport": ai_report,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/threat-research", methods=["POST"])
def ai_threat_research(req: func.HttpRequest) -> func.HttpResponse:
    """
    AI-powered threat research — malware families, APTs, campaigns, IOCs.

    Request body:
        {
            "query": "RedLine Stealer",
            "type": "malware"  // general|malware|apt|campaign|ioc
        }

    Returns:
        Threat intelligence report with SpyCloud context if applicable.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    query = body.get("query", "").strip()
    research_type = body.get("type", "general")

    if not query:
        return func.HttpResponse(
            json.dumps({"error": "query required"}),
            status_code=400,
            mimetype="application/json",
        )

    valid_types = {"general", "malware", "apt", "campaign", "ioc"}
    if research_type not in valid_types:
        research_type = "general"

    # Gather SpyCloud context if email/domain provided
    spycloud_context = ""
    if "@" in query:
        encoded = requests.utils.quote(query, safe="")
        data = call_spycloud_api(f"/breach/data/emails/{encoded}")
        if data.get("results"):
            malware_families = set()
            for r in data["results"]:
                if r.get("malware_family"):
                    malware_families.add(r["malware_family"])
            spycloud_context = (
                f"\n\nSpyCloud data shows {data.get('hits', 0)} exposures. "
                f"Malware families detected: "
                f"{', '.join(malware_families) or 'None identified'}"
            )
    elif "." in query and not query.startswith("CVE"):
        encoded = requests.utils.quote(query, safe="")
        data = call_spycloud_api(
            f"/breach/data/domains/{encoded}", params={"limit": 100}
        )
        if data.get("results"):
            spycloud_context = (
                f"\n\nSpyCloud shows {data.get('hits', 0)} exposures "
                f"for domain {query}."
            )

    type_instructions = {
        "general": "Provide a comprehensive threat intelligence assessment.",
        "malware": (
            "Focus on malware family analysis: capabilities, C2 infrastructure, "
            "detection signatures, MITRE ATT&CK mapping, and remediation."
        ),
        "apt": (
            "Focus on APT group analysis: known campaigns, TTPs, targets, "
            "infrastructure, and attribution confidence."
        ),
        "campaign": (
            "Focus on campaign analysis: timeline, scope, attack chain, IOCs, "
            "and defensive recommendations."
        ),
        "ioc": (
            "Focus on IOC enrichment: categorize, score, map to threats, "
            "and provide detection rules."
        ),
    }

    user_prompt = f"""Research the following threat intelligence topic:

**Query:** {query}
**Research Type:** {research_type}
{spycloud_context}

{type_instructions.get(research_type, type_instructions["general"])}

Provide a detailed threat intelligence report including:
1. Overview & Context
2. Technical Analysis (TTPs, MITRE ATT&CK mapping)
3. Known IOCs (IPs, domains, hashes, file paths)
4. Related Campaigns & Threat Actors
5. Detection Opportunities (Sentinel KQL queries, Defender rules)
6. Remediation & Prevention Recommendations
7. References & Further Reading"""

    ai_report = call_ai(THREAT_RESEARCH_PROMPT, user_prompt, max_tokens=4096)

    return func.HttpResponse(
        json.dumps(
            {
                "query": query,
                "researchType": research_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "aiReport": ai_report,
                "spycloudContext": spycloud_context or None,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/incident-report", methods=["POST"])
def ai_incident_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate a full analyst incident report from Sentinel incident data.

    Request body:
        {"incidentId": "12345"}

    Returns:
        Comprehensive incident report with SpyCloud enrichment and AI analysis.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    incident_id = body.get("incidentId", "")
    if not incident_id:
        return func.HttpResponse(
            json.dumps({"error": "incidentId required"}),
            status_code=400,
            mimetype="application/json",
        )

    # Validate incident_id is numeric to prevent injection
    try:
        incident_num = int(incident_id)
    except (ValueError, TypeError):
        return func.HttpResponse(
            json.dumps({"error": "incidentId must be numeric"}),
            status_code=400,
            mimetype="application/json",
        )

    # Query incident from Sentinel
    incident_data = query_log_analytics(
        f"""
        SecurityIncident
        | where IncidentNumber == {incident_num}
        | project IncidentNumber, Title, Description, Severity, Status,
                  Classification, CreatedTime, LastModifiedTime, Owner,
                  Labels, AlertIds, AdditionalData
        | take 1
        """
    )

    if not incident_data:
        return func.HttpResponse(
            json.dumps(
                {"error": f"Incident {incident_num} not found in Sentinel"}
            ),
            status_code=404,
            mimetype="application/json",
        )

    incident = incident_data[0]

    # Get associated alerts
    alerts = query_log_analytics(
        f"""
        SecurityIncident
        | where IncidentNumber == {incident_num}
        | mv-expand AlertIds
        | extend AlertId = tostring(AlertIds)
        | join kind=inner (
            SecurityAlert
            | project AlertId=SystemAlertId, AlertName=DisplayName,
                      AlertSeverity, TimeGenerated, Tactics, Techniques,
                      Description
        ) on AlertId
        | project TimeGenerated, AlertName, AlertSeverity, Tactics,
                  Techniques, Description
        | order by TimeGenerated asc
        """
    )

    # Get associated entities for SpyCloud enrichment
    entities = query_log_analytics(
        f"""
        SecurityIncident
        | where IncidentNumber == {incident_num}
        | mv-expand AlertIds
        | extend AlertId = tostring(AlertIds)
        | join kind=inner (
            SecurityAlert
            | mv-expand todynamic(Entities)
            | extend Entity = parse_json(Entities)
            | project AlertId=SystemAlertId, Entity,
                      EntityType=tostring(Entity.Type)
        ) on AlertId
        | summarize
            Users=make_set_if(tostring(Entity.Name), EntityType == "account"),
            Hosts=make_set_if(tostring(Entity.HostName), EntityType == "host"),
            IPs=make_set_if(tostring(Entity.Address), EntityType == "ip")
        """
    )

    # Enrich user entities with SpyCloud
    spycloud_enrichment = {}
    if entities:
        ent = entities[0]
        users = ent.get("Users") or []
        if isinstance(users, str):
            try:
                users = json.loads(users)
            except (json.JSONDecodeError, TypeError):
                users = []
        for user in users[:5]:
            user_str = str(user)
            if "@" in user_str:
                encoded = requests.utils.quote(user_str, safe="")
                data = call_spycloud_api(f"/breach/data/emails/{encoded}")
                results = data.get("results", [])
                spycloud_enrichment[user_str] = {
                    "hits": data.get("hits", 0),
                    "maxSeverity": max(
                        (r.get("severity", 0) for r in results), default=0
                    ),
                    "hasPlaintext": any(
                        r.get("password_plaintext") for r in results
                    ),
                    "infectedDevices": len(
                        set(
                            r.get("infected_machine_id", "")
                            for r in results
                            if r.get("infected_machine_id")
                        )
                    ),
                }

    entity_summary = entities[0] if entities else {}

    user_prompt = f"""Generate a comprehensive analyst incident report:

**Incident #{incident_num}:**
{json.dumps(incident, indent=2, default=str)}

**Associated Alerts ({len(alerts)}):**
{json.dumps(alerts[:10], indent=2, default=str)}

**Entities:**
{json.dumps(entity_summary, indent=2, default=str)}

**SpyCloud Enrichment:**
{json.dumps(spycloud_enrichment, indent=2, default=str)}

Generate a detailed incident report with:
1. Incident Summary (what happened, when, who's affected)
2. Alert Timeline & Kill Chain Analysis
3. Entity Analysis (users, devices, IPs with SpyCloud enrichment)
4. SpyCloud Dark Web Context (exposure history, credential risk)
5. MITRE ATT&CK Mapping (techniques observed with evidence)
6. Impact Assessment (scope, business impact, data at risk)
7. Remediation Actions (completed and recommended)
8. Root Cause Analysis (if determinable)
9. Lessons Learned & Prevention Recommendations
10. Appendix: IOCs and Detection Signatures"""

    ai_report = call_ai(ANALYST_SYSTEM_PROMPT, user_prompt, max_tokens=4096)

    return func.HttpResponse(
        json.dumps(
            {
                "incidentId": str(incident_num),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "incident": incident,
                "alertCount": len(alerts),
                "entityCount": {
                    "users": len(entity_summary.get("Users", []))
                    if isinstance(entity_summary.get("Users"), list)
                    else 0,
                    "hosts": len(entity_summary.get("Hosts", []))
                    if isinstance(entity_summary.get("Hosts"), list)
                    else 0,
                    "ips": len(entity_summary.get("IPs", []))
                    if isinstance(entity_summary.get("IPs"), list)
                    else 0,
                },
                "spycloudEnrichment": spycloud_enrichment,
                "aiReport": ai_report,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/remediation-plan", methods=["POST"])
def ai_remediation_plan(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate AI-powered remediation and prevention plan.

    Request body:
        {"email": "user@domain.com", "includePrevention": true}

    Returns:
        Detailed remediation plan with immediate, short-term, and long-term actions.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    email = body.get("email", "").strip()
    if not email or "@" not in email:
        return func.HttpResponse(
            json.dumps({"error": "Valid email address required"}),
            status_code=400,
            mimetype="application/json",
        )

    encoded_email = requests.utils.quote(email, safe="")
    data = call_spycloud_api(f"/breach/data/emails/{encoded_email}")
    exposures = data.get("results", [])

    # Check remediation status from Sentinel audit log
    remediation_status = query_log_analytics(
        f"""
        SpyCloudEnrichmentAudit_CL
        | where email_s =~ "{email}"
        | where action_s in (
            "ForcePasswordReset", "RevokeSessions",
            "IsolateDevice", "DisableAccount"
        )
        | summarize
            Actions=make_set(action_s),
            LastAction=max(TimeGenerated)
        """
    )

    max_sev = max((e.get("severity", 0) for e in exposures), default=0)
    device_count = len(
        set(
            e.get("infected_machine_id", "")
            for e in exposures
            if e.get("infected_machine_id")
        )
    )

    user_prompt = f"""Create a detailed remediation and prevention plan for:

**User:** {email}
**Exposure Count:** {data.get('hits', 0)}
**Max Severity:** {max_sev}
**Has Plaintext Passwords:** {any(e.get('password_plaintext') for e in exposures)}
**Infected Devices:** {device_count}

**Existing Remediation Actions:**
{json.dumps(remediation_status, indent=2, default=str) if remediation_status else "No remediation actions found in audit log."}

**Sample Exposures:**
{json.dumps(exposures[:5], indent=2, default=str)}

Generate a comprehensive plan with:
1. Immediate Actions (within 1 hour) — password reset, session revoke, device isolation
2. Short-term Remediation (within 24 hours) — credential audit, MFA enforcement
3. Medium-term Hardening (within 1 week) — policy updates, monitoring rules
4. Long-term Prevention Strategy (ongoing) — security awareness, architectural changes
5. Specific Microsoft Configuration Changes:
   - Entra ID: Conditional Access policies, MFA requirements, risk policies
   - Defender for Endpoint: device isolation, AV scans, investigation packages
   - Intune: compliance policies, app protection policies
   - Sentinel: analytics rules, automation rules, workbook alerts
6. Monitoring & Detection Rules (KQL queries for ongoing monitoring)
7. User Communication Template (notification email to affected user)
8. Verification Checklist (how to confirm remediation is complete)"""

    ai_report = call_ai(ANALYST_SYSTEM_PROMPT, user_prompt, max_tokens=4096)

    return func.HttpResponse(
        json.dumps(
            {
                "email": email,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "exposureCount": data.get("hits", 0),
                "maxSeverity": max_sev,
                "infectedDevices": device_count,
                "remediationStatus": remediation_status,
                "aiPlan": ai_report,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/health", methods=["GET"])
def ai_health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check for AI investigation engine."""
    status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "13.12.0",
        "aiProvider": AI_PROVIDER,
        "aiConfigured": bool(_get_ai_headers()),
        "spycloudConfigured": bool(SPYCLOUD_API_KEY),
        "sentinelConfigured": bool(LOG_ANALYTICS_WORKSPACE_ID),
        "graphConfigured": bool(GRAPH_TENANT_ID and GRAPH_CLIENT_ID),
        "endpoints": [
            "POST /api/ai/investigate — Full AI-powered investigation",
            "POST /api/ai/executive-report — Board-level executive report",
            "POST /api/ai/threat-research — Threat intelligence research",
            "POST /api/ai/incident-report — Sentinel incident analysis",
            "POST /api/ai/remediation-plan — Remediation & prevention plan",
            "GET  /api/ai/health — This endpoint",
        ],
    }
    return func.HttpResponse(
        json.dumps(status), mimetype="application/json"
    )
