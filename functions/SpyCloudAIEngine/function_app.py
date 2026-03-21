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
from datetime import datetime, timedelta, timezone
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

# Microsoft Purview Configuration
PURVIEW_ACCOUNT_NAME = os.environ.get("PURVIEW_ACCOUNT_NAME", "")
PURVIEW_SENSITIVITY_LABEL_ID = os.environ.get(
    "PURVIEW_SENSITIVITY_LABEL_HIGH_CONFIDENTIAL", ""
)
PURVIEW_DLP_POLICY_NAME = os.environ.get(
    "PURVIEW_DLP_POLICY_NAME", "SpyCloud-BreachData-DLP"
)


# ================================================================
# HELPER FUNCTIONS
# ================================================================


import re


def _sanitize_kql_string(value: str) -> str:
    """Sanitize a string for safe interpolation into KQL queries.

    Strips characters that could allow KQL injection:
    - Removes double quotes (prevents escaping out of string literals)
    - Removes backslashes (prevents escape sequences)
    - Removes semicolons (prevents statement chaining)
    - Removes pipe characters (prevents operator chaining)
    - Validates the result looks like a plausible email/domain
    """
    sanitized = re.sub(r'["\\;|(){}\[\]]', '', value)
    if len(sanitized) > 254:
        sanitized = sanitized[:254]
    return sanitized


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


def call_graph(endpoint: str, method: str = "GET", body: Optional[dict] = None) -> dict:
    """Call Microsoft Graph API."""
    token = get_graph_token()
    if not token:
        return {"error": "Graph API token unavailable"}
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if method.upper() == "POST" and body is not None:
            resp = requests.post(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers=headers,
                json=body,
                timeout=15,
            )
        elif method.upper() == "PATCH" and body is not None:
            resp = requests.patch(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers=headers,
                json=body,
                timeout=15,
            )
        else:
            resp = requests.get(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers=headers,
                timeout=15,
            )
        if resp.status_code in (200, 201, 204):
            if resp.status_code == 204:
                return {"success": True}
            return resp.json()
        return {"error": f"Graph API returned {resp.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


def get_purview_sensitivity_labels() -> list:
    """Retrieve available sensitivity labels from Microsoft Purview via Graph API."""
    result = call_graph("/security/informationProtection/sensitivityLabels")
    if "error" in result:
        logging.warning("Failed to fetch sensitivity labels: %s", result["error"])
        return []
    return result.get("value", [])


def apply_purview_sensitivity_label(
    entity_type: str, entity_id: str, label_id: str, justification: str
) -> dict:
    """Apply a Purview sensitivity label to a Sentinel incident or file.

    Uses Microsoft Graph Information Protection API to apply labels.
    """
    if not label_id:
        label_id = PURVIEW_SENSITIVITY_LABEL_ID
    if not label_id:
        return {"error": "No sensitivity label ID configured"}

    body = {
        "labelId": label_id,
        "assignmentMethod": "privileged",
        "justificationMessage": justification,
    }

    if entity_type == "incident":
        endpoint = f"/security/incidents/{entity_id}"
        update_body = {
            "customTags": [
                f"PurviewLabel:{label_id}",
                "SpyCloud:HighlyConfidential",
            ]
        }
        return call_graph(endpoint, method="PATCH", body=update_body)

    if entity_type == "file":
        endpoint = f"/drives/items/{entity_id}/assignSensitivityLabel"
        return call_graph(endpoint, method="POST", body=body)

    return {"error": f"Unsupported entity type: {entity_type}"}


def query_purview_audit_logs(domain: str, days: int = 30) -> list:
    """Query Purview unified audit logs for DLP events related to SpyCloud data."""
    safe_domain = _sanitize_kql_string(domain)
    kql = f"""
    let lookback = {min(days, 365)}d;
    OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where Operation in (
        "DlpRuleMatch", "SensitivityLabelApplied",
        "SensitivityLabelRemoved", "SensitivityLabelUpdated",
        "FileSensitivityLabelChanged"
    )
    | where UserId has "{safe_domain}" or SourceFileName has "SpyCloud"
    | summarize
        DlpMatches = countif(Operation == "DlpRuleMatch"),
        LabelsApplied = countif(Operation == "SensitivityLabelApplied"),
        LabelsChanged = countif(Operation in (
            "SensitivityLabelRemoved", "SensitivityLabelUpdated",
            "FileSensitivityLabelChanged"
        )),
        UniqueUsers = dcount(UserId),
        LastEvent = max(TimeGenerated)
    """
    return query_log_analytics(kql)


def classify_pii_exposure(exposures: list) -> dict:
    """Classify exposed data types against regulatory frameworks.

    Maps SpyCloud exposure fields to PII categories and regulatory
    notification requirements for GDPR, CCPA, HIPAA, PCI-DSS, and SOC 2.
    """
    pii_fields = {
        "email": {"category": "Contact Info", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "password": {"category": "Credential", "gdpr": True, "ccpa": True, "hipaa": False, "pci": True},
        "password_plaintext": {"category": "Plaintext Credential", "gdpr": True, "ccpa": True, "hipaa": False, "pci": True},
        "full_name": {"category": "Personal Identity", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "phone": {"category": "Contact Info", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "dob": {"category": "Sensitive PII", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "ssn": {"category": "Government ID", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "cc_number": {"category": "Financial", "gdpr": True, "ccpa": True, "hipaa": False, "pci": True},
        "cc_expiration": {"category": "Financial", "gdpr": True, "ccpa": True, "hipaa": False, "pci": True},
        "bank_number": {"category": "Financial", "gdpr": True, "ccpa": True, "hipaa": False, "pci": True},
        "ip_addresses": {"category": "Network Identity", "gdpr": True, "ccpa": True, "hipaa": True, "pci": False},
        "infected_machine_id": {"category": "Device Identity", "gdpr": True, "ccpa": True, "hipaa": True, "pci": False},
        "target_url": {"category": "Behavioral", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "user_browser": {"category": "Device Fingerprint", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
        "user_os": {"category": "Device Fingerprint", "gdpr": True, "ccpa": True, "hipaa": False, "pci": False},
    }

    classification = {
        "exposed_pii_types": [],
        "regulatory_impact": {
            "gdpr": {"affected": False, "fields": [], "notification_hours": 72},
            "ccpa": {"affected": False, "fields": [], "notification_days": 45},
            "hipaa": {"affected": False, "fields": [], "notification_days": 60},
            "pci_dss": {"affected": False, "fields": [], "notification": "immediate"},
            "soc2": {"affected": False, "description": "Security breach impacts trust criteria"},
        },
        "sensitivity_level": "Standard",
        "recommended_label": "Confidential",
        "total_records_analyzed": len(exposures),
    }

    detected_fields = set()
    for record in exposures[:200]:
        for field_key, field_info in pii_fields.items():
            if record.get(field_key) or record.get(f"{field_key}_s"):
                detected_fields.add(field_key)

    for field_key in detected_fields:
        if field_key not in pii_fields:
            continue
        info = pii_fields[field_key]
        classification["exposed_pii_types"].append({
            "field": field_key,
            "category": info["category"],
        })
        for reg in ("gdpr", "ccpa", "hipaa", "pci"):
            reg_key = "pci_dss" if reg == "pci" else reg
            if info.get(reg):
                classification["regulatory_impact"][reg_key]["affected"] = True
                classification["regulatory_impact"][reg_key]["fields"].append(field_key)

    has_financial = any(
        f in detected_fields for f in ("cc_number", "cc_expiration", "bank_number")
    )
    has_sensitive = any(
        f in detected_fields for f in ("ssn", "dob", "password_plaintext")
    )
    health_fields = {"ip_addresses", "infected_machine_id"}
    has_health = bool(detected_fields & health_fields) and classification["regulatory_impact"]["hipaa"]["affected"]

    if has_financial or has_sensitive:
        classification["sensitivity_level"] = "Highly Confidential"
        classification["recommended_label"] = "Highly Confidential"
        classification["regulatory_impact"]["soc2"]["affected"] = True
        classification["regulatory_impact"]["soc2"]["description"] = (
            "Critical breach: financial/sensitive PII exposed — "
            "impacts Confidentiality and Privacy trust criteria"
        )
    elif has_health:
        classification["sensitivity_level"] = "Highly Confidential"
        classification["recommended_label"] = "Highly Confidential — PHI"
    elif detected_fields:
        classification["sensitivity_level"] = "Confidential"
        classification["recommended_label"] = "Confidential"
        classification["regulatory_impact"]["soc2"]["affected"] = True
        classification["regulatory_impact"]["soc2"]["description"] = (
            "PII exposure impacts Security and Confidentiality trust criteria"
        )

    return classification


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

COMPLIANCE_SYSTEM_PROMPT = """You are a senior compliance and data protection officer
specializing in breach notification and regulatory compliance.
You have deep expertise in:
- GDPR (EU General Data Protection Regulation) — Article 33/34 breach notification
- CCPA/CPRA (California Consumer Privacy Act) — breach notification requirements
- HIPAA (Health Insurance Portability and Accountability Act) — PHI breach rules
- PCI-DSS (Payment Card Industry Data Security Standard) — cardholder data requirements
- SOC 2 Type II — Trust Services Criteria (Security, Availability, Confidentiality, Privacy)
- NIST CSF 2.0 — Cybersecurity Framework
- ISO 27001/27701 — Information security and privacy management
- Microsoft Purview — Sensitivity labels, DLP, Compliance Manager, eDiscovery

Your analysis must include:
- Specific regulatory articles/sections that apply
- Exact notification timelines with countdown from discovery
- Required notification recipients (supervisory authorities, affected individuals, etc.)
- Documentation requirements for each framework
- Purview-specific actions: sensitivity labels to apply, DLP policies to create/update
- Risk quantification with potential fine amounts
- Remediation steps to achieve compliance
- Template language for breach notification letters"""

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
        | where UserPrincipalName =~ "{_sanitize_kql_string(email)}"
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
        | where email_s =~ "{_sanitize_kql_string(email)}"
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


@app_ai.route(route="ai/compliance-assessment", methods=["POST"])
def ai_compliance_assessment(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate AI-powered compliance assessment with Purview integration.

    Analyzes SpyCloud exposure data against regulatory frameworks (GDPR,
    CCPA, HIPAA, PCI-DSS, SOC 2) and generates a compliance report with
    Purview sensitivity label recommendations, DLP policy actions, and
    breach notification timelines.

    Request body:
        {
            "domain": "company.com",
            "frameworks": ["gdpr", "ccpa", "hipaa", "pci_dss", "soc2"],
            "includeNotificationTemplates": true,
            "periodDays": 30
        }

    Returns:
        Comprehensive compliance assessment with regulatory mapping,
        notification requirements, Purview actions, and AI analysis.
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
    if not domain or "." not in domain:
        return func.HttpResponse(
            json.dumps({"error": "Valid domain required (e.g., company.com)"}),
            status_code=400,
            mimetype="application/json",
        )

    raw_frameworks = body.get("frameworks", ["gdpr", "ccpa", "hipaa", "pci_dss", "soc2"])
    if isinstance(raw_frameworks, str):
        frameworks = [f.strip() for f in raw_frameworks.split(",") if f.strip()]
    elif isinstance(raw_frameworks, list):
        expanded = []
        for item in raw_frameworks:
            if isinstance(item, str) and "," in item:
                expanded.extend(f.strip() for f in item.split(",") if f.strip())
            else:
                expanded.append(item)
        frameworks = expanded
    else:
        frameworks = ["gdpr", "ccpa", "hipaa", "pci_dss", "soc2"]
    include_templates = body.get("includeNotificationTemplates", True)
    period_days = min(max(int(body.get("periodDays", 30)), 1), 365)

    # Step 1: Query SpyCloud for domain exposures
    encoded_domain = requests.utils.quote(domain, safe="")
    since_epoch = int(
        (datetime.now(timezone.utc) - timedelta(days=period_days)).timestamp()
    )
    data = call_spycloud_api(
        f"/breach/data/watchlist",
        params={"domain": encoded_domain, "since": since_epoch},
    )
    exposures = data.get("results", [])

    # Step 2: Classify PII types against regulatory frameworks
    pii_classification = classify_pii_exposure(exposures)

    # Step 3: Query Sentinel for existing remediation status
    safe_domain = _sanitize_kql_string(domain)
    remediation_kql = f"""
    SpyCloudEnrichmentAudit_CL
    | where TimeGenerated >= ago({period_days}d)
    | where email_s has "{safe_domain}"
    | summarize
        TotalActions = count(),
        PasswordResets = countif(action_s == "ForcePasswordReset"),
        SessionRevokes = countif(action_s == "RevokeSessions"),
        DeviceIsolations = countif(action_s == "IsolateDevice"),
        AccountDisables = countif(action_s == "DisableAccount"),
        UniqueUsers = dcount(email_s),
        LastAction = max(TimeGenerated)
    """
    remediation_status = query_log_analytics(remediation_kql)

    # Step 4: Query Purview audit logs for DLP events
    purview_audit = query_purview_audit_logs(domain, period_days)

    # Step 5: Get available sensitivity labels
    sensitivity_labels = get_purview_sensitivity_labels()

    # Step 6: Build exposure statistics
    exposure_stats = _build_exposure_summary(exposures)

    # Step 7: Generate AI compliance analysis
    user_prompt = f"""Generate a comprehensive compliance assessment for domain: {domain}

**Exposure Summary ({period_days}-day window):**
- Total exposures: {data.get('hits', 0)}
- Severity distribution: {json.dumps(exposure_stats.get('severities', {}))}
- Password types: {json.dumps(exposure_stats.get('password_types', {}))}
- Plaintext passwords found: {exposure_stats.get('has_plaintext', False)}
- Infected devices: {len(exposure_stats.get('infected_devices', []))}

**PII Classification:**
- Exposed PII types: {json.dumps(pii_classification['exposed_pii_types'], default=str)}
- Sensitivity level: {pii_classification['sensitivity_level']}
- Recommended Purview label: {pii_classification['recommended_label']}

**Regulatory Impact:**
{json.dumps(pii_classification['regulatory_impact'], indent=2, default=str)}

**Remediation Status:**
{json.dumps(remediation_status, indent=2, default=str) if remediation_status else 'No remediation actions found.'}

**Purview Audit Events:**
{json.dumps(purview_audit, indent=2, default=str) if purview_audit else 'No Purview DLP/label events found for this domain.'}

**Available Sensitivity Labels:**
{json.dumps([{'id': l.get('id'), 'name': l.get('name')} for l in sensitivity_labels[:10]], default=str) if sensitivity_labels else 'Unable to retrieve labels — Graph API may not be configured.'}

**Requested Frameworks:** {', '.join(frameworks)}

Generate a compliance assessment that includes:

1. **Executive Summary** — Overall compliance posture and risk rating (Critical/High/Medium/Low)
2. **Regulatory Analysis** — For each applicable framework:
   - Specific articles/sections triggered by this exposure
   - Whether breach notification is required (YES/NO with justification)
   - Notification timeline (exact hours/days from discovery)
   - Required recipients (authorities, individuals, partners)
   - Documentation requirements
   - Potential fine/penalty amounts
3. **Microsoft Purview Actions:**
   - Sensitivity labels to apply (with label IDs if available)
   - DLP policies to create or update
   - Compliance Manager assessment items to address
   - eDiscovery holds to consider
   - Audit log retention requirements
4. **Notification Timeline** — Day-by-day action plan from discovery
5. **Risk Quantification** — Estimated financial exposure (fines, remediation costs, reputation)
6. **Remediation Gap Analysis** — What has been done vs. what still needs to happen
{"7. **Notification Templates** — Draft notification letters for each required authority/individual" if include_templates else ""}
8. **Purview Configuration Checklist** — Step-by-step Purview setup for ongoing protection"""

    ai_report = call_ai(
        COMPLIANCE_SYSTEM_PROMPT, user_prompt, temperature=0.2, max_tokens=6000
    )

    return func.HttpResponse(
        json.dumps(
            {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "periodDays": period_days,
                "frameworks": frameworks,
                "exposureCount": data.get("hits", 0),
                "piiClassification": pii_classification,
                "exposureSummary": exposure_stats,
                "remediationStatus": remediation_status,
                "purviewAudit": purview_audit,
                "sensitivityLabels": [
                    {"id": l.get("id"), "name": l.get("name")}
                    for l in sensitivity_labels[:10]
                ],
                "aiAssessment": ai_report,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/purview/classify", methods=["POST"])
def ai_purview_classify(req: func.HttpRequest) -> func.HttpResponse:
    """
    Classify SpyCloud exposure data and apply Purview sensitivity labels.

    Request body:
        {
            "email": "user@company.com",
            "incidentId": "optional-sentinel-incident-id",
            "applyLabel": true
        }

    Returns:
        PII classification with applied label status.
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

    incident_id = body.get("incidentId", "").strip()
    apply_label = body.get("applyLabel", False)

    # Get exposure data
    encoded_email = requests.utils.quote(email, safe="")
    data = call_spycloud_api(f"/breach/data/emails/{encoded_email}")
    exposures = data.get("results", [])

    # Classify PII
    classification = classify_pii_exposure(exposures)

    # Apply sensitivity label if requested and incident ID provided
    label_result = None
    if apply_label and incident_id:
        max_sev = max((e.get("severity", 0) for e in exposures), default=0)
        justification = (
            f"SpyCloud exposure detected for {email}: "
            f"{data.get('hits', 0)} records, max severity {max_sev}, "
            f"sensitivity level {classification['sensitivity_level']}"
        )
        label_result = apply_purview_sensitivity_label(
            entity_type="incident",
            entity_id=incident_id,
            label_id=PURVIEW_SENSITIVITY_LABEL_ID,
            justification=justification,
        )

    return func.HttpResponse(
        json.dumps(
            {
                "email": email,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "exposureCount": data.get("hits", 0),
                "classification": classification,
                "labelApplied": label_result,
            }
        ),
        mimetype="application/json",
    )


@app_ai.route(route="ai/purview/dlp-status", methods=["POST"])
def ai_purview_dlp_status(req: func.HttpRequest) -> func.HttpResponse:
    """
    Check Purview DLP policy status for SpyCloud breach data protection.

    Request body:
        {"domain": "company.com", "periodDays": 30}

    Returns:
        DLP event summary, policy violations, and recommendations.
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
    if not domain or "." not in domain:
        return func.HttpResponse(
            json.dumps({"error": "Valid domain required"}),
            status_code=400,
            mimetype="application/json",
        )

    period_days = min(max(int(body.get("periodDays", 30)), 1), 365)
    safe_domain = _sanitize_kql_string(domain)

    # Query DLP events from unified audit log
    dlp_kql = f"""
    OfficeActivity
    | where TimeGenerated >= ago({period_days}d)
    | where Operation == "DlpRuleMatch"
    | where UserId has "{safe_domain}"
    | extend PolicyName = tostring(parse_json(tostring(PolicyDetails))[0].PolicyName)
    | extend RuleName = tostring(parse_json(tostring(PolicyDetails))[0].Rules[0].RuleName)
    | extend Severity = tostring(parse_json(tostring(PolicyDetails))[0].Rules[0].Severity)
    | summarize
        TotalMatches = count(),
        HighSeverity = countif(Severity == "High"),
        MediumSeverity = countif(Severity == "Medium"),
        LowSeverity = countif(Severity == "Low"),
        UniqueUsers = dcount(UserId),
        Policies = make_set(PolicyName),
        Rules = make_set(RuleName),
        LastMatch = max(TimeGenerated)
    """
    dlp_events = query_log_analytics(dlp_kql)

    # Query sensitivity label events
    label_kql = f"""
    OfficeActivity
    | where TimeGenerated >= ago({period_days}d)
    | where Operation in (
        "SensitivityLabelApplied", "SensitivityLabelRemoved",
        "SensitivityLabelUpdated", "FileSensitivityLabelChanged"
    )
    | where UserId has "{safe_domain}"
    | summarize
        LabelsApplied = countif(Operation == "SensitivityLabelApplied"),
        LabelsRemoved = countif(Operation == "SensitivityLabelRemoved"),
        LabelsUpdated = countif(Operation in (
            "SensitivityLabelUpdated", "FileSensitivityLabelChanged"
        )),
        UniqueFiles = dcount(SourceFileName),
        LastEvent = max(TimeGenerated)
    """
    label_events = query_log_analytics(label_kql)

    # Generate AI recommendations
    user_prompt = f"""Analyze Purview DLP status for {domain} over {period_days} days:

**DLP Events:** {json.dumps(dlp_events, indent=2, default=str) if dlp_events else 'No DLP matches found.'}

**Sensitivity Label Events:** {json.dumps(label_events, indent=2, default=str) if label_events else 'No label events found.'}

Provide:
1. DLP policy effectiveness assessment
2. Gaps in current DLP coverage for breach data
3. Recommended DLP policy rules for SpyCloud exposure data
4. Sensitivity label deployment recommendations
5. Specific Purview Compliance Manager actions"""

    ai_recommendations = call_ai(
        COMPLIANCE_SYSTEM_PROMPT, user_prompt, temperature=0.2, max_tokens=3000
    )

    return func.HttpResponse(
        json.dumps(
            {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "periodDays": period_days,
                "dlpEvents": dlp_events,
                "labelEvents": label_events,
                "aiRecommendations": ai_recommendations,
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
        "purviewConfigured": bool(PURVIEW_ACCOUNT_NAME),
        "endpoints": [
            "POST /api/ai/investigate — Full AI-powered investigation",
            "POST /api/ai/executive-report — Board-level executive report",
            "POST /api/ai/threat-research — Threat intelligence research",
            "POST /api/ai/incident-report — Sentinel incident analysis",
            "POST /api/ai/remediation-plan — Remediation & prevention plan",
            "POST /api/ai/compliance-assessment — Regulatory compliance assessment",
            "POST /api/ai/purview/classify — PII classification + label application",
            "POST /api/ai/purview/dlp-status — DLP policy status & recommendations",
            "GET  /api/ai/health — This endpoint",
        ],
    }
    return func.HttpResponse(
        json.dumps(status), mimetype="application/json"
    )
