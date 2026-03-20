"""
SpyCloud Sentinel Enrichment Function App
==========================================
Azure Function App providing:
- Identity Risk Score computation (0-100)
- SpyCloud API enrichment (email, domain, IP, device, cookies)
- Full multi-product investigation orchestration
- Entra ID custom security attribute push (risk score → CA policy)
- Daily/executive reporting data
- Health checks and usage auditing

All API keys stored in Azure Key Vault. All actions logged to
SpyCloudEnrichmentAudit_CL via Log Analytics Data Collector API.
"""

import azure.functions as func
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

try:
    from azure.data.tables import TableServiceClient
    _HAS_TABLE_STORAGE = True
except ImportError:
    _HAS_TABLE_STORAGE = False

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# ================================================================
# CONFIGURATION
# ================================================================

SPYCLOUD_BASE_URL = "https://api.spycloud.io/enterprise-v2"
SPYCLOUD_INVESTIGATIONS_URL = "https://api.spycloud.io/investigations-v2"

# Key Vault secret names (resolved at runtime via app settings referencing KV)
ENV_KEYS = {
    "enterprise": "SPYCLOUD_ENTERPRISE_KEY",
    "compass": "SPYCLOUD_COMPASS_KEY",
    "sip": "SPYCLOUD_SIP_KEY",
    "investigations": "SPYCLOUD_INVESTIGATIONS_KEY",
    "idlink": "SPYCLOUD_IDLINK_KEY",
}

# Rate limiting — persisted to Azure Table Storage when available, file-based fallback
DAILY_LIMIT = int(os.environ.get("ENRICHMENT_DAILY_LIMIT", "200"))
_RATE_LIMIT_TABLE = "SpyCloudRateLimits"
_RATE_LIMIT_FILE = "/tmp/spycloud_rate_limits.json"
_rate_limit_lock = threading.Lock()
_cached_table_client = None
_table_client_initialized = False


def _get_table_client():
    """Return Azure Table Storage client if connection string is configured.

    Caches the client after first successful creation to avoid redundant
    create_table_if_not_exists HTTP calls on every invocation.
    """
    global _cached_table_client, _table_client_initialized
    if _table_client_initialized:
        return _cached_table_client
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
    if conn_str and _HAS_TABLE_STORAGE:
        try:
            svc = TableServiceClient.from_connection_string(conn_str)
            svc.create_table_if_not_exists(_RATE_LIMIT_TABLE)
            _cached_table_client = svc.get_table_client(_RATE_LIMIT_TABLE)
            _table_client_initialized = True
            return _cached_table_client
        except Exception as e:
            logging.warning(f"Table Storage unavailable, using file fallback: {e}")
    _table_client_initialized = True
    return None


def _get_call_count(today: str) -> int:
    """Read today's call count from Table Storage or local file."""
    tc = _get_table_client()
    if tc:
        try:
            entity = tc.get_entity(partition_key="rate_limit", row_key=today)
            return int(entity.get("count", 0))
        except Exception:
            return 0
    # File-based fallback
    try:
        with open(_RATE_LIMIT_FILE, "r") as f:
            data = json.load(f)
        return data.get(today, 0)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0


def _increment_call_count(today: str) -> None:
    """Increment today's call count in Table Storage or local file."""
    tc = _get_table_client()
    if tc:
        try:
            current = _get_call_count(today)
            tc.upsert_entity({
                "PartitionKey": "rate_limit",
                "RowKey": today,
                "count": current + 1,
            })
            return
        except Exception as e:
            logging.warning(f"Table Storage write failed: {e}")
    # File-based fallback
    try:
        with open(_RATE_LIMIT_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[today] = data.get(today, 0) + 1
    with open(_RATE_LIMIT_FILE, "w") as f:
        json.dump(data, f)

LOG_ANALYTICS_WORKSPACE_ID = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID", "")
LOG_ANALYTICS_KEY = os.environ.get("LOG_ANALYTICS_SHARED_KEY", "")


def _query_log_analytics(workspace_id: str, query: str) -> list:
    """Execute a KQL query against Log Analytics using the REST API.

    Uses the Log Analytics Query API with shared key authentication.
    Returns the rows as a list of dicts (column_name -> value).
    """
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {"Content-Type": "application/json"}

    # Prefer managed identity via azure-identity if available
    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
        token = credential.get_token("https://api.loganalytics.io/.default")
        headers["Authorization"] = f"Bearer {token.token}"
    except Exception:
        # Managed identity unavailable — Log Analytics REST API requires OAuth
        # bearer token; shared key auth uses HMAC-SHA256 signing which is not
        # supported here.  Return empty when no credential is available.
        logging.warning("DefaultAzureCredential unavailable; Log Analytics queries require "
                        "managed identity or a service principal. Configure a system-assigned "
                        "managed identity on the Function App with Log Analytics Reader role.")
        return []

    try:
        resp = requests.post(url, headers=headers, json={"query": query.strip()}, timeout=60)
        if resp.status_code != 200:
            logging.error(f"Log Analytics query failed: {resp.status_code} {resp.text[:200]}")
            return []
        body = resp.json()
        tables = body.get("tables", [])
        if not tables:
            return []
        columns = [col["name"] for col in tables[0].get("columns", [])]
        rows = tables[0].get("rows", [])
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logging.error(f"Log Analytics query error: {e}")
        return []

# Email validation regex (RFC 5322 simplified)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def _validate_email(email: str) -> bool:
    """Validate email format."""
    return bool(email and _EMAIL_RE.match(email) and len(email) <= 254)


def get_api_key(product: str = "enterprise") -> Optional[str]:
    """Get SpyCloud API key from environment (Key Vault reference)."""
    env_var = ENV_KEYS.get(product, ENV_KEYS["enterprise"])
    key = os.environ.get(env_var, "")
    return key if key else None


def call_spycloud(endpoint: str, product: str = "enterprise",
                   params: dict = None, timeout: int = 30) -> dict:
    """Call SpyCloud API with rate limiting, retry, and audit logging."""
    key = get_api_key(product)
    if not key:
        return {"error": f"No API key configured for {product}", "hits": 0, "results": []}

    # Rate limiting (thread-safe)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _rate_limit_lock:
        if _get_call_count(today) >= DAILY_LIMIT:
            return {"error": "Daily API call limit reached", "hits": 0, "results": []}

    base = SPYCLOUD_INVESTIGATIONS_URL if "investigations" in endpoint else SPYCLOUD_BASE_URL
    url = f"{base}{endpoint}"
    headers = {"X-API-Key": key, "Accept": "application/json"}

    for attempt in range(3):
        try:
            start = time.time()
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            duration_ms = int((time.time() - start) * 1000)
            with _rate_limit_lock:
                _increment_call_count(today)

            if resp.status_code == 200:
                data = resp.json()
                data["_meta"] = {
                    "statusCode": 200,
                    "durationMs": duration_ms,
                    "product": product,
                    "endpoint": endpoint,
                }
                return data
            elif resp.status_code == 429:
                wait = min(2 ** attempt * 10, 60)
                logging.warning(f"Rate limited on {endpoint}, waiting {wait}s")
                time.sleep(wait)
                continue
            else:
                return {
                    "error": f"API returned {resp.status_code}",
                    "hits": 0, "results": [],
                    "_meta": {"statusCode": resp.status_code, "durationMs": duration_ms}
                }
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout on {endpoint}, attempt {attempt + 1}")
            continue
        except Exception as e:
            logging.error(f"Error calling {endpoint}: {e}")
            return {"error": str(e), "hits": 0, "results": []}

    return {"error": "Max retries exceeded", "hits": 0, "results": []}


# ================================================================
# RISK SCORE COMPUTATION
# ================================================================

def compute_risk_score(exposures: list, cookies: list = None,
                       devices: list = None, remediations: list = None) -> dict:
    """
    Compute SpyCloud Identity Risk Score (0-100).

    Components:
      Severity (0-30), Credential (0-25), Session (0-25),
      Device (0-10), Temporal (0.2-1.0x), Remediation (-20 to 0)
    """
    if not exposures:
        return {
            "riskScore": 0, "riskTier": "LOW",
            "components": {}, "topFactors": [], "recommendedActions": ["No exposures found"]
        }

    # Component 1: Severity (0-30)
    sev_counts = {2: 0, 5: 0, 20: 0, 25: 0}
    for e in exposures:
        s = e.get("severity", 0)
        if s >= 25:
            sev_counts[25] += 1
        elif s >= 20:
            sev_counts[20] += 1
        elif s >= 5:
            sev_counts[5] += 1
        else:
            sev_counts[2] += 1

    severity_score = min(30,
        min(sev_counts[2], 5) * 1 +
        min(sev_counts[5], 8) * 2 +
        min(sev_counts[20], 4) * 5 +
        min(sev_counts[25], 4) * 8
    )

    # Component 2: Credential (0-25)
    has_plaintext = any(e.get("password_plaintext") for e in exposures)
    has_weak_hash = any(e.get("password_type", "").lower() in ("md5", "sha1", "ntlm", "des")
                        for e in exposures)
    distinct_passwords = len(set(e.get("password_plaintext", "") for e in exposures if e.get("password_plaintext")))
    distinct_domains = len(set(e.get("target_domain", "") for e in exposures if e.get("target_domain")))

    credential_score = min(25,
        (15 if has_plaintext else (8 if has_weak_hash else 2)) +
        (5 if distinct_passwords > 1 else 0) +
        (5 if distinct_domains >= 3 else 0)
    )

    # Component 3: Session (0-25) — from SIP cookies
    session_score = 0
    if cookies:
        session_score = min(25, len(cookies) * 5)
        valid_cookies = [c for c in cookies
                         if c.get("cookie_expiry") and c["cookie_expiry"] > datetime.now(timezone.utc).isoformat()]
        if valid_cookies:
            session_score = min(25, session_score + 10)
        high_value = [c for c in cookies
                      if any(kw in str(c.get("domain", "")).lower()
                             for kw in ("okta", "azure", "aws", "vpn", "globalprotect", "admin"))]
        if high_value:
            session_score = min(25, session_score + 5)

    # Component 4: Device (0-10)
    device_score = 0
    if devices:
        unique_devices = len(set(d.get("infected_machine_id", "") for d in devices))
        device_score = min(10, unique_devices * 3)
    else:
        unique_machines = len(set(e.get("infected_machine_id", "") for e in exposures
                                   if e.get("infected_machine_id")))
        device_score = min(10, unique_machines * 3)

    # Component 5: Temporal decay
    most_recent = max(
        (e.get("spycloud_publish_date") or e.get("TimeGenerated") or "2020-01-01"
         for e in exposures),
        default="2020-01-01"
    )
    try:
        if isinstance(most_recent, str):
            recent_dt = datetime.fromisoformat(most_recent.replace("Z", "+00:00"))
        else:
            recent_dt = most_recent
        age_days = (datetime.now(timezone.utc) - recent_dt).days
    except Exception:
        age_days = 365

    if age_days <= 1:
        temporal = 1.0
    elif age_days <= 7:
        temporal = 0.9
    elif age_days <= 30:
        temporal = 0.7
    elif age_days <= 90:
        temporal = 0.5
    elif age_days <= 365:
        temporal = 0.3
    else:
        temporal = 0.2

    # Component 6: Remediation credit
    remediation_credit = 0
    if remediations:
        pw_resets = any(r.get("ForcedPasswordResetOnNextSignIn") for r in remediations)
        sessions_revoked = any(r.get("UserSessionsRevoked") for r in remediations)
        disabled = any(r.get("UserDisabled") for r in remediations)
        remediation_credit = -(
            (10 if pw_resets else 0) +
            (5 if sessions_revoked else 0) +
            (15 if disabled else 0)
        )

    # Final score
    raw = (severity_score + credential_score + session_score + device_score) * temporal + remediation_credit
    final_score = int(min(100, max(0, raw)))

    # Risk tier
    if final_score <= 20:
        tier = "LOW"
    elif final_score <= 40:
        tier = "MODERATE"
    elif final_score <= 60:
        tier = "HIGH"
    elif final_score <= 80:
        tier = "CRITICAL"
    else:
        tier = "EMERGENCY"

    # Top factors
    factors = []
    if has_plaintext:
        factors.append(f"Plaintext password available ({sev_counts[25] + sev_counts[20]} infostealer exposures)")
    if session_score > 10:
        factors.append(f"{len(cookies or [])} stolen session cookies detected")
    if device_score > 5:
        factors.append(f"{device_score // 3} infected devices identified")
    if distinct_domains >= 3:
        factors.append(f"Password reused across {distinct_domains} domains")
    if age_days <= 7:
        factors.append(f"Most recent exposure only {age_days} day(s) ago")
    if remediation_credit < 0:
        factors.append(f"Remediation actions taken (credit: {remediation_credit} points)")

    # Recommended actions
    actions = []
    if tier == "EMERGENCY":
        actions = [
            "IMMEDIATELY disable account",
            "Isolate ALL associated devices",
            "Engage incident response team",
            "Revoke all sessions and tokens",
            "Force password reset on re-enable"
        ]
    elif tier == "CRITICAL":
        actions = [
            "Force immediate password reset",
            "Revoke all active sessions",
            "Isolate infected devices",
            "Investigate sign-in logs for last 72 hours"
        ]
    elif tier == "HIGH":
        actions = [
            "Force password reset within 4 hours",
            "Revoke sessions for high-value apps",
            "Review device compliance status"
        ]
    elif tier == "MODERATE":
        actions = [
            "Schedule password reset within 24 hours",
            "Monitor sign-in activity",
            "Verify MFA enrollment"
        ]
    else:
        actions = ["Continue monitoring — no immediate action required"]

    return {
        "riskScore": final_score,
        "riskTier": tier,
        "components": {
            "severity": severity_score,
            "credential": credential_score,
            "session": session_score,
            "device": device_score,
            "temporalMultiplier": temporal,
            "remediationCredit": remediation_credit,
        },
        "exposureCount": len(exposures),
        "mostRecentExposure": most_recent,
        "exposureAgeDays": age_days,
        "topFactors": factors,
        "recommendedActions": actions,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
    }


# ================================================================
# FUNCTION ENDPOINTS
# ================================================================

@app.route(route="risk-score", methods=["POST"])
def risk_score(req: func.HttpRequest) -> func.HttpResponse:
    """Compute SpyCloud Identity Risk Score for a single user."""
    try:
        body = req.get_json()
        email = body.get("email", "")
        if not email:
            return func.HttpResponse(json.dumps({"error": "email required"}), status_code=400)
        if not _validate_email(email):
            return func.HttpResponse(json.dumps({"error": "invalid email format"}), status_code=400)

        # Fetch exposures from SpyCloud
        exposures_resp = call_spycloud(f"/breach/data/emails/{email}")
        exposures = exposures_resp.get("results", [])

        # Fetch SIP cookies if key available
        cookies = []
        if get_api_key("sip"):
            cookies_resp = call_spycloud(f"/sip/cookies/emails/{email}", product="sip")
            cookies = cookies_resp.get("results", [])

        # Compute score
        score = compute_risk_score(exposures, cookies=cookies)
        score["email"] = email

        return func.HttpResponse(json.dumps(score), mimetype="application/json")
    except Exception as e:
        logging.error(f"risk_score error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="risk-score/batch", methods=["POST"])
def risk_score_batch(req: func.HttpRequest) -> func.HttpResponse:
    """Batch risk scoring for up to 100 users (parallel execution)."""
    try:
        body = req.get_json()
        emails = body.get("emails", [])[:100]
        # Validate all emails up front
        invalid = [e for e in emails if not _validate_email(e)]
        if invalid:
            return func.HttpResponse(
                json.dumps({"error": f"Invalid email(s): {', '.join(invalid[:5])}"}),
                status_code=400,
            )

        def _score_one(email: str) -> dict:
            exposures_resp = call_spycloud(f"/breach/data/emails/{email}")
            exposures = exposures_resp.get("results", [])
            score = compute_risk_score(exposures)
            score["email"] = email
            return score

        results = []
        max_workers = min(len(emails), 10)
        if max_workers == 0:
            return func.HttpResponse(json.dumps({"results": [], "count": 0}),
                                      mimetype="application/json")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_score_one, em): em for em in emails}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({"email": futures[future], "error": str(exc)})

        return func.HttpResponse(json.dumps({"results": results, "count": len(results)}),
                                  mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="risk-score/domain", methods=["POST"])
def risk_score_domain(req: func.HttpRequest) -> func.HttpResponse:
    """Domain-level risk assessment with distribution and top risk users."""
    try:
        body = req.get_json()
        domain = body.get("domain", "")
        top_n = min(body.get("top", 20), 50)

        if not domain:
            return func.HttpResponse(json.dumps({"error": "domain required"}), status_code=400)

        domain_resp = call_spycloud(f"/breach/data/domains/{domain}", params={"limit": 1000})
        all_exposures = domain_resp.get("results", [])

        # Group by email
        by_email = {}
        for e in all_exposures:
            em = e.get("email", "unknown")
            by_email.setdefault(em, []).append(e)

        # Score each user
        user_scores = []
        distribution = {"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0, "EMERGENCY": 0}

        for em, exps in by_email.items():
            score = compute_risk_score(exps)
            score["email"] = em
            user_scores.append(score)
            distribution[score["riskTier"]] += 1

        user_scores.sort(key=lambda x: x["riskScore"], reverse=True)
        avg = sum(s["riskScore"] for s in user_scores) / len(user_scores) if user_scores else 0

        return func.HttpResponse(json.dumps({
            "domain": domain,
            "totalUsers": len(user_scores),
            "averageRiskScore": round(avg, 1),
            "distribution": distribution,
            "topRiskUsers": user_scores[:top_n],
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


# ================================================================
# ENRICHMENT ENDPOINTS
# ================================================================

@app.route(route="enrich/email", methods=["POST"])
def enrich_email(req: func.HttpRequest) -> func.HttpResponse:
    """Email enrichment with risk score."""
    try:
        body = req.get_json()
        email = body.get("email", "")
        if not _validate_email(email):
            return func.HttpResponse(json.dumps({"error": "invalid email format"}), status_code=400)
        resp = call_spycloud(f"/breach/data/emails/{email}")
        exposures = resp.get("results", [])
        score = compute_risk_score(exposures)

        return func.HttpResponse(json.dumps({
            "email": email,
            "hits": resp.get("hits", 0),
            "riskScore": score["riskScore"],
            "riskTier": score["riskTier"],
            "summary": f"{resp.get('hits', 0)} exposures found. Risk: {score['riskTier']} ({score['riskScore']}/100).",
            "topFactors": score["topFactors"],
            "recommendedActions": score["recommendedActions"],
            "results": exposures[:25],
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="enrich/domain", methods=["POST"])
def enrich_domain(req: func.HttpRequest) -> func.HttpResponse:
    """Domain enrichment — org-level exposure assessment."""
    try:
        body = req.get_json()
        domain = body.get("domain", "")
        resp = call_spycloud(f"/breach/data/domains/{domain}", params={"limit": 100})

        results = resp.get("results", [])
        severity_dist = {}
        for r in results:
            s = r.get("severity", 0)
            severity_dist[s] = severity_dist.get(s, 0) + 1

        return func.HttpResponse(json.dumps({
            "domain": domain,
            "hits": resp.get("hits", 0),
            "severityDistribution": severity_dist,
            "uniqueEmails": len(set(r.get("email", "") for r in results)),
            "results": results[:25],
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="enrich/ip", methods=["POST"])
def enrich_ip(req: func.HttpRequest) -> func.HttpResponse:
    """IP enrichment — infected devices at this IP."""
    try:
        body = req.get_json()
        ip = body.get("ip", "")
        resp = call_spycloud(f"/breach/data/ips/{ip}")
        return func.HttpResponse(json.dumps({
            "ip": ip,
            "hits": resp.get("hits", 0),
            "results": resp.get("results", [])[:25],
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="enrich/compass-device", methods=["POST"])
def enrich_compass_device(req: func.HttpRequest) -> func.HttpResponse:
    """Compass device enrichment — full blast radius."""
    try:
        body = req.get_json()
        machine_id = body.get("machineId", "")
        if not get_api_key("compass"):
            return func.HttpResponse(json.dumps({"error": "Compass API key not configured"}), status_code=400)

        resp = call_spycloud(f"/compass/devices/{machine_id}", product="compass")
        return func.HttpResponse(json.dumps({
            "machineId": machine_id,
            "hits": resp.get("hits", 0),
            "results": resp.get("results", []),
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="enrich/sip-cookies", methods=["POST"])
def enrich_sip_cookies(req: func.HttpRequest) -> func.HttpResponse:
    """SIP cookie enrichment — MFA bypass risk assessment."""
    try:
        body = req.get_json()
        email = body.get("email", "")
        if not _validate_email(email):
            return func.HttpResponse(json.dumps({"error": "invalid email format"}), status_code=400)
        if not get_api_key("sip"):
            return func.HttpResponse(json.dumps({"error": "SIP API key not configured"}), status_code=400)

        resp = call_spycloud(f"/sip/cookies/emails/{email}", product="sip")
        cookies = resp.get("results", [])

        valid_count = sum(1 for c in cookies
                          if c.get("cookie_expiry") and c["cookie_expiry"] > datetime.now(timezone.utc).isoformat())

        risk = "CRITICAL" if valid_count > 0 else ("HIGH" if cookies else "LOW")

        return func.HttpResponse(json.dumps({
            "email": email,
            "totalCookies": len(cookies),
            "validCookies": valid_count,
            "mfaBypassRisk": risk,
            "results": cookies[:25],
        }), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="enrich/catalog", methods=["POST"])
def enrich_catalog(req: func.HttpRequest) -> func.HttpResponse:
    """Breach catalog enrichment — source context."""
    try:
        body = req.get_json()
        source_id = body.get("sourceId", "")
        resp = call_spycloud(f"/breach/catalog/{source_id}")
        return func.HttpResponse(json.dumps(resp), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


# ================================================================
# FULL INVESTIGATION
# ================================================================

@app.route(route="investigate/full", methods=["POST"])
def investigate_full(req: func.HttpRequest) -> func.HttpResponse:
    """Full multi-product investigation orchestration."""
    try:
        body = req.get_json()
        email = body.get("email", "")
        if not email:
            return func.HttpResponse(json.dumps({"error": "email required"}), status_code=400)
        if not _validate_email(email):
            return func.HttpResponse(json.dumps({"error": "invalid email format"}), status_code=400)

        report = {"email": email, "timestamp": datetime.now(timezone.utc).isoformat()}

        # Step 1: Enterprise breach data
        ent_resp = call_spycloud(f"/breach/data/emails/{email}")
        report["enterprise"] = {
            "hits": ent_resp.get("hits", 0),
            "maxSeverity": max((r.get("severity", 0) for r in ent_resp.get("results", [])), default=0),
            "hasPlaintext": any(r.get("password_plaintext") for r in ent_resp.get("results", [])),
        }

        # Step 2: Compass (if available)
        if get_api_key("compass"):
            comp_resp = call_spycloud(f"/compass/data/emails/{email}", product="compass")
            report["compass"] = {
                "hits": comp_resp.get("hits", 0),
                "devices": len(set(r.get("infected_machine_id", "") for r in comp_resp.get("results", []))),
            }

        # Step 3: SIP cookies (if available)
        cookies = []
        if get_api_key("sip"):
            sip_resp = call_spycloud(f"/sip/cookies/emails/{email}", product="sip")
            cookies = sip_resp.get("results", [])
            valid = sum(1 for c in cookies
                        if c.get("cookie_expiry") and c["cookie_expiry"] > datetime.now(timezone.utc).isoformat())
            report["sip"] = {"totalCookies": len(cookies), "validCookies": valid}

        # Step 4: Compute risk score
        score = compute_risk_score(
            ent_resp.get("results", []),
            cookies=cookies,
        )
        report["riskScore"] = score["riskScore"]
        report["riskTier"] = score["riskTier"]
        report["components"] = score["components"]
        report["topFactors"] = score["topFactors"]
        report["recommendedActions"] = score["recommendedActions"]

        # Step 5: Generate markdown report
        report["markdownReport"] = _generate_investigation_report(email, report)

        return func.HttpResponse(json.dumps(report), mimetype="application/json")
    except Exception as e:
        logging.error(f"investigate_full error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


def _generate_investigation_report(email: str, data: dict) -> str:
    """Generate a markdown investigation report for incident comments."""
    tier = data.get("riskTier", "UNKNOWN")
    score = data.get("riskScore", 0)
    emoji = {"LOW": "🟢", "MODERATE": "🟡", "HIGH": "🟠", "CRITICAL": "🔴", "EMERGENCY": "🟣"}.get(tier, "⚪")

    lines = [
        f"## SpyCloud Investigation Report",
        f"**User:** {email}",
        f"**Risk Score:** {emoji} **{score}/100 ({tier})**",
        f"**Timestamp:** {data.get('timestamp', 'N/A')}",
        "",
        "### Exposure Summary",
    ]

    ent = data.get("enterprise", {})
    lines.append(f"- **Enterprise:** {ent.get('hits', 0)} exposures (max severity: {ent.get('maxSeverity', 0)}, plaintext: {'Yes' if ent.get('hasPlaintext') else 'No'})")

    if "compass" in data:
        comp = data["compass"]
        lines.append(f"- **Compass:** {comp.get('hits', 0)} records across {comp.get('devices', 0)} devices")

    if "sip" in data:
        sip = data["sip"]
        lines.append(f"- **SIP Cookies:** {sip.get('totalCookies', 0)} stolen cookies ({sip.get('validCookies', 0)} still valid)")

    lines.extend(["", "### Risk Factors"])
    for f in data.get("topFactors", []):
        lines.append(f"- {f}")

    lines.extend(["", "### Recommended Actions"])
    for i, a in enumerate(data.get("recommendedActions", []), 1):
        lines.append(f"{i}. {a}")

    lines.extend(["", f"---", f"*Generated by SpyCloud Sentinel Enrichment Function App*"])
    return "\n".join(lines)


# ================================================================
# REPORTING
# ================================================================

@app.route(route="report/daily", methods=["GET"])
def report_daily(req: func.HttpRequest) -> func.HttpResponse:
    """Daily SOC brief — query Log Analytics for today's metrics."""
    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        workspace_id = LOG_ANALYTICS_WORKSPACE_ID
        if not workspace_id:
            return func.HttpResponse(
                json.dumps({"error": "LOG_ANALYTICS_WORKSPACE_ID not configured"}),
                status_code=500, mimetype="application/json",
            )

        metrics = _query_log_analytics(workspace_id, f"""
            let today = datetime({today});
            let new_exposures = SpyCloudBreachWatchlist_CL
                | where TimeGenerated >= today
                | summarize NewExposures=count(),
                            CriticalCount=countif(severity_d >= 20),
                            PlaintextCount=countif(isnotempty(password_plaintext_s)),
                            UniqueEmails=dcount(email_s);
            let remediations = SpyCloudEnrichmentAudit_CL
                | where TimeGenerated >= today
                | where action_s in ("ForcePasswordReset", "RevokeSessions", "IsolateDevice")
                | summarize RemediationActions=count();
            let api_calls = SpyCloudEnrichmentAudit_CL
                | where TimeGenerated >= today
                | summarize ApiCalls=count(), AvgLatencyMs=avg(duration_ms_d);
            new_exposures | extend placeholder=1
            | join kind=fullouter (remediations | extend placeholder=1) on placeholder
            | join kind=fullouter (api_calls | extend placeholder=1) on placeholder
            | project NewExposures, CriticalCount, PlaintextCount, UniqueEmails,
                      RemediationActions, ApiCalls, AvgLatencyMs
        """)

        row = metrics[0] if metrics else {}
        report = {
            "date": today,
            "newExposures": row.get("NewExposures", 0),
            "criticalExposures": row.get("CriticalCount", 0),
            "plaintextCredentials": row.get("PlaintextCount", 0),
            "uniqueAffectedUsers": row.get("UniqueEmails", 0),
            "remediationActions": row.get("RemediationActions", 0),
            "apiCalls": row.get("ApiCalls", 0),
            "avgLatencyMs": round(row.get("AvgLatencyMs", 0), 1),
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
        return func.HttpResponse(json.dumps(report), mimetype="application/json")
    except Exception as e:
        logging.error(f"report_daily error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


@app.route(route="report/executive", methods=["GET"])
def report_executive(req: func.HttpRequest) -> func.HttpResponse:
    """Executive dashboard — trend data over configurable period."""
    try:
        period = req.params.get("period", "30d")
        days = int(period.rstrip("d")) if period.endswith("d") else 30
        days = min(days, 365)  # cap at 1 year
        workspace_id = LOG_ANALYTICS_WORKSPACE_ID
        if not workspace_id:
            return func.HttpResponse(
                json.dumps({"error": "LOG_ANALYTICS_WORKSPACE_ID not configured"}),
                status_code=500, mimetype="application/json",
            )

        trend = _query_log_analytics(workspace_id, f"""
            SpyCloudBreachWatchlist_CL
            | where TimeGenerated >= ago({days}d)
            | summarize
                TotalExposures=count(),
                CriticalExposures=countif(severity_d >= 20),
                InfostealerExposures=countif(severity_d >= 20),
                PlaintextCredentials=countif(isnotempty(password_plaintext_s)),
                UniqueUsers=dcount(email_s),
                UniqueDomains=dcount(target_domain_s),
                UniqueDevices=dcount(infected_machine_id_s)
                by bin(TimeGenerated, 1d)
            | order by TimeGenerated asc
        """)

        # Compute summary from trend data
        total_exposures = sum(r.get("TotalExposures", 0) for r in trend)
        total_critical = sum(r.get("CriticalExposures", 0) for r in trend)
        total_plaintext = sum(r.get("PlaintextCredentials", 0) for r in trend)

        # Determine trend direction from first vs second half
        mid = len(trend) // 2
        first_half = sum(r.get("TotalExposures", 0) for r in trend[:mid]) if mid > 0 else 0
        second_half = sum(r.get("TotalExposures", 0) for r in trend[mid:]) if mid > 0 else 0
        if first_half == 0:
            direction = "stable"
        elif second_half > first_half * 1.1:
            direction = "degrading"
        elif second_half < first_half * 0.9:
            direction = "improving"
        else:
            direction = "stable"

        report = {
            "period": period,
            "days": days,
            "summary": {
                "totalExposures": total_exposures,
                "criticalExposures": total_critical,
                "plaintextCredentials": total_plaintext,
                "trendDirection": direction,
            },
            "dailyTrend": [
                {
                    "date": r.get("TimeGenerated", "")[:10] if isinstance(r.get("TimeGenerated"), str) else "",
                    "exposures": r.get("TotalExposures", 0),
                    "critical": r.get("CriticalExposures", 0),
                    "uniqueUsers": r.get("UniqueUsers", 0),
                }
                for r in trend
            ],
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
        return func.HttpResponse(json.dumps(report), mimetype="application/json")
    except Exception as e:
        logging.error(f"report_executive error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


# ================================================================
# HEALTH & AUDIT
# ================================================================

@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check — verify API key validity."""
    status = {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat(), "apiKeys": {}}

    for product, env_var in ENV_KEYS.items():
        key = os.environ.get(env_var, "")
        if key:
            # Quick validation call
            try:
                resp = requests.get(
                    f"{SPYCLOUD_BASE_URL}/breach/catalog",
                    headers={"X-API-Key": key, "Accept": "application/json"},
                    params={"limit": 1},
                    timeout=10
                )
                status["apiKeys"][product] = {
                    "configured": True,
                    "valid": resp.status_code == 200,
                    "statusCode": resp.status_code
                }
            except Exception as e:
                status["apiKeys"][product] = {"configured": True, "valid": False, "error": str(e)}
        else:
            status["apiKeys"][product] = {"configured": False}

    return func.HttpResponse(json.dumps(status), mimetype="application/json")


@app.route(route="audit/usage", methods=["GET"])
def audit_usage(req: func.HttpRequest) -> func.HttpResponse:
    """API usage audit — daily call count vs limit."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used = _get_call_count(today)
    return func.HttpResponse(json.dumps({
        "date": today,
        "callsUsed": used,
        "dailyLimit": DAILY_LIMIT,
        "remaining": max(0, DAILY_LIMIT - used),
        "utilizationPercent": round(used / DAILY_LIMIT * 100, 1) if DAILY_LIMIT > 0 else 0,
    }), mimetype="application/json")
