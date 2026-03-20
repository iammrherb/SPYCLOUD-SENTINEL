#!/usr/bin/env python3
"""
SpyCloud Identity Risk Score — Algorithm Design & Azure Function Specification

This defines the risk scoring algorithm, the Function App endpoints,
and the integration points with Sentinel, Entra ID, and workbooks.
"""

# ================================================================
# RISK SCORE ALGORITHM v1.0
# ================================================================
#
# Score range: 0-100 (0 = no known risk, 100 = critical/active compromise)
#
# The score is computed per-identity (email address) and considers:
#
# COMPONENT 1: Exposure Severity (0-30 points)
# - Each exposure contributes points based on severity:
#   Severity 2 (public breach):     1 point per exposure (cap: 5)
#   Severity 5 (private breach):    2 points per exposure (cap: 8)
#   Severity 20 (infostealer):      5 points per exposure (cap: 20)
#   Severity 25 (infostealer+app):  8 points per exposure (cap: 30)
#
# COMPONENT 2: Credential Availability (0-25 points)
# - Plaintext password available:       15 points
# - Weak hash (MD5/SHA1/NTLM):          8 points
# - Strong hash (bcrypt/argon2):         2 points
# - Multiple distinct passwords found:  +5 points
# - Password reused across 3+ domains:  +5 points
#
# COMPONENT 3: Active Session Risk (0-25 points)  [SIP data]
# - Stolen session cookies found:       15 points
# - Cookies still valid (not expired):  +10 points (CRITICAL)
# - SSO/VPN/Admin portal cookies:       +5 points per high-value app
# - Cap: 25 points
#
# COMPONENT 4: Device Risk (0-10 points)  [Compass data]
# - Infected device count:               3 points per device (cap: 9)
# - Device re-infection:                 +5 points
# - Unmanaged/BYOD device:              +3 points
# - Cap: 10 points
#
# COMPONENT 5: Temporal Decay (multiplier: 0.3 - 1.0)
# - Exposure < 24 hours:                1.0x (full weight)
# - Exposure 1-7 days:                  0.9x
# - Exposure 7-30 days:                 0.7x
# - Exposure 30-90 days:                0.5x
# - Exposure 90-365 days:               0.3x
# - Exposure > 365 days:                0.2x (never fully zero)
#
# COMPONENT 6: Remediation Credit (negative: 0 to -20 points)
# - Password reset forced:              -10 points
# - Sessions revoked:                   -5 points
# - Device isolated:                    -5 points
# - MFA method changed (by admin):      -3 points
# - Account disabled:                   -15 points
#
# FINAL SCORE = min(100, max(0,
#   (Severity + Credential + Session + Device) × TemporalDecay + Remediation
# ))
#
# RISK TIERS:
#   0-20:   LOW       — Historical exposure, remediated or aged out
#   21-40:  MODERATE  — Active exposure but no plaintext/cookies
#   41-60:  HIGH      — Plaintext passwords or recent infostealer
#   61-80:  CRITICAL  — Active stolen sessions or multiple high-sev
#   81-100: EMERGENCY — Valid cookies + plaintext + unmediated + recent
#

RISK_TIERS = {
    (0, 20):   {"tier": "LOW",       "color": "#4CAF50", "action": "Monitor"},
    (21, 40):  {"tier": "MODERATE",  "color": "#FFC107", "action": "Schedule password reset"},
    (41, 60):  {"tier": "HIGH",      "color": "#FF9800", "action": "Force password reset + revoke sessions"},
    (61, 80):  {"tier": "CRITICAL",  "color": "#F44336", "action": "Immediate reset + isolate device + investigate"},
    (81, 100): {"tier": "EMERGENCY", "color": "#9C27B0", "action": "Disable account + isolate all devices + IR team engaged"},
}

# ================================================================
# AZURE FUNCTION APP — ENDPOINT SPECIFICATION
# ================================================================

FUNCTION_ENDPOINTS = {
    # ──────────────────────────────────────────────
    # RISK SCORING
    # ──────────────────────────────────────────────
    "/api/risk-score": {
        "method": "POST",
        "input": {"email": "user@contoso.com"},
        "output": {
            "email": "user@contoso.com",
            "riskScore": 73,
            "riskTier": "CRITICAL",
            "components": {
                "severity": 22,
                "credential": 15,
                "session": 10,
                "device": 6,
                "temporal": 0.85,
                "remediation": -5
            },
            "topFactors": [
                "Plaintext password available (severity 25 infostealer)",
                "2 stolen session cookies (1 still valid for Okta SSO)",
                "Device re-infected within 30 days"
            ],
            "recommendedActions": [
                "Force immediate password reset",
                "Revoke all active sessions",
                "Isolate device DESKTOP-ABC123",
                "Investigate Okta SSO access logs"
            ],
            "lastUpdated": "2026-03-19T18:00:00Z"
        },
        "description": "Compute SpyCloud Identity Risk Score for a user. Queries all SpyCloud tables + remediation logs."
    },

    "/api/risk-score/batch": {
        "method": "POST",
        "input": {"emails": ["user1@contoso.com", "user2@contoso.com"]},
        "output": [{"email": "...", "riskScore": 73, "riskTier": "CRITICAL"}],
        "description": "Batch risk scoring for up to 100 users. Used by workbooks and scheduled reports."
    },

    "/api/risk-score/domain": {
        "method": "POST",
        "input": {"domain": "contoso.com", "top": 20},
        "output": {
            "domain": "contoso.com",
            "averageRiskScore": 34,
            "totalUsers": 1250,
            "distribution": {"LOW": 800, "MODERATE": 300, "HIGH": 100, "CRITICAL": 40, "EMERGENCY": 10},
            "topRiskUsers": [{"email": "...", "riskScore": 95}]
        },
        "description": "Domain-level risk assessment. Returns distribution + top risk users."
    },

    # ──────────────────────────────────────────────
    # ENRICHMENT (replaces direct SpyCloud API calls)
    # ──────────────────────────────────────────────
    "/api/enrich/email": {
        "method": "POST",
        "input": {"email": "user@contoso.com", "product": "enterprise"},
        "output": {"hits": 15, "results": [], "riskScore": 73, "summary": "..."},
        "description": "Email enrichment via SpyCloud Enterprise API. Adds risk score to response."
    },

    "/api/enrich/domain": {
        "method": "POST",
        "input": {"domain": "contoso.com"},
        "output": {"hits": 1250, "topUsers": [], "severityDistribution": {}},
        "description": "Domain enrichment — org-level exposure assessment."
    },

    "/api/enrich/ip": {
        "method": "POST",
        "input": {"ip": "203.0.113.42"},
        "output": {"hits": 5, "devices": [], "users": []},
        "description": "IP enrichment — infected devices at this IP."
    },

    "/api/enrich/compass-device": {
        "method": "POST",
        "input": {"machineId": "abc123"},
        "output": {"device": {}, "apps": [], "users": [], "riskScore": 82},
        "description": "Compass device enrichment — full blast radius assessment."
    },

    "/api/enrich/sip-cookies": {
        "method": "POST",
        "input": {"email": "user@contoso.com"},
        "output": {"cookies": [], "validCount": 2, "mfaBypassRisk": "HIGH"},
        "description": "SIP cookie enrichment — MFA bypass risk assessment."
    },

    "/api/enrich/catalog": {
        "method": "POST",
        "input": {"sourceId": 12345},
        "output": {"breach": {}, "malwareFamily": "RedLine", "confidence": 4},
        "description": "Breach catalog enrichment — source context."
    },

    "/api/enrich/investigate": {
        "method": "POST",
        "input": {"email": "user@contoso.com", "limit": 50},
        "output": {"hits": 200, "results": [], "identityGraph": {}},
        "description": "Deep investigation — full database lookup. Rate limited: 10/day."
    },

    # ──────────────────────────────────────────────
    # ORCHESTRATION
    # ──────────────────────────────────────────────
    "/api/investigate/full": {
        "method": "POST",
        "input": {"email": "user@contoso.com"},
        "output": {
            "riskScore": 73,
            "enterprise": {"hits": 15},
            "compass": {"devices": 2, "apps": 8},
            "sip": {"cookies": 3, "valid": 1},
            "catalog": {"sources": 4},
            "remediation": {"passwordReset": True, "sessionsRevoked": True},
            "timeline": [],
            "report": "## SpyCloud Investigation Report\n..."
        },
        "description": "Full multi-product investigation. Chains all available APIs based on Key Vault keys. Generates markdown report."
    },

    # ──────────────────────────────────────────────
    # ENTRA ID INTEGRATION
    # ──────────────────────────────────────────────
    "/api/entra/update-risk": {
        "method": "POST",
        "input": {"email": "user@contoso.com", "riskScore": 73},
        "output": {"success": True, "customAttribute": "spycloudRiskScore", "value": 73},
        "description": "Push risk score to Entra ID custom security attribute. Enables CA policies based on SpyCloud risk."
    },

    "/api/entra/ca-trigger": {
        "method": "POST",
        "input": {"email": "user@contoso.com", "riskTier": "CRITICAL"},
        "output": {"groupAdded": "SpyCloud-HighRisk", "sessionRevoked": True, "passwordResetForced": True},
        "description": "Trigger Conditional Access actions based on risk tier."
    },

    # ──────────────────────────────────────────────
    # REPORTING
    # ──────────────────────────────────────────────
    "/api/report/daily": {
        "method": "GET",
        "output": {"date": "2026-03-19", "newExposures": 45, "criticalUsers": 3, "remediations": 12},
        "description": "Daily SOC brief data. Called by scheduled Logic App for Teams/email notification."
    },

    "/api/report/executive": {
        "method": "GET",
        "input": {"period": "30d"},
        "output": {"riskTrend": [], "remediationRate": 0.87, "mttr": "4.2h", "coverage": 0.94},
        "description": "Executive dashboard data. Risk trend, remediation effectiveness, SLA compliance."
    },

    # ──────────────────────────────────────────────
    # HEALTH & AUDIT
    # ──────────────────────────────────────────────
    "/api/health": {
        "method": "GET",
        "output": {"status": "healthy", "apiKeys": {"enterprise": True, "compass": True, "sip": False}},
        "description": "Health check — verifies API key validity and connectivity."
    },

    "/api/audit/usage": {
        "method": "GET",
        "output": {"today": 145, "limit": 200, "remaining": 55},
        "description": "API usage audit — daily call count vs limit."
    }
}

# ================================================================
# ENTRA ID CUSTOM SECURITY ATTRIBUTE — CONDITIONAL ACCESS INTEGRATION
# ================================================================
#
# This is the game-changer: SpyCloud risk score → Entra ID → Conditional Access
#
# Setup:
# 1. Create custom security attribute set "SpyCloud" in Entra ID
# 2. Create attribute "riskScore" (type: integer, 0-100)
# 3. Create attribute "riskTier" (type: string, enum: LOW/MODERATE/HIGH/CRITICAL/EMERGENCY)
# 4. Create attribute "lastExposureDate" (type: string, ISO date)
# 5. Function App pushes scores via Graph API
# 6. CA policy: "If spycloudRiskScore > 60 → require hardware MFA + restrict app access"
#
# Result: Darknet intelligence → identity policy in near-real-time
# No other vendor offers this closed-loop integration.
#
# CA Policy Examples:
# - riskScore > 80: Block all access except password reset portal
# - riskScore 61-80: Require hardware security key MFA
# - riskScore 41-60: Require MFA re-authentication every 1 hour
# - riskScore 21-40: Standard MFA policy (no change)
# - riskScore 0-20: Allow passwordless/phone MFA
#

# ================================================================
# KQL — RISK SCORE FUNCTION (for workbooks and rules)
# ================================================================

RISK_SCORE_KQL = """
// SpyCloud Identity Risk Score — KQL Function
// Deploy as a saved function in Log Analytics
// Usage: SpyCloudRiskScore("user@contoso.com")

let SpyCloudRiskScore = (targetEmail: string) {
    let exposures = SpyCloudBreachWatchlist_CL
        | where email =~ targetEmail
        | where TimeGenerated > ago(365d);
    let severity_score = toscalar(
        exposures
        | summarize
            s2 = min(countif(severity == 2), 5) * 1,
            s5 = min(countif(severity == 5), 8) * 2,
            s20 = min(countif(severity >= 20 and severity < 25), 20) * 5,
            s25 = min(countif(severity >= 25), 30) * 8
        | project score = min(s2 + s5 + s20 + s25, 30)
    );
    let credential_score = toscalar(
        exposures
        | summarize
            has_plaintext = countif(isnotempty(password_plaintext)) > 0,
            has_weak_hash = countif(password_type in ("md5","sha1","ntlm","des")) > 0,
            distinct_passwords = dcount(password_plaintext),
            reuse_domains = dcount(target_domain)
        | project score = min(
            iff(has_plaintext, 15, iff(has_weak_hash, 8, 2))
            + iff(distinct_passwords > 1, 5, 0)
            + iff(reuse_domains >= 3, 5, 0),
            25)
    );
    let device_score = toscalar(
        exposures
        | where isnotempty(infected_machine_id)
        | summarize
            device_count = dcount(infected_machine_id),
            reinfection = dcount(source_id) > dcount(infected_machine_id)
        | project score = min(device_count * 3 + iff(reinfection, 5, 0), 10)
    );
    let most_recent = toscalar(exposures | summarize max(TimeGenerated));
    let age_days = datetime_diff('day', now(), most_recent);
    let temporal = case(
        age_days <= 1, 1.0,
        age_days <= 7, 0.9,
        age_days <= 30, 0.7,
        age_days <= 90, 0.5,
        age_days <= 365, 0.3,
        0.2
    );
    let remediation_credit = toscalar(
        SpyCloud_ConditionalAccessLogs_CL
        | where UserEmail =~ targetEmail
        | where TimeGenerated > ago(30d)
        | summarize
            pw_reset = countif(ForcedPasswordResetOnNextSignIn == true),
            sessions = countif(UserSessionsRevoked == true),
            disabled = countif(UserDisabled == true)
        | project credit = -(min(pw_reset, 1) * 10 + min(sessions, 1) * 5 + min(disabled, 1) * 15)
    );
    let raw_score = (severity_score + credential_score + device_score) * temporal + remediation_credit;
    let final_score = min(toreal(100), max(toreal(0), raw_score));
    let risk_tier = case(
        final_score <= 20, "LOW",
        final_score <= 40, "MODERATE",
        final_score <= 60, "HIGH",
        final_score <= 80, "CRITICAL",
        "EMERGENCY"
    );
    print
        Email = targetEmail,
        RiskScore = toint(final_score),
        RiskTier = risk_tier,
        SeverityComponent = severity_score,
        CredentialComponent = credential_score,
        DeviceComponent = device_score,
        TemporalMultiplier = temporal,
        RemediationCredit = remediation_credit,
        MostRecentExposure = most_recent,
        ExposureAgeDays = age_days
};
// Example usage:
// SpyCloudRiskScore("user@contoso.com")
"""

# ================================================================
# ANALYTICS RULE — Risk Score Based Alerting
# ================================================================

RISK_SCORE_RULE = """
// SpyCloud — Identity Risk Score Exceeds Threshold
// Runs daily, scores all users with recent exposures
// Creates incidents for users crossing into CRITICAL or EMERGENCY tier

SpyCloudBreachWatchlist_CL
| where TimeGenerated > ago(7d)
| distinct email
| mv-apply email to typeof(string) on (
    SpyCloudBreachWatchlist_CL
    | where email =~ email
    | where TimeGenerated > ago(365d)
    | summarize
        ExposureCount = count(),
        MaxSeverity = max(severity),
        HasPlaintext = countif(isnotempty(password_plaintext)) > 0,
        HasCookies = countif(severity >= 25) > 0,
        DeviceCount = dcount(infected_machine_id),
        DomainCount = dcount(target_domain),
        MostRecent = max(TimeGenerated)
    | extend AgeDays = datetime_diff('day', now(), MostRecent)
    | extend SeverityScore = min(
        countif(MaxSeverity == 2) * 1 + countif(MaxSeverity == 5) * 2 +
        countif(MaxSeverity >= 20) * 5 + countif(MaxSeverity >= 25) * 8, 30)
    | extend CredentialScore = iff(HasPlaintext, 15, 0) + iff(DomainCount >= 3, 5, 0)
    | extend DeviceScore = min(DeviceCount * 3, 10)
    | extend Temporal = case(AgeDays <= 1, 1.0, AgeDays <= 7, 0.9, AgeDays <= 30, 0.7, 0.5)
    | extend RiskScore = min(100, max(0, (SeverityScore + CredentialScore + DeviceScore) * Temporal))
    | extend RiskTier = case(RiskScore <= 20, "LOW", RiskScore <= 40, "MODERATE",
                             RiskScore <= 60, "HIGH", RiskScore <= 80, "CRITICAL", "EMERGENCY")
)
| where RiskScore > 60
| project email, RiskScore, RiskTier, ExposureCount, MaxSeverity,
          HasPlaintext, HasCookies, DeviceCount, DomainCount, MostRecent
| sort by RiskScore desc
"""

if __name__ == "__main__":
    print("SpyCloud Identity Risk Score — Algorithm Design")
    print(f"  Endpoints: {len(FUNCTION_ENDPOINTS)}")
    print(f"  Risk tiers: {len(RISK_TIERS)}")
    for (lo, hi), info in RISK_TIERS.items():
        print(f"    {lo}-{hi}: {info['tier']} — {info['action']}")
    print(f"\n  KQL function: {len(RISK_SCORE_KQL)} chars")
    print(f"  Analytics rule: {len(RISK_SCORE_RULE)} chars")
    
    print(f"\n  Function App endpoints:")
    for path, spec in FUNCTION_ENDPOINTS.items():
        print(f"    {spec['method']:4s} {path} — {spec['description'][:60]}")
