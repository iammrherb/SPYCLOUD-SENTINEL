#!/usr/bin/env python3
"""
SpyCloud Sentinel -- Purple Team Scenario Engine
==================================================
Generates correlated attack-chain events across multiple data sources to
simulate realistic adversary activity combining SpyCloud darknet intelligence
with Microsoft security signals.

Each scenario produces a coherent timeline of events spanning:
  - SpyCloud exposure data  (Watchlist, Compass, SIP, IDLink, CAP, etc.)
  - Azure AD / Entra ID sign-in logs  (simulated)
  - Microsoft Defender for Endpoint alerts  (simulated)
  - Office 365 / M365 audit logs  (simulated)
  - Conditional Access evaluation logs  (simulated)

Scenarios:
  credential-stuffing   -- Exposure -> failed sign-ins -> success -> exfil
  session-hijack        -- Cookie theft -> impossible travel -> mailbox rule
  ransomware-precursor  -- Infostealer -> lateral movement -> persistence
  insider-threat        -- VIP exposure -> unusual access -> bulk download
  supply-chain          -- Third-party cred -> OAuth consent -> API abuse
  mfa-fatigue           -- Exposure -> MFA push spam -> accept -> ATO
  identity-pivot        -- IDLink correlation -> cross-domain -> cloud abuse
  cap-breach            -- CAP exposure -> asset access -> data staging

Usage:
  python3 purple-team-scenarios.py --scenario credential-stuffing \\
      --target-user alice.johnson@example.com --timeline 24

  python3 purple-team-scenarios.py --scenario session-hijack \\
      --target-user bob.smith@example.com --intensity high --output file

  python3 purple-team-scenarios.py --scenario ransomware-precursor \\
      --teach-agent --output file --output-dir ./purple-team-output

Version: 1.0.0
"""

import argparse
import datetime
import json
import logging
import os
import random
import string
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("purple-team")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SYNTH_DOMAINS = [
    "example.com", "test-corp.example.com", "acme-labs.example.net",
    "contoso.example.com", "fabrikam.example.net",
]

SYNTH_TARGET_DOMAINS = [
    "login.microsoftonline.example.com", "accounts.google.example.com",
    "github.example.com", "okta.example.com", "aws.example.com",
    "salesforce.example.com", "slack.example.com", "office365.example.com",
]

MALWARE_FAMILIES = ["Raccoon", "RedLine", "Vidar", "LummaC2", "StealC",
                    "Titan", "Aurora", "MetaStealer", "RisePro", "Mystic"]

LOCATIONS = [
    {"city": "New York", "state": "NY", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "London", "state": "", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"city": "Moscow", "state": "", "country": "RU", "lat": 55.7558, "lon": 37.6173},
    {"city": "Beijing", "state": "", "country": "CN", "lat": 39.9042, "lon": 116.4074},
    {"city": "Sao Paulo", "state": "SP", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    {"city": "Lagos", "state": "", "country": "NG", "lat": 6.5244, "lon": 3.3792},
    {"city": "Seattle", "state": "WA", "country": "US", "lat": 47.6062, "lon": -122.3321},
    {"city": "Chicago", "state": "IL", "country": "US", "lat": 41.8781, "lon": -87.6298},
]

MITRE_TECHNIQUES = {
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1539": "Steal Web Session Cookie",
    "T1550.004": "Use Alternate Authentication Material: Web Session Cookie",
    "T1556": "Modify Authentication Process",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1114.002": "Email Collection: Remote Email Collection",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1098.005": "Account Manipulation: Device Registration",
    "T1136.003": "Create Account: Cloud Account",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1055": "Process Injection",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.006": "OS Credential Dumping: DCSync",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1486": "Data Encrypted for Impact",
    "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    "T1530": "Data from Cloud Storage",
    "T1213.002": "Data from Information Repositories: SharePoint",
    "T1528": "Steal Application Access Token",
    "T1550.001": "Use Alternate Authentication Material: Application Access Token",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1074.002": "Data Staged: Remote Data Staging",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
}

INTENSITY_MULTIPLIERS = {"low": 1, "medium": 3, "high": 7}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def synth_uuid() -> str:
    return f"SYNTH-{uuid.uuid4()}"


def synth_ip(prefix: str = "10") -> str:
    return f"{prefix}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


def synth_machine_id() -> str:
    return f"SYNTH-MACHINE-{uuid.uuid4().hex[:12].upper()}"


def synth_hostname() -> str:
    dept = random.choice(["WS", "LAP", "DT", "SRV"])
    return f"SYNTH-{dept}-{random.randint(1000,9999)}"


def ts_offset(base: datetime.datetime, minutes: int) -> str:
    """Return ISO timestamp offset from base by N minutes."""
    return (base + datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts_from_dt(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def pick_attacker_location() -> Dict:
    """Pick a location that is clearly different from US corporate."""
    return random.choice([loc for loc in LOCATIONS if loc["country"] not in ("US",)])


def pick_corporate_location() -> Dict:
    return random.choice([loc for loc in LOCATIONS if loc["country"] == "US"])


# ---------------------------------------------------------------------------
# Event builder helpers
# ---------------------------------------------------------------------------

def spycloud_watchlist_event(ts: str, email: str, severity: int,
                             malware: str = "", **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudBreachWatchlist_CL",
        "TimeGenerated": ts,
        "document_id": synth_uuid(),
        "source_id": random.randint(40000, 49999),
        "email": email,
        "email_domain": parts[1],
        "email_username": parts[0],
        "severity": severity,
        "sighting": random.randint(1, 5),
        "breach_category": "infostealer" if malware else "combolist",
        "breach_title": f"SYNTH Purple-Team Breach",
        "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
        "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
        "infected_machine_id": synth_machine_id() if malware else "",
        "infected_time": ts if malware else "",
        "malware_family": malware,
        "password": f"$sha256$SYNTH{uuid.uuid4().hex[:16]}",
        "password_plaintext": f"SynthP@ss{random.randint(100,999)}!" if severity >= 20 else "",
        "password_type": "plaintext" if severity >= 20 else "hashed_sha256",
        "ip_addresses": [synth_ip()],
        "user_hostname": synth_hostname() if malware else "",
        "user_os": "Windows 11 Enterprise" if malware else "",
        "log_id": synth_uuid(),
        "spycloud_publish_date": ts[:10],
    }
    record.update(extra)
    return record


def spycloud_sip_event(ts: str, email: str, cookie_domain: str,
                       malware: str, **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudSipCookies_CL",
        "TimeGenerated": ts,
        "document_id": synth_uuid(),
        "source_id": random.randint(40000, 49999),
        "email": email,
        "email_domain": parts[1],
        "cookie_domain": f".{cookie_domain}",
        "cookie_name": random.choice(["ESTSAUTHPERSISTENT", "SSID", "session_id", "auth_token"]),
        "cookie_value": f"SYNTH_COOKIE_{uuid.uuid4().hex[:24]}",
        "cookie_path": "/",
        "cookie_secure": True,
        "cookie_http_only": True,
        "target_domain": cookie_domain,
        "severity": 25,
        "infected_machine_id": synth_machine_id(),
        "infected_time": ts,
        "malware_family": malware,
        "user_hostname": synth_hostname(),
        "user_os": "Windows 11 Enterprise",
        "ip_addresses": [synth_ip()],
        "log_id": synth_uuid(),
        "spycloud_publish_date": ts[:10],
    }
    record.update(extra)
    return record


def spycloud_compass_event(ts: str, email: str, malware: str,
                           severity: int = 25, **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudCompassData_CL",
        "TimeGenerated": ts,
        "document_id": synth_uuid(),
        "source_id": random.randint(40000, 49999),
        "email": email,
        "email_domain": parts[1],
        "email_username": parts[0],
        "severity": severity,
        "malware_family": malware,
        "breach_category": "infostealer",
        "infected_machine_id": synth_machine_id(),
        "infected_time": ts,
        "user_hostname": synth_hostname(),
        "user_os": "Windows 11 Enterprise",
        "ip_addresses": [synth_ip()],
        "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
        "password": f"$sha256$SYNTH{uuid.uuid4().hex[:16]}",
        "password_plaintext": f"SynthP@ss{random.randint(100,999)}!",
        "password_type": "plaintext",
        "record_type": "infostealer",
        "log_id": synth_uuid(),
        "spycloud_publish_date": ts[:10],
    }
    record.update(extra)
    return record


def spycloud_idlink_event(ts: str, email: str, linked_emails: List[str],
                          **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudIdLink_CL",
        "TimeGenerated": ts,
        "identity_id": f"SYNTH-ID-{uuid.uuid4().hex[:12]}",
        "email": email,
        "email_domain": parts[1],
        "linked_emails": linked_emails,
        "linked_usernames": [e.split("@")[0] for e in linked_emails],
        "linked_ips": [synth_ip() for _ in range(random.randint(1, 3))],
        "linked_devices": [synth_machine_id() for _ in range(random.randint(1, 2))],
        "link_strength": round(random.uniform(0.7, 1.0), 3),
        "link_type": random.choice(["password_reuse", "device_shared", "cookie_overlap"]),
        "breach_sources": [f"SYNTH-SRC-{random.randint(100,999)}"],
        "first_seen": (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(30,365))).strftime("%Y-%m-%d"),
        "last_seen": ts[:10],
        "total_exposures": random.randint(5, 50),
        "risk_score": random.randint(70, 100),
        "graph_depth": random.randint(1, 3),
        "log_id": synth_uuid(),
    }
    record.update(extra)
    return record


def spycloud_cap_event(ts: str, email: str, action: str,
                       status: str = "success", **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudCAP_CL",
        "TimeGenerated": ts,
        "cap_id": f"SYNTH-CAP-{uuid.uuid4().hex[:12]}",
        "email": email,
        "email_domain": parts[1],
        "policy_id": f"POL-{random.randint(100,999)}",
        "policy_name": "High-Risk Credential Reset",
        "action_type": action,
        "action_status": status,
        "trigger_severity": 25,
        "trigger_source": "watchlist",
        "credential_type": "password",
        "reset_timestamp": ts,
        "notification_sent": True,
        "affected_applications": random.sample(SYNTH_TARGET_DOMAINS, k=random.randint(1, 3)),
        "compliance_tags": ["SOC2", "NIST-800-53"],
        "log_id": synth_uuid(),
    }
    record.update(extra)
    return record


def spycloud_exposure_event(ts: str, email: str, risk_score: int,
                            **extra) -> Dict[str, Any]:
    parts = email.split("@")
    record = {
        "_source": "SpyCloudExposure_CL",
        "TimeGenerated": ts,
        "email": email,
        "email_domain": parts[1],
        "exposure_id": f"SYNTH-EXP-{uuid.uuid4().hex[:12]}",
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium",
        "total_breaches": random.randint(3, 15),
        "total_infostealers": random.randint(1, 5),
        "total_credentials": random.randint(5, 25),
        "plaintext_passwords": random.randint(2, 8),
        "hashed_passwords": random.randint(1, 10),
        "stolen_cookies": random.randint(5, 40),
        "infected_devices": random.randint(1, 4),
        "first_exposure_date": (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(90,365))).strftime("%Y-%m-%d"),
        "latest_exposure_date": ts[:10],
        "remediation_status": "not_started",
        "log_id": synth_uuid(),
    }
    record.update(extra)
    return record


def azure_ad_signin_event(ts: str, email: str, ip: str, location: Dict,
                          status: str = "Success", app: str = "Microsoft 365",
                          mfa_result: str = "", ca_status: str = "notApplied",
                          risk_level: str = "none", **extra) -> Dict[str, Any]:
    record = {
        "_source": "SigninLogs (simulated)",
        "TimeGenerated": ts,
        "CorrelationId": synth_uuid(),
        "UserPrincipalName": email,
        "UserId": synth_uuid(),
        "AppDisplayName": app,
        "IPAddress": ip,
        "Location": location,
        "ResultType": 0 if status == "Success" else 50126,
        "ResultDescription": status,
        "ClientAppUsed": random.choice(["Browser", "Mobile Apps and Desktop clients"]),
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Synth-Browser/1.0",
        "DeviceDetail": {
            "deviceId": synth_uuid(),
            "displayName": synth_hostname(),
            "operatingSystem": "Windows 10",
            "isCompliant": status == "Success",
            "trustType": "AzureAd",
        },
        "ConditionalAccessStatus": ca_status,
        "MfaDetail": {"authMethod": "PhoneAppNotification", "authDetail": mfa_result} if mfa_result else {},
        "RiskLevelDuringSignIn": risk_level,
        "RiskLevelAggregated": risk_level,
        "AuthenticationRequirement": "multiFactorAuthentication" if mfa_result else "singleFactorAuthentication",
        "IsInteractive": True,
    }
    record.update(extra)
    return record


def mde_alert_event(ts: str, hostname: str, alert_title: str,
                    severity: str = "High", category: str = "Malware",
                    mitre_techniques: Optional[List[str]] = None,
                    **extra) -> Dict[str, Any]:
    record = {
        "_source": "SecurityAlert (MDE, simulated)",
        "TimeGenerated": ts,
        "AlertId": synth_uuid(),
        "AlertName": alert_title,
        "Severity": severity,
        "Category": category,
        "Description": f"[SYNTHETIC] {alert_title} detected on {hostname}.",
        "ComputerDnsName": hostname,
        "MachineId": synth_machine_id(),
        "RemediationSteps": "This is synthetic test data. No action required.",
        "MitreTechniques": mitre_techniques or [],
        "Status": "New",
        "InvestigationState": "PendingApproval",
    }
    record.update(extra)
    return record


def o365_audit_event(ts: str, email: str, operation: str,
                     workload: str = "Exchange", result: str = "Succeeded",
                     **extra) -> Dict[str, Any]:
    record = {
        "_source": "OfficeActivity (simulated)",
        "TimeGenerated": ts,
        "OfficeObjectId": synth_uuid(),
        "UserId": email,
        "Operation": operation,
        "Workload": workload,
        "ResultStatus": result,
        "ClientIP": synth_ip(),
        "OrganizationId": synth_uuid(),
        "RecordType": random.randint(1, 50),
    }
    record.update(extra)
    return record


def conditional_access_eval_event(ts: str, email: str, policy_name: str,
                                  result: str = "success",
                                  **extra) -> Dict[str, Any]:
    record = {
        "_source": "ConditionalAccessEvaluation (simulated)",
        "TimeGenerated": ts,
        "UserPrincipalName": email,
        "PolicyName": policy_name,
        "PolicyId": f"SYNTH-POL-{uuid.uuid4().hex[:8]}",
        "Result": result,
        "GrantControls": ["mfa"] if "MFA" in policy_name else ["block"],
        "SessionControls": [],
        "EnforcedGrantControls": ["mfa"] if result == "success" else ["block"],
        "ConditionsSatisfied": random.choice(["Application,Users,Location", "Application,Users"]),
    }
    record.update(extra)
    return record


# ---------------------------------------------------------------------------
# Scenario implementations
# ---------------------------------------------------------------------------

def scenario_credential_stuffing(target_user: str, timeline_hours: int,
                                 intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    Attack chain: SpyCloud exposure -> failed sign-ins -> successful sign-in
    -> mailbox data exfil.
    """
    events = []
    mitre = ["T1110.004", "T1078", "T1114.002"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    corp_loc = pick_corporate_location()
    atk_loc = pick_attacker_location()
    atk_ip = synth_ip("198.51")
    malware = random.choice(["RedLine", "Raccoon"])

    # Phase 1: SpyCloud detects credential exposure (T-0)
    events.append(spycloud_watchlist_event(
        ts_offset(base, 0), target_user, severity=20, malware=malware))
    events.append(spycloud_exposure_event(
        ts_offset(base, 1), target_user, risk_score=85))

    # Phase 2: Attacker credential stuffing attempts (T+60..T+120 min)
    fail_count = 5 * multiplier
    for i in range(fail_count):
        events.append(azure_ad_signin_event(
            ts_offset(base, 60 + i * 2), target_user, atk_ip, atk_loc,
            status="Failure", risk_level="medium"))

    # Phase 3: Successful sign-in (T+150 min)
    events.append(azure_ad_signin_event(
        ts_offset(base, 150), target_user, atk_ip, atk_loc,
        status="Success", risk_level="high"))
    events.append(conditional_access_eval_event(
        ts_offset(base, 150), target_user, "Require MFA for risky sign-ins",
        result="notApplied"))

    # Phase 4: Data exfiltration via mailbox (T+160..T+200 min)
    events.append(o365_audit_event(
        ts_offset(base, 160), target_user, "New-InboxRule",
        Workload="Exchange", Details={"RuleName": "SYNTH-AutoForward", "ForwardTo": "attacker@synth-c2.example.net"}))
    for i in range(3 * multiplier):
        events.append(o365_audit_event(
            ts_offset(base, 165 + i * 5), target_user, "MailItemsAccessed",
            Workload="Exchange"))

    report = {
        "scenario": "credential-stuffing",
        "description": "Credential stuffing attack using exposed credentials from SpyCloud watchlist",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Initial Access", "time": "T+0", "description": "SpyCloud detects credential in darknet breach"},
            {"phase": "Credential Stuffing", "time": "T+60min", "description": f"{fail_count} failed sign-in attempts from {atk_loc['city']}, {atk_loc['country']}"},
            {"phase": "Account Compromise", "time": "T+150min", "description": "Successful authentication with stolen credential"},
            {"phase": "Exfiltration", "time": "T+160min", "description": "Inbox rule created, mail items accessed"},
        ],
    }
    return events, mitre, report


def scenario_session_hijack(target_user: str, timeline_hours: int,
                            intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    Attack chain: SpyCloud cookie theft -> impossible travel sign-in
    -> mailbox rule creation.
    """
    events = []
    mitre = ["T1539", "T1550.004", "T1078.004", "T1114.002"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    corp_loc = pick_corporate_location()
    atk_loc = pick_attacker_location()
    atk_ip = synth_ip("203.0")
    malware = random.choice(["LummaC2", "StealC"])

    # Phase 1: SpyCloud detects stolen session cookie
    events.append(spycloud_sip_event(
        ts_offset(base, 0), target_user,
        "login.microsoftonline.example.com", malware))
    events.append(spycloud_compass_event(
        ts_offset(base, 5), target_user, malware))

    # Phase 2: Legitimate sign-in from corporate location
    events.append(azure_ad_signin_event(
        ts_offset(base, 30), target_user, synth_ip(), corp_loc,
        status="Success", app="Microsoft 365"))

    # Phase 3: Impossible travel -- attacker uses stolen cookie
    events.append(azure_ad_signin_event(
        ts_offset(base, 35), target_user, atk_ip, atk_loc,
        status="Success", app="Microsoft 365", risk_level="high",
        UserAgent="Mozilla/5.0 (SYNTH-Attacker-Browser)"))

    # Phase 4: Mailbox rule + data access
    events.append(o365_audit_event(
        ts_offset(base, 45), target_user, "Set-Mailbox",
        Details={"ForwardingSmtpAddress": "synth-exfil@c2.example.net"}))
    events.append(o365_audit_event(
        ts_offset(base, 50), target_user, "New-InboxRule",
        Details={"RuleName": "SYNTH-HideForward", "DeleteMessage": True}))

    for i in range(4 * multiplier):
        events.append(o365_audit_event(
            ts_offset(base, 55 + i * 3), target_user, "MailItemsAccessed"))

    # MDE alert on the infected endpoint
    events.append(mde_alert_event(
        ts_offset(base, 10), synth_hostname(),
        f"{malware} infostealer activity detected",
        category="Malware", mitre_techniques=["T1539"]))

    report = {
        "scenario": "session-hijack",
        "description": "Session cookie stolen by infostealer, used for impossible travel account takeover",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Cookie Theft", "time": "T+0", "description": f"SpyCloud detects stolen session cookie ({malware} stealer)"},
            {"phase": "Normal Activity", "time": "T+30min", "description": f"Legitimate sign-in from {corp_loc['city']}"},
            {"phase": "Impossible Travel", "time": "T+35min", "description": f"Attacker sign-in from {atk_loc['city']} using stolen cookie (5 min gap)"},
            {"phase": "Persistence & Exfil", "time": "T+45min", "description": "Mailbox forwarding rule + mail access"},
        ],
    }
    return events, mitre, report


def scenario_ransomware_precursor(target_user: str, timeline_hours: int,
                                  intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    Infostealer -> lateral movement -> privilege escalation -> persistence.
    """
    events = []
    mitre = ["T1078", "T1021.001", "T1003.001", "T1053.005",
             "T1562.001", "T1486", "T1059.001", "T1547.001"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    malware = random.choice(["Vidar", "RedLine", "Raccoon"])
    hostname0 = synth_hostname()
    hostname_dc = "SYNTH-DC-001"

    # Phase 1: Infostealer exposure
    events.append(spycloud_watchlist_event(
        ts_offset(base, 0), target_user, severity=25, malware=malware,
        user_hostname=hostname0))
    events.append(spycloud_compass_event(
        ts_offset(base, 5), target_user, malware, severity=25))
    events.append(mde_alert_event(
        ts_offset(base, 10), hostname0,
        f"{malware} infostealer detected",
        severity="High", category="Malware", mitre_techniques=["T1078"]))

    # Phase 2: Lateral movement (T+60 min)
    lateral_targets = [synth_hostname() for _ in range(2 * multiplier)]
    for i, h in enumerate(lateral_targets):
        events.append(mde_alert_event(
            ts_offset(base, 60 + i * 10), h,
            "Suspicious RDP connection from compromised host",
            severity="Medium", category="LateralMovement",
            mitre_techniques=["T1021.001"]))

    # Phase 3: Credential dumping (T+120 min)
    events.append(mde_alert_event(
        ts_offset(base, 120), lateral_targets[0],
        "LSASS memory access detected (credential dumping)",
        severity="High", category="CredentialAccess",
        mitre_techniques=["T1003.001"]))

    # Phase 4: Domain controller access (T+180 min)
    events.append(mde_alert_event(
        ts_offset(base, 180), hostname_dc,
        "Suspicious DCSync operation detected",
        severity="Critical", category="CredentialAccess",
        mitre_techniques=["T1003.006"]))

    # Phase 5: Persistence & defense evasion (T+200 min)
    events.append(mde_alert_event(
        ts_offset(base, 200), hostname_dc,
        "Scheduled task created for persistence",
        severity="High", category="Persistence",
        mitre_techniques=["T1053.005"]))
    events.append(mde_alert_event(
        ts_offset(base, 210), hostname_dc,
        "Security product tampering detected",
        severity="High", category="DefenseEvasion",
        mitre_techniques=["T1562.001"]))

    # Phase 6: Pre-ransomware PowerShell activity (T+240 min)
    events.append(mde_alert_event(
        ts_offset(base, 240), hostname_dc,
        "Suspicious PowerShell execution - potential ransomware staging",
        severity="Critical", category="Execution",
        mitre_techniques=["T1059.001"]))

    report = {
        "scenario": "ransomware-precursor",
        "description": "Infostealer-to-ransomware kill chain: credential theft, lateral movement, domain compromise",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Initial Compromise", "time": "T+0", "description": f"{malware} infostealer detected by SpyCloud"},
            {"phase": "Lateral Movement", "time": "T+60min", "description": f"RDP to {len(lateral_targets)} hosts"},
            {"phase": "Credential Dumping", "time": "T+120min", "description": "LSASS memory access on compromised host"},
            {"phase": "Domain Compromise", "time": "T+180min", "description": "DCSync operation against domain controller"},
            {"phase": "Persistence", "time": "T+200min", "description": "Scheduled task + AV tampering"},
            {"phase": "Pre-Ransomware", "time": "T+240min", "description": "Suspicious PowerShell staging activity"},
        ],
    }
    return events, mitre, report


def scenario_insider_threat(target_user: str, timeline_hours: int,
                            intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    VIP exposure -> unusual data access -> bulk download -> exfiltration.
    """
    events = []
    mitre = ["T1078", "T1213.002", "T1530", "T1567.002"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    corp_loc = pick_corporate_location()

    # Phase 1: VIP credential exposure
    events.append(spycloud_watchlist_event(
        ts_offset(base, 0), target_user, severity=25,
        job_title="CFO", company_name="Synth Corp"))
    events.append(spycloud_exposure_event(
        ts_offset(base, 5), target_user, risk_score=92))

    # Phase 2: Unusual sign-in patterns (off-hours)
    off_hours_base = base.replace(hour=2, minute=30)  # 2:30 AM
    events.append(azure_ad_signin_event(
        ts_from_dt(off_hours_base), target_user, synth_ip(), corp_loc,
        status="Success", app="SharePoint Online", risk_level="medium"))

    # Phase 3: Bulk data access (T+30 min)
    for i in range(10 * multiplier):
        events.append(o365_audit_event(
            ts_offset(off_hours_base, 30 + i * 2), target_user,
            "FileDownloaded", workload="SharePoint",
            ObjectId=f"/sites/synth-finance/Shared Documents/Q4-Report-{i}.xlsx"))

    # Phase 4: Cloud storage exfiltration
    events.append(o365_audit_event(
        ts_offset(off_hours_base, 90), target_user,
        "SharingSet", workload="OneDrive",
        Details={"TargetUser": "external-synth@personal-mail.example.com", "SharingType": "AnonymousLink"}))

    report = {
        "scenario": "insider-threat",
        "description": "VIP credential exposure followed by anomalous off-hours bulk data access and exfiltration",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Exposure Detection", "time": "T+0", "description": "SpyCloud detects VIP credential in darknet"},
            {"phase": "Unusual Access", "time": "T+2:30AM", "description": "Off-hours sign-in to SharePoint"},
            {"phase": "Bulk Download", "time": "+30min", "description": f"{10 * multiplier} files downloaded from finance site"},
            {"phase": "Exfiltration", "time": "+90min", "description": "Anonymous sharing link created for external user"},
        ],
    }
    return events, mitre, report


def scenario_supply_chain(target_user: str, timeline_hours: int,
                          intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    Third-party credential exposure -> OAuth app consent -> API abuse.
    """
    events = []
    mitre = ["T1195.002", "T1528", "T1550.001", "T1078.004"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    atk_ip = synth_ip("198.51")
    atk_loc = pick_attacker_location()
    third_party_email = target_user.replace("@", "@vendor-synth.")

    # Phase 1: Third-party partner credential exposed
    events.append(spycloud_watchlist_event(
        ts_offset(base, 0), third_party_email, severity=20))
    events.append({
        "_source": "SpyCloudDataPartnership_CL",
        "TimeGenerated": ts_offset(base, 5),
        "document_id": synth_uuid(),
        "partner_id": "SYNTH-PTR-001",
        "partner_name": "Synthetic Vendor Alpha",
        "email": third_party_email,
        "email_domain": third_party_email.split("@")[1],
        "severity": 20,
        "source_type": "darknet_forum",
        "log_id": synth_uuid(),
        "spycloud_publish_date": ts_offset(base, 0)[:10],
    })

    # Phase 2: Attacker uses vendor cred to register OAuth app
    events.append(azure_ad_signin_event(
        ts_offset(base, 60), third_party_email, atk_ip, atk_loc,
        status="Success", app="Azure Portal", risk_level="medium"))
    events.append(o365_audit_event(
        ts_offset(base, 65), third_party_email,
        "Consent to application", workload="AzureActiveDirectory",
        Details={"AppName": "SYNTH-MaliciousApp", "Permissions": "Mail.Read, Files.ReadWrite.All, User.ReadAll"}))

    # Phase 3: API abuse using consented app (T+90 min)
    for i in range(5 * multiplier):
        events.append(o365_audit_event(
            ts_offset(base, 90 + i * 5), f"app:SYNTH-MaliciousApp",
            "MailItemsAccessed", workload="Exchange",
            TargetUser=target_user))

    events.append(conditional_access_eval_event(
        ts_offset(base, 90), third_party_email,
        "Block legacy authentication", result="notApplied"))

    report = {
        "scenario": "supply-chain",
        "description": "Third-party vendor credential exposure leading to OAuth app consent abuse",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Vendor Compromise", "time": "T+0", "description": f"Vendor credential ({third_party_email}) found in darknet"},
            {"phase": "OAuth Consent", "time": "T+65min", "description": "Malicious OAuth app registered with excessive permissions"},
            {"phase": "API Abuse", "time": "T+90min", "description": f"App reads {5 * multiplier} mail items from {target_user}"},
        ],
    }
    return events, mitre, report


def scenario_mfa_fatigue(target_user: str, timeline_hours: int,
                         intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    SpyCloud exposure -> repeated MFA push -> MFA accept -> ATO.
    """
    events = []
    mitre = ["T1078", "T1621", "T1098.003"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    atk_ip = synth_ip("203.0")
    atk_loc = pick_attacker_location()

    # Phase 1: SpyCloud credential exposure
    events.append(spycloud_watchlist_event(
        ts_offset(base, 0), target_user, severity=25, malware="RedLine"))
    events.append(spycloud_exposure_event(
        ts_offset(base, 5), target_user, risk_score=88))

    # Phase 2: Successful password auth, MFA push bombardment
    push_count = 8 * multiplier
    for i in range(push_count):
        events.append(azure_ad_signin_event(
            ts_offset(base, 60 + i * 2), target_user, atk_ip, atk_loc,
            status="Failure", mfa_result="Denied",
            risk_level="medium"))

    # Phase 3: User fatigued -- accepts MFA push
    events.append(azure_ad_signin_event(
        ts_offset(base, 60 + push_count * 2 + 1), target_user, atk_ip, atk_loc,
        status="Success", mfa_result="Approved",
        risk_level="high"))

    # Phase 4: ATO -- attacker adds cloud admin role
    events.append(o365_audit_event(
        ts_offset(base, 60 + push_count * 2 + 10), target_user,
        "Add member to role", workload="AzureActiveDirectory",
        Details={"RoleName": "Global Administrator", "TargetUser": f"backdoor-synth@{target_user.split('@')[1]}"}))
    events.append(o365_audit_event(
        ts_offset(base, 60 + push_count * 2 + 15), target_user,
        "Add application", workload="AzureActiveDirectory",
        Details={"AppName": "SYNTH-Backdoor-App"}))

    report = {
        "scenario": "mfa-fatigue",
        "description": "MFA push bombardment after credential exposure, leading to account takeover",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Credential Exposure", "time": "T+0", "description": "SpyCloud detects RedLine stealer credential"},
            {"phase": "MFA Bombardment", "time": "T+60min", "description": f"{push_count} MFA pushes sent in rapid succession"},
            {"phase": "MFA Fatigue Accept", "time": f"T+{60 + push_count * 2 + 1}min", "description": "User approves MFA push out of fatigue"},
            {"phase": "Privilege Escalation", "time": "Later", "description": "Attacker adds Global Admin role and backdoor app"},
        ],
    }
    return events, mitre, report


def scenario_identity_pivot(target_user: str, timeline_hours: int,
                            intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    IDLink correlation -> cross-domain access -> cloud app abuse.
    """
    events = []
    mitre = ["T1078", "T1078.004", "T1528", "T1530"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    atk_ip = synth_ip("198.51")
    atk_loc = pick_attacker_location()

    # Build linked identity graph
    domain = target_user.split("@")[1]
    alt_email = f"{target_user.split('@')[0]}@personal-synth.example.com"
    linked_emails = [alt_email, f"admin-synth@{domain}"]

    # Phase 1: IDLink discovers identity graph
    events.append(spycloud_idlink_event(
        ts_offset(base, 0), target_user, linked_emails))
    events.append(spycloud_watchlist_event(
        ts_offset(base, 5), alt_email, severity=25, malware="LummaC2"))

    # Phase 2: Personal email credential used to pivot to corporate
    events.append(azure_ad_signin_event(
        ts_offset(base, 60), target_user, atk_ip, atk_loc,
        status="Success", app="Microsoft 365", risk_level="high"))

    # Phase 3: Cross-domain abuse
    for i in range(3 * multiplier):
        events.append(o365_audit_event(
            ts_offset(base, 90 + i * 5), target_user,
            "FileDownloaded", workload="SharePoint",
            ObjectId=f"/sites/synth-engineering/designs/blueprint-{i}.pdf"))

    events.append(o365_audit_event(
        ts_offset(base, 150), target_user,
        "Add service principal", workload="AzureActiveDirectory",
        Details={"AppName": "SYNTH-DataExfil-App"}))

    report = {
        "scenario": "identity-pivot",
        "description": "Identity graph reveals linked personal account, used to pivot into corporate environment",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "Identity Discovery", "time": "T+0", "description": f"IDLink reveals {target_user} linked to {alt_email}"},
            {"phase": "Personal Compromise", "time": "T+5min", "description": "Personal email credential exposed via LummaC2"},
            {"phase": "Corporate Pivot", "time": "T+60min", "description": "Attacker authenticates to corporate using reused password"},
            {"phase": "Data Access", "time": "T+90min", "description": f"{3 * multiplier} engineering files downloaded"},
        ],
    }
    return events, mitre, report


def scenario_cap_breach(target_user: str, timeline_hours: int,
                        intensity: str) -> Tuple[List[Dict], List[str], Dict]:
    """
    CAP exposure -> corporate asset access -> data staging.
    """
    events = []
    mitre = ["T1078", "T1530", "T1074.002", "T1567.002"]
    multiplier = INTENSITY_MULTIPLIERS[intensity]
    base = datetime.datetime.utcnow() - datetime.timedelta(hours=timeline_hours)
    atk_ip = synth_ip("203.0")
    atk_loc = pick_attacker_location()

    # Phase 1: CAP detects credential exposure and attempts auto-remediation
    events.append(spycloud_cap_event(
        ts_offset(base, 0), target_user, "password_reset", status="failed"))
    events.append(spycloud_watchlist_event(
        ts_offset(base, 5), target_user, severity=25, malware="StealC"))
    events.append(spycloud_exposure_event(
        ts_offset(base, 10), target_user, risk_score=95))

    # Phase 2: Failed CAP remediation -- attacker still has access
    events.append(azure_ad_signin_event(
        ts_offset(base, 30), target_user, atk_ip, atk_loc,
        status="Success", app="Azure Portal", risk_level="high"))
    events.append(conditional_access_eval_event(
        ts_offset(base, 30), target_user,
        "Block compromised credentials", result="failure"))

    # Phase 3: Corporate asset enumeration and access
    events.append(o365_audit_event(
        ts_offset(base, 45), target_user,
        "SearchQueryPerformed", workload="SharePoint",
        Details={"Query": "confidential budget forecast 2026"}))
    for i in range(6 * multiplier):
        events.append(o365_audit_event(
            ts_offset(base, 50 + i * 3), target_user,
            "FileDownloaded", workload="SharePoint",
            ObjectId=f"/sites/synth-executive/Documents/budget-{i}.xlsx"))

    # Phase 4: Data staging in OneDrive
    events.append(o365_audit_event(
        ts_offset(base, 120), target_user,
        "FolderCreated", workload="OneDrive",
        ObjectId="/personal/staging-synth"))
    events.append(o365_audit_event(
        ts_offset(base, 130), target_user,
        "SharingSet", workload="OneDrive",
        Details={"SharingType": "AnonymousLink", "Folder": "/personal/staging-synth"}))

    # CAP retry succeeds late
    events.append(spycloud_cap_event(
        ts_offset(base, 180), target_user, "session_revoke", status="success"))

    report = {
        "scenario": "cap-breach",
        "description": "CAP auto-remediation fails, attacker accesses corporate assets before manual intervention",
        "target": target_user,
        "timeline_hours": timeline_hours,
        "phases": [
            {"phase": "CAP Detection", "time": "T+0", "description": "CAP detects exposure, password reset FAILS"},
            {"phase": "Credential Use", "time": "T+30min", "description": f"Attacker authenticates from {atk_loc['city']}"},
            {"phase": "Data Access", "time": "T+45min", "description": f"SharePoint search + {6 * multiplier} file downloads"},
            {"phase": "Data Staging", "time": "T+120min", "description": "Files staged in OneDrive with anonymous sharing link"},
            {"phase": "Late Remediation", "time": "T+180min", "description": "CAP session revocation succeeds (too late)"},
        ],
    }
    return events, mitre, report


SCENARIO_RUNNERS = {
    "credential-stuffing": scenario_credential_stuffing,
    "session-hijack": scenario_session_hijack,
    "ransomware-precursor": scenario_ransomware_precursor,
    "insider-threat": scenario_insider_threat,
    "supply-chain": scenario_supply_chain,
    "mfa-fatigue": scenario_mfa_fatigue,
    "identity-pivot": scenario_identity_pivot,
    "cap-breach": scenario_cap_breach,
}


# ---------------------------------------------------------------------------
# MITRE ATT&CK report
# ---------------------------------------------------------------------------

def build_mitre_report(techniques_used: List[str]) -> List[Dict[str, str]]:
    return [
        {"technique_id": tid, "technique_name": MITRE_TECHNIQUES.get(tid, "Unknown")}
        for tid in techniques_used
    ]


# ---------------------------------------------------------------------------
# Teach-Agent mode
# ---------------------------------------------------------------------------

def generate_teach_agent_doc(scenario_name: str, report: Dict,
                             mitre_report: List[Dict],
                             events: List[Dict]) -> str:
    """
    Generate a training document for Security Copilot that explains the
    scenario, the expected sequence of events, detection logic, and
    recommended response actions.
    """
    lines = [
        f"# SpyCloud Purple Team Training: {scenario_name}",
        "",
        f"## Scenario Description",
        f"{report['description']}",
        "",
        f"## Target: {report['target']}",
        f"## Timeline: {report['timeline_hours']} hours",
        "",
        "## Attack Phases",
    ]
    for p in report.get("phases", []):
        lines.append(f"### {p['phase']} ({p['time']})")
        lines.append(f"{p['description']}")
        lines.append("")

    lines.append("## MITRE ATT&CK Mapping")
    for m in mitre_report:
        lines.append(f"- **{m['technique_id']}**: {m['technique_name']}")
    lines.append("")

    lines.append("## Data Sources Involved")
    sources = sorted(set(e.get("_source", "Unknown") for e in events))
    for s in sources:
        count = sum(1 for e in events if e.get("_source") == s)
        lines.append(f"- {s}: {count} events")
    lines.append("")

    lines.append("## Detection Guidance for Security Copilot")
    lines.append("")
    lines.append("When investigating this type of attack, the AI agent should:")
    lines.append("1. Query SpyCloud tables for the affected user's exposure history")
    lines.append("2. Correlate exposure timestamps with Azure AD sign-in anomalies")
    lines.append("3. Check for impossible travel or unusual geolocations in sign-in logs")
    lines.append("4. Look for new inbox rules, OAuth app consents, or role assignments")
    lines.append("5. Verify if CAP/Conditional Access policies were evaluated and their results")
    lines.append("6. Check MDE for endpoint alerts on infected machines")
    lines.append("7. Recommend immediate remediation: password reset, session revocation, MFA re-enrollment")
    lines.append("")

    lines.append("## Recommended Response Actions")
    lines.append("- Force password reset for affected accounts")
    lines.append("- Revoke all active sessions (Azure AD: Revoke-AzureADUserAllRefreshToken)")
    lines.append("- Isolate infected endpoints via MDE")
    lines.append("- Review and remove suspicious OAuth app consents")
    lines.append("- Enable Conditional Access policy to block compromised credentials")
    lines.append("- Run SpyCloud Investigations API for deeper exposure analysis")
    lines.append("- Report incident to SOC and update incident timeline")
    lines.append("")

    lines.append("## Sample KQL Queries")
    lines.append("```kql")
    lines.append("// Check SpyCloud watchlist for this user")
    lines.append(f"SpyCloudBreachWatchlist_CL")
    lines.append(f"| where email == \"{report['target']}\"")
    lines.append(f"| where severity >= 20")
    lines.append(f"| project TimeGenerated, severity, breach_category, malware_family, target_domain")
    lines.append(f"| order by TimeGenerated desc")
    lines.append("```")
    lines.append("")
    lines.append("```kql")
    lines.append("// Correlate with sign-in anomalies")
    lines.append(f"SigninLogs")
    lines.append(f"| where UserPrincipalName == \"{report['target']}\"")
    lines.append(f"| where RiskLevelDuringSignIn in (\"medium\", \"high\")")
    lines.append(f"| project TimeGenerated, IPAddress, Location, ResultDescription, RiskLevelDuringSignIn")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output handlers
# ---------------------------------------------------------------------------

def output_stdout(events: List[Dict], report: Dict, mitre_report: List[Dict],
                  teach_doc: Optional[str] = None) -> None:
    output = {
        "scenario_report": report,
        "mitre_attack_mapping": mitre_report,
        "event_count": len(events),
        "events": events,
    }
    print(json.dumps(output, indent=2, default=str))
    if teach_doc:
        print("\n" + "=" * 80)
        print(teach_doc)


def output_files(events: List[Dict], report: Dict, mitre_report: List[Dict],
                 scenario_name: str, output_dir: str,
                 teach_doc: Optional[str] = None) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # Group events by source
    by_source: Dict[str, List[Dict]] = {}
    for e in events:
        src = e.get("_source", "unknown").replace(" ", "_").replace("(", "").replace(")", "").replace(",", "")
        by_source.setdefault(src, []).append(e)

    for src, src_events in by_source.items():
        filepath = os.path.join(output_dir, f"{scenario_name}_{src}.json")
        with open(filepath, "w") as f:
            json.dump(src_events, f, indent=2, default=str)
        log.info(f"  Wrote {len(src_events)} events to {filepath}")

    # Scenario report
    report_path = os.path.join(output_dir, f"{scenario_name}_report.json")
    with open(report_path, "w") as f:
        json.dump({"scenario_report": report, "mitre_attack_mapping": mitre_report},
                  f, indent=2, default=str)
    log.info(f"  Wrote scenario report to {report_path}")

    # Teach-agent doc
    if teach_doc:
        teach_path = os.path.join(output_dir, f"{scenario_name}_training.md")
        with open(teach_path, "w") as f:
            f.write(teach_doc)
        log.info(f"  Wrote training document to {teach_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SpyCloud Sentinel -- Purple Team Scenario Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:
  credential-stuffing   Exposure -> failed sign-ins -> success -> data exfil
  session-hijack        Cookie theft -> impossible travel -> mailbox rule
  ransomware-precursor  Infostealer -> lateral movement -> privilege escalation
  insider-threat        VIP exposure -> unusual access -> bulk download -> exfil
  supply-chain          Third-party cred -> OAuth consent -> API abuse
  mfa-fatigue           Exposure -> MFA push spam -> accept -> ATO
  identity-pivot        IDLink -> cross-domain access -> cloud app abuse
  cap-breach            CAP exposure -> asset access -> data staging

Examples:
  %(prog)s --scenario credential-stuffing --target-user alice@example.com
  %(prog)s --scenario session-hijack --intensity high --output file
  %(prog)s --scenario ransomware-precursor --teach-agent
""",
    )

    parser.add_argument(
        "--scenario", type=str, required=True,
        choices=list(SCENARIO_RUNNERS.keys()),
        help="Attack scenario to simulate.",
    )
    parser.add_argument(
        "--target-user", type=str, default="alice.johnson@example.com",
        help="Target user email (default: alice.johnson@example.com).",
    )
    parser.add_argument(
        "--timeline", type=int, default=24,
        help="Timeline window in hours (default: 24).",
    )
    parser.add_argument(
        "--intensity", type=str, choices=["low", "medium", "high"], default="medium",
        help="Event intensity / volume multiplier (default: medium).",
    )
    parser.add_argument(
        "--output", type=str, choices=["stdout", "file"], default="stdout",
        help="Output destination (default: stdout).",
    )
    parser.add_argument(
        "--output-dir", type=str, default="./purple-team-output",
        help="Directory for file output (default: ./purple-team-output).",
    )
    parser.add_argument(
        "--teach-agent", action="store_true",
        help="Generate a training document for Security Copilot.",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducible output.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.seed is not None:
        random.seed(args.seed)
        log.info(f"Random seed set to {args.seed}")

    log.info(f"Running purple team scenario: {args.scenario}")
    log.info(f"  Target user: {args.target_user}")
    log.info(f"  Timeline: {args.timeline} hours")
    log.info(f"  Intensity: {args.intensity}")

    runner = SCENARIO_RUNNERS[args.scenario]
    events, mitre_ids, report = runner(args.target_user, args.timeline, args.intensity)

    mitre_report = build_mitre_report(mitre_ids)

    log.info(f"Generated {len(events)} events across {len(set(e.get('_source','') for e in events))} data sources")
    log.info(f"MITRE ATT&CK techniques: {', '.join(mitre_ids)}")

    # Teach-agent document
    teach_doc = None
    if args.teach_agent:
        teach_doc = generate_teach_agent_doc(args.scenario, report, mitre_report, events)
        log.info("Generated Security Copilot training document")

    # Output
    if args.output == "stdout":
        output_stdout(events, report, mitre_report, teach_doc)
    elif args.output == "file":
        output_files(events, report, mitre_report, args.scenario,
                     args.output_dir, teach_doc)
        log.info(f"Files written to {os.path.abspath(args.output_dir)}")

    # Summary
    print("\n" + "=" * 70, file=sys.stderr)
    print(f"  PURPLE TEAM SCENARIO COMPLETE: {args.scenario}", file=sys.stderr)
    print(f"  Target: {args.target_user}", file=sys.stderr)
    print(f"  Events generated: {len(events)}", file=sys.stderr)
    print(f"  MITRE techniques: {len(mitre_ids)}", file=sys.stderr)
    print(f"  Attack phases: {len(report.get('phases', []))}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


if __name__ == "__main__":
    main()
