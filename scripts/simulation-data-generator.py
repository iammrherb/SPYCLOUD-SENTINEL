#!/usr/bin/env python3
"""
SpyCloud Sentinel -- Simulation Data Generator
================================================
Generates realistic synthetic test data for ALL SpyCloud Sentinel custom tables.
Used for testing the full Sentinel deployment without a live SpyCloud API connection.

All data is clearly synthetic: example.com domains, 10.x.x.x IPs, SYNTH- prefixed IDs.
No actual breach data or real credentials are included.

Tables supported:
  - SpyCloudBreachWatchlist_CL      (Enterprise breach watchlist records)
  - SpyCloudBreachCatalog_CL        (Breach catalog metadata)
  - SpyCloudCompassData_CL          (Compass infostealer intelligence)
  - SpyCloudCompassDevices_CL       (Compass infected device inventory)
  - SpyCloudCompassApplications_CL  (Compass stolen-app data)
  - SpyCloudSipCookies_CL           (Session Identity Protection cookies)
  - SpyCloudIdentityExposure_CL     (Identity exposure summary)
  - SpyCloudInvestigations_CL       (Investigations API deep-dive)
  - SpyCloudIdLink_CL               (Identity link graph)
  - SpyCloudExposure_CL             (Exposure risk roll-up)
  - SpyCloudCAP_CL                  (Continuous Access Policy actions)
  - SpyCloudDataPartnership_CL      (Third-party data partnership)
  - Spycloud_MDE_Logs_CL            (MDE isolation action logs)
  - SpyCloud_ConditionalAccessLogs_CL (Conditional Access action logs)

Usage examples:
  # Generate 50 BreachWatchlist records to stdout
  python3 simulation-data-generator.py --table BreachWatchlist --count 50

  # Generate all tables, 20 records each, to files
  python3 simulation-data-generator.py --table all --count 20 --output file

  # Run the infostealer-outbreak scenario
  python3 simulation-data-generator.py --scenario infostealer-outbreak --count 30

  # Send data directly to Log Analytics workspace
  python3 simulation-data-generator.py --table all --count 10 --output sentinel \\
      --workspace-id <id> --shared-key <key>

Version: 1.0.0
"""

import argparse
import datetime
import hashlib
import hmac
import base64
import json
import logging
import os
import random
import string
import sys
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants -- all synthetic
# ---------------------------------------------------------------------------
SYNTH_DOMAINS = [
    "example.com", "test-corp.example.com", "acme-labs.example.net",
    "globex-corp.example.org", "initech.example.com", "contoso.example.com",
    "fabrikam.example.net", "woodgrove.example.org", "northwind.example.com",
    "tailspin.example.net",
]

SYNTH_TARGET_DOMAINS = [
    "login.microsoftonline.example.com", "accounts.google.example.com",
    "github.example.com", "okta.example.com", "aws.example.com",
    "salesforce.example.com", "slack.example.com", "zoom.example.com",
    "jira.example.com", "confluence.example.com", "office365.example.com",
    "dropbox.example.com", "box.example.com", "servicenow.example.com",
    "workday.example.com", "bamboohr.example.com",
]

SYNTH_FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Edward", "Fiona", "George",
    "Hannah", "Ivan", "Julia", "Kevin", "Laura", "Michael", "Nancy",
    "Oscar", "Patricia", "Quinn", "Rachel", "Samuel", "Tina",
]

SYNTH_LAST_NAMES = [
    "Anderson", "Brown", "Clark", "Davis", "Evans", "Foster", "Garcia",
    "Harris", "Ingram", "Johnson", "Kim", "Lopez", "Martinez", "Nelson",
    "Olsen", "Patel", "Quinn", "Robinson", "Smith", "Thompson",
]

MALWARE_FAMILIES = [
    "Raccoon", "RedLine", "Vidar", "LummaC2", "StealC",
    "Titan", "Aurora", "MetaStealer", "RisePro", "Mystic",
]

SEVERITY_LEVELS = [2, 5, 20, 25]

PASSWORD_TYPES = ["plaintext", "hashed_sha256", "hashed_bcrypt", "hashed_md5", "hashed_sha1"]

BREACH_CATEGORIES = [
    "infostealer", "combolist", "database_dump", "paste_site",
    "credential_stuffing", "phishing", "ransomware_leak",
]

OPERATING_SYSTEMS = [
    "Windows 10 Pro", "Windows 11 Enterprise", "Windows 10 Home",
    "Windows Server 2019", "macOS 14.2", "Ubuntu 22.04",
]

AV_SOFTWARE = [
    "Windows Defender", "CrowdStrike Falcon", "SentinelOne",
    "Carbon Black", "Sophos", "Malwarebytes", "Norton 360",
]

COOKIE_NAMES = [
    "session_id", "JSESSIONID", "SSID", "NID", "SID", "HSID",
    "APISID", "__Secure-1PSID", "_ga", "csrf_token", "auth_token",
    "XSRF-TOKEN", "connect.sid", "PHPSESSID",
]

COUNTRY_CODES = ["US", "GB", "DE", "FR", "RU", "CN", "BR", "IN", "JP", "AU"]

DISPLAY_RESOLUTIONS = ["1920x1080", "2560x1440", "3840x2160", "1366x768", "1440x900"]

JOB_TITLES = [
    "Software Engineer", "VP of Engineering", "CISO", "CFO", "CEO",
    "DevOps Engineer", "Security Analyst", "IT Admin", "Product Manager",
    "Data Scientist", "Intern", "Sales Director", "HR Manager",
]

COMPLIANCE_TAGS = ["SOC2", "PCI-DSS", "HIPAA", "GDPR", "NIST-800-53", "ISO-27001"]

CAP_POLICY_NAMES = [
    "High-Risk Credential Reset", "Infostealer Auto-Remediation",
    "VIP Account Protection", "Session Revocation Policy",
    "MFA Re-enrollment Required", "Conditional Block on Compromised Cred",
]

SCENARIO_DEFINITIONS = {
    "infostealer-outbreak": {
        "description": "Simulates a wave of infostealer infections hitting corporate endpoints",
        "tables": ["BreachWatchlist", "Compass", "CompassDevices", "CompassApplications", "SIP", "MDE"],
        "malware_families": ["Raccoon", "RedLine", "LummaC2"],
        "severity_bias": [20, 25],
    },
    "executive-compromise": {
        "description": "VIP / C-suite credentials exposed in a darknet marketplace",
        "tables": ["BreachWatchlist", "Investigations", "Exposure", "CAP", "ConditionalAccess"],
        "job_titles": ["CEO", "CFO", "CISO", "VP of Engineering"],
        "severity_bias": [25],
    },
    "session-hijack": {
        "description": "Stolen session cookies enabling account takeover",
        "tables": ["SIP", "Compass", "BreachWatchlist", "ConditionalAccess"],
        "malware_families": ["LummaC2", "StealC"],
        "severity_bias": [20, 25],
    },
    "mass-credential-dump": {
        "description": "Large combolist dump affecting many corporate users",
        "tables": ["BreachWatchlist", "BreachCatalog", "Exposure", "IdentityExposure"],
        "breach_categories": ["combolist", "database_dump"],
        "severity_bias": [2, 5],
    },
    "reinfection-campaign": {
        "description": "Previously remediated endpoints re-infected with new stealer variant",
        "tables": ["Compass", "CompassDevices", "CompassApplications", "BreachWatchlist", "MDE"],
        "malware_families": ["Vidar", "RisePro"],
        "severity_bias": [20, 25],
    },
}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("spycloud-sim")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def synth_uuid() -> str:
    return f"SYNTH-{uuid.uuid4()}"


def synth_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


def synth_machine_id() -> str:
    return f"SYNTH-MACHINE-{uuid.uuid4().hex[:12].upper()}"


def synth_email(domain: Optional[str] = None) -> str:
    first = random.choice(SYNTH_FIRST_NAMES).lower()
    last = random.choice(SYNTH_LAST_NAMES).lower()
    d = domain or random.choice(SYNTH_DOMAINS)
    return f"{first}.{last}@{d}"


def synth_username() -> str:
    first = random.choice(SYNTH_FIRST_NAMES).lower()
    last = random.choice(SYNTH_LAST_NAMES).lower()
    return f"{first}.{last}"


def synth_full_name() -> str:
    return f"{random.choice(SYNTH_FIRST_NAMES)} {random.choice(SYNTH_LAST_NAMES)}"


def synth_phone() -> str:
    return f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}"


def synth_password() -> str:
    """Generate a clearly-fake synthetic password."""
    return f"SynthPass{random.randint(1000,9999)}!{''.join(random.choices(string.ascii_letters, k=4))}"


def synth_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def synth_hostname() -> str:
    dept = random.choice(["WS", "LAP", "DT", "SRV", "VDI"])
    return f"SYNTH-{dept}-{random.randint(1000,9999)}"


def synth_timestamp(hours_ago_max: int = 720) -> str:
    """ISO 8601 timestamp within the last N hours."""
    delta = datetime.timedelta(hours=random.randint(0, hours_ago_max))
    ts = datetime.datetime.utcnow() - delta
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def synth_date(days_ago_max: int = 365) -> str:
    delta = datetime.timedelta(days=random.randint(0, days_ago_max))
    d = datetime.date.today() - delta
    return d.isoformat()


def synth_cookie_value() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")[:48]


def pick_severity(bias: Optional[List[int]] = None) -> int:
    if bias:
        return random.choice(bias)
    return random.choice(SEVERITY_LEVELS)


# ---------------------------------------------------------------------------
# Table generators
# ---------------------------------------------------------------------------

def gen_breach_watchlist(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudBreachWatchlist_CL"""
    severity_bias = kwargs.get("severity_bias")
    records = []
    for _ in range(count):
        email = synth_email()
        email_parts = email.split("@")
        severity = pick_severity(severity_bias)
        malware = random.choice(MALWARE_FAMILIES) if severity >= 20 else ""
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "email": email,
            "email_domain": email_parts[1],
            "email_username": email_parts[0],
            "domain": email_parts[1],
            "password": synth_hash(synth_password()),
            "password_plaintext": synth_password() if severity >= 20 else "",
            "password_type": random.choice(PASSWORD_TYPES),
            "severity": severity,
            "sighting": random.randint(1, 12),
            "breach_category": random.choice(BREACH_CATEGORIES),
            "breach_title": f"SYNTH Breach #{random.randint(1000,9999)}",
            "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
            "target_subdomain": f"auth.{random.choice(SYNTH_TARGET_DOMAINS)}",
            "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
            "infected_machine_id": synth_machine_id() if severity >= 20 else "",
            "infected_path": f"C:\\Users\\synth_user\\AppData\\Local\\Temp\\{malware.lower()}.exe" if malware else "",
            "infected_time": synth_timestamp(hours_ago_max=168) if severity >= 20 else "",
            "user_hostname": synth_hostname() if severity >= 20 else "",
            "user_os": random.choice(OPERATING_SYSTEMS) if severity >= 20 else "",
            "user_sys_registered_owner": synth_full_name() if severity >= 20 else "",
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 3))],
            "av_softwares": random.sample(AV_SOFTWARE, k=random.randint(1, 2)),
            "country_code": random.choice(COUNTRY_CODES),
            "display_resolution": random.choice(DISPLAY_RESOLUTIONS),
            "keyboard_languages": random.choice(["en-US", "en-GB", "de-DE", "fr-FR"]),
            "timezone": random.choice(["UTC-5", "UTC-8", "UTC+0", "UTC+1", "UTC+8"]),
            "log_id": synth_uuid(),
            "spycloud_publish_date": synth_date(days_ago_max=90),
        })
    return records


def gen_breach_catalog(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudBreachCatalog_CL"""
    records = []
    for i in range(count):
        malware = random.choice(MALWARE_FAMILIES)
        cat = random.choice(BREACH_CATEGORIES)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "uuid": synth_uuid(),
            "short_title": f"SYNTH-{cat.upper()}-{random.randint(1000,9999)}",
            "site": random.choice(SYNTH_TARGET_DOMAINS),
            "site_description": f"Synthetic breach catalog entry for testing. Category: {cat}.",
            "breach_category": cat,
            "breach_main_category": "infostealer" if cat == "infostealer" else "breach",
            "consumer_category": random.choice(["corporate", "consumer", "mixed"]),
            "malware_family": malware if cat == "infostealer" else "",
            "confidence": random.choice([3, 4, 5]),
            "num_records": random.randint(500, 5000000),
            "sensitive_source": random.choice([True, False]),
            "premium_flag": random.choice(["yes", "no"]),
            "tlp": random.choice(["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]),
            "spycloud_publish_date": synth_date(days_ago_max=180),
            "acquisition_date": synth_date(days_ago_max=365),
            "assets": {
                "email": random.randint(100, 1000000),
                "password": random.randint(100, 900000),
                "cookie": random.randint(0, 500000),
                "ip_address": random.randint(50, 200000),
            },
        })
    return records


def gen_compass_data(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudCompassData_CL"""
    severity_bias = kwargs.get("severity_bias")
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        malware = random.choice(MALWARE_FAMILIES)
        severity = pick_severity(severity_bias or [20, 25])
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "email": email,
            "email_domain": parts[1],
            "email_username": parts[0],
            "domain": parts[1],
            "password": synth_hash(synth_password()),
            "password_plaintext": synth_password(),
            "password_type": random.choice(PASSWORD_TYPES),
            "severity": severity,
            "sighting": random.randint(1, 5),
            "breach_category": "infostealer",
            "breach_title": f"SYNTH {malware} Stealer Log #{random.randint(1000,9999)}",
            "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
            "target_subdomain": f"auth.{random.choice(SYNTH_TARGET_DOMAINS)}",
            "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
            "infected_machine_id": synth_machine_id(),
            "infected_path": f"C:\\Users\\synth_user\\AppData\\Local\\Temp\\{malware.lower()}_payload.exe",
            "infected_time": synth_timestamp(hours_ago_max=168),
            "user_hostname": synth_hostname(),
            "user_os": random.choice(OPERATING_SYSTEMS),
            "user_sys_registered_owner": synth_full_name(),
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 3))],
            "av_softwares": random.sample(AV_SOFTWARE, k=random.randint(1, 2)),
            "country_code": random.choice(COUNTRY_CODES),
            "display_resolution": random.choice(DISPLAY_RESOLUTIONS),
            "keyboard_languages": random.choice(["en-US", "en-GB", "de-DE"]),
            "timezone": random.choice(["UTC-5", "UTC-8", "UTC+0", "UTC+1"]),
            "log_id": synth_uuid(),
            "spycloud_publish_date": synth_date(days_ago_max=60),
            "malware_family": malware,
            "username": parts[0],
            "full_name": synth_full_name(),
            "phone": synth_phone(),
            "company_name": parts[1].split(".")[0].replace("-", " ").title(),
            "job_title": random.choice(JOB_TITLES),
            "record_type": "infostealer",
            "account_type": random.choice(["corporate", "personal"]),
            "breach_date": synth_date(days_ago_max=120),
            "breach_description": f"Synthetic {malware} stealer log collected from darknet marketplace.",
            "stolen_cookies": [
                {"domain": random.choice(SYNTH_TARGET_DOMAINS), "name": random.choice(COOKIE_NAMES)}
                for _ in range(random.randint(0, 5))
            ],
            "autofill_fields": [
                {"field": f, "value": "SYNTH_REDACTED"}
                for f in random.sample(["name", "address", "phone", "email", "company"], k=random.randint(0, 3))
            ],
            "crypto_wallets": [],
            "installed_software": random.sample(
                ["Chrome 120", "Firefox 121", "Edge 120", "Outlook 365", "Slack 4.x", "Teams 1.x", "VS Code"],
                k=random.randint(2, 5),
            ),
            "browser_history_domains": random.sample(SYNTH_TARGET_DOMAINS, k=random.randint(2, 6)),
            "bot_id": f"SYNTH-BOT-{uuid.uuid4().hex[:8]}",
            "campaign_id": f"SYNTH-CAMP-{random.randint(100,999)}",
            "c2_url": f"https://c2-synth-{random.randint(1,99)}.example.net/gate.php",
            "infection_build_id": f"BUILD-{uuid.uuid4().hex[:8].upper()}",
            "hardware_id": f"HWID-{uuid.uuid4().hex[:12].upper()}",
            "screenshot_available": random.choice([True, False]),
            "keylog_available": random.choice([True, False]),
            "file_exfiltration": random.choice([True, False]),
            "salt": "",
            "credit_card_number": "",
            "credit_card_expiration": "",
        })
    return records


def gen_compass_devices(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudCompassDevices_CL"""
    records = []
    for _ in range(count):
        records.append({
            "TimeGenerated": synth_timestamp(),
            "source_id": random.randint(40000, 49999),
            "log_id": synth_uuid(),
            "user_hostname": synth_hostname(),
            "user_os": random.choice(OPERATING_SYSTEMS),
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 3))],
            "infected_time": synth_timestamp(hours_ago_max=168),
            "application_count": random.randint(5, 120),
            "spycloud_publish_date": synth_date(days_ago_max=60),
        })
    return records


def gen_compass_applications(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudCompassApplications_CL"""
    severity_bias = kwargs.get("severity_bias")
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        malware = random.choice(MALWARE_FAMILIES)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "infected_machine_id": synth_machine_id(),
            "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
            "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
            "target_subdomain": f"auth.{random.choice(SYNTH_TARGET_DOMAINS)}",
            "credential_count": random.randint(1, 15),
            "cookie_count": random.randint(0, 40),
            "email": email,
            "email_domain": parts[1],
            "log_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "severity": pick_severity(severity_bias or [20, 25]),
            "infected_time": synth_timestamp(hours_ago_max=168),
            "user_hostname": synth_hostname(),
            "user_os": random.choice(OPERATING_SYSTEMS),
            "malware_family": malware,
            "spycloud_publish_date": synth_date(days_ago_max=60),
        })
    return records


def gen_sip_cookies(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudSipCookies_CL"""
    severity_bias = kwargs.get("severity_bias")
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        target = random.choice(SYNTH_TARGET_DOMAINS)
        malware = random.choice(MALWARE_FAMILIES)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "email": email,
            "email_domain": parts[1],
            "cookie_domain": f".{target}",
            "cookie_name": random.choice(COOKIE_NAMES),
            "cookie_value": synth_cookie_value(),
            "cookie_path": "/",
            "cookie_expiration": (datetime.datetime.utcnow() + datetime.timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),  # future
            "cookie_secure": random.choice([True, False]),
            "cookie_http_only": random.choice([True, False]),
            "target_url": f"https://{target}/",
            "target_domain": target,
            "target_subdomain": f"app.{target}",
            "severity": pick_severity(severity_bias or [20, 25]),
            "infected_machine_id": synth_machine_id(),
            "infected_time": synth_timestamp(hours_ago_max=72),
            "user_hostname": synth_hostname(),
            "user_os": random.choice(OPERATING_SYSTEMS),
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 2))],
            "malware_family": malware,
            "log_id": synth_uuid(),
            "spycloud_publish_date": synth_date(days_ago_max=30),
            "country_code": random.choice(COUNTRY_CODES),
            "username": parts[0],
            "password": synth_hash(synth_password()),
            "password_type": random.choice(PASSWORD_TYPES),
        })
    return records


def gen_identity_exposure(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudIdentityExposure_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        malware = random.choice(MALWARE_FAMILIES) if random.random() > 0.4 else ""
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "email": email,
            "email_domain": parts[1],
            "email_username": parts[0],
            "domain": parts[1],
            "password": synth_hash(synth_password()),
            "password_plaintext": synth_password() if random.random() > 0.3 else "",
            "password_type": random.choice(PASSWORD_TYPES),
            "severity": pick_severity(kwargs.get("severity_bias")),
            "sighting": random.randint(1, 8),
            "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
            "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
            "target_subdomain": f"auth.{random.choice(SYNTH_TARGET_DOMAINS)}",
            "infected_machine_id": synth_machine_id() if malware else "",
            "infected_time": synth_timestamp(hours_ago_max=168) if malware else "",
            "malware_family": malware,
            "breach_category": random.choice(BREACH_CATEGORIES),
            "breach_title": f"SYNTH Exposure #{random.randint(1000,9999)}",
            "country_code": random.choice(COUNTRY_CODES),
            "log_id": synth_uuid(),
            "spycloud_publish_date": synth_date(days_ago_max=90),
            "record_type": "infostealer" if malware else "breach",
        })
    return records


def gen_investigations(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudInvestigations_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        malware = random.choice(MALWARE_FAMILIES) if random.random() > 0.3 else ""
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "source_id": random.randint(40000, 49999),
            "email": email,
            "email_domain": parts[1],
            "email_username": parts[0],
            "username": parts[0],
            "domain": parts[1],
            "password": synth_hash(synth_password()),
            "password_plaintext": synth_password() if random.random() > 0.4 else "",
            "password_type": random.choice(PASSWORD_TYPES),
            "severity": pick_severity(kwargs.get("severity_bias")),
            "sighting": random.randint(1, 10),
            "target_url": f"https://{random.choice(SYNTH_TARGET_DOMAINS)}/login",
            "target_domain": random.choice(SYNTH_TARGET_DOMAINS),
            "target_subdomain": f"auth.{random.choice(SYNTH_TARGET_DOMAINS)}",
            "infected_machine_id": synth_machine_id() if malware else "",
            "infected_time": synth_timestamp(hours_ago_max=168) if malware else "",
            "malware_family": malware,
            "breach_category": random.choice(BREACH_CATEGORIES),
            "breach_title": f"SYNTH Investigation #{random.randint(1000,9999)}",
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 3))],
            "country_code": random.choice(COUNTRY_CODES),
            "log_id": synth_uuid(),
            "spycloud_publish_date": synth_date(days_ago_max=90),
            "full_name": synth_full_name(),
            "phone": synth_phone(),
            "record_type": "infostealer" if malware else "breach",
        })
    return records


def gen_idlink(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudIdLink_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        linked_count = random.randint(1, 5)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "identity_id": f"SYNTH-ID-{uuid.uuid4().hex[:12]}",
            "email": email,
            "email_domain": parts[1],
            "linked_emails": [synth_email(parts[1]) for _ in range(linked_count)],
            "linked_usernames": [synth_username() for _ in range(linked_count)],
            "linked_ips": [synth_ip() for _ in range(random.randint(1, 4))],
            "linked_devices": [synth_machine_id() for _ in range(random.randint(1, 3))],
            "link_strength": round(random.uniform(0.3, 1.0), 3),
            "link_type": random.choice([
                "email_reuse", "device_shared", "ip_overlap",
                "password_reuse", "cookie_overlap", "username_alias",
            ]),
            "breach_sources": [f"SYNTH-SRC-{random.randint(100,999)}" for _ in range(random.randint(1, 4))],
            "first_seen": synth_date(days_ago_max=365),
            "last_seen": synth_date(days_ago_max=30),
            "total_exposures": random.randint(1, 50),
            "risk_score": random.randint(10, 100),
            "graph_depth": random.randint(1, 4),
            "log_id": synth_uuid(),
        })
    return records


def gen_exposure(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudExposure_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        risk = random.randint(10, 100)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "email": email,
            "email_domain": parts[1],
            "exposure_id": f"SYNTH-EXP-{uuid.uuid4().hex[:12]}",
            "risk_score": risk,
            "risk_level": "critical" if risk >= 80 else "high" if risk >= 60 else "medium" if risk >= 30 else "low",
            "total_breaches": random.randint(1, 20),
            "total_infostealers": random.randint(0, 8),
            "total_credentials": random.randint(1, 30),
            "plaintext_passwords": random.randint(0, 10),
            "hashed_passwords": random.randint(0, 20),
            "stolen_cookies": random.randint(0, 50),
            "infected_devices": random.randint(0, 5),
            "first_exposure_date": synth_date(days_ago_max=730),
            "latest_exposure_date": synth_date(days_ago_max=30),
            "remediation_status": random.choice(["pending", "in_progress", "completed", "not_started"]),
            "remediation_actions": random.sample(
                ["password_reset", "session_revoke", "mfa_reenroll", "device_isolate", "ca_block"],
                k=random.randint(0, 3),
            ),
            "data_classes_exposed": random.sample(
                ["email", "password", "cookie", "credit_card", "phone", "address", "ssn", "ip_address"],
                k=random.randint(2, 5),
            ),
            "breach_sources": [f"SYNTH Breach #{random.randint(1000,9999)}" for _ in range(random.randint(1, 5))],
            "timeline": [
                {"date": synth_date(days_ago_max=365), "event": random.choice(["exposure", "remediation", "re-exposure"])}
                for _ in range(random.randint(1, 4))
            ],
            "log_id": synth_uuid(),
        })
    return records


def gen_cap(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudCAP_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        records.append({
            "TimeGenerated": synth_timestamp(),
            "cap_id": f"SYNTH-CAP-{uuid.uuid4().hex[:12]}",
            "email": email,
            "email_domain": parts[1],
            "policy_id": f"POL-{random.randint(100,999)}",
            "policy_name": random.choice(CAP_POLICY_NAMES),
            "action_type": random.choice(["password_reset", "session_revoke", "mfa_reenroll", "block_access"]),
            "action_status": random.choice(["success", "failed", "pending", "partial"]),
            "trigger_severity": pick_severity(kwargs.get("severity_bias")),
            "trigger_source": random.choice(["watchlist", "compass", "sip", "investigation"]),
            "credential_type": random.choice(["password", "session_cookie", "oauth_token", "api_key"]),
            "reset_timestamp": synth_timestamp(hours_ago_max=48),
            "notification_sent": random.choice([True, False]),
            "affected_applications": random.sample(SYNTH_TARGET_DOMAINS, k=random.randint(1, 4)),
            "compliance_tags": random.sample(COMPLIANCE_TAGS, k=random.randint(1, 3)),
            "log_id": synth_uuid(),
        })
    return records


def gen_data_partnership(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloudDataPartnership_CL"""
    partners = [
        ("SYNTH-PTR-001", "Synthetic Partner Alpha"),
        ("SYNTH-PTR-002", "Synthetic Partner Beta"),
        ("SYNTH-PTR-003", "Synthetic Partner Gamma"),
    ]
    records = []
    for _ in range(count):
        email = synth_email()
        parts = email.split("@")
        pid, pname = random.choice(partners)
        records.append({
            "TimeGenerated": synth_timestamp(),
            "document_id": synth_uuid(),
            "partner_id": pid,
            "partner_name": pname,
            "email": email,
            "email_domain": parts[1],
            "username": parts[0],
            "domain": parts[1],
            "password": synth_hash(synth_password()),
            "password_type": random.choice(PASSWORD_TYPES),
            "severity": pick_severity(kwargs.get("severity_bias")),
            "source_type": random.choice(["darknet_forum", "paste_site", "marketplace", "telegram"]),
            "source_description": f"Synthetic data from {pname} partner feed.",
            "ip_addresses": [synth_ip() for _ in range(random.randint(1, 2))],
            "country_code": random.choice(COUNTRY_CODES),
            "data_classes": random.sample(
                ["email", "password", "phone", "ip_address", "cookie", "credit_card"],
                k=random.randint(2, 4),
            ),
            "spycloud_publish_date": synth_date(days_ago_max=60),
            "log_id": synth_uuid(),
        })
    return records


def gen_mde_logs(count: int, **kwargs) -> List[Dict[str, Any]]:
    """Spycloud_MDE_Logs_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        hostname = synth_hostname()
        records.append({
            "TimeGenerated": synth_timestamp(),
            "IncidentId": f"SYNTH-INC-{random.randint(10000,99999)}",
            "DeviceName": hostname,
            "DeviceId": synth_uuid(),
            "MachineId": synth_machine_id(),
            "Action": random.choice(["Isolate", "Unisolate", "RunAntiVirusScan", "CollectInvestigationPackage"]),
            "IsolationType": random.choice(["Full", "Selective", ""]),
            "Tag": f"SpyCloud-Severity-{random.choice([20, 25])}",
            "ActionStatus": random.choice(["Succeeded", "Failed", "Pending", "InProgress"]),
            "Email": email,
            "Severity": pick_severity(kwargs.get("severity_bias") or [20, 25]),
            "InfectedMachineId": synth_machine_id(),
            "UserHostname": hostname,
        })
    return records


def gen_conditional_access_logs(count: int, **kwargs) -> List[Dict[str, Any]]:
    """SpyCloud_ConditionalAccessLogs_CL"""
    records = []
    for _ in range(count):
        email = synth_email()
        records.append({
            "TimeGenerated": synth_timestamp(),
            "IncidentId": f"SYNTH-INC-{random.randint(10000,99999)}",
            "UserPrincipalName": email,
            "UserId": synth_uuid(),
            "Action": random.choice([
                "PasswordReset", "SessionRevoke", "AddToCAGroup",
                "MFA_ReEnroll", "BlockSignIn",
            ]),
            "ActionStatus": random.choice(["Succeeded", "Failed", "Pending"]),
            "PasswordReset": random.choice([True, False]),
            "SessionsRevoked": random.choice([True, False]),
            "AddedToCAGroup": random.choice([True, False]),
            "CAGroupId": f"SYNTH-CAGRP-{uuid.uuid4().hex[:8]}",
            "Email": email,
            "Severity": pick_severity(kwargs.get("severity_bias")),
        })
    return records


# ---------------------------------------------------------------------------
# Generator registry
# ---------------------------------------------------------------------------
TABLE_GENERATORS = {
    "BreachWatchlist":      ("SpyCloudBreachWatchlist_CL",      gen_breach_watchlist),
    "BreachCatalog":        ("SpyCloudBreachCatalog_CL",        gen_breach_catalog),
    "Compass":              ("SpyCloudCompassData_CL",          gen_compass_data),
    "CompassDevices":       ("SpyCloudCompassDevices_CL",       gen_compass_devices),
    "CompassApplications":  ("SpyCloudCompassApplications_CL",  gen_compass_applications),
    "SIP":                  ("SpyCloudSipCookies_CL",           gen_sip_cookies),
    "IdentityExposure":     ("SpyCloudIdentityExposure_CL",     gen_identity_exposure),
    "Investigations":       ("SpyCloudInvestigations_CL",       gen_investigations),
    "IDLink":               ("SpyCloudIdLink_CL",               gen_idlink),
    "Exposure":             ("SpyCloudExposure_CL",             gen_exposure),
    "CAP":                  ("SpyCloudCAP_CL",                  gen_cap),
    "DataPartnership":      ("SpyCloudDataPartnership_CL",      gen_data_partnership),
    "MDE":                  ("Spycloud_MDE_Logs_CL",            gen_mde_logs),
    "ConditionalAccess":    ("SpyCloud_ConditionalAccessLogs_CL", gen_conditional_access_logs),
}

# ---------------------------------------------------------------------------
# Log Analytics HTTP Data Collector API
# ---------------------------------------------------------------------------

def build_signature(workspace_id: str, shared_key: str, date: str,
                    content_length: int, method: str = "POST",
                    content_type: str = "application/json",
                    resource: str = "/api/logs") -> str:
    """Build the authorization header for the Log Analytics Data Collector API."""
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def send_to_log_analytics(workspace_id: str, shared_key: str,
                          log_type: str, records: List[Dict[str, Any]]) -> bool:
    """
    Send records to Azure Log Analytics via the HTTP Data Collector API.
    Requires the 'requests' package.
    """
    try:
        import requests
    except ImportError:
        log.error("The 'requests' package is required for --output sentinel. Install: pip install requests")
        return False

    # Remove _CL suffix -- the API appends it automatically
    if log_type.endswith("_CL"):
        log_type = log_type[:-3]

    body = json.dumps(records, default=str)
    content_length = len(body)
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    signature = build_signature(workspace_id, shared_key, rfc1123date, content_length)
    uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    headers = {
        "content-type": "application/json",
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
        "time-generated-field": "TimeGenerated",
    }

    # Data Collector API has a 30 MB limit per post; chunk at 25 MB to be safe
    MAX_CHUNK = 25 * 1024 * 1024
    if content_length > MAX_CHUNK:
        log.info(f"Payload too large ({content_length} bytes). Chunking...")
        chunk_size = max(1, len(records) // (content_length // MAX_CHUNK + 1))
        success = True
        for i in range(0, len(records), chunk_size):
            chunk = records[i:i + chunk_size]
            if not send_to_log_analytics(workspace_id, shared_key, log_type + "_CL", chunk):
                success = False
        return success

    response = requests.post(uri, data=body, headers=headers, timeout=60)
    if 200 <= response.status_code <= 299:
        log.info(f"  Sent {len(records)} records to {log_type}_CL (HTTP {response.status_code})")
        return True
    else:
        log.error(f"  Failed to send to {log_type}_CL: HTTP {response.status_code} -- {response.text}")
        return False


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

def run_scenario(scenario_name: str, count: int, **kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Execute a named scenario and return data for all involved tables.
    """
    if scenario_name not in SCENARIO_DEFINITIONS:
        log.error(f"Unknown scenario: {scenario_name}")
        log.info(f"Available scenarios: {', '.join(SCENARIO_DEFINITIONS.keys())}")
        sys.exit(1)

    scenario = SCENARIO_DEFINITIONS[scenario_name]
    log.info(f"Running scenario: {scenario_name}")
    log.info(f"  Description: {scenario['description']}")
    log.info(f"  Tables: {', '.join(scenario['tables'])}")

    gen_kwargs = dict(kwargs)
    if "severity_bias" in scenario:
        gen_kwargs["severity_bias"] = scenario["severity_bias"]

    results: Dict[str, List[Dict[str, Any]]] = {}
    for table_key in scenario["tables"]:
        if table_key not in TABLE_GENERATORS:
            log.warning(f"  Skipping unknown table key: {table_key}")
            continue
        la_table, gen_fn = TABLE_GENERATORS[table_key]
        log.info(f"  Generating {count} records for {la_table}...")
        records = gen_fn(count, **gen_kwargs)
        results[la_table] = records

    return results


# ---------------------------------------------------------------------------
# Output handlers
# ---------------------------------------------------------------------------

def output_stdout(all_data: Dict[str, List[Dict[str, Any]]]) -> None:
    for table_name, records in all_data.items():
        print(json.dumps({"table": table_name, "count": len(records), "records": records}, indent=2, default=str))


def output_files(all_data: Dict[str, List[Dict[str, Any]]], output_dir: str = ".") -> None:
    os.makedirs(output_dir, exist_ok=True)
    for table_name, records in all_data.items():
        filepath = os.path.join(output_dir, f"{table_name}.json")
        with open(filepath, "w") as f:
            json.dump(records, f, indent=2, default=str)
        log.info(f"  Wrote {len(records)} records to {filepath}")


def output_sentinel(all_data: Dict[str, List[Dict[str, Any]]],
                    workspace_id: str, shared_key: str) -> None:
    if not workspace_id or not shared_key:
        log.error("--workspace-id and --shared-key are required for --output sentinel")
        sys.exit(1)

    total_sent = 0
    total_failed = 0
    for table_name, records in all_data.items():
        if send_to_log_analytics(workspace_id, shared_key, table_name, records):
            total_sent += len(records)
        else:
            total_failed += len(records)

    log.info(f"Ingestion complete. Sent: {total_sent}, Failed: {total_failed}")
    if total_sent > 0:
        log.info("Note: Data may take 5-15 minutes to appear in Log Analytics tables.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SpyCloud Sentinel -- Simulation Data Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Table names:
  BreachWatchlist, BreachCatalog, Compass, CompassDevices,
  CompassApplications, SIP, IdentityExposure, Investigations,
  IDLink, Exposure, CAP, DataPartnership, MDE, ConditionalAccess
  (or 'all' for every table)

Scenarios:
  infostealer-outbreak    -- Stealer wave across corporate endpoints
  executive-compromise    -- VIP credentials on darknet
  session-hijack          -- Stolen cookies enabling ATO
  mass-credential-dump    -- Large combolist affecting many users
  reinfection-campaign    -- Re-infection of remediated endpoints

Examples:
  %(prog)s --table BreachWatchlist --count 50
  %(prog)s --table all --count 20 --output file --output-dir ./test-data
  %(prog)s --scenario infostealer-outbreak --count 30
  %(prog)s --table Compass --count 10 --output sentinel --workspace-id <id> --shared-key <key>
""",
    )

    parser.add_argument(
        "--table", type=str, default="all",
        help="Which table to generate (name or 'all'). Ignored if --scenario is set.",
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of records per table (default: 10).",
    )
    parser.add_argument(
        "--output", type=str, choices=["stdout", "file", "sentinel"], default="stdout",
        help="Output destination (default: stdout).",
    )
    parser.add_argument(
        "--output-dir", type=str, default="./spycloud-test-data",
        help="Directory for file output (default: ./spycloud-test-data).",
    )
    parser.add_argument(
        "--scenario", type=str, default=None,
        choices=list(SCENARIO_DEFINITIONS.keys()),
        help="Run a preset scenario instead of per-table generation.",
    )
    parser.add_argument(
        "--workspace-id", type=str, default=os.environ.get("LOG_ANALYTICS_WORKSPACE_ID", ""),
        help="Log Analytics workspace ID (for --output sentinel). Env: LOG_ANALYTICS_WORKSPACE_ID",
    )
    parser.add_argument(
        "--shared-key", type=str, default=os.environ.get("LOG_ANALYTICS_SHARED_KEY", ""),
        help="Log Analytics shared key (for --output sentinel). Env: LOG_ANALYTICS_SHARED_KEY",
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

    # Collect all generated data
    all_data: Dict[str, List[Dict[str, Any]]] = {}

    if args.scenario:
        all_data = run_scenario(args.scenario, args.count)
    elif args.table.lower() == "all":
        log.info(f"Generating {args.count} records for ALL {len(TABLE_GENERATORS)} tables...")
        for table_key, (la_table, gen_fn) in TABLE_GENERATORS.items():
            log.info(f"  {la_table}...")
            all_data[la_table] = gen_fn(args.count)
    else:
        if args.table not in TABLE_GENERATORS:
            log.error(f"Unknown table: {args.table}")
            log.info(f"Valid tables: {', '.join(TABLE_GENERATORS.keys())}")
            sys.exit(1)
        la_table, gen_fn = TABLE_GENERATORS[args.table]
        log.info(f"Generating {args.count} records for {la_table}...")
        all_data[la_table] = gen_fn(args.count)

    # Summary
    total = sum(len(v) for v in all_data.values())
    log.info(f"Generated {total} total records across {len(all_data)} tables.")

    # Output
    if args.output == "stdout":
        output_stdout(all_data)
    elif args.output == "file":
        output_files(all_data, args.output_dir)
        log.info(f"Files written to {os.path.abspath(args.output_dir)}")
    elif args.output == "sentinel":
        output_sentinel(all_data, args.workspace_id, args.shared_key)


if __name__ == "__main__":
    main()
