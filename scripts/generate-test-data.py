#!/usr/bin/env python3
"""
SpyCloud Sentinel Supreme — Comprehensive Test Data Generator
Generates realistic data for ALL 14 custom tables + simulated
Azure/Sentinel events to trigger analytics rules and test Copilot skills.

Usage:
  python3 generate-test-data.py --workspace WORKSPACE --rg RESOURCE_GROUP
  python3 generate-test-data.py --output-json  # Just write JSON files locally
"""

import json, random, string, uuid, hashlib, argparse, os
from datetime import datetime, timedelta

# ================================================================
# CONFIGURATION — realistic test identities
# ================================================================
COMPANY_DOMAIN = "contoso.com"
MALWARE_FAMILIES = ["RedLine", "Vidar", "LummaC2", "RisePro", "StealC", "Raccoon", "MetaStealer", "Aurora"]
BREACH_CATEGORIES = ["infostealer", "phishing", "combo_list", "data_breach", "credential_stuffing"]
COUNTRIES = ["US", "RU", "CN", "BR", "IN", "DE", "UA", "VN", "NG", "KR"]
OS_LIST = ["Windows 10 Pro", "Windows 11 Enterprise", "Windows 10 Home", "Windows Server 2019"]
AV_LIST = ["Windows Defender", "CrowdStrike Falcon", "SentinelOne", "Carbon Black", "Symantec EP"]
TARGET_DOMAINS = ["outlook.com", "github.com", "slack.com", "salesforce.com", "aws.amazon.com",
                  "portal.azure.com", "okta.com", "google.com", "dropbox.com", "zoom.us"]
BROWSERS = ["Chrome", "Edge", "Firefox", "Brave"]
COOKIE_NAMES = ["session_id", "auth_token", "JSESSIONID", "csrftoken", "_ga", "access_token",
                "refresh_token", "PHPSESSID", "cf_clearance", "sso_token"]

# Test users — mix of executives, IT admins, regular users
USERS = [
    {"email": f"ceo@{COMPANY_DOMAIN}", "name": "Sarah Chen", "title": "Chief Executive Officer", "vip": True},
    {"email": f"cfo@{COMPANY_DOMAIN}", "name": "Michael Torres", "title": "Chief Financial Officer", "vip": True},
    {"email": f"ciso@{COMPANY_DOMAIN}", "name": "James Wright", "title": "CISO", "vip": True},
    {"email": f"admin@{COMPANY_DOMAIN}", "name": "Alex Kumar", "title": "IT Administrator", "vip": True},
    {"email": f"svc-backup@{COMPANY_DOMAIN}", "name": "Service Account", "title": "Backup Service", "vip": True},
    {"email": f"john.doe@{COMPANY_DOMAIN}", "name": "John Doe", "title": "Sales Manager", "vip": False},
    {"email": f"jane.smith@{COMPANY_DOMAIN}", "name": "Jane Smith", "title": "Software Engineer", "vip": False},
    {"email": f"bob.wilson@{COMPANY_DOMAIN}", "name": "Bob Wilson", "title": "Marketing Analyst", "vip": False},
    {"email": f"sarah.johnson@{COMPANY_DOMAIN}", "name": "Sarah Johnson", "title": "HR Manager", "vip": False},
    {"email": f"david.lee@{COMPANY_DOMAIN}", "name": "David Lee", "title": "DevOps Engineer", "vip": False},
    {"email": f"lisa.wang@{COMPANY_DOMAIN}", "name": "Lisa Wang", "title": "Finance Analyst", "vip": False},
    {"email": f"mike.brown@{COMPANY_DOMAIN}", "name": "Mike Brown", "title": "Support Technician", "vip": False},
]

# Test devices
DEVICES = [
    {"hostname": "WS-CEO-01", "os": "Windows 11 Enterprise", "machine_id": str(uuid.uuid4())},
    {"hostname": "WS-ADMIN-01", "os": "Windows 10 Pro", "machine_id": str(uuid.uuid4())},
    {"hostname": "SRV-DC-01", "os": "Windows Server 2019", "machine_id": str(uuid.uuid4())},
    {"hostname": "WS-DEV-01", "os": "Windows 11 Enterprise", "machine_id": str(uuid.uuid4())},
    {"hostname": "WS-SALES-01", "os": "Windows 10 Pro", "machine_id": str(uuid.uuid4())},
    {"hostname": "WS-HR-01", "os": "Windows 10 Pro", "machine_id": str(uuid.uuid4())},
    {"hostname": "LAPTOP-REMOTE-01", "os": "Windows 11 Home", "machine_id": str(uuid.uuid4())},
    {"hostname": "WS-FINANCE-01", "os": "Windows 10 Pro", "machine_id": str(uuid.uuid4())},
]

def rand_ip(): return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def rand_password(): return ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=random.randint(8,16)))
def rand_time(days_back=30): return (datetime.utcnow() - timedelta(hours=random.randint(1, days_back*24))).strftime("%Y-%m-%dT%H:%M:%SZ")
def now_iso(): return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ================================================================
# TABLE GENERATORS
# ================================================================

def gen_watchlist(count=200):
    """SpyCloudBreachWatchlist_CL — core exposure data"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        device = random.choice(DEVICES)
        severity = random.choice([2, 5, 5, 20, 20, 20, 25, 25])
        pw = rand_password()
        is_infostealer = severity >= 20
        records.append({
            "TimeGenerated": rand_time(14),
            "document_id": str(uuid.uuid4()),
            "source_id": random.randint(100000, 200000),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "email_username": user["email"].split("@")[0],
            "domain": COMPANY_DOMAIN,
            "password": hashlib.sha256(pw.encode()).hexdigest()[:20] if severity < 20 else pw,
            "password_plaintext": pw if severity >= 20 else "",
            "password_type": "plaintext" if severity >= 20 else "hashed",
            "severity": severity,
            "sighting": random.randint(1, 10),
            "breach_category": "infostealer" if is_infostealer else random.choice(["phishing", "combo_list", "data_breach"]),
            "breach_title": f"{random.choice(MALWARE_FAMILIES)} Stealer" if is_infostealer else f"Breach-{random.randint(2020,2026)}",
            "target_domain": random.choice(TARGET_DOMAINS),
            "target_subdomain": f"login.{random.choice(TARGET_DOMAINS)}",
            "target_url": f"https://login.{random.choice(TARGET_DOMAINS)}/auth",
            "infected_machine_id": device["machine_id"] if is_infostealer else "",
            "infected_path": f"c:\\users\\{user['email'].split('@')[0]}\\downloads\\setup.exe" if is_infostealer else "",
            "infected_time": rand_time(7) if is_infostealer else "",
            "user_hostname": device["hostname"] if is_infostealer else "",
            "user_os": device["os"] if is_infostealer else "",
            "user_sys_registered_owner": user["name"] if is_infostealer else "",
            "ip_addresses": [rand_ip(), rand_ip()] if is_infostealer else [],
            "av_softwares": [random.choice(AV_LIST)] if is_infostealer else [],
            "country_code": random.choice(COUNTRIES),
            "display_resolution": "1920 x 1080" if is_infostealer else "",
            "keyboard_languages": "english" if is_infostealer else "",
            "timezone": str(random.randint(-8, 8)),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "spycloud_publish_date": rand_time(3),
        })
    return records

def gen_catalog(count=30):
    """SpyCloudBreachCatalog_CL — breach metadata"""
    records = []
    for i in range(count):
        mf = random.choice(MALWARE_FAMILIES)
        records.append({
            "TimeGenerated": rand_time(30),
            "uuid": str(uuid.uuid4()),
            "short_title": f"{mf} Stealer" if random.random() > 0.3 else f"Data Breach {2024+random.randint(0,2)}",
            "site": random.choice(["n/a", "darkforum.onion", "breachforums.is"]),
            "site_description": "Underground marketplace",
            "breach_category": random.choice(BREACH_CATEGORIES),
            "breach_main_category": random.choice(["malware", "breach", "phishing"]),
            "consumer_category": random.choice(["infostealer", "credential_dump"]),
            "malware_family": mf if random.random() > 0.3 else "",
            "confidence": random.choice([1, 2, 3]),
            "num_records": random.randint(1000, 5000000),
            "sensitive_source": random.choice([True, False]),
            "premium_flag": random.choice(["YES", "NO"]),
            "tlp": random.choice(["clear", "green", "amber"]),
            "spycloud_publish_date": rand_time(14),
            "acquisition_date": rand_time(30),
            "assets": {"email": random.randint(100,50000), "ip_addresses": random.randint(10,5000)},
        })
    return records

def gen_compass_data(count=150):
    """SpyCloudCompassData_CL — consumer identity exposures (57 cols)"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        device = random.choice(DEVICES)
        severity = random.choice([5, 20, 20, 25, 25])
        mf = random.choice(MALWARE_FAMILIES)
        pw = rand_password()
        records.append({
            "TimeGenerated": rand_time(14),
            "document_id": str(uuid.uuid4()),
            "source_id": random.randint(100000, 200000),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "email_username": user["email"].split("@")[0],
            "domain": COMPANY_DOMAIN,
            "password": pw,
            "password_plaintext": pw,
            "password_type": "plaintext",
            "severity": severity,
            "sighting": random.randint(1, 5),
            "breach_category": "infostealer",
            "breach_title": f"{mf} Stealer",
            "target_domain": random.choice(TARGET_DOMAINS),
            "target_subdomain": f"app.{random.choice(TARGET_DOMAINS)}",
            "target_url": f"https://app.{random.choice(TARGET_DOMAINS)}/login",
            "infected_machine_id": device["machine_id"],
            "infected_path": f"c:\\users\\{user['email'].split('@')[0]}\\appdata\\local\\temp\\{mf.lower()}.exe",
            "infected_time": rand_time(7),
            "user_hostname": device["hostname"],
            "user_os": device["os"],
            "user_sys_registered_owner": user["name"],
            "ip_addresses": [rand_ip()],
            "av_softwares": [random.choice(AV_LIST)],
            "country_code": random.choice(COUNTRIES),
            "display_resolution": "1920 x 1080",
            "keyboard_languages": "english",
            "timezone": str(random.randint(-8, 8)),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "spycloud_publish_date": rand_time(3),
            "malware_family": mf,
            "username": user["email"].split("@")[0],
            "full_name": user["name"],
            "phone": f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}",
            "company_name": "Contoso Ltd",
            "job_title": user["title"],
            "record_type": "corporate",
            "account_type": "employee",
            "breach_date": rand_time(60),
            "breach_description": f"Credentials stolen by {mf} infostealer",
            "stolen_cookies": [{"domain": d, "name": random.choice(COOKIE_NAMES), "value": hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()} for d in random.sample(TARGET_DOMAINS, min(3, len(TARGET_DOMAINS)))],
            "autofill_fields": [{"field": "email", "value": user["email"]}, {"field": "name", "value": user["name"]}],
            "crypto_wallets": [],
            "installed_software": [random.choice(BROWSERS), "Microsoft Office", "Slack"],
            "browser_history_domains": random.sample(TARGET_DOMAINS, min(5, len(TARGET_DOMAINS))),
            "bot_id": str(uuid.uuid4())[:8],
            "campaign_id": f"CAMP-{random.randint(1000,9999)}",
            "c2_url": f"http://{rand_ip()}:{random.choice([80,443,8080,4444])}/gate",
            "infection_build_id": f"BUILD-{random.randint(100,999)}",
            "hardware_id": hashlib.md5(device["machine_id"].encode()).hexdigest()[:16],
            "screenshot_available": random.choice([True, False]),
            "keylog_available": random.choice([True, False]),
            "file_exfiltration": random.choice([True, False]),
            "salt": "",
            "credit_card_number": "",
            "credit_card_expiration": "",
        })
    return records

def gen_compass_devices(count=20):
    """SpyCloudCompassDevices_CL"""
    records = []
    for device in DEVICES:
        for _ in range(random.randint(1, 3)):
            records.append({
                "TimeGenerated": rand_time(14),
                "source_id": random.randint(100000, 200000),
                "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
                "user_hostname": device["hostname"],
                "user_os": device["os"],
                "ip_addresses": [rand_ip()],
                "infected_time": rand_time(7),
                "application_count": random.randint(3, 25),
                "spycloud_publish_date": rand_time(3),
            })
    return records

def gen_compass_applications(count=50):
    """SpyCloudCompassApplications_CL"""
    records = []
    for _ in range(count):
        device = random.choice(DEVICES)
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(14),
            "infected_machine_id": device["machine_id"],
            "target_url": f"https://{random.choice(TARGET_DOMAINS)}/login",
            "target_domain": random.choice(TARGET_DOMAINS),
            "target_subdomain": f"login.{random.choice(TARGET_DOMAINS)}",
            "credential_count": random.randint(1, 5),
            "cookie_count": random.randint(0, 15),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "source_id": random.randint(100000, 200000),
            "severity": random.choice([20, 25]),
            "infected_time": rand_time(7),
            "user_hostname": device["hostname"],
            "user_os": device["os"],
            "malware_family": random.choice(MALWARE_FAMILIES),
            "spycloud_publish_date": rand_time(3),
        })
    return records

def gen_sip_cookies(count=80):
    """SpyCloudSipCookies_CL — stolen cookies"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        device = random.choice(DEVICES)
        domain = random.choice(TARGET_DOMAINS)
        records.append({
            "TimeGenerated": rand_time(7),
            "document_id": str(uuid.uuid4()),
            "source_id": random.randint(100000, 200000),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "cookie_domain": f".{domain}",
            "cookie_name": random.choice(COOKIE_NAMES),
            "cookie_value": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32],
            "cookie_path": "/",
            "cookie_expiration": (datetime.utcnow() + timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cookie_secure": random.choice([True, False]),
            "cookie_http_only": random.choice([True, False]),
            "target_url": f"https://{domain}/",
            "target_domain": domain,
            "target_subdomain": f"app.{domain}",
            "severity": random.choice([20, 25]),
            "infected_machine_id": device["machine_id"],
            "infected_time": rand_time(7),
            "user_hostname": device["hostname"],
            "user_os": device["os"],
            "ip_addresses": [rand_ip()],
            "malware_family": random.choice(MALWARE_FAMILIES),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "spycloud_publish_date": rand_time(3),
            "country_code": random.choice(COUNTRIES),
            "username": user["email"].split("@")[0],
            "password": rand_password(),
            "password_type": "plaintext",
        })
    return records

def gen_mde_logs(count=30):
    """Spycloud_MDE_Logs_CL — MDE isolation audit"""
    records = []
    for _ in range(count):
        device = random.choice(DEVICES)
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(7),
            "IncidentId": str(uuid.uuid4())[:8],
            "DeviceName": device["hostname"],
            "DeviceId": str(uuid.uuid4()),
            "MachineId": device["machine_id"],
            "Action": random.choice(["Isolate", "Unisolate", "RunScript"]),
            "IsolationType": random.choice(["Full", "Selective"]),
            "Tag": "SpyCloud-Infostealer",
            "ActionStatus": random.choice(["Success", "Success", "Success", "Failed", "Pending"]),
            "Email": user["email"],
            "Severity": random.choice([20, 25]),
            "InfectedMachineId": device["machine_id"],
            "UserHostname": device["hostname"],
        })
    return records

def gen_ca_logs(count=40):
    """SpyCloud_ConditionalAccessLogs_CL — CA remediation audit"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(7),
            "IncidentId": str(uuid.uuid4())[:8],
            "UserPrincipalName": user["email"],
            "UserId": str(uuid.uuid4()),
            "Action": random.choice(["PasswordReset", "SessionRevoke", "AddToCAGroup", "DisableAccount"]),
            "ActionStatus": random.choice(["Success", "Success", "Success", "Failed"]),
            "PasswordReset": random.choice([True, False]),
            "SessionsRevoked": random.choice([True, False]),
            "AddedToCAGroup": random.choice([True, False]),
            "CAGroupId": str(uuid.uuid4()) if random.random() > 0.5 else "",
            "Email": user["email"],
            "Severity": random.choice([5, 20, 25]),
            "UserDisabled": random.choice([True, False, False, False]),
            "PlaybookName": random.choice(["SpyCloud-CA-Remediation", "SpyCloud-CredResponse"]),
            "BreachTitle": f"{random.choice(MALWARE_FAMILIES)} Stealer",
            "DocumentId": str(uuid.uuid4()),
            "InfectedMachineId": random.choice(DEVICES)["machine_id"],
        })
    return records

def gen_identity_exposure(count=60):
    """SpyCloudIdentityExposure_CL"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(14),
            "document_id": str(uuid.uuid4()),
            "source_id": random.randint(100000, 200000),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "email_username": user["email"].split("@")[0],
            "domain": COMPANY_DOMAIN,
            "password": rand_password(),
            "password_plaintext": rand_password() if random.random() > 0.4 else "",
            "password_type": random.choice(["plaintext", "hashed_sha256", "hashed_md5"]),
            "severity": random.choice([2, 5, 20, 25]),
            "sighting": random.randint(1, 8),
            "target_url": f"https://{random.choice(TARGET_DOMAINS)}/login",
            "target_domain": random.choice(TARGET_DOMAINS),
            "target_subdomain": f"login.{random.choice(TARGET_DOMAINS)}",
            "infected_machine_id": random.choice(DEVICES)["machine_id"] if random.random() > 0.5 else "",
            "infected_time": rand_time(7) if random.random() > 0.5 else "",
            "malware_family": random.choice(MALWARE_FAMILIES) if random.random() > 0.3 else "",
            "breach_category": random.choice(BREACH_CATEGORIES),
            "breach_title": f"{random.choice(MALWARE_FAMILIES)} Stealer",
            "country_code": random.choice(COUNTRIES),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "spycloud_publish_date": rand_time(3),
            "record_type": random.choice(["corporate", "consumer", "infected"]),
        })
    return records

def gen_exposure_summary(count=12):
    """SpyCloudExposure_CL — per-user exposure summaries"""
    records = []
    for user in USERS:
        records.append({
            "TimeGenerated": now_iso(),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "exposure_id": str(uuid.uuid4()),
            "risk_score": random.randint(10, 100),
            "risk_level": random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
            "total_breaches": random.randint(1, 20),
            "total_infostealers": random.randint(0, 8),
            "total_credentials": random.randint(1, 30),
            "plaintext_passwords": random.randint(0, 10),
            "hashed_passwords": random.randint(0, 15),
            "stolen_cookies": random.randint(0, 50),
            "infected_devices": random.randint(0, 3),
            "first_exposure_date": rand_time(365),
            "latest_exposure_date": rand_time(7),
            "remediation_status": random.choice(["pending", "in_progress", "completed", "failed"]),
            "remediation_actions": [{"action": "PasswordReset", "timestamp": rand_time(3)}] if random.random() > 0.5 else [],
            "data_classes_exposed": random.sample(["email", "password", "phone", "ssn", "credit_card", "address"], random.randint(2, 5)),
            "breach_sources": [str(uuid.uuid4())[:8] for _ in range(random.randint(1, 5))],
            "exposure_timeline": [{"date": rand_time(30), "severity": random.choice([5, 20, 25])} for _ in range(random.randint(1, 5))],
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
        })
    return records

def gen_investigations(count=30):
    """SpyCloudInvestigations_CL"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(14),
            "document_id": str(uuid.uuid4()),
            "source_id": random.randint(100000, 200000),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "email_username": user["email"].split("@")[0],
            "username": user["email"].split("@")[0],
            "domain": COMPANY_DOMAIN,
            "password": rand_password(),
            "password_plaintext": rand_password(),
            "password_type": "plaintext",
            "severity": random.choice([20, 25]),
            "sighting": random.randint(1, 5),
            "target_url": f"https://{random.choice(TARGET_DOMAINS)}/",
            "target_domain": random.choice(TARGET_DOMAINS),
            "target_subdomain": f"login.{random.choice(TARGET_DOMAINS)}",
            "infected_machine_id": random.choice(DEVICES)["machine_id"],
            "infected_time": rand_time(7),
            "malware_family": random.choice(MALWARE_FAMILIES),
            "breach_category": "infostealer",
            "breach_title": f"{random.choice(MALWARE_FAMILIES)} Stealer",
            "ip_addresses": [rand_ip()],
            "country_code": random.choice(COUNTRIES),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
            "spycloud_publish_date": rand_time(3),
            "full_name": user["name"],
            "phone": f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}",
            "record_type": "corporate",
        })
    return records

def gen_idlink(count=12):
    """SpyCloudIdLink_CL — identity link graph"""
    records = []
    for user in USERS:
        linked_emails = random.sample([u["email"] for u in USERS if u["email"] != user["email"]], min(3, len(USERS)-1))
        records.append({
            "TimeGenerated": now_iso(),
            "identity_id": str(uuid.uuid4()),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "linked_emails": linked_emails[:2],
            "linked_usernames": [user["email"].split("@")[0], user["email"].split("@")[0] + "123"],
            "linked_ips": [rand_ip() for _ in range(random.randint(1, 4))],
            "linked_devices": [random.choice(DEVICES)["machine_id"]],
            "link_strength": round(random.uniform(0.3, 1.0), 2),
            "link_type": random.choice(["email_correlation", "device_correlation", "credential_reuse", "ip_overlap"]),
            "breach_sources": [str(uuid.uuid4())[:8] for _ in range(random.randint(1, 5))],
            "first_seen": rand_time(365),
            "last_seen": rand_time(7),
            "total_exposures": random.randint(1, 50),
            "risk_score": random.randint(10, 100),
            "graph_depth": random.randint(1, 4),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
        })
    return records

def gen_cap_logs(count=20):
    """SpyCloudCAP_CL — credential access protection"""
    records = []
    for _ in range(count):
        user = random.choice(USERS)
        records.append({
            "TimeGenerated": rand_time(7),
            "cap_id": str(uuid.uuid4()),
            "email": user["email"],
            "email_domain": COMPANY_DOMAIN,
            "policy_id": f"POL-{random.randint(100,999)}",
            "policy_name": random.choice(["Force MFA Reset", "Block Compromised Credentials", "Require Password Change", "Session Revocation"]),
            "action_type": random.choice(["password_reset", "mfa_reset", "session_revoke", "account_disable"]),
            "action_status": random.choice(["success", "success", "failed", "pending"]),
            "trigger_severity": random.choice([5, 20, 25]),
            "trigger_source": random.choice(["watchlist", "compass", "identity_exposure"]),
            "credential_type": random.choice(["corporate", "personal", "service_account"]),
            "reset_timestamp": rand_time(3),
            "notification_sent": random.choice([True, False]),
            "affected_applications": random.sample(TARGET_DOMAINS, min(3, len(TARGET_DOMAINS))),
            "compliance_tags": random.sample(["SOC2", "HIPAA", "PCI-DSS", "GDPR", "NIST"], random.randint(1, 3)),
            "log_id": hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:50],
        })
    return records

# ================================================================
# MAIN
# ================================================================
def main():
    parser = argparse.ArgumentParser(description="SpyCloud Test Data Generator")
    parser.add_argument("--output-json", action="store_true", help="Write JSON files locally")
    parser.add_argument("--output-dir", default="test-data", help="Output directory")
    args = parser.parse_args()

    all_tables = {
        "SpyCloudBreachWatchlist_CL": gen_watchlist(200),
        "SpyCloudBreachCatalog_CL": gen_catalog(30),
        "SpyCloudCompassData_CL": gen_compass_data(150),
        "SpyCloudCompassDevices_CL": gen_compass_devices(20),
        "SpyCloudCompassApplications_CL": gen_compass_applications(50),
        "SpyCloudSipCookies_CL": gen_sip_cookies(80),
        "Spycloud_MDE_Logs_CL": gen_mde_logs(30),
        "SpyCloud_ConditionalAccessLogs_CL": gen_ca_logs(40),
        "SpyCloudIdentityExposure_CL": gen_identity_exposure(60),
        "SpyCloudExposure_CL": gen_exposure_summary(12),
        "SpyCloudInvestigations_CL": gen_investigations(30),
        "SpyCloudIdLink_CL": gen_idlink(12),
        "SpyCloudCAP_CL": gen_cap_logs(20),
    }

    os.makedirs(args.output_dir, exist_ok=True)

    total = 0
    print("=" * 60)
    print("  SpyCloud Test Data Generator")
    print("=" * 60)

    for table, records in all_tables.items():
        filepath = os.path.join(args.output_dir, f"{table}.json")
        with open(filepath, 'w') as f:
            json.dump(records, f, indent=2)
        total += len(records)
        print(f"  {table}: {len(records)} records → {filepath}")

    # Also generate a combined ingestion script
    ingest_script = f"""#!/bin/bash
# SpyCloud Test Data Ingestion via Azure Monitor Data Collection API
# Usage: ./ingest-test-data.sh -e <DCE_ENDPOINT> -r <DCR_IMMUTABLE_ID>

DCE_ENDPOINT="${{1:-$DCE_ENDPOINT}}"
DCR_ID="${{2:-$DCR_IMMUTABLE_ID}}"
TOKEN=$(az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv)

for TABLE in {' '.join(all_tables.keys())}; do
  STREAM="Custom-$TABLE"
  FILE="{args.output_dir}/$TABLE.json"
  [ ! -f "$FILE" ] && continue
  echo -n "  $TABLE: "
  curl -s -X POST "$DCE_ENDPOINT/dataCollectionRules/$DCR_ID/streams/$STREAM?api-version=2023-01-01" \\
    -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d @"$FILE" \\
    -o /dev/null -w "%{{http_code}}" && echo " ✅" || echo " ❌"
done
"""
    with open(os.path.join(args.output_dir, "ingest-test-data.sh"), 'w') as f:
        f.write(ingest_script)
    os.chmod(os.path.join(args.output_dir, "ingest-test-data.sh"), 0o755)

    print(f"\n  TOTAL: {total} records across {len(all_tables)} tables")
    print(f"  Ingestion script: {args.output_dir}/ingest-test-data.sh")
    print(f"\n  Test users: {len(USERS)} ({sum(1 for u in USERS if u['vip'])} VIP)")
    print(f"  Test devices: {len(DEVICES)}")
    print(f"  Malware families: {len(MALWARE_FAMILIES)}")

if __name__ == "__main__":
    main()
