# ═══════════════════════════════════════════════════════════════════════
# SCORCH — SpyCloud Agent Prompt Library v2.0
# 150+ Categorized Investigation Prompts
# ═══════════════════════════════════════════════════════════════════════
# Date:     2026-03-19
# Purpose:  Complete prompt catalog for the SpyCloud Investigation Agent
#           organized by investigation type, complexity, and persona
# ═══════════════════════════════════════════════════════════════════════

## PROMPT CATEGORIES

### 1. GETTING STARTED & ORIENTATION (10 prompts)

- What can you help me investigate?
- What data sources do you have access to?
- Show me what SpyCloud tables are available and their record counts
- What's the current health status of our SpyCloud data pipeline?
- How fresh is our data? When was the last ingestion?
- Walk me through your investigation capabilities
- What severity levels exist and what do they mean?
- How do you prioritize different types of exposures?
- What MITRE ATT&CK techniques can you map to?
- Give me the 30-second elevator pitch on what you do

---

### 2. ORGANIZATIONAL OVERVIEW (15 prompts)

- Show me an overview of our dark web exposure — hit me with the bad news
- What's our overall risk posture? Give me the executive summary
- How many total credential exposures do we have?
- Break down our exposure by severity level
- Compare exposure across our corporate domains
- Which business unit has the worst credential hygiene?
- What's our exposure trend over the last 30/60/90 days? Getting better or worse?
- Show me the top 20 most-exposed users in our organization
- How many unique devices have been infected with infostealers?
- What percentage of our exposures have been auto-remediated?
- Give me the numbers I need for a board presentation
- What's our exposure-to-remediation SLA compliance rate?
- How do we compare to typical enterprise exposure levels?
- Show me a risk heatmap by severity and domain
- What would happen if an attacker had all this data? Walk me through the kill chain

---

### 3. USER INVESTIGATION (20 prompts)

- Investigate john.doe@company.com
- What SpyCloud exposures exist for {email}?
- Show me the full PII profile for {email} — name, DOB, SSN, everything
- What passwords were stolen for {email}? Are any plaintext?
- How many breach sources contain this user's credentials?
- Show me the activity timeline for {email} — when was each exposure?
- Is this user's password reused across multiple sites?
- What devices were infected that compromised this user?
- Has this user's password been automatically reset?
- Were this user's sessions revoked after the exposure?
- Show social media and LinkedIn exposure for {email}
- Is this user in any VIP or executive watchlists?
- What applications had credentials stolen for this user?
- Map the full identity graph for {email} — all linked accounts
- What would an attacker do first with this user's stolen data?
- Cross-reference {email} against Entra sign-in logs — any suspicious activity?
- Has {email} been compromised by multiple malware families?
- Compare this user's exposure to the org average
- When was the first and most recent exposure for {email}?
- Generate an incident report for {email}'s exposure

---

### 4. PASSWORD ANALYSIS (15 prompts)

- Show me all plaintext passwords exposed in our organization
- Break down password types by crackability — how fast can they be cracked?
- Which password hash algorithms are most common in our exposures?
- Are there users with the same password across 3+ domains?
- What's the credential stuffing risk for our top-exposed users?
- How many MD5-hashed passwords do we have? Those are basically plaintext
- Show me bcrypt vs plaintext distribution — how's our vendor password hygiene?
- Which target domains stored passwords in the weakest format?
- Are any admin or service account passwords exposed in plaintext?
- What percentage of our exposed passwords are crackable within 1 hour?
- Show the top 10 target domains with the worst password storage practices
- How many of our users have high-sighting credentials (seen in 3+ breaches)?
- What's the average time-to-crack for our exposed password corpus?
- Are there any passwords exposed that match common patterns (seasonal, company name)?
- Generate a password hygiene report card for leadership

---

### 5. DEVICE FORENSICS (15 prompts)

- Which devices are infected with infostealer malware?
- Show device forensics for {machine_id} — malware path, AV, IPs, OS
- What other users were compromised from this same device?
- Has this device been isolated in Microsoft Defender?
- What antivirus was running when the infection occurred? Did it fail?
- Which AV products have the highest failure rate against infostealers?
- Show me all devices infected in the last 7 days
- Are there any devices that have been re-infected multiple times?
- Which operating systems are most commonly infected?
- What countries are the infections coming from?
- Show BYOD/unmanaged devices that have corporate credential infections
- Map infected devices to their geographic locations
- What malware paths are most common across infections?
- Are any infected devices still online and communicating?
- Generate a device quarantine priority list

---

### 6. INFOSTEALER & MALWARE ANALYSIS (15 prompts)

- What malware families are targeting our organization?
- Show me everything about the Raccoon Stealer campaign hitting our users
- Which infostealer has compromised the most of our devices?
- Research {malware_family} — TTPs, C2, recent campaigns
- What MITRE ATT&CK techniques map to our infostealer infections?
- Are there any new malware families in our recent breach catalog entries?
- Which breach sources have the highest confidence scores?
- Show me the infostealer campaign pattern — same source, same timeframe
- What stolen session cookies could bypass our MFA right now?
- Are any severity 25 exposures (cookies + sessions) unaddressed?
- What AV products are failing to detect these infostealers?
- Show me the infection kill chain from initial access to data exfiltration
- Which infostealer families are trending in our industry?
- Are there common infection paths across our compromised devices?
- Map our infections to known threat actor campaigns

---

### 7. REMEDIATION & RESPONSE (15 prompts)

- What's the overall effectiveness of our automated playbooks?
- Show all MDE remediation actions taken in the last 30 days
- Show all Conditional Access remediation actions taken
- How many devices have been isolated vs how many should have been?
- How many password resets have been forced? How many are outstanding?
- What's our mean-time-to-remediate for infostealer exposures?
- Show me the remediation gap — high-severity exposures with NO action taken
- Which users had their sessions revoked?
- Were any accounts disabled for critical exposures?
- Show remediation statistics broken down by playbook
- What's our false positive rate on automated isolation?
- Are there any remediation actions that failed?
- Show the timeline from exposure detection to remediation completion
- Generate a remediation effectiveness KPI report
- What would it take to reach 95% auto-remediation coverage?

---

### 8. COMPLIANCE & LEGAL (15 prompts)

- Do we have sensitive PII exposed requiring breach notification?
- Show all SSN/financial/health data exposures
- What compliance frameworks apply to our exposed data?
- Calculate breach notification deadlines for our current exposures
- Generate a compliance evidence package for this incident
- Which state breach notification laws apply to our affected users?
- Do we have GDPR-triggering exposures? What's our 72-hour deadline?
- Are there HIPAA-triggering health data exposures?
- Show PCI-DSS relevant exposures — payment card data, bank accounts
- Document the detection-to-remediation timeline for auditors
- What evidence do we need to demonstrate adequate response?
- Are there any SOX-relevant executive credential exposures?
- Generate a breach notification recommendation memo for legal
- What's our total count of individuals requiring notification?
- Map exposed data categories to regulatory notification requirements

---

### 9. THREAT HUNTING (15 prompts)

- Run a full threat hunt across all our exposure data
- Hunt for infostealer campaign patterns — same source, same path, cluster
- Look for credential stuffing indicators — high sighting, multiple domains
- Hunt for lateral movement potential from compromised admin accounts
- Find MFA bypass risk from stolen session cookies
- Hunt for service account or privileged identity exposures
- Look for recently compromised users who are still actively signing in
- Hunt for credential exposure + suspicious Entra sign-in correlation
- Find devices that are compromised but NOT isolated
- Hunt for infections from anomalous geographic locations
- Look for credential reuse across critical corporate applications
- Hunt for exposure patterns that suggest a targeted attack
- Find users compromised across multiple malware families
- Look for shadow IT credentials — corporate emails on consumer sites
- Hunt for supply chain risk — vendor credentials accessing our systems

---

### 10. CROSS-ECOSYSTEM CORRELATION (10 prompts)

- Cross-reference our SpyCloud exposures with Entra sign-in logs
- Correlate infostealer infections with MDE device health data
- Check if any compromised users have suspicious Okta/Duo sign-ins
- Correlate stolen cookies with active cloud app sessions
- Cross-reference compromised credentials with M365 mailbox rule changes
- Check if any compromised admin accounts have DCSync attempts in MDI
- Correlate infostealer infections with VPN access patterns
- Cross-reference exposures with ThreatIntelligenceIndicator matches
- Check compromised users against recent DLP policy triggers
- Correlate device infections with Intune compliance status

---

### 11. EXECUTIVE REPORTING (10 prompts)

- Draft an executive summary for the CISO
- Generate a board-ready risk posture slide
- Create a monthly exposure trend report
- Produce a remediation effectiveness dashboard summary
- Write a risk-adjusted exposure score explanation for leadership
- Generate a vendor/supply chain risk report for procurement
- Create a weekly SOC brief from our exposure data
- Produce a quarterly compliance posture report
- Draft talking points for the security budget discussion
- Summarize our ROI from automated remediation playbooks

---

### 12. RESEARCH & THREAT INTELLIGENCE (15 prompts)

- Research the latest infostealer trends — what's hot in 2026?
- What are the most common attack vectors for credential theft?
- Brief me on the Lumma Stealer — capabilities, targeting, TTPs
- What does the Redline Stealer infrastructure look like?
- How are infostealers evolving to bypass modern EDR?
- What are the latest dark web marketplace trends for stolen credentials?
- Research MFA bypass techniques using stolen session cookies
- What are the top infostealer families by volume in Q1 2026?
- How do initial access brokers price stolen credentials?
- What's the typical timeline from credential theft to account takeover?
- Research post-exploitation techniques after credential compromise
- What are current best practices for infostealer prevention?
- How effective are passkeys at preventing credential theft?
- What's the relationship between infostealers and ransomware gangs?
- Brief me on identity threat detection and response (ITDR) best practices

---

## PROMPT COMPLEXITY TIERS

### Tier 1: Quick Check (1-2 skill calls, <30 seconds)
- "Check {email} for exposures"
- "How many plaintext passwords do we have?"
- "Is the data pipeline healthy?"
- "What's the latest breach in our catalog?"

### Tier 2: Standard Investigation (3-5 skill calls, 30-60 seconds)
- "Investigate {email} — full exposure report"
- "Show device forensics for {machine_id}"
- "Break down our exposure by severity"
- "Show remediation effectiveness"

### Tier 3: Deep Investigation (6-10 skill calls, 60-120 seconds)
- "Full org-wide exposure overview with trends"
- "Complete threat hunt across all tables"
- "Compliance assessment with notification requirements"
- "Cross-ecosystem correlation for {email}"

### Tier 4: Research & Analysis (10+ skill calls + GPT analysis, 2-5 minutes)
- "Generate executive brief with trend analysis"
- "Full compliance evidence package"
- "Research {malware_family} with org impact assessment"
- "Weekly SOC brief with all KPIs"

---

## PERSONA-SPECIFIC PROMPT SETS

### For SOC Analyst (Persona 1):
Focus: Incident triage, user investigation, device forensics, remediation status
Tone: Technical, detailed, action-oriented

### For Threat Hunter (Persona 2):
Focus: Campaign detection, IOC correlation, MITRE mapping, proactive hunting
Tone: Deep-dive, pattern-focused, hypothesis-driven

### For Security Manager / CISO (Persona 3):
Focus: Exposure overview, trends, KPIs, compliance, executive reporting
Tone: Summary-level, risk-focused, business-impact oriented

### For GRC / Compliance (Persona 0):
Focus: PII exposure, notification requirements, evidence collection, audit prep
Tone: Formal, framework-aligned, documentation-focused
