# SpyCloud Sentinel Supreme — Permissions, Managed Identities & Playbook Reference

## 1. Managed Identity Summary

All 5 Logic Apps use **SystemAssigned** managed identities (created automatically by ARM deployment). Each identity requires specific API permissions granted post-deploy.

### Required Permissions Matrix

| Logic App | API | Permission | Scope | License Required |
|-----------|-----|-----------|-------|-----------------|
| **MDE Remediation** | Microsoft Defender | Machine.Isolate | Organization | MDE P2 |
| | Microsoft Defender | Machine.ReadWrite.All | Organization | MDE P2 |
| | Microsoft Graph | Mail.Send | Application | Exchange Online |
| | Azure Monitor | Monitoring Metrics Publisher | Resource Group | — |
| **CA Remediation** | Microsoft Graph | User.ReadWrite.All | Application | Entra P1+ |
| | Microsoft Graph | Directory.ReadWrite.All | Application | Entra P1+ |
| | Microsoft Graph | Mail.Send | Application | Exchange Online |
| | Azure Monitor | Monitoring Metrics Publisher | Resource Group | — |
| **CredResponse** | Microsoft Graph | User.ReadWrite.All | Application | Entra P1+ |
| | Microsoft Graph | AuditLog.Read.All | Application | Entra P1+ |
| | Microsoft Graph | Mail.Send | Application | Exchange Online |
| **MDE Blocklist** | Microsoft Defender | Machine.Isolate | Organization | MDE P2 |
| | Microsoft Defender | Machine.ReadWrite.All | Organization | MDE P2 |
| | Microsoft Graph | Mail.Send | Application | Exchange Online |
| | Log Analytics | Reader | Workspace | — |
| **TI Enrichment** | VirusTotal | API Key (parameter) | — | Free tier OK |
| | AbuseIPDB | API Key (parameter) | — | Free tier OK |

### Granting Permissions

```bash
# Run from Cloud Shell after deployment:
curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh | bash -s -- -g <RG> -w <WS>
```

Or manually:

```bash
# Get Logic App principal IDs
MDE_PID=$(az logic workflow show -n "SpyCloud-MDE-Remediation-<WS>" -g <RG> --query "identity.principalId" -o tsv)
CA_PID=$(az logic workflow show -n "SpyCloud-CA-Remediation-<WS>" -g <RG> --query "identity.principalId" -o tsv)

# Grant Graph API permissions (requires Global Admin or Privileged Role Administrator)
# User.ReadWrite.All
az ad app permission grant --id $CA_PID --api 00000003-0000-0000-c000-000000000000 --scope User.ReadWrite.All

# Grant MDE API permissions
# Machine.Isolate (WindowsDefenderATP app ID: fc780465-2017-40d4-a0c5-307022471b92)
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MDE_PID/appRoleAssignments" \
  --body '{"principalId":"'$MDE_PID'","resourceId":"<MDE_SP_ID>","appRoleId":"<MACHINE_ISOLATE_ROLE_ID>"}'

# Grant Monitoring Metrics Publisher role on resource group
az role assignment create --assignee $MDE_PID --role "Monitoring Metrics Publisher" --scope "/subscriptions/<SUB>/resourceGroups/<RG>"

# Grant Microsoft Sentinel Responder role
az role assignment create --assignee $MDE_PID --role "Microsoft Sentinel Responder" --scope "/subscriptions/<SUB>/resourceGroups/<RG>"
```

## 2. Playbook Decision Logic

### Playbook 1: MDE Device Remediation
**Trigger:** Sentinel incident with SpyCloud infostealer exposure (severity ≥ 20)
**Decision Tree:**
1. Extract `infected_machine_id` and `user_hostname` from incident entities
2. Search MDE for matching device by hostname
3. **IF** device found AND device is online:
   - Isolate device (Full or Selective based on severity)
   - Tag device with "SpyCloud-Infostealer"
   - Log action to `Spycloud_MDE_Logs_CL`
   - Notify via Slack/Teams/Email
4. **IF** device found BUT offline:
   - Tag device, schedule isolation for next check-in
   - Log pending action
5. **IF** device NOT found:
   - Log "device not in MDE inventory"
   - Create investigation task

### Playbook 2: Conditional Access Remediation
**Trigger:** Sentinel incident with credential exposure
**Decision Tree:**
1. Extract `email` from incident entities
2. Look up user in Entra ID via Graph API
3. **IF** user exists AND severity ≥ 20 (infostealer):
   - Force password reset on next sign-in
   - Revoke all active sessions
   - Add to Conditional Access "compromised users" security group
   - Log all actions to `SpyCloud_ConditionalAccessLogs_CL`
4. **IF** severity ≥ 25 (cookies/sessions stolen):
   - All of above PLUS disable account pending review
5. **IF** user exists AND severity < 20 (breach only):
   - Force password reset (no session revocation)
   - Notify user via email
6. **IF** user NOT found:
   - Log "user not in directory"
   - May be external/guest — create investigation task

### Playbook 3: Credential Response (Full Investigation)
**Trigger:** Sentinel incident (any SpyCloud exposure)
**Decision Tree:**
1. Extract all entities (email, IP, hostname, domain)
2. **Enrich:**
   - Look up user in Entra (role, group membership, last sign-in)
   - Check recent sign-in logs for anomalies (impossible travel, new device)
   - Query SpyCloud for full exposure history for this user
3. **Assess Risk:**
   - VIP/admin account? → Escalate immediately
   - Multiple breaches? → Higher priority
   - Plaintext password exposed? → Critical
   - Stolen cookies? → MFA bypass risk
4. **Remediate (based on assessment):**
   - Force password reset + session revocation
   - If VIP: page on-call security team
5. **Notify (all channels):**
   - Slack, Teams, Email, ServiceNow, Jira, Azure DevOps
   - Include: user context, exposure details, actions taken

### Playbook 4: MDE Blocklist (Scheduled)
**Trigger:** Recurrence (every 4 hours)
**Logic:**
1. Query `SpyCloudBreachWatchlist_CL` for severity 25 records in last 4h
2. For each infected_machine_id:
   - Search MDE for matching device
   - If found and not already isolated: isolate + tag
   - Log all actions
3. Summarize run: devices found, isolated, already handled

### Playbook 5: TI Enrichment
**Trigger:** Sentinel incident with IP entities
**Logic:**
1. Extract IP addresses from incident
2. Query VirusTotal for each IP
3. Query AbuseIPDB for each IP
4. Add enrichment as incident comments
5. Update incident severity if malicious IPs found

## 3. Analytics Rules by Category

### Rules That Require Only SpyCloud Tables (always work)
- Rules 1-15: Severity-based detection, password exposure, cookie theft, device reinfection, multi-domain reuse, geographic anomalies, VIP exposure, unremediated alerts

### Rules That Require Additional Data Sources
| Rule | Additional Table | Required Connector |
|------|-----------------|-------------------|
| Sign-in after exposure | SigninLogs | Entra ID |
| Impossible travel | SigninLogs | Entra ID |
| MDE device correlation | DeviceInfo, AlertInfo | M365 Defender |
| Mail forwarding | OfficeActivity | Office 365 |
| DNS resolution | DnsEvents | DNS connector (AMA) |
| Entra risk events | AADUserRiskEvents | AD Identity Protection |
| Cloud app access | CloudAppEvents | Defender for Cloud Apps |
| Okta auth correlation | Okta_CL | Okta SSO |
| Duo MFA correlation | Duo_CL | Cisco Duo |
| TI indicator match | ThreatIntelligenceIndicator | Threat Intelligence |
| UEBA anomaly | BehaviorAnalytics | UEBA (Sentinel setting) |
| Firewall traffic | CommonSecurityLog | CEF/Syslog |
| Azure resource change | AzureActivity | Azure Activity |

## 4. Workbook Panels

The SpyCloud workbook includes 22+ panels across 4 tabs:
- **Overview:** Exposure trends, severity distribution, top users, top breaches
- **Infostealer Analysis:** Device infections, malware families, cookie theft
- **Remediation:** MDE isolation status, CA actions, response times
- **Executive:** Risk score trends, compliance posture, VIP exposure
