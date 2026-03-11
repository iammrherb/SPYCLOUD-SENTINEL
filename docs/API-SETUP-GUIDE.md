# SpyCloud API Setup Guide

Complete guide for configuring SpyCloud API connectivity across Microsoft Sentinel and Security Copilot.

---

## 1. Get Your SpyCloud API Key

1. Log in to [portal.spycloud.com](https://portal.spycloud.com)
2. Navigate to **Account Settings** > **API Keys**
3. Copy your API key

**Test connectivity:**

```bash
curl -s -H "X-API-Key: YOUR_KEY" \
  "https://api.spycloud.io/enterprise-v2/breach/catalog?limit=1" | head -c 200
```

A successful response returns JSON with breach catalog data. A `401` means invalid key.

---

## 2. API Tiers & Entitlements

| Tier | Endpoints | Included With |
|------|-----------|---------------|
| **Enterprise** | Breach Watchlist, Breach Catalog, Identity Exposure | All SpyCloud subscriptions |
| **Enterprise+** | Compass Data, Compass Devices, Compass Applications | Compass entitlement |
| **SIP** | Session Identity Protection (stolen cookies) | SIP entitlement |
| **Investigations** | Full database search across all breach sources | Investigations entitlement |

You only need **one API key** for all tiers. The key's permissions determine which endpoints are accessible.

---

## 3. API Endpoints Reference

**Base URL:** `https://api.spycloud.io`

**Authentication:** All requests require the `X-API-Key` header.

### Enterprise Breach API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/enterprise-v2/breach/data/emails/{email}` | GET | Breach records for a specific email |
| `/enterprise-v2/breach/data/emails?domain={domain}` | GET | All breach records for a corporate domain |
| `/enterprise-v2/breach/data/ips/{ip}` | GET | Breach records associated with an IP |
| `/enterprise-v2/breach/data/usernames/{username}` | GET | Breach records for a username |
| `/enterprise-v2/breach/data/passwords` | POST | Check if a password appears in breaches |
| `/enterprise-v2/breach/data/watchlist` | GET | Full watchlist data for your organization |
| `/enterprise-v2/breach/catalog` | GET | Browse all breach sources in SpyCloud |
| `/enterprise-v2/breach/catalog/{id}` | GET | Details for a specific breach source |

**Common query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | string | Return records published on or after this date (YYYY-MM-DD) |
| `until` | string | Return records published on or before this date (YYYY-MM-DD) |
| `severity` | integer | Minimum severity threshold (2, 5, 20, 25) |
| `type` | string | `corporate` or `infected` |
| `limit` | integer | Max records per page (1-10000, default 100) |
| `cursor` | string | Pagination cursor from previous response |
| `password_type` | string | Filter: `plaintext`, `hashed`, `cracked` |

**Example — Look up breach data by email:**

```bash
curl -s -H "X-API-Key: YOUR_KEY" \
  "https://api.spycloud.io/enterprise-v2/breach/data/emails/user@example.com?severity=20&limit=10"
```

### Compass Investigation API (Enterprise+)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/compass/data/emails/{email}` | GET | Deep infostealer data for an email |
| `/compass/data/emails?domain={domain}` | GET | Infostealer data for all emails in a domain |
| `/compass/data/ips/{ip}` | GET | Infostealer data associated with an IP |
| `/compass/devices` | GET | List infected device fingerprints |
| `/compass/devices/{infected_machine_id}` | GET | Details for a specific infected device |
| `/compass/applications/{infected_machine_id}` | GET | Application targets on an infected device |

### Session Identity Protection (SIP) API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sip/breach/data/cookie-domains/{domain}` | GET | Stolen session cookies for a domain |
| `/sip/breach/catalog` | GET | SIP breach catalog |
| `/sip/breach/catalog/{id}` | GET | SIP breach source details |

### Investigations API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/investigations-v2/data/emails/{email}` | GET | Full database search by email |
| `/investigations-v2/data/emails?domain={domain}` | GET | Full database search by domain |
| `/investigations-v2/data/ips/{ip}` | GET | Full database search by IP |
| `/investigations-v2/data/usernames/{username}` | GET | Full database search by username |
| `/investigations-v2/data/passwords` | POST | Full database search by password |

---

## 4. Sentinel Connector Setup

The SpyCloud Sentinel connector uses the Codeless Connector Framework (CCF) with REST API pollers that call these endpoints automatically.

### What You Need

1. **SpyCloud API Key** — Enter during connector setup (Step 1)
2. **Azure Permissions:**
   - Microsoft Sentinel Contributor role
   - Monitoring Metrics Publisher role on the Data Collection Rule
3. **Sentinel Workspace** — Log Analytics workspace with Sentinel enabled

### Data Flow

```
SpyCloud API (api.spycloud.io)
    ↓
CCF REST Pollers (9 pollers, one per endpoint)
    ↓
Data Collection Endpoint (DCE)
    ↓
Data Collection Rule (DCR) — KQL transforms
    ↓
Log Analytics Workspace (10 custom tables)
    ↓
Analytics Rules → Incidents → Playbooks
```

### Tables Created

| Table | Source Endpoint | Polling |
|-------|----------------|---------|
| `SpyCloudBreachWatchlist_CL` | `/enterprise-v2/breach/data/watchlist` | Automatic |
| `SpyCloudBreachCatalog_CL` | `/enterprise-v2/breach/catalog` | Automatic |
| `SpyCloudIdentityExposure_CL` | `/enterprise-v2/breach/data/watchlist?type=corporate` | Automatic |
| `SpyCloudCompassData_CL` | `/compass/data/emails?domain=*` | Enterprise+ only |
| `SpyCloudCompassDevices_CL` | `/compass/devices` | Enterprise+ only |
| `SpyCloudCompassApplications_CL` | `/compass/applications/*` | Enterprise+ only |
| `SpyCloudSipCookies_CL` | `/sip/breach/data/cookie-domains/{domain}` | SIP only |
| `SpyCloudInvestigations_CL` | `/investigations-v2/data/*` | Investigations only |
| `Spycloud_MDE_Logs_CL` | Internal (playbook-generated) | N/A |
| `SpyCloud_ConditionalAccessLogs_CL` | Internal (playbook-generated) | N/A |

### Verify Data Ingestion

After connecting, run in Log Analytics:

```kql
union
  (SpyCloudBreachWatchlist_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Watchlist'),
  (SpyCloudBreachCatalog_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Catalog'),
  (SpyCloudIdentityExposure_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Identity'),
  (SpyCloudCompassData_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Compass'),
  (SpyCloudCompassDevices_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Devices'),
  (SpyCloudCompassApplications_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Apps'),
  (SpyCloudSipCookies_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='SIP'),
  (SpyCloudInvestigations_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Investigations'),
  (Spycloud_MDE_Logs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='MDE Logs'),
  (SpyCloud_ConditionalAccessLogs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='CA Logs')
| project Table, Records, Latest
| order by Table asc
```

**Expected timing:**
- Watchlist and Catalog: 5-10 minutes after connecting
- Compass tables: Only if Enterprise+ tier and enableCompass=true
- SIP/Investigations: Only if those entitlements are enabled
- MDE/CA Logs: Only after playbooks execute

---

## 5. Security Copilot Plugin Setup

### Which Files to Upload

Upload each YAML file separately to Security Copilot. **Do NOT upload manifest.json** — it is for reference only.

| File | Upload Format | Auth Required | What It Does |
|------|--------------|---------------|-------------|
| `SpyCloud_Plugin.yaml` | Security Copilot plugin | None (uses Sentinel connection) | 90 KQL skills querying Sentinel tables |
| `SpyCloud_API_Plugin.yaml` | Security Copilot plugin | SpyCloud API Key | 20 REST API skills for real-time lookups |
| `SpyCloud_Agent.yaml` | Security Copilot plugin | None (uses Sentinel connection) | 17 investigation sub-agents |

### Install the KQL Plugin

1. In Security Copilot, go to **Sources** > **Manage plugins** > **Custom** > **Add plugin**
2. Select **Security Copilot plugin** as the upload format
3. Upload `SpyCloud_Plugin.yaml`
4. Configure the required settings when prompted:

| Setting | Where to Find It |
|---------|-----------------|
| **TenantId** | Azure Portal > Entra ID > Overview > Tenant ID |
| **SubscriptionId** | Azure Portal > Subscriptions > select your subscription > Subscription ID |
| **ResourceGroupName** | Azure Portal > Resource groups > name of the group containing your Sentinel workspace |
| **WorkspaceName** | Azure Portal > Log Analytics workspaces > name of your Sentinel workspace |

### Install the API Plugin

1. In Security Copilot, go to **Sources** > **Manage plugins** > **Custom** > **Add plugin**
2. Select **Security Copilot plugin** as the upload format
3. Upload `SpyCloud_API_Plugin.yaml`
4. When prompted for authentication, enter your SpyCloud API key in the **Value** field
5. The plugin sends it automatically as the `X-API-Key` header — no additional configuration needed

**Important:** Do NOT change the Key, Location, or AuthScheme fields. They are pre-configured in the YAML:
- Key: `X-API-Key`
- Location: `Header`
- AuthScheme: (empty)

### Install the Investigation Agent

1. In Security Copilot, go to **Sources** > **Manage plugins** > **Custom** > **Add plugin**
2. Select **Security Copilot plugin** as the upload format
3. Upload `SpyCloud_Agent.yaml`
4. Configure the same Sentinel settings as the KQL Plugin (TenantId, SubscriptionId, ResourceGroupName, WorkspaceName)

---

## 6. Severity Levels

SpyCloud assigns severity scores to exposure records:

| Severity | Category | Description | SOC Priority |
|----------|----------|-------------|-------------|
| **2** | Breach Credential | Username/password from a data breach | Low |
| **5** | Breach + PII | Breach data with personal information | Medium |
| **20** | Infostealer | Credentials stolen by malware | High |
| **25** | Infostealer + Application | Infostealer with application targets, stolen cookies | Critical |

Severity 20+ records indicate **active infostealer infections** and should be prioritized for immediate remediation (password reset, session revocation, device isolation).

---

## 7. Troubleshooting

### Connector Issues

| Problem | Solution |
|---------|----------|
| No data after 15 minutes | Verify API key with curl test above. Check DCR ingestion metrics in Azure Monitor. |
| 401 Unauthorized | API key is invalid or expired. Generate a new one at portal.spycloud.com. |
| 403 Forbidden | Your API tier doesn't include this endpoint (e.g., Compass without Enterprise+). |
| Compass tables empty | Verify `enableCompass=true` in deployment and Enterprise+ tier. |
| SIP tables empty | Verify `enableSip=true` and SIP entitlement. |

### Security Copilot Plugin Issues

| Error | Solution |
|-------|----------|
| `Property 'AuthorizationHeader' not found` | Re-download and re-upload `SpyCloud_API_Plugin.yaml` — the invalid property has been removed. |
| `No SkillsetDescriptor` | You uploaded the wrong file. Upload `SpyCloud_API_Plugin.yaml`, NOT `SpyCloud_API_Plugin_OpenAPI.yaml`. The OpenAPI spec is referenced automatically. |
| `Unsupported authorization header type` | You uploaded `manifest.json`. Do NOT upload it — upload the individual YAML files instead. |
| API skills return no data | Verify your API key is entered in the plugin settings and test with curl. |
| KQL skills return no data | Verify TenantId, SubscriptionId, ResourceGroupName, and WorkspaceName settings match your Sentinel deployment. |

### API Rate Limits

SpyCloud applies rate limits based on your subscription tier. If you hit rate limits:
- Increase the polling interval in the connector settings
- Reduce concurrent API plugin calls in Security Copilot
- Contact SpyCloud support for rate limit increases

---

## 8. Support

- **SpyCloud API issues:** support@spycloud.com
- **SpyCloud Portal:** [portal.spycloud.com](https://portal.spycloud.com)
- **Sentinel/Copilot issues:** [GitHub Issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues)
