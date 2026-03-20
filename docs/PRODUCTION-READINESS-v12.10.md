# SpyCloud Sentinel Supreme — Production Readiness Assessment v12.10

## Executive Summary

The current template deploys 116 resources and 110/112 succeed. However, several
architectural issues prevent Content Hub visibility, updateability, and marketplace
readiness. This document identifies every gap and the fix path.

---

## 1. MONITORED DOMAIN — Remove or Make Truly Optional

### Current State
- `monitoredDomain` parameter used by 6 pollers (SIP, Investigations, IdLink,
  Data Partnership, Exposure, CAP)
- When blank, API calls fail because the endpoint URL becomes invalid:
  `https://api.spycloud.io/.../domains/` (empty string)
- Enterprise Watchlist + Breach Catalog + Compass do NOT need a domain — they
  use the SpyCloud-side watchlist configuration

### Assessment
SpyCloud's Enterprise API watchlist is configured server-side via portal.spycloud.com.
The domain-specific endpoints (SIP cookies by domain, Investigations by domain, etc.)
DO require a domain parameter, but these are optional products.

### Recommendation
- **Remove monitoredDomain from the connector page entirely** for v12.10
- Core pollers (Watchlist, Catalog, Compass) work without any domain
- Domain-specific pollers (SIP, Investigations, IdLink, Exposure, CAP, DataPartnership)
  should have their condition updated to require BOTH the API key AND a non-empty domain:
  `[and(greater(length(parameters('sipApiKey')), 0), greater(length(parameters('monitoredDomain')), 0))]`
- Add monitoredDomain as optional field with clear guidance: "Required only for
  SIP, Investigations, IdLink, Exposure, CAP, and Data Partnership pollers"

---

## 2. CONTENT PACKAGE — Missing Dependencies

### Current State
The ContentPackage only declares 1 dependency:
```json
{
  "kind": "DataConnector",
  "contentId": "SpyCloudIdentityIntelligence"
}
```

### Problem
Content Hub shows the solution but doesn't associate the 38 analytics rules,
16 hunting queries, or workbook with it. Users go to Analytics and don't see
SpyCloud rule templates. Workbooks don't load.

### Fix Required
The ContentPackage `dependencies.criteria` array must include ALL content items:
- 1 DataConnector
- 38 AnalyticsRule entries (one per rule contentId)
- 16 HuntingQuery entries (need content templates created)
- 1 Workbook entry (needs content template created)

This is the single most important fix for Content Hub visibility.

---

## 3. HUNTING QUERIES — Not Content-Templated

### Current State
16 `savedSearches` deployed as standalone resources. These work but:
- Not visible in Content Hub as part of the solution
- Not updateable through package version bumps
- No association with the SpyCloud solution in the UI

### Fix Required
Each hunting query needs a `contentTemplates` wrapper with:
- `contentKind: "HuntingQuery"`
- `contentId: unique GUID`
- Proper `mainTemplate` containing the `savedSearches` resource
- Listed in ContentPackage `dependencies.criteria`

---

## 4. WORKBOOK — Not Content-Templated

### Current State
1 `Microsoft.Insights/workbooks` deployed standalone. Not linked to the package.

### Fix Required
Wrap the workbook in a `contentTemplates` resource with `contentKind: "Workbook"`
and add to ContentPackage dependencies.

---

## 5. LOGIC APPS — Cannot Be Updated via Content Hub

### Architectural Reality
Logic Apps are NOT a supported content type for Sentinel Content Hub packages.
Supported types: AnalyticsRule, DataConnector, HuntingQuery, Parser, Playbook,
Workbook, AutomationRule.

### However
The 13 Logic Apps we deploy are **Playbooks** in Sentinel terminology.
They CAN be content-templated as `contentKind: "Playbook"` if we wrap them
properly. But this is complex and not strictly required for v1.

### Recommendation for v12.10
- Keep Logic Apps as standalone ARM resources (current approach)
- Add proper `tags` with `hidden-SentinelTemplateName` and
  `hidden-SentinelTemplateVersion` so Sentinel associates them
- Future: Wrap in content templates for full updateability

---

## 6. SpyCloud PRODUCT API RELEVANCE ASSESSMENT

### KEEP — High Value, Unique Data

| Product | API | Value for Sentinel | Enrichment Use | Storage Impact |
|---------|-----|-------------------|---------------|----------------|
| **Enterprise Watchlist** | `/breach/data/watchlist` | **ESSENTIAL** — Core credential exposure data. Every rule, workbook, and playbook depends on this. | Email, domain, IP, username enrichment | Medium (10-500MB/day depending on org size) |
| **Breach Catalog** | `/breach/catalog` | **ESSENTIAL** — Provides "where did this come from?" context. Without it, exposures are just raw records with no attribution. | Catalog ID enrichment on every incident | Low (~1MB/day) |
| **Compass Data** | `/compass/data` | **HIGH** — Shows the full blast radius of infections: every application credential stolen, not just corporate email. Critical for understanding if VPN/SSO/cloud creds were stolen. | Email enrichment for application-level exposure | Medium-High |
| **Compass Devices** | `/compass/devices` | **HIGH** — Device forensics: machine fingerprint, OS, AV installed, malware path, all users who logged in. Essential for MDE correlation. | Host/device enrichment | Low-Medium |
| **SIP Cookies** | `/sip/cookies` | **CRITICAL** — Stolen session cookies = MFA bypass. This is the most operationally urgent data type. If an attacker has valid cookies, they don't need the password. | Cookie enrichment + session revocation | Low |

### KEEP BUT REASSESS — Moderate Value

| Product | API | Assessment |
|---------|-----|-----------|
| **Compass Applications** | `/compass/applications` | Useful for application exposure mapping but overlaps with Compass Data. **Keep the poller but don't create dedicated enrichment playbook** — the Compass Data enrichment already returns application info. |
| **Investigations** | `/investigations-v2` | Full database access is powerful for manual threat hunting but **should NOT be a polling data source** — it's the entire SpyCloud database, not org-scoped. Use it ONLY for on-demand enrichment playbooks. **Remove the Investigations poller, keep only the enrichment playbook.** |
| **Exposure Stats** | `/exposure/stats` | Domain-level aggregate statistics for executive dashboards. Low volume, low noise. **Keep but make it weekly polling (10080 min) not 30 min** — stats don't change rapidly. |

### CONSIDER REMOVING — Low Value or Noise Risk

| Product | API | Assessment |
|---------|-----|-----------|
| **IdLink** | `/idlink/records` | Identity correlation is interesting conceptually but in practice: (a) it requires a domain parameter, (b) the correlation logic is better done in KQL joins between existing tables than via a dedicated poller, (c) the data overlaps heavily with Watchlist. **Remove the poller. If needed, add as enrichment-only playbook.** |
| **CAP** | `/cap/records` | Consumer Compromised Account Protection is for B2C businesses protecting their customers, NOT for SOC teams protecting employees. Most Sentinel customers are B2B SOCs. **Remove unless the customer explicitly has CAP license and B2C use case.** |
| **Data Partnership** | `/data-partnership` | Requires a specific partnership agreement with SpyCloud. Very few customers have this. **Remove from default deployment. Can be added back by customers who need it.** |

### ENRICHMENT PLAYBOOK ASSESSMENT

| Playbook | Keep? | Reasoning |
|----------|-------|-----------|
| **Email Enrichment** | ✅ KEEP | Most frequently triggered, highest value |
| **Domain Enrichment** | ✅ KEEP | Org-level exposure assessment |
| **IP Enrichment** | ✅ KEEP | Infostealer investigation pivot |
| **Username Enrichment** | ✅ KEEP | Service account / non-email identity |
| **Catalog Enrichment** | ✅ KEEP | Essential "where from?" context |
| **Compass Enrichment** | ✅ KEEP | Device blast radius (if licensed) |
| **SIP Cookie Enrichment** | ✅ KEEP | MFA bypass detection (if licensed) |
| **Investigation Enrichment** | ⚠️ REASSESS | High API cost, low QPS limit. Keep but rate-limit aggressively (max 10/day). Manual trigger only, not auto-triggered. |

---

## 7. CUSTOM API CONNECTOR — Single vs Multiple

### Current Design
One Custom API Connector with 10 operations, authenticated with Enterprise API key.

### Problem
Compass, SIP, and Investigations may use different API keys. The single connector
only stores one key.

### Options

**Option A: Single connector, key per playbook (RECOMMENDED)**
- Keep one Custom API Connector for branding/icon purposes
- Each enrichment playbook uses raw HTTP actions with the specific product API key
  passed from ARM parameters
- Simpler, fewer Azure resources, still shows SpyCloud icon via connector definition

**Option B: Multiple connectors (one per product)**
- SpyCloud-Enterprise-API, SpyCloud-Compass-API, SpyCloud-SIP-API, etc.
- Each with its own API connection authenticated with the product-specific key
- More Azure resources, harder to manage, but cleaner API key isolation

**Option C: Azure Functions (FUTURE)**
- Single Function App with HTTP-triggered functions per product
- Handles authentication, rate limiting, retry logic internally
- Most scalable but significant development effort
- Best for marketplace/ISV deployment

### Recommendation for v12.10
Go with **Option A** — single connector for branding, HTTP actions with per-product
API keys. This is what we have now and it works. The enrichment playbooks already
use `[parameters('compassApiKey')]` for Compass, etc.

---

## 8. UPDATEABILITY — Version Bumping Strategy

### What Can Be Updated via Content Hub
When a customer installs a new version of the package:
- **Analytics Rule Templates** — updated automatically, but ACTIVE rules created
  from templates are NOT overwritten (user customizations preserved)
- **Hunting Queries** — updated if content-templated
- **Workbooks** — updated if content-templated
- **Data Connector** — definition updated, existing connections preserved
- **Parsers** — updated if content-templated

### What Cannot Be Updated via Content Hub
- **Logic Apps** — always standalone, must be redeployed via ARM
- **Tables** — schema updates require separate deployment
- **DCR/DCE** — require redeployment
- **Watchlists** — not overwritten if data exists

### Version Bump Process
1. Increment `_solutionVersion` variable
2. Increment `dataConnectorVersionConnectorDefinition` and `dataConnectorVersionConnections`
3. Increment individual content template versions
4. Push to GitHub → customer redeploys from Content Hub → templates update

---

## 9. ACTION ITEMS FOR v12.10

### Priority 1 — Must Fix (Deployment Blockers)
- [x] Remove `<img>` tag from description (PR #137)
- [x] Fix connectorDefinitionName SpyCloudCCF → SpyCloudIdentityIntelligence (PR #136)
- [x] Fix enable Dropdown type mismatch (PR #135)
- [ ] Fix monitoredDomain causing API failures — make truly optional with conditions
- [ ] Fix Content Package dependencies to include all analytics rules

### Priority 2 — Content Hub Visibility
- [ ] Add all 38 analytics rules to ContentPackage dependencies
- [ ] Content-template the workbook for Content Hub visibility
- [ ] Content-template hunting queries for Content Hub visibility
- [ ] Add `hidden-SentinelTemplateName` tags to Logic Apps

### Priority 3 — Product Rationalization
- [ ] Remove Investigations POLLER (keep enrichment playbook only)
- [ ] Remove IdLink POLLER (or make enrichment-only)
- [ ] Remove CAP and Data Partnership pollers from default
- [ ] Change Exposure Stats to weekly polling
- [ ] Make Compass Applications enrichment use Compass Data endpoint instead

### Priority 4 — Polish
- [ ] Verify all icons render correctly in every Azure surface
- [ ] Ensure workbook loads data correctly
- [ ] Add proper error handling for empty monitoredDomain
- [ ] Review and optimize all 38 analytics rule KQL queries
