# SpyCloud Identity Exposure Intelligence for Sentinel — ISV & Marketplace Strategy v12.10

**Date:** March 19, 2026
**Purpose:** Comprehensive architecture decisions for marketplace-ready production deployment

---

## 1. AZURE FUNCTIONS vs LOGIC APPS — Full Comparison

### When to Use Each

| Capability | Logic Apps (Current) | Azure Functions (Proposed) |
|-----------|---------------------|--------------------------|
| **Incident-triggered enrichment** | ✅ Native Sentinel trigger | ⚠️ Requires webhook relay via automation rule |
| **Custom API branding** | ✅ Custom Connector with icon | ❌ No visual branding in Sentinel UI |
| **Cost at scale** | ❌ $0.000125/action × N actions × M incidents/day | ✅ Consumption plan: first 1M exec/month free |
| **Cold start** | ✅ None (always warm) | ⚠️ 1-5 sec cold start on Consumption plan |
| **Rate limiting** | ⚠️ Must build manually (variables + counters) | ✅ Built-in with code (semaphores, queues) |
| **Multi-API orchestration** | ⚠️ Complex nested foreach loops | ✅ Simple async/await code with error handling |
| **Marketplace packaging** | ✅ Content-templatable as "Playbook" | ✅ Can be included as ARM resource |
| **API key management** | ⚠️ Stored in API Connection (per-connection) | ✅ Stored in App Settings or Key Vault |
| **Logging/Audit** | ⚠️ Must build custom (write to table) | ✅ Built-in Application Insights + custom logging |
| **Retry/circuit breaker** | ⚠️ Basic retry policy only | ✅ Polly library, exponential backoff, circuit breaker |
| **Secret rotation** | ❌ Must recreate API Connection | ✅ Key Vault reference auto-rotates |
| **Content Hub visibility** | ✅ Shows as "Playbook" in solution | ⚠️ Shows as generic ARM resource |
| **No-code editing** | ✅ Visual designer for SOC analysts | ❌ Requires code changes |
| **Deployment complexity** | ✅ ARM resource, single template | ⚠️ Requires Function App + App Service Plan + Storage Account |

### Recommendation: HYBRID APPROACH

**Use Azure Functions for:**
- Data connector polling (replaces or supplements CCF pollers)
- Multi-product API orchestration (Full Investigation)
- High-volume enrichment (>100 incidents/day)
- API key management (single Key Vault, all products)
- Rate limiting and circuit breaker patterns

**Keep Logic Apps for:**
- Incident-triggered enrichment playbooks (native Sentinel trigger)
- Response actions (MDE isolation, CA password reset)
- SOC-customizable workflows (visual designer)
- Content Hub visibility as "Playbooks"

**Why both?** Logic Apps give you Content Hub presence and SOC-friendly customization. Azure Functions give you performance, scalability, and clean API key management. The Function App handles the heavy lifting (API calls, rate limiting, multi-product orchestration) while Logic Apps handle the Sentinel integration layer (triggers, entity extraction, incident comments).

### Architecture: Function App as API Backend

```
┌─────────────────────────────────────────────────────┐
│  Microsoft Sentinel                                   │
│                                                       │
│  Incident Created                                     │
│       │                                               │
│       ▼                                               │
│  Automation Rule → Logic App (Playbook)               │
│       │                                               │
│       ▼                                               │
│  Logic App extracts entities                          │
│       │                                               │
│       ▼                                               │
│  HTTP Action → Azure Function App                     │
│       │         ┌──────────────────────────┐          │
│       │         │  /api/enrich-email        │          │
│       │         │  /api/enrich-ip           │          │
│       │         │  /api/enrich-domain       │          │
│       │         │  /api/investigate         │          │
│       │         │  /api/compass-device      │          │
│       │         │  /api/sip-cookies         │          │
│       │         │                           │          │
│       │         │  Key Vault Reference:     │          │
│       │         │  → Enterprise API Key     │          │
│       │         │  → Compass API Key        │          │
│       │         │  → SIP API Key            │          │
│       │         │  → Investigations Key     │          │
│       │         │                           │          │
│       │         │  Built-in:                │          │
│       │         │  → Rate limiting          │          │
│       │         │  → Retry with backoff     │          │
│       │         │  → Circuit breaker        │          │
│       │         │  → Response formatting    │          │
│       │         │  → Audit logging to LAW   │          │
│       │         └──────────────────────────┘          │
│       │                                               │
│       ▼                                               │
│  Logic App writes to incident comment                 │
│  Logic App logs to EnrichmentAudit_CL                 │
└─────────────────────────────────────────────────────┘
```

### Azure Function App ARM Resources Required

```
1. Microsoft.Storage/storageAccounts          (Function App storage)
2. Microsoft.Insights/components              (Application Insights)
3. Microsoft.Web/serverfarms                  (App Service Plan - Consumption)
4. Microsoft.Web/sites                        (Function App)
5. Microsoft.KeyVault/vaults                  (API Key storage)
6. Microsoft.KeyVault/vaults/secrets          (8 API key secrets)
```

Total: 6 additional ARM resources. The Function App contains all enrichment
functions as code, deployed from a ZIP package hosted on GitHub.

---

## 2. API KEY FLOW — Simplification Strategy

### Current Problem
API keys are entered in 3 places:
1. createUiDefinition.json wizard (ARM deployment) — ALL keys
2. Connector page (CCF connection) — Enterprise + product keys
3. Logic App API Connections — Enterprise key (for enrichment)

### Proposed Solution: Key Vault as Single Source of Truth

```
ARM Deployment Wizard (createUiDefinition.json)
  → User enters API keys ONCE
  → ARM template creates Key Vault secrets
  → CCF connector references Key Vault for poller auth
  → Function App references Key Vault for enrichment
  → Logic Apps reference Function App (which uses Key Vault)
  → NO duplicate key entry anywhere
```

### For Content Hub / Marketplace Deployment

When deploying from Content Hub:
1. Solution installs → creates Key Vault + tables + DCR + rules + workbooks
2. User goes to Data Connector page → enters API keys (stored to Key Vault)
3. Clicks Connect → CCF pollers activate using Key Vault secrets
4. Enrichment playbooks automatically use the same keys via Function App

**Key insight:** The CCF connector page API key fields DO persist — they're stored
in the connection resource. The issue is that enrichment Logic Apps use a SEPARATE
API Connection that needs its own key. With the Function App approach, the Function
reads from Key Vault, so there's only ONE place to update keys.

### If We Stay Logic Apps Only (No Functions)

The simplification is: remove API keys from createUiDefinition.json entirely.
- CCF connector page is the ONLY place users enter keys
- Enrichment Logic Apps use HTTP actions with keys from Key Vault
- Key Vault secrets populated during connector page "Connect" action
- This requires a small helper Logic App that writes keys to Key Vault on connect

---

## 3. MARKETPLACE PUBLISHING — Step by Step

### Prerequisites
1. Microsoft Partner Network membership (MPN)
2. Partner Center account (partner.microsoft.com)
3. Solution code approved in Azure-Sentinel GitHub repo

### Publishing Process

**Step 1: Submit to Azure-Sentinel GitHub**
- Fork https://github.com/Azure/Azure-Sentinel
- Create solution in `Solutions/SpyCloud/` directory
- Structure:
  ```
  Solutions/SpyCloud/
    Package/
      mainTemplate.json         ← Our azuredeploy.json
      createUiDefinition.json   ← Our wizard
    Data Connectors/
      SpyCloudCCF.json         ← Connector definition
    Analytic Rules/
      rule1.yaml ... rule38.yaml
    Hunting Queries/
      query1.yaml ... query16.yaml
    Workbooks/
      SpyCloudDashboard.json
    Playbooks/
      SpyCloud-Enrich-Email/
        azuredeploy.json       ← Each playbook as separate ARM template
      SpyCloud-MDE-Remediation/
        azuredeploy.json
    SolutionMetadata.json
  ```
- Submit PR → Microsoft reviews → merge to main branch

**Step 2: Create Offer in Partner Center**
- partner.microsoft.com → Marketplace offers → New offer → Azure Application
- Plan type: Solution Template
- Upload deployment package (ZIP of mainTemplate.json + createUiDefinition.json)
- Add listing details, screenshots, support info

**Step 3: Certification**
- Microsoft validates ARM template
- Security review
- Content review
- Typically 2-4 weeks

**Step 4: Go Live**
- Offer published to Azure Marketplace
- Automatically appears in Sentinel Content Hub
- Customers can install with one click

### Update Process
1. Increment `_solutionVersion` in ARM template
2. Update Content Template versions for changed items
3. Submit updated PR to Azure-Sentinel GitHub
4. Update deployment package in Partner Center
5. Microsoft re-certifies
6. Customers see "Update available" in Content Hub

### Package Location for Updates
The ARM template references a `packageId` and `packageVersion` in the ContentPackage
resource. When you publish a new version:
- Content Hub shows "Update available" badge
- Customer clicks Update → re-deploys with new template
- Analytics rule TEMPLATES update (active rules are NOT overwritten)
- Workbooks update
- Hunting queries update
- Data connector definition updates
- Existing connections and data are preserved

---

## 4. CONTENT PACKAGE — What Must Be In It

### Current State (BROKEN)
```json
{
  "dependencies": {
    "criteria": [
      { "kind": "DataConnector", "contentId": "SpyCloudIdentityIntelligence" }
    ]
  }
}
```
Only 1 dependency. Content Hub sees the solution but nothing is associated with it.

### Required State (MARKETPLACE READY)
```json
{
  "dependencies": {
    "operator": "AND",
    "criteria": [
      {
        "kind": "DataConnector",
        "contentId": "[variables('_dataConnectorContentIdConnectorDefinition')]",
        "version": "[variables('dataConnectorVersionConnectorDefinition')]"
      },
      {
        "kind": "AnalyticsRule",
        "contentId": "[variables('analyticRuleContentId1')]",
        "version": "2.0.0"
      },
      // ... all 38 analytics rules ...
      {
        "kind": "HuntingQuery",
        "contentId": "[variables('huntingQueryContentId1')]",
        "version": "2.0.0"
      },
      // ... all 16 hunting queries ...
      {
        "kind": "Workbook",
        "contentId": "[variables('workbookContentId1')]",
        "version": "2.0.0"
      }
    ]
  }
}
```

### What This Enables
- Content Hub → Manage → shows ALL items: 38 rules, 16 queries, 1+ workbooks
- Each item shows version number and "Update available" when bumped
- Analytics blade → Rule Templates → SpyCloud rules appear as templates
- Hunting → Queries → SpyCloud queries appear
- Workbooks → SpyCloud workbooks appear with data

---

## 5. WORKBOOK STRATEGY — Multiple Dashboards

### Workbook 1: SOC Operational Dashboard
**Audience:** SOC Analysts, Tier 1-3
**Tabs:**
- Overview (severity tiles, trend chart, top users, top devices)
- Credential Exposures (email/domain/IP breakdown, password types)
- Infostealer Infections (device forensics, malware families, AV gaps)
- Enrichment Activity (audit table metrics, API call trends)
- Remediation Tracker (MDE actions, CA actions, resolution SLAs)
- Data Health (ingestion volume, latency, error rates)

### Workbook 2: Executive Risk Dashboard
**Audience:** CISO, VP Security, Board
**Tabs:**
- Risk Score (composite metric based on exposure volume + severity + remediation rate)
- Exposure Trend (90/180/365 day line chart)
- Breach Source Analysis (public vs private vs infostealer)
- Remediation Effectiveness (MTTR, auto-resolve rate, coverage)
- Benchmark (industry comparison if available)
- Compliance Evidence (audit trail summary)

### Workbook 3: Compass & SIP Deep Dive (Optional — if licensed)
**Audience:** Threat Hunters, IR Team
**Tabs:**
- Infected Device Map (device fingerprints, OS, AV)
- Application Exposure (which apps had creds stolen)
- Stolen Session Cookies (MFA bypass risk assessment)
- Consumer vs Corporate Overlap (personal device risk)

### Implementation Note
Sentinel workbooks DO support multiple tabs via the `group` element with
`type: "editable/pinnable"`. A single workbook JSON can have multiple tabs.
However, for Content Hub packaging, each workbook needs its own content template.

---

## 6. ANALYTICS RULES — Exhaustive Cross-Connector Correlation

### Current: 38 rules (SpyCloud data only + basic Entra/MDE correlation)

### Proposed: 60+ rules organized by category

**Category 1: Core Credential Exposure (8 rules)** — SpyCloud only
- Infostealer Exposure (sev 20+)
- Plaintext Password Exposure
- Sensitive PII (SSN, bank, tax)
- Session Cookie/Token Theft
- Device Re-infection
- Multi-Domain Credential Reuse
- High-Sighting Credential
- Password Reuse Across Critical Systems

**Category 2: Identity Provider Correlation (8 rules)** — SpyCloud + IdP
- Exposed Credential + Entra Sign-In (within 24h)
- Exposed Credential + Entra Risky Sign-In
- Exposed Credential + Impossible Travel
- Exposed Credential + MFA Registration Change
- Exposed Credential + Okta Sign-In
- Exposed Credential + Duo Auth
- Exposed Credential + Ping Auth
- Exposed Credential + AWS/GCP Console Sign-In

**Category 3: Endpoint Correlation (6 rules)** — SpyCloud + MDE/Defender
- Infected Device Still Active in MDE
- Infected Device + Defender Alert
- BYOD/Unmanaged Device Infection
- Compass Application Exposure + VPN/SSO Match
- Device Re-infection After Remediation
- Infected IP in Firewall Logs

**Category 4: Email & Collaboration (4 rules)** — SpyCloud + M365
- Exposed User + Suspicious Mailbox Rule
- Exposed User + OAuth App Consent
- Exposed User + eDiscovery/Content Search
- Exposed User + SharePoint Mass Download

**Category 5: UEBA & Behavioral (4 rules)** — SpyCloud + UEBA
- Exposed User + UEBA Anomaly Score Spike
- Exposed User + First-Time Resource Access
- Exposed User + Rare Application Usage
- Exposed User + Anomalous Token Activity

**Category 6: Network & Infrastructure (4 rules)** — SpyCloud + Firewall/DNS
- Infected IP via Fortinet/PAN-OS/Cisco
- Infected Host DNS to Malware C2
- Exposed User VPN from New Location
- Infected Device IP in Allow Rules

**Category 7: Admin & Privilege (4 rules)** — SpyCloud + Entra
- Exposed User + Admin Role Grant
- Exposed User + Self-Service Password Change
- Executive/VIP Account Exposure
- Service Account Credential Exposure

**Category 8: SLA & Operations (4 rules)** — SpyCloud internal
- Stale Credential Without Remediation (>24h, >72h, >7d)
- Credential Volume Spike (anomaly detection)
- First-Time Domain Exposure
- Data Ingestion Health Alert

**Category 9: Multi-Product Fusion (4 rules)** — Multiple SpyCloud products
- Enterprise + Compass: Full Infection Blast Radius
- Enterprise + SIP: Credential + Cookie Double Exposure
- Enterprise + Exposure: Exposure Spike + New Breach
- Compass + SIP: Device Infection with Active Sessions

---

## 7. BUILD ROADMAP — Phased Approach

### Phase 1: Fix What's Broken (This Week) ← WE ARE HERE
- [x] v12.5: Remove enable Dropdowns
- [x] v12.6: Branding overhaul
- [x] v12.7: connectorDefinitionName fix
- [x] v12.8: Icons everywhere
- [x] v12.9: Remove <img>, EntityAnalytics ETag
- [ ] v12.10: Content Package dependencies (all 38 rules + 16 queries + workbook)
- [ ] v12.10: monitoredDomain fix (optional, condition on key + domain)
- [ ] v12.10: Content-template the workbook
- [ ] v12.10: Content-template hunting queries

### Phase 2: Function App + Key Vault (Next Sprint)
- [ ] Create Azure Function App with enrichment endpoints
- [ ] Create Key Vault for centralized API key storage
- [ ] Migrate enrichment Logic Apps to call Function App instead of direct HTTP
- [ ] Add Function App ARM resources to template
- [ ] Update createUiDefinition to remove duplicate key fields
- [ ] Test end-to-end with Function App backend

### Phase 3: Multiple Workbooks + Additional Rules (Following Sprint)
- [ ] Build SOC Operational Dashboard workbook
- [ ] Build Executive Risk Dashboard workbook
- [ ] Build Compass/SIP Deep Dive workbook (optional)
- [ ] Add 22+ new cross-connector correlation rules
- [ ] Add UEBA fusion rules
- [ ] Content-template ALL new workbooks and rules

### Phase 4: Marketplace Submission
- [ ] Submit PR to Azure/Azure-Sentinel GitHub repository
- [ ] Create Partner Center offer
- [ ] Submit for certification
- [ ] Address certification feedback
- [ ] Go live in Azure Marketplace + Content Hub

### Phase 5: Ongoing Maintenance
- [ ] Version bump process documented
- [ ] CI/CD pipeline for automated package building
- [ ] Automated testing for ARM template validation
- [ ] Customer feedback integration
- [ ] New rule development for emerging threat patterns
