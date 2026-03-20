![SpyCloud](https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/spycloud-wordmark-200.png)

# SpyCloud Sentinel Supreme

**The most comprehensive darknet identity threat intelligence integration for Microsoft Sentinel.**

SpyCloud recaptures stolen credentials, session cookies, and infected device data from the criminal underground — hours after exposure, not weeks after disclosure. This solution turns that intelligence into automated detection, enrichment, and response across your entire security stack.

![Architecture](https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/architecture-overview.svg)

---

## What You Get

| Component | Count | Description |
|-----------|-------|-------------|
| **Data Connector** | 13 pollers | CCF-based ingestion across 8 SpyCloud products into 15 custom tables |
| **Analytics Rules** | 38 templates | Credential exposure, infostealer, cross-platform (MDE, Entra, M365, IdPs, firewalls, UEBA) |
| **Hunting Queries** | 16 queries | Proactive threat hunting across all SpyCloud tables |
| **Playbooks** | 13 Logic Apps | MDE isolation, CA password reset, enrichment (email/domain/IP/device/cookies), investigation |
| **Azure Function App** | 17 endpoints | Identity Risk Score (0-100), enrichment, investigation, reporting |
| **Key Vault** | 4+ secrets | Centralized API keys with managed identity |
| **Workbook** | Dashboard | SOC operational: exposure trends, severity, remediation tracking |
| **Watchlists** | 4 lists | VIP, exclusions, severity mapping, domains |
| **Automation Rules** | 4 rules | Auto-trigger enrichment on incidents |
| **Security Copilot** | 28+ skills | KQL investigation + AI agent + 5 promptbooks |
| **MCP Server** | Full API | External tool integration, SCORCH orchestration |
| **Content Package** | 56 deps | One-click install + updatable via Content Hub |

---

## Identity Risk Score — The Innovation

A composite metric (0-100) per user combining:

| Component | Weight | Measures |
|-----------|--------|---------|
| **Severity** | 0-30 | Exposure count x type (breach vs infostealer vs cookies) |
| **Credential** | 0-25 | Plaintext? Weak hash? Password reuse across domains? |
| **Session** | 0-25 | Stolen cookies? Still valid? SSO/VPN/admin portals? |
| **Device** | 0-10 | Infected devices, re-infections, unmanaged BYOD |
| **Temporal** | 0.2-1.0x | Recent = full weight. Decays naturally over time. |
| **Remediation** | -20 to 0 | Reset (-10), revoke (-5), disable (-15). Actions reduce score. |

**Tiers:** LOW (0-20) → MODERATE (21-40) → HIGH (41-60) → CRITICAL (61-80) → EMERGENCY (81-100)

**The Closed Loop:** Risk Score → Entra ID custom attribute → Conditional Access policy → automated remediation → score decreases → access restored. No analyst required.

---

## Quick Start

### Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

### Steps
1. **Deploy** — Click button above, enter Enterprise API key, configure playbooks
2. **Connect** — Data Connectors → SpyCloud → enter API keys → Connect
3. **Enable Rules** — Analytics → Rule Templates → filter "SpyCloud" → enable
4. **Authorize** — Entra ID → Enterprise Apps → grant consent to Logic App identities
5. **Deploy Function** — `func azure functionapp publish <name> --python`
6. **Verify** — `SpyCloudBreachWatchlist_CL | take 10`

### Prerequisites
- SpyCloud Enterprise API key ([portal.spycloud.com](https://portal.spycloud.com))
- Sentinel Contributor + Log Analytics Contributor
- Outbound HTTPS to api.spycloud.io
- Optional: MDE P2 (device isolation), Entra P1+ (password reset)

---

## Cost Estimation

| Org Size | Employees | Daily Ingestion | Monthly Cost |
|----------|-----------|-----------------|-------------|
| Small | <1K | 1-10 MB | $5-30 |
| Medium | 1K-10K | 10-100 MB | $30-300 |
| Large | 10K-50K | 100-500 MB | $300-1,500 |
| Enterprise | 50K+ | 500+ MB | $1,500+ |

Function App (Consumption) is virtually free. Key Vault ~$0.03/month. Primary cost is Log Analytics ingestion.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/images/architecture-overview.svg) | Visual architecture diagram |
| [API Coverage & Integration](docs/API-COVERAGE-AND-INTEGRATION-ARCHITECTURE.md) | Full API endpoint mapping |
| [Cross-Ecosystem Integration Map](docs/CROSS-ECOSYSTEM-INTEGRATION-MAP-v12.10.md) | 100+ integrations across all vendors |
| [ISV & Marketplace Strategy](docs/ISV-MARKETPLACE-STRATEGY-v12.10.md) | Publishing, updates, certification |
| [Product Catalog](docs/PRODUCT-CATALOG-v12.md) | All 8 SpyCloud products with use cases |
| [Enrichment Architecture](docs/ENRICHMENT-ARCHITECTURE-v12.md) | Playbook design and API flow |
| [Production Readiness](docs/PRODUCTION-READINESS-v12.10.md) | Deployment validation checklist |
| [Security Copilot Guide](docs/SECURITY-COPILOT-SPEC.md) | Plugin + agent setup |
| [Agents & Plugins](docs/AGENTS-AND-PLUGINS-GUIDE.md) | SCORCH agent, promptbooks |
| [Permissions & Playbooks](docs/PERMISSIONS-AND-PLAYBOOKS.md) | Required roles and consent |
| [Roadmap](docs/ROADMAP.md) | Development roadmap |

---

## Support

| Resource | Link |
|----------|------|
| SpyCloud Portal | [portal.spycloud.com](https://portal.spycloud.com) |
| API Docs | [docs.spycloud.com](https://docs.spycloud.com) |
| Support | [support@spycloud.com](mailto:support@spycloud.com) |
| Integration Help | [integrations@spycloud.com](mailto:integrations@spycloud.com) |
| GitHub Issues | [Issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues) |

---

*Copyright 2026 SpyCloud, Inc. Requires active SpyCloud API subscription.*
