# Testing SpyCloud Portal SPA

## Overview
The SpyCloud Portal is a static HTML/CSS/JS single-page application located at `portal/index.html`. It has no backend dependencies — all content is rendered client-side via JavaScript. It can be tested by opening the file directly in a browser.

## How to Open
```bash
# Open in Chrome from local filesystem
google-chrome file:///home/ubuntu/repos/SPYCLOUD-SENTINEL/portal/index.html
```

Or navigate to `file:///home/ubuntu/repos/SPYCLOUD-SENTINEL/portal/index.html` in the browser address bar.

## Portal Structure
- **portal/index.html** — Main HTML with sidebar navigation (17 pages), header, and page containers
- **portal/styles.css** — CSS with SpyCloud branding, dark theme, responsive layout (~287 lines)
- **portal/app.js** — JavaScript for interactivity and dynamic content rendering (~545 lines)

## Pages to Test (17 total)
All pages are navigated via sidebar clicks which call `showPage(pageId)`:

| Category | Page | Key Content |
|----------|------|-------------|
| Overview | Dashboard | Stats cards (38/23/3/3/11/7/26), Content Hub table, Infrastructure table |
| Overview | Architecture | SVG diagrams (Overview + Data Flow), tab switching |
| Content Hub | Analytics Rules | 38 rule cards with search/filter, severity tags, MITRE tactics |
| Content Hub | Playbooks | 23 playbook cards with category tags |
| Content Hub | Workbooks | 3 workbook descriptions |
| Content Hub | Data Connector | Connector config details, 7 API products |
| Content Hub | Notebooks | 3 notebook descriptions |
| Deployment | Deploy Guide | 10-step deployment checklist |
| Deployment | Post-Deploy Config | 11-phase post-deploy checklist |
| Toolkit | Health Check | 12-item health checklist with checkboxes |
| Toolkit | Simulation & QA | 6 test scenarios with validation steps, ISV readiness checklist |
| Toolkit | API Testing | 7 API endpoints table with Test buttons showing curl commands |
| Intelligence | Copilot & Agents | SCORCH agent, Security Copilot, MCP tools |
| Intelligence | Graph Analysis | 6-step graph setup guide |
| Intelligence | Purview | Compliance integration guide |
| Documentation | Use Cases | 6 use case cards (Enterprise, MSSP, Government, etc.) |
| Documentation | Troubleshooting | 10 accordion items with expand/collapse |

## Interactive Features to Verify
1. **Navigation** — Click sidebar items → page switches, sidebar highlight updates, scrolls to top
2. **Search/Filter** — Type in search box on Analytics Rules page → `filterRules()` hides non-matching cards
3. **Tab switching** — Architecture page has Overview/Data Flow/Deployment Paths tabs via `showTab()`
4. **Accordion toggle** — Troubleshooting page items expand/collapse on click
5. **API Test buttons** — Click "Test" on API Testing page → `showApiTest()` shows curl command below table
6. **SVG rendering** — Architecture page renders two SVG diagrams via `drawArchOverview()` and `drawArchDataflow()`
7. **Health check checkboxes** — Can be toggled on Health Check page

## Key Assertions
- Dashboard shows exactly: 38 Analytics Rules, 23 Playbooks, 3 Workbooks, 3 Notebooks, 11 Custom Log Tables, 7 SpyCloud API Products, 26 SCORCH Sub-Agents
- Analytics Rules page renders exactly 38 rule cards (check `document.querySelectorAll('.rule-card').length`)
- Playbooks page renders exactly 23 cards (check `document.querySelectorAll('#playbooks-grid .card').length`)
- Browser console has zero JavaScript errors (TypeError, ReferenceError, SyntaxError)
- SpyCloud logo loads from GitHub raw URL (may show broken image if offline)
- Header shows "SpyCloud Identity Exposure Intelligence for Sentinel" with "v2.0.0" badge

## External Dependencies
- **Google Fonts** (Inter, JetBrains Mono) — loaded from fonts.googleapis.com
- **SpyCloud logo** — loaded from raw.githubusercontent.com (GitHub-hosted PNG)
- No API calls, no backend, no npm packages

## Known Limitations
- The `browser_console` tool may report "Chrome is not in the foreground" even when Chrome is visible. Use DevTools (F12 → Console tab) as a workaround to visually inspect for JS errors.
- External images (SpyCloud logo) may not load if network is restricted — this causes broken image icons but no JS errors.
- The portal is designed for dark theme by default. Light mode CSS variables exist but there's no toggle button in the UI.

## Devin Secrets Needed
None — the portal is fully static and requires no credentials or API keys to test.
