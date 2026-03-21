/* SpyCloud Identity Exposure Intelligence for Sentinel — Portal App */

// ─── Navigation ───────────────────────────────────────────────
function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(s => s.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  if (page) page.classList.add('active');
  const item = document.querySelector(`.sidebar-item[data-page="${pageId}"]`);
  if (item) item.classList.add('active');
  window.scrollTo(0, 0);
}

function showTab(el, tabId) {
  const parent = el.closest('.page') || document;
  parent.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  parent.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  const content = document.getElementById(tabId);
  if (content) content.classList.add('active');
}

function showCloudShellInstructions() {
  const el = document.getElementById('cloudshell-instructions');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function toast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + (type || 'info') + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ─── Analytics Rules Data ─────────────────────────────────────
const analyticsRules = [
  { id: 1, name: 'Infostealer Exposure Detected', severity: 'High', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1555', 'T1078'], desc: 'Detects credentials stolen by infostealer malware (severity 20+). Requires immediate device investigation and credential reset.' },
  { id: 2, name: 'Breach Watchlist — New Exposure', severity: 'Medium', tactics: ['CredentialAccess'], techniques: ['T1589'], desc: 'New breach exposure found for monitored domain in SpyCloud watchlist data.' },
  { id: 3, name: 'Breach Watchlist — High Severity', severity: 'High', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1078'], desc: 'High-severity breach exposure (severity 20+) detected for monitored domain.' },
  { id: 4, name: 'Breach Watchlist — Password Plaintext', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1555.003'], desc: 'Plaintext password found in breach data for monitored domain user.' },
  { id: 5, name: 'Breach Catalog — New Source', severity: 'Informational', tactics: ['Reconnaissance'], techniques: ['T1589'], desc: 'New breach source added to SpyCloud catalog that may affect monitored domains.' },
  { id: 6, name: 'Compass — Active Infection', severity: 'High', tactics: ['CredentialAccess', 'Collection'], techniques: ['T1555', 'T1539'], desc: 'Active infostealer infection detected via Compass data with stolen credentials and cookies.' },
  { id: 7, name: 'Compass — Cookie Theft', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1539'], desc: 'Session cookies stolen by infostealer malware, enabling session hijacking.' },
  { id: 8, name: 'Compass — Multiple Devices', severity: 'High', tactics: ['LateralMovement'], techniques: ['T1078'], desc: 'Same user credentials found on multiple infected devices, indicating lateral spread.' },
  { id: 9, name: 'SIP — Stolen Session Token', severity: 'High', tactics: ['CredentialAccess', 'DefenseEvasion'], techniques: ['T1539', 'T1550'], desc: 'Stolen session cookie/token detected that could bypass MFA.' },
  { id: 10, name: 'SIP — Corporate SSO Cookie', severity: 'Critical', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1539', 'T1078'], desc: 'Corporate SSO session cookie stolen, providing access to multiple applications.' },
  { id: 11, name: 'Identity Link — Cross-Account Correlation', severity: 'Medium', tactics: ['Reconnaissance'], techniques: ['T1589.001'], desc: 'Multiple accounts linked to same identity across different breach sources.' },
  { id: 12, name: 'Identity Link — Credential Reuse', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1078'], desc: 'Password reuse detected across multiple accounts for the same identity.' },
  { id: 13, name: 'MDE — Compromised Device Found', severity: 'High', tactics: ['Execution', 'CredentialAccess'], techniques: ['T1204', 'T1555'], desc: 'Device with SpyCloud exposure data matches MDE device inventory.' },
  { id: 14, name: 'MDE — Infostealer on Managed Device', severity: 'Critical', tactics: ['Execution', 'CredentialAccess'], techniques: ['T1204', 'T1555'], desc: 'Infostealer infection confirmed on MDE-managed device. Immediate isolation recommended.' },
  { id: 15, name: 'Conditional Access — Policy Trigger', severity: 'Medium', tactics: ['DefenseEvasion'], techniques: ['T1556'], desc: 'SpyCloud exposure triggered Conditional Access policy enforcement.' },
  { id: 16, name: 'Conditional Access — Block Enforced', severity: 'High', tactics: ['DefenseEvasion', 'InitialAccess'], techniques: ['T1556', 'T1078'], desc: 'User blocked by Conditional Access due to high SpyCloud exposure severity.' },
  { id: 17, name: 'CAP — New Assessment Results', severity: 'Medium', tactics: ['CredentialAccess'], techniques: ['T1589'], desc: 'New Credential Assessment Program results received from SpyCloud.' },
  { id: 18, name: 'CAP — Critical Exposure Score', severity: 'Critical', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1078'], desc: 'User with critical CAP exposure score (90+) detected.' },
  { id: 19, name: 'Data Partnership — New Records', severity: 'Low', tactics: ['Reconnaissance'], techniques: ['T1589'], desc: 'New records ingested from SpyCloud data partnership feeds.' },
  { id: 20, name: 'Exposure — VIP Account Compromised', severity: 'Critical', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1078'], desc: 'VIP/executive account found in SpyCloud exposure data.' },
  { id: 21, name: 'Exposure — Admin Account Compromised', severity: 'Critical', tactics: ['CredentialAccess', 'PrivilegeEscalation'], techniques: ['T1078.002'], desc: 'Administrative account credentials found in breach data.' },
  { id: 22, name: 'Exposure — Service Account Compromised', severity: 'Critical', tactics: ['CredentialAccess', 'Persistence'], techniques: ['T1078.001'], desc: 'Service account credentials exposed in darknet data.' },
  { id: 23, name: 'Exposure — Bulk Credential Dump', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1589.001'], desc: '50+ credentials from same domain exposed in single breach source.' },
  { id: 24, name: 'Exposure — Recurring Compromise', severity: 'High', tactics: ['CredentialAccess', 'Persistence'], techniques: ['T1078'], desc: 'User has been compromised in 3+ separate breaches within 90 days.' },
  { id: 25, name: 'Investigation — Darknet Mention', severity: 'Medium', tactics: ['Reconnaissance'], techniques: ['T1593'], desc: 'Organization or domain mentioned in darknet investigation data.' },
  { id: 26, name: 'Investigation — Ransomware Indicator', severity: 'Critical', tactics: ['Impact'], techniques: ['T1486'], desc: 'Ransomware group associated with breach affecting monitored domain.' },
  { id: 27, name: 'Investigation — APT Indicator', severity: 'Critical', tactics: ['InitialAccess', 'Persistence'], techniques: ['T1078'], desc: 'Advanced persistent threat group linked to exposure data.' },
  { id: 28, name: 'Malware — New Family Detected', severity: 'High', tactics: ['Execution'], techniques: ['T1204'], desc: 'Previously unseen malware family detected in infostealer logs.' },
  { id: 29, name: 'Malware — Credential Harvester', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1555'], desc: 'Active credential harvesting malware detected on user device.' },
  { id: 30, name: 'Malware — Banking Trojan', severity: 'Critical', tactics: ['CredentialAccess', 'Collection'], techniques: ['T1555', 'T1185'], desc: 'Banking trojan detected stealing financial credentials and session data.' },
  { id: 31, name: 'Risk Score — Threshold Exceeded', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1078'], desc: 'User risk score exceeded configurable threshold based on combined exposure metrics.' },
  { id: 32, name: 'Risk Score — Rapid Increase', severity: 'High', tactics: ['CredentialAccess', 'InitialAccess'], techniques: ['T1078'], desc: 'User risk score increased by 30+ points in 24 hours.' },
  { id: 33, name: 'Remediation — Incomplete Reset', severity: 'Medium', tactics: ['Persistence'], techniques: ['T1078'], desc: 'Password reset initiated but not completed within SLA window.' },
  { id: 34, name: 'Remediation — Re-exposure After Reset', severity: 'High', tactics: ['CredentialAccess'], techniques: ['T1078'], desc: 'User re-exposed in breach data after password reset was completed.' },
  { id: 35, name: 'Domain — New Subdomain Exposed', severity: 'Low', tactics: ['Reconnaissance'], techniques: ['T1589'], desc: 'Previously unseen subdomain appeared in SpyCloud exposure data.' },
  { id: 36, name: 'Domain — Typosquat Detection', severity: 'Medium', tactics: ['Reconnaissance', 'InitialAccess'], techniques: ['T1583'], desc: 'Potential typosquatting domain detected in breach data targeting monitored domain.' },
  { id: 37, name: 'Compliance — PII Exposure', severity: 'High', tactics: ['Collection'], techniques: ['T1530'], desc: 'Personally identifiable information (PII) found in breach exposure requiring compliance notification.' },
  { id: 38, name: 'Compliance — Regulatory Threshold', severity: 'Critical', tactics: ['Collection'], techniques: ['T1530'], desc: 'Exposure count exceeds regulatory notification threshold (GDPR/CCPA/HIPAA).' }
];

function renderAnalyticsRules() {
  const container = document.getElementById('rules-list');
  if (!container) return;
  container.innerHTML = analyticsRules.map(r => {
    const sevClass = { Critical: 'tag-red', High: 'tag-orange', Medium: 'tag-blue', Low: 'tag-green', Informational: 'tag-green' }[r.severity] || 'tag-blue';
    return `<div class="card rule-card" data-name="${r.name.toLowerCase()}">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
        <span class="tag ${sevClass}">${r.severity}</span>
        <strong style="font-size:15px;">${r.name}</strong>
        <span style="font-size:12px;color:var(--sc-gray);margin-left:auto;">Rule #${r.id}</span>
      </div>
      <p style="font-size:14px;margin-bottom:8px;">${r.desc}</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${r.tactics.map(t => `<span class="tag tag-blue">${t}</span>`).join('')}
        ${r.techniques.map(t => `<span class="tag tag-green">${t}</span>`).join('')}
      </div>
    </div>`;
  }).join('');
}

function filterRules(query) {
  const q = query.toLowerCase();
  document.querySelectorAll('.rule-card').forEach(c => {
    c.style.display = c.dataset.name.includes(q) ? 'block' : 'none';
  });
}

// ─── Playbooks Data ───────────────────────────────────────────
const playbooks = [
  { name: 'Enrich Incident', icon: '&#128269;', category: 'Enrichment', desc: 'Enriches Sentinel incidents with SpyCloud breach data including exposure count, severity scores, and malware indicators.' },
  { name: 'Force Password Reset', icon: '&#128274;', category: 'Remediation', desc: 'Forces password reset via Azure AD for compromised accounts detected by SpyCloud.' },
  { name: 'Disable Account', icon: '&#128683;', category: 'Remediation', desc: 'Disables compromised Azure AD accounts to prevent unauthorized access.' },
  { name: 'Isolate Device', icon: '&#128421;', category: 'Remediation', desc: 'Isolates infected devices via MDE when infostealer malware is detected.' },
  { name: 'Revoke Sessions', icon: '&#128260;', category: 'Remediation', desc: 'Revokes all active sessions and refresh tokens for compromised users.' },
  { name: 'Enforce MFA', icon: '&#128272;', category: 'Remediation', desc: 'Enforces MFA registration and re-authentication for exposed accounts.' },
  { name: 'Full Remediation', icon: '&#9889;', category: 'Orchestration', desc: 'Orchestrates complete remediation: password reset + session revoke + MFA enforce + device isolate.' },
  { name: 'Block Conditional Access', icon: '&#128219;', category: 'Remediation', desc: 'Creates Conditional Access policies to block compromised users from signing in.' },
  { name: 'Block Firewall', icon: '&#128737;', category: 'Remediation', desc: 'Blocks malicious IPs on network firewall based on SpyCloud threat data.' },
  { name: 'Add to Security Group', icon: '&#128101;', category: 'Remediation', desc: 'Adds compromised users to a security group for targeted policy enforcement.' },
  { name: 'Remove Mailbox Rules', icon: '&#128231;', category: 'Remediation', desc: 'Removes suspicious mailbox forwarding rules created by attackers.' },
  { name: 'Revoke OAuth Consent', icon: '&#128275;', category: 'Remediation', desc: 'Revokes OAuth app consents that may have been granted by compromised users.' },
  { name: 'CAP Response', icon: '&#128202;', category: 'Assessment', desc: 'Processes Credential Assessment Program results and triggers appropriate remediation.' },
  { name: 'Exposure Assessment', icon: '&#128200;', category: 'Assessment', desc: 'Runs comprehensive exposure assessment across all SpyCloud data products.' },
  { name: 'IDLINK Correlation', icon: '&#128279;', category: 'Investigation', desc: 'Correlates identities across breach sources using SpyCloud IDLINK data.' },
  { name: 'Investigations Lookup', icon: '&#128270;', category: 'Investigation', desc: 'Deep investigation lookup against SpyCloud darknet intelligence database.' },
  { name: 'Notify SOC', icon: '&#128276;', category: 'Notification', desc: 'Sends enriched alert notifications to SOC team via Teams/email.' },
  { name: 'Notify User', icon: '&#128172;', category: 'Notification', desc: 'Notifies affected users about credential compromise with remediation instructions.' },
  { name: 'Email Notify', icon: '&#128233;', category: 'Notification', desc: 'Sends customizable email notifications for SpyCloud incidents.' },
  { name: 'Slack Notify', icon: '&#128172;', category: 'Notification', desc: 'Posts enriched incident summaries to Slack channels.' },
  { name: 'Webhook Notify', icon: '&#128268;', category: 'Notification', desc: 'Sends incident data to configurable webhook endpoints.' },
  { name: 'Jira Ticket', icon: '&#127915;', category: 'Ticketing', desc: 'Creates Jira tickets for SpyCloud incidents with full breach context.' },
  { name: 'ServiceNow Incident', icon: '&#127919;', category: 'Ticketing', desc: 'Creates ServiceNow incidents for SpyCloud findings with enrichment data.' }
];

function renderPlaybooks() {
  const container = document.getElementById('playbooks-grid');
  if (!container) return;
  const catColors = { Enrichment: 'tag-blue', Remediation: 'tag-red', Orchestration: 'tag-orange', Assessment: 'tag-green', Investigation: 'tag-blue', Notification: 'tag-green', Ticketing: 'tag-orange' };
  container.innerHTML = playbooks.map(p => `<div class="card">
    <div style="font-size:32px;margin-bottom:8px;">${p.icon}</div>
    <div class="card-title" style="font-size:16px;">${p.name}</div>
    <span class="tag ${catColors[p.category] || 'tag-blue'}" style="margin-bottom:8px;">${p.category}</span>
    <p style="font-size:13px;margin-top:8px;">${p.desc}</p>
  </div>`).join('');
}

// ─── Deploy Steps ─────────────────────────────────────────────
const deploySteps = [
  { title: 'Prerequisites Check', desc: 'Verify Azure subscription, Sentinel workspace, and SpyCloud API access.' },
  { title: 'Click Deploy to Azure', desc: 'Use the Deploy to Azure button to launch the ARM template deployment wizard.' },
  { title: 'Configure Basic Settings', desc: 'Select subscription, resource group, and region. Enter workspace name.' },
  { title: 'Enter SpyCloud Configuration', desc: 'Provide SpyCloud API key, monitored domains, and severity threshold.' },
  { title: 'Configure Function App', desc: 'Set polling interval, batch size, and enabled API products.' },
  { title: 'Review and Deploy', desc: 'Review all settings and click Create to begin deployment (takes 10-15 minutes).' },
  { title: 'Run Post-Deploy Script', desc: 'Execute scripts/post-deploy.sh to configure RBAC, API connections, and permissions.' },
  { title: 'Verify in Sentinel', desc: 'Open Sentinel, check Content Hub for installed solution, verify data connector status.' },
  { title: 'Enable Analytics Rules', desc: 'Go to Analytics > Rule Templates, find SpyCloud rules, and enable desired rules.' },
  { title: 'Configure Playbooks', desc: 'Authorize Logic App API connections and create automation rules to trigger playbooks.' }
];

function renderDeploySteps() {
  const container = document.getElementById('deploy-steps');
  if (!container) return;
  container.innerHTML = deploySteps.map((s, i) => `<div class="checklist-item">
    <div class="check-box" onclick="this.classList.toggle('checked')"></div>
    <div class="check-text">
      <div class="check-title">Step ${i + 1}: ${s.title}</div>
      <div class="check-desc">${s.desc}</div>
    </div>
  </div>`).join('');
}

// ─── Post-Deploy Phases ───────────────────────────────────────
const postDeployPhases = [
  { phase: 1, title: 'Azure Authentication & Resource Discovery', desc: 'Authenticates to Azure and discovers all deployed resources (Function App, Key Vault, Logic Apps, workspace).' },
  { phase: 2, title: 'Resolve DCE Logs Ingestion URI', desc: 'Retrieves the Data Collection Endpoint URI for log ingestion configuration.' },
  { phase: 3, title: 'Resolve DCR Immutable ID', desc: 'Gets the Data Collection Rule immutable ID needed for data routing.' },
  { phase: 4, title: 'RBAC — Monitoring Metrics Publisher on DCR', desc: 'Grants Logic Apps the Monitoring Metrics Publisher role on the DCR for data ingestion.' },
  { phase: 5, title: 'RBAC — Function App Permissions', desc: 'Grants the Function App managed identity Key Vault Secrets User role for secret access.' },
  { phase: 6, title: 'RBAC — Deploying User Permissions', desc: 'Grants the deploying user Website Contributor on Function App and Key Vault Secrets User.' },
  { phase: 7, title: 'MDE API Permissions', desc: 'Configures Microsoft Defender for Endpoint API permissions for device correlation.' },
  { phase: 8, title: 'Graph API Permissions', desc: 'Sets up Microsoft Graph API permissions for user management and directory operations.' },
  { phase: 9, title: 'Logic App API Connection Consent', desc: 'Authorizes all Logic App API connections (Sentinel, Office 365, Teams).' },
  { phase: 10, title: 'Admin Consent for Managed Identities', desc: 'Grants admin consent for all managed identity API permissions.' },
  { phase: 11, title: 'Deployment Verification & Health Check', desc: 'Validates all 11 custom tables, checks Function App health, verifies Logic App states, and generates report.' }
];

function renderPostDeployPhases() {
  const container = document.getElementById('postdeploy-phases');
  if (!container) return;
  container.innerHTML = postDeployPhases.map(p => `<div class="checklist-item">
    <div class="check-box" onclick="this.classList.toggle('checked')"></div>
    <div class="check-text">
      <div class="check-title">Phase ${p.phase}: ${p.title}</div>
      <div class="check-desc">${p.desc}</div>
    </div>
  </div>`).join('');
}

// ─── Health Checklist ─────────────────────────────────────────
const healthChecks = [
  { title: 'Function App Running', desc: 'Verify spycloud-fn-* Function App is in Running state' },
  { title: 'Key Vault Accessible', desc: 'Verify Function App can read secrets from Key Vault (RBAC check)' },
  { title: 'SpyCloud API Key Valid', desc: 'Test API key by calling /breach/catalog endpoint' },
  { title: 'Custom Tables Created', desc: 'Verify all 11 SpyCloud custom log tables exist in workspace' },
  { title: 'Data Collection Endpoint Active', desc: 'Check DCE is in provisioned/active state' },
  { title: 'Data Collection Rules Configured', desc: 'Verify DCR routes data to correct tables' },
  { title: 'Logic Apps Enabled', desc: 'Check all SpyCloud Logic Apps are in Enabled state' },
  { title: 'API Connections Authorized', desc: 'Verify Sentinel, O365, and Teams API connections are authorized' },
  { title: 'Analytics Rules Active', desc: 'Confirm desired analytics rules are enabled and running' },
  { title: 'Data Ingestion Flowing', desc: 'Query tables to verify recent data (last 24h)' },
  { title: 'Automation Rules Configured', desc: 'Verify automation rules trigger correct playbooks on incidents' },
  { title: 'RBAC Permissions Set', desc: 'Verify all role assignments (Function App, Logic Apps, DCR) are correct' }
];

function renderHealthChecklist() {
  const container = document.getElementById('health-checklist');
  if (!container) return;
  container.innerHTML = healthChecks.map(h => `<div class="checklist-item">
    <div class="check-box" onclick="this.classList.toggle('checked')"></div>
    <div class="check-text">
      <div class="check-title">${h.title}</div>
      <div class="check-desc">${h.desc}</div>
    </div>
  </div>`).join('');
}

// ─── Simulation Scenarios ─────────────────────────────────────
const scenarios = [
  { title: 'Infostealer Infection', severity: 'Critical', desc: 'Simulates an infostealer malware infection that exfiltrates credentials, cookies, and session tokens from a corporate device. Tests: detection rules, device isolation, password reset, session revocation.', steps: ['Inject test record into SpyCloudBreachWatchlist_CL with infected_machine_id', 'Verify analytics rule fires within query frequency window', 'Confirm incident created with correct entity mappings', 'Verify automation rule triggers Full Remediation playbook', 'Check device isolation command sent to MDE', 'Validate password reset executed in Azure AD'] },
  { title: 'Bulk Credential Dump', severity: 'High', desc: 'Simulates discovery of 100+ corporate credentials in a new breach source. Tests: bulk detection, SOC notification, executive reporting.', steps: ['Insert 100+ test records for same domain into SpyCloudBreachWatchlist_CL', 'Verify "Bulk Credential Dump" analytics rule fires', 'Confirm SOC notification playbook triggers', 'Check executive report generation'] },
  { title: 'VIP Account Compromise', severity: 'Critical', desc: 'Simulates compromise of C-suite executive account. Tests: VIP detection, escalated response, compliance notification.', steps: ['Insert test record with VIP account email', 'Verify "VIP Account Compromised" rule fires with Critical severity', 'Confirm escalated notification to CISO', 'Verify Purview compliance assessment triggers'] },
  { title: 'Session Hijacking via Cookie Theft', severity: 'High', desc: 'Simulates stolen SSO session cookie enabling MFA bypass. Tests: cookie detection, session revocation, CA policy enforcement.', steps: ['Insert test record into SpyCloudSipCookies_CL with corporate SSO domain', 'Verify "Corporate SSO Cookie" rule fires', 'Confirm session revocation playbook triggers', 'Verify Conditional Access block policy created'] },
  { title: 'Ransomware Indicator', severity: 'Critical', desc: 'Simulates association with known ransomware group in investigation data. Tests: ransomware detection, full incident response, executive notification.', steps: ['Insert test record into SpyCloudInvestigations_CL with ransomware indicators', 'Verify "Ransomware Indicator" rule fires', 'Confirm full remediation orchestration', 'Verify executive report generation with ransomware context'] },
  { title: 'Compliance Threshold Breach', severity: 'High', desc: 'Simulates exposure count exceeding GDPR/CCPA notification threshold. Tests: compliance detection, Purview integration, notification timeline.', steps: ['Insert records exceeding configured compliance threshold', 'Verify "Regulatory Threshold" rule fires', 'Confirm Purview compliance assessment playbook triggers', 'Verify breach notification timeline generated'] }
];

function renderScenarios() {
  const container = document.getElementById('scenarios-grid');
  if (!container) return;
  const sevColors = { Critical: 'tag-red', High: 'tag-orange', Medium: 'tag-blue' };
  container.innerHTML = scenarios.map(s => `<div class="card">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
      <span class="tag ${sevColors[s.severity]}">${s.severity}</span>
      <strong>${s.title}</strong>
    </div>
    <p style="font-size:13px;margin-bottom:12px;">${s.desc}</p>
    <h4 style="color:var(--sc-accent);font-size:13px;margin-bottom:6px;">Validation Steps:</h4>
    <ol style="font-size:12px;line-height:1.8;padding-left:16px;color:var(--sc-gray);">
      ${s.steps.map(st => `<li>${st}</li>`).join('')}
    </ol>
  </div>`).join('');
}

// ─── ISV Checklist ────────────────────────────────────────────
const isvChecks = [
  { title: 'LICENSE file present at repo root', desc: 'MIT license as declared in package.json' },
  { title: '.gitignore covers all standard patterns', desc: 'Node.js, Python, Azure Functions, .env, local.settings.json' },
  { title: 'Consistent versioning (2.0.0) across all files', desc: 'azuredeploy.json, mainTemplate.json, solutionMetadata.json, createUiDefinition.json, package.json' },
  { title: 'Content Hub dependencies match content IDs', desc: 'solutionMetadata.json contentIds match mainTemplate.json variables' },
  { title: 'All content templates have required metadata', desc: 'packageKind, packageVersion, packageName, packageId on every template' },
  { title: 'SpyCloud branding on all UI surfaces', desc: 'Logos, icons, descriptions consistent across Content Hub, wizard, connectors' },
  { title: 'ARM template validates without errors', desc: 'az deployment group validate passes for both templates' },
  { title: 'createUiDefinition.json wizard works', desc: 'All steps render, parameters pass through, no orphaned outputs' },
  { title: 'Function App requirements.txt present', desc: 'All Python dependencies listed with minimum versions' },
  { title: 'host.json configured for all Function Apps', desc: 'Correct version, logging, and extension settings' },
  { title: 'CI/CD pipeline validates all templates', desc: 'GitHub Actions checks JSON syntax, ARM validation, version consistency' },
  { title: 'Documentation complete and accurate', desc: 'README, setup guide, deployment guide, troubleshooting, use cases' }
];

function renderIsvChecklist() {
  const container = document.getElementById('isv-checklist');
  if (!container) return;
  container.innerHTML = isvChecks.map(c => `<div class="checklist-item">
    <div class="check-box" onclick="this.classList.toggle('checked')"></div>
    <div class="check-text">
      <div class="check-title">${c.title}</div>
      <div class="check-desc">${c.desc}</div>
    </div>
  </div>`).join('');
}

// ─── API Testing ──────────────────────────────────────────────
const apiTests = {
  watchlist: { title: 'Breach Watchlist', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/breach/data/watchlist?domain=yourdomain.com&since=2024-01-01&severity=2"' },
  catalog: { title: 'Breach Catalog', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/breach/catalog?since=2024-01-01"' },
  compass: { title: 'Compass Data', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/compass/data?domain=yourdomain.com&since=2024-01-01"' },
  sip: { title: 'SIP Cookie Data', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/sip/data?domain=yourdomain.com&type=cookie"' },
  investigations: { title: 'Investigations Search', curl: 'curl -s -X POST -H "Authorization: YOUR_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"query":"yourdomain.com","type":"domain"}\' \\\n  "https://api.spycloud.io/enterprise-v2/investigations/search"' },
  idlink: { title: 'Identity Link', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/idlink/data?email=user@yourdomain.com"' },
  enrichment: { title: 'Email Enrichment', curl: 'curl -s -H "Authorization: YOUR_API_KEY" \\\n  "https://api.spycloud.io/enterprise-v2/enrichment/email?email=user@yourdomain.com"' }
};

function showApiTest(endpoint) {
  const test = apiTests[endpoint];
  if (!test) return;
  document.getElementById('api-test-panel').style.display = 'block';
  document.getElementById('api-test-title').textContent = 'Test: ' + test.title;
  document.getElementById('api-test-curl').textContent = test.curl;
}

// ─── Use Cases ────────────────────────────────────────────────
const useCases = [
  { title: 'Enterprise Security Operations', icon: '&#127970;', audience: 'Large Enterprise', desc: 'Full deployment with all analytics rules, playbooks, and AI-powered investigation. Integrated with MDE, Conditional Access, and Purview for comprehensive identity protection.', benefits: ['Automated credential compromise detection and remediation', 'AI-powered executive reporting for CISO', 'Compliance automation (GDPR, CCPA, HIPAA)', 'Identity graph analysis for lateral movement detection'] },
  { title: 'MSSP / Managed SOC', icon: '&#128187;', audience: 'Service Providers', desc: 'Multi-tenant deployment with centralized monitoring, automated triage, and white-label reporting capabilities.', benefits: ['Multi-tenant workspace support', 'Automated incident triage and enrichment', 'White-label executive reports for clients', 'SLA-driven automation with escalation paths'] },
  { title: 'Government / Federal', icon: '&#127963;', audience: 'Government Agencies', desc: 'Azure Government deployment with FedRAMP compliance, enhanced audit logging, and strict RBAC controls.', benefits: ['Azure Government cloud support', 'FedRAMP-aligned security controls', 'Enhanced audit trail and evidence collection', 'CISA threat intelligence correlation'] },
  { title: 'Financial Services', icon: '&#127974;', audience: 'Banking & Finance', desc: 'Focus on account takeover prevention, fraud detection, and regulatory compliance with PCI-DSS and SOX integration.', benefits: ['Account takeover (ATO) prevention', 'Banking trojan detection and response', 'PCI-DSS compliance monitoring', 'Real-time fraud indicator correlation'] },
  { title: 'Healthcare', icon: '&#127973;', audience: 'Healthcare Organizations', desc: 'HIPAA-focused deployment with PHI exposure detection, breach notification automation, and medical device correlation.', benefits: ['HIPAA breach notification automation', 'PHI exposure detection in darknet data', 'Medical device credential monitoring', 'Compliance timeline generation'] },
  { title: 'Incident Response', icon: '&#128680;', audience: 'IR Teams', desc: 'Rapid deployment for active incident response with deep investigation notebooks, identity correlation, and evidence collection.', benefits: ['Rapid darknet exposure assessment', 'Identity correlation across breach sources', 'Jupyter notebook investigation workflows', 'Evidence collection and chain of custody'] }
];

function renderUseCases() {
  const container = document.getElementById('usecases-list');
  if (!container) return;
  container.innerHTML = useCases.map(u => `<div class="card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
      <span style="font-size:36px;">${u.icon}</span>
      <div>
        <div class="card-title" style="margin-bottom:2px;">${u.title}</div>
        <span class="tag tag-blue">${u.audience}</span>
      </div>
    </div>
    <p style="font-size:14px;margin-bottom:12px;">${u.desc}</p>
    <h4 style="color:var(--sc-accent);font-size:13px;margin-bottom:6px;">Key Benefits:</h4>
    <ul style="font-size:13px;line-height:2;padding-left:16px;">
      ${u.benefits.map(b => `<li>${b}</li>`).join('')}
    </ul>
  </div>`).join('');
}

// ─── Troubleshooting ──────────────────────────────────────────
const troubleshootItems = [
  { title: 'Content Hub: "Cannot read properties of undefined (reading \'kind\')"', solution: 'All content templates must have packageKind, packageVersion, packageName, and packageId in their metadata properties. This was fixed in v2.0.0.' },
  { title: 'Function App: Key Vault access denied', solution: 'The Function App managed identity needs "Key Vault Secrets User" role on the Key Vault. Run the post-deploy script (Phase 5) or manually assign via: az role assignment create --assignee-object-id [FN_PRINCIPAL_ID] --role "Key Vault Secrets User" --scope [KV_RESOURCE_ID]' },
  { title: 'Function App: Cannot list host keys', solution: 'Your user account needs "Website Contributor" role on the Function App resource. Run post-deploy script (Phase 6) or assign via Azure Portal > Function App > IAM.' },
  { title: 'Logic App: API connection unauthorized', solution: 'Go to Azure Portal > Logic App > API connections > Edit > Authorize. Or run post-deploy script (Phase 9) for automated consent.' },
  { title: 'Analytics rules: No incidents generated', solution: 'Check: 1) Rules are enabled, 2) Data is flowing to custom tables (query last 24h), 3) Severity threshold matches your data, 4) Query frequency has elapsed since enablement.' },
  { title: 'Data Connector: No data ingested', solution: 'Verify: 1) SpyCloud API key is valid, 2) Function App is running, 3) Key Vault secret reference resolves, 4) DCE/DCR are properly configured, 5) Check Function App logs for errors.' },
  { title: 'Custom tables not created', solution: 'Tables are created by the DCR during first data ingestion. If tables are missing, verify the DCR configuration and trigger a manual Function App run.' },
  { title: 'Playbook: Managed identity permission error', solution: 'Logic App managed identities need appropriate roles. For Sentinel operations: "Microsoft Sentinel Responder". For MDE: "SecurityReader". Run post-deploy script for automated RBAC setup.' },
  { title: 'Deployment fails with template validation error', solution: 'Common causes: 1) Resource provider not registered (Microsoft.Logic, Microsoft.Web), 2) Workspace doesn\'t exist, 3) Region not supported. Check deployment logs in Azure Portal > Deployments.' },
  { title: 'SpyCloud logo not showing in Content Hub', solution: 'Ensure the icon URL in solutionMetadata.json and mainTemplate.json points to: https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/docs/images/SpyCloud-icon-SC_2.png' }
];

function renderTroubleshooting() {
  const container = document.getElementById('troubleshoot-list');
  if (!container) return;
  container.innerHTML = troubleshootItems.map(t => `<div class="accordion" onclick="this.classList.toggle('open')">
    <div class="accordion-header">
      <span>${t.title}</span>
      <span class="accordion-arrow">&#9654;</span>
    </div>
    <div class="accordion-body">
      <p style="font-size:14px;">${t.solution}</p>
    </div>
  </div>`).join('');
}

// ─── Graph Setup Steps ────────────────────────────────────────
const graphSteps = [
  { title: 'Enable Sentinel Custom Graphs (Preview)', desc: 'Navigate to Microsoft Sentinel > Settings > Preview Features and enable "Custom Graphs".' },
  { title: 'Create Graph Definition', desc: 'Define nodes (users, devices, breach sources) and edges (exposed_in, infected_by, linked_to) using KQL materialization.' },
  { title: 'Configure Materialization', desc: 'Set up scheduled materialization to build the graph from SpyCloud custom tables.' },
  { title: 'Install MCP Graph Tools', desc: 'Deploy the MCP server with graph-tools.js for programmatic graph queries.' },
  { title: 'Set Up Workbook Visualization', desc: 'Import the SpyCloud-Graph-Analysis workbook for interactive graph exploration.' },
  { title: 'Configure Notebook Integration', desc: 'Install SpyCloud-Graph-Analysis.ipynb with networkx and pyvis for advanced analysis.' }
];

function renderGraphSteps() {
  const container = document.getElementById('graph-steps');
  if (!container) return;
  container.innerHTML = graphSteps.map((s, i) => `<div class="checklist-item">
    <div class="check-box" onclick="this.classList.toggle('checked')"></div>
    <div class="check-text">
      <div class="check-title">Step ${i + 1}: ${s.title}</div>
      <div class="check-desc">${s.desc}</div>
    </div>
  </div>`).join('');
}

// ─── Architecture Diagrams (SVG) ──────────────────────────────
function drawArchOverview() {
  const svg = document.getElementById('arch-svg-overview');
  if (!svg) return;
  svg.innerHTML = `
    <defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#00b4d8"/>
      </marker>
      <linearGradient id="glow1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#0077b6;stop-opacity:0.3"/>
        <stop offset="100%" style="stop-color:#00b4d8;stop-opacity:0.1"/>
      </linearGradient>
    </defs>

    <!-- SpyCloud APIs box -->
    <rect x="20" y="40" width="180" height="260" rx="12" fill="url(#glow1)" stroke="#00b4d8" stroke-width="2"/>
    <text x="110" y="70" text-anchor="middle" fill="#00b4d8" font-size="14" font-weight="700">SpyCloud APIs</text>
    <text x="40" y="100" fill="#e0e1dd" font-size="11">Breach Watchlist</text>
    <text x="40" y="120" fill="#e0e1dd" font-size="11">Breach Catalog</text>
    <text x="40" y="140" fill="#e0e1dd" font-size="11">Compass (Infostealer)</text>
    <text x="40" y="160" fill="#e0e1dd" font-size="11">SIP (Cookies)</text>
    <text x="40" y="180" fill="#e0e1dd" font-size="11">Investigations</text>
    <text x="40" y="200" fill="#e0e1dd" font-size="11">Identity Links</text>
    <text x="40" y="220" fill="#e0e1dd" font-size="11">Data Partnership</text>
    <text x="40" y="250" fill="#778da9" font-size="10">7 API Products</text>
    <text x="40" y="270" fill="#778da9" font-size="10">Enterprise + Compass</text>

    <!-- Arrow to Function App -->
    <line x1="200" y1="170" x2="280" y2="170" stroke="#00b4d8" stroke-width="2" marker-end="url(#arrow)"/>
    <text x="230" y="160" fill="#778da9" font-size="10">Poll</text>

    <!-- Function App -->
    <rect x="280" y="120" width="160" height="100" rx="10" fill="#1b2838" stroke="#0077b6" stroke-width="2"/>
    <text x="360" y="152" text-anchor="middle" fill="#0077b6" font-size="12" font-weight="700">&#9881; Function App</text>
    <text x="360" y="172" text-anchor="middle" fill="#e0e1dd" font-size="11">Enrichment Engine</text>
    <text x="360" y="192" text-anchor="middle" fill="#778da9" font-size="10">+ AI Engine</text>

    <!-- Arrow to DCE -->
    <line x1="440" y1="170" x2="520" y2="170" stroke="#00b4d8" stroke-width="2" marker-end="url(#arrow)"/>
    <text x="470" y="160" fill="#778da9" font-size="10">Ingest</text>

    <!-- DCE/DCR + Tables -->
    <rect x="520" y="80" width="180" height="180" rx="12" fill="url(#glow1)" stroke="#50e6ff" stroke-width="2"/>
    <text x="610" y="110" text-anchor="middle" fill="#50e6ff" font-size="14" font-weight="700">Log Analytics</text>
    <text x="540" y="135" fill="#e0e1dd" font-size="11">DCE + DCR</text>
    <text x="540" y="158" fill="#e0e1dd" font-size="11">11 Custom Tables</text>
    <text x="540" y="178" fill="#778da9" font-size="10">SpyCloudBreachWatchlist_CL</text>
    <text x="540" y="195" fill="#778da9" font-size="10">SpyCloudIdentityExposure_CL</text>
    <text x="540" y="212" fill="#778da9" font-size="10">SpyCloudSipCookies_CL</text>
    <text x="540" y="229" fill="#778da9" font-size="10">... and 8 more</text>

    <!-- Arrow to Sentinel -->
    <line x1="700" y1="170" x2="780" y2="170" stroke="#00b4d8" stroke-width="2" marker-end="url(#arrow)"/>

    <!-- Sentinel -->
    <rect x="780" y="40" width="180" height="300" rx="12" fill="url(#glow1)" stroke="#ef476f" stroke-width="2"/>
    <text x="870" y="70" text-anchor="middle" fill="#ef476f" font-size="14" font-weight="700">Microsoft Sentinel</text>
    <text x="800" y="100" fill="#e0e1dd" font-size="11">38 Analytics Rules</text>
    <text x="800" y="122" fill="#e0e1dd" font-size="11">23 Playbooks</text>
    <text x="800" y="144" fill="#e0e1dd" font-size="11">3 Workbooks</text>
    <text x="800" y="166" fill="#e0e1dd" font-size="11">3 Notebooks</text>
    <text x="800" y="188" fill="#e0e1dd" font-size="11">Automation Rules</text>
    <text x="800" y="215" fill="#ffd166" font-size="12" font-weight="600">Incidents</text>
    <text x="800" y="240" fill="#778da9" font-size="10">Auto-remediation</text>
    <text x="800" y="258" fill="#778da9" font-size="10">Enrichment</text>
    <text x="800" y="276" fill="#778da9" font-size="10">Notification</text>
    <text x="800" y="294" fill="#778da9" font-size="10">Compliance</text>

    <!-- Key Vault below Function App -->
    <rect x="290" y="280" width="140" height="60" rx="8" fill="#1b2838" stroke="#ffd166" stroke-width="2"/>
    <text x="360" y="308" text-anchor="middle" fill="#ffd166" font-size="12" font-weight="700">&#128272; Key Vault</text>
    <text x="360" y="326" text-anchor="middle" fill="#778da9" font-size="10">API Keys + Secrets</text>
    <line x1="360" y1="220" x2="360" y2="280" stroke="#ffd166" stroke-width="1.5" marker-end="url(#arrow)" stroke-dasharray="4"/>

    <!-- AI Engine below -->
    <rect x="520" y="310" width="180" height="60" rx="8" fill="#1b2838" stroke="#06d6a0" stroke-width="2"/>
    <text x="610" y="338" text-anchor="middle" fill="#06d6a0" font-size="12" font-weight="700">&#129302; AI + Copilot</text>
    <text x="610" y="356" text-anchor="middle" fill="#778da9" font-size="10">SCORCH Agent + MCP</text>
    <line x1="610" y1="260" x2="610" y2="310" stroke="#06d6a0" stroke-width="1.5" marker-end="url(#arrow)" stroke-dasharray="4"/>

    <!-- Purview below Sentinel -->
    <rect x="790" y="370" width="160" height="50" rx="8" fill="#1b2838" stroke="#d2a8ff" stroke-width="2"/>
    <text x="870" y="398" text-anchor="middle" fill="#d2a8ff" font-size="12" font-weight="700">&#128274; Purview</text>
    <text x="870" y="412" text-anchor="middle" fill="#778da9" font-size="10">Compliance + DLP</text>
    <line x1="870" y1="340" x2="870" y2="370" stroke="#d2a8ff" stroke-width="1.5" marker-end="url(#arrow)" stroke-dasharray="4"/>

    <!-- Labels -->
    <text x="110" y="330" text-anchor="middle" fill="#778da9" font-size="10" font-style="italic">Darknet Intelligence</text>
    <text x="360" y="380" text-anchor="middle" fill="#778da9" font-size="10" font-style="italic">Processing Layer</text>
    <text x="610" y="400" text-anchor="middle" fill="#778da9" font-size="10" font-style="italic">Intelligence Layer</text>
    <text x="870" y="440" text-anchor="middle" fill="#778da9" font-size="10" font-style="italic">Detection &amp; Response</text>
  `;
}

function drawArchDataflow() {
  const svg = document.getElementById('arch-svg-dataflow');
  if (!svg) return;
  svg.innerHTML = `
    <defs>
      <marker id="arrow2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#00b4d8"/>
      </marker>
    </defs>

    <!-- Flow steps -->
    ${[
      { x: 40, y: 60, w: 150, label: '1. API Polling', sub: 'Function App', color: '#00b4d8' },
      { x: 40, y: 150, w: 150, label: '2. Data Transform', sub: 'Normalize + Enrich', color: '#0077b6' },
      { x: 40, y: 240, w: 150, label: '3. DCE Ingestion', sub: 'Data Collection', color: '#50e6ff' },
      { x: 40, y: 330, w: 150, label: '4. Table Storage', sub: '11 Custom Tables', color: '#06d6a0' },
      { x: 300, y: 60, w: 150, label: '5. KQL Detection', sub: '38 Analytics Rules', color: '#ffd166' },
      { x: 300, y: 150, w: 150, label: '6. Incident Create', sub: 'Entity Mapping', color: '#ef476f' },
      { x: 300, y: 240, w: 150, label: '7. Automation', sub: 'Rule Triggers', color: '#ef476f' },
      { x: 300, y: 330, w: 150, label: '8. Playbooks', sub: '23 Logic Apps', color: '#d2a8ff' },
      { x: 560, y: 60, w: 150, label: '9. Remediation', sub: 'Reset + Isolate', color: '#ef476f' },
      { x: 560, y: 150, w: 150, label: '10. Enrichment', sub: 'AI Engine', color: '#06d6a0' },
      { x: 560, y: 240, w: 150, label: '11. Notification', sub: 'SOC + User + ITSM', color: '#00b4d8' },
      { x: 560, y: 330, w: 150, label: '12. Compliance', sub: 'Purview + Reports', color: '#d2a8ff' }
    ].map(n => `
      <rect x="${n.x}" y="${n.y}" width="${n.w}" height="60" rx="8" fill="#1b2838" stroke="${n.color}" stroke-width="2"/>
      <text x="${n.x + n.w/2}" y="${n.y + 28}" text-anchor="middle" fill="${n.color}" font-size="12" font-weight="700">${n.label}</text>
      <text x="${n.x + n.w/2}" y="${n.y + 46}" text-anchor="middle" fill="#778da9" font-size="10">${n.sub}</text>
    `).join('')}

    <!-- Vertical arrows (left column) -->
    <line x1="115" y1="120" x2="115" y2="150" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>
    <line x1="115" y1="210" x2="115" y2="240" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>
    <line x1="115" y1="300" x2="115" y2="330" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>

    <!-- Horizontal arrow to middle -->
    <line x1="190" y1="360" x2="300" y2="90" stroke="#ffd166" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4"/>

    <!-- Vertical arrows (middle column) -->
    <line x1="375" y1="120" x2="375" y2="150" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>
    <line x1="375" y1="210" x2="375" y2="240" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>
    <line x1="375" y1="300" x2="375" y2="330" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)"/>

    <!-- Horizontal arrows to right column -->
    <line x1="450" y1="360" x2="560" y2="90" stroke="#ef476f" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4"/>
    <line x1="450" y1="360" x2="560" y2="180" stroke="#06d6a0" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4"/>
    <line x1="450" y1="360" x2="560" y2="270" stroke="#00b4d8" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4"/>
    <line x1="450" y1="360" x2="560" y2="360" stroke="#d2a8ff" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4"/>

    <!-- Legend -->
    <text x="780" y="80" fill="#778da9" font-size="11" font-weight="600">Data Flow</text>
    <line x1="780" y1="95" x2="810" y2="95" stroke="#00b4d8" stroke-width="2"/>
    <text x="815" y="99" fill="#778da9" font-size="10">Sequential</text>
    <line x1="780" y1="115" x2="810" y2="115" stroke="#ef476f" stroke-width="2" stroke-dasharray="4"/>
    <text x="815" y="119" fill="#778da9" font-size="10">Trigger</text>
  `;
}

// ─── Initialize ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderAnalyticsRules();
  renderPlaybooks();
  renderDeploySteps();
  renderPostDeployPhases();
  renderHealthChecklist();
  renderScenarios();
  renderIsvChecklist();
  renderUseCases();
  renderTroubleshooting();
  renderGraphSteps();
  drawArchOverview();
  drawArchDataflow();
});
