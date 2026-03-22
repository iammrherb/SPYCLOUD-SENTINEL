# Playbook Templates

ARM deployment templates for Microsoft Sentinel playbooks (Logic Apps).

Each playbook automates a specific response action triggered by Sentinel incidents or alerts.

## Categories

- **Enrichment**: EnrichIncident, InvestigationsLookup, IdLinkCorrelation, ExposureAssessment
- **Remediation**: ForcePasswordReset, DisableAccount, RevokeSessions, EnforceMFA, RemoveMailboxRules, RevokeOAuthConsent
- **Containment**: BlockConditionalAccess, BlockFirewall, IsolateDevice, AddToSecurityGroup, CAPResponse
- **Notification**: EmailNotify, NotifySOC, NotifyUser, SlackNotify, WebhookNotify
- **Integration**: Jira, ServiceNow, FullRemediation
- **Compliance**: PurviewComplianceCheck, PurviewLabelIncident
- **AI**: Copilot-Triage
