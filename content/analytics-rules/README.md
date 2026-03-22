# Analytics Rule Templates

YAML rule definitions for Microsoft Sentinel analytics (scheduled and NRT detection rules).

## Rule Categories

| File | Category | Rules |
|------|----------|-------|
| `spycloud-core-detection-templates.yaml` | Core Detection | New credential exposure, high severity, password reuse |
| `spycloud-exposure-templates.yaml` | Exposure Monitoring | Bulk exposure, VIP monitoring, domain-wide alerts |
| `spycloud-cap-templates.yaml` | Conditional Access | CA bypass detection, policy violation alerts |
| `spycloud-idlink-templates.yaml` | Identity Linking | Cross-identity correlation, shadow account detection |
| `spycloud-investigations-templates.yaml` | Investigations | Deep investigation triggers, malware indicators |
| `spycloud-o365-entra-templates.yaml` | O365/Entra | Sign-in anomalies, mailbox compromise, Entra ID alerts |
| `spycloud-ueba-network-templates.yaml` | UEBA/Network | Behavioral analytics, network anomalies |
| `spycloud-advanced-threat-templates.yaml` | Advanced Threats | Multi-stage attacks, APT indicators |
| `spycloud-defender-ca-extended.yaml` | Defender Extended | MDE correlation, device risk |
