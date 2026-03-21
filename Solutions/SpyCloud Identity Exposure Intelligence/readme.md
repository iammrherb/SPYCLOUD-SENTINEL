# SpyCloud Identity Exposure Intelligence for Sentinel

## Table of Contents

1. [Overview](#overview)
2. [Content Types](#content)
3. [Feed Use Case](#feed)
4. [Enrichment Use Case](#enrichment)
5. [Deployment Instructions](#deployorder)
6. [Log Tables](#logtables)

<a name="overview"></a>

## Overview

Cybercriminals utilize stolen corporate credentials as the primary technique for account takeover (ATO), resulting in billions of dollars in losses annually. SpyCloud Identity Exposure Intelligence helps prevent account takeover and ransomware attacks by identifying exposed credentials related to your organization's domains, IP addresses, and emails.

This solution provides:

- **1 Custom Connector** for SpyCloud Enterprise Protection API
- **8 Logic App Playbooks** for automated breach response
- **12 Analytic Rules** for threat detection
- **18 Workbooks** for visualization and reporting
- **Hunting Queries** for proactive threat hunting

<a name="content"></a>

## Content Types

| Content Type | Count | Description |
|---|---|---|
| Custom Connector | 1 | SpyCloud Enterprise Protection API connector |
| Playbooks | 8 | Automated response and enrichment workflows |
| Analytic Rules | 12 | Breach and malware detection rules |
| Workbooks | 18 | Dashboards and visualization |
| Hunting Queries | 1 | Proactive threat hunting |

<a name="feed"></a>

## Feed Use Case

| Playbook | Description |
| --------- | -------------- |
| **SpyCloud-Monitor-Watchlist-Data** | Runs daily to fetch watchlist data from SpyCloud API, parse results, and save to custom log table |

### Analytics Rules (Feed)

| Analytic Rule | Description |
| --------- | -------------- |
| **SpyCloud Malware Rule** | Monitors custom log table for new malware records (severity=25). Creates High Priority incident. |
| **SpyCloud Breach Rule** | Monitors custom log table for new breach records (severity=20). Creates High Priority incident. |

<a name="enrichment"></a>

## Enrichment Use Case

| Playbook | Description |
| --------- | -------------- |
| **SpyCloud-Breach-Playbook** | Incident trigger from Breach Rule - investigates breach data |
| **SpyCloud-Malware-Playbook** | Incident trigger from Malware Rule - investigates malware/compass data |
| **SpyCloud-Get-Domain-Breach-Data-Playbook** | Fetches DNS entities, retrieves domain breach data |
| **SpyCloud-Get-Email-Breach-Data-Playbook** | Fetches Account entities, retrieves email breach data |
| **SpyCloud-Get-IP-Breach-Data-Playbook** | Fetches IP entities, retrieves IP breach data |
| **SpyCloud-Get-Username-Breach-Data-Playbook** | Fetches Account entities, retrieves username breach data |
| **SpyCloud-Get-Password-Breach-Data-Playbook** | Identifies breach data for a given password |

<a name="deployorder"></a>

## Deployment Instructions

Deploy in the following order:

1. **Custom Connector** - Deploy the SpyCloud API connector first
2. **SpyCloud-Monitor-Watchlist-Data** - Deploy the watchlist poller
3. **SpyCloud-Malware-Playbook** - Deploy malware response
4. **SpyCloud-Breach-Playbook** - Deploy breach response
5. **Analytic Rules** - Enable detection rules
6. **Enrichment Playbooks** - Deploy remaining playbooks as needed

<a name="logtables"></a>

## Log Tables

The following custom log tables are used by this solution. They are created automatically by the data connector or can be created via the full infrastructure deployment (`deploy/azuredeploy.json`).

| Table | Description |
|---|---|
| `SpyCloudBreachWatchlist_CL` | Breach watchlist monitoring data |
| `SpyCloudBreachCatalog_CL` | Breach catalog metadata |
| `SpyCloudExposure_CL` | Identity exposure data |
| `SpyCloudCompassData_CL` | Compass malware intelligence |
| `SpyCloudCompassDevices_CL` | Infected device data |
| `SpyCloudCompassApplications_CL` | Malware-stolen application credentials |
| `SpyCloudIdLink_CL` | Identity link correlation data |
| `SpyCloudInvestigations_CL` | Investigation results |
| `SpyCloudCAP_CL` | Conditional Access Policy logs |
| `SpyCloudIdentityExposure_CL` | Comprehensive identity exposure |
| `SpyCloudSipCookies_CL` | Session/cookie theft data |
| `SpyCloud_ConditionalAccessLogs_CL` | Conditional Access integration logs |
| `Spycloud_MDE_Logs_CL` | Microsoft Defender for Endpoint integration logs |
