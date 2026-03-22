# SpyCloud Identity Exposure Intelligence - Custom Connector

![SpyCloud](images/logo.png)

## Table of Contents

1. [Overview](#overview)
2. [Actions](#actions)
3. [Deployment](#deployment)
4. [Authentication](#authentication)

<a name="overview"></a>

## Overview
The SpyCloud Identity Exposure Intelligence connector provides access to SpyCloud's Enterprise Protection API. It enables Logic App playbooks to query breach data, monitor watchlists, investigate malware infections via Compass, and assess identity exposure risk.

<a name="actions"></a>

## Actions Supported

| Action | Description |
| --------- | -------------- |
| **List or Query the Breach Catalog** | List or query the breach catalog for breach metadata |
| **Get Catalog by ID** | Retrieve breach catalog information by specific breach ID |
| **Get Breach Data by Domain** | Search breach records by domain name |
| **Get Breach Data by Email** | Search breach records by email address |
| **Get Breach Data by IP Address** | Search breach records by IP address |
| **Get Breach Data by Password** | Search breach records by password |
| **Get Breach Data by Username** | Search breach records by username |
| **Get Breach Data for Watchlist** | Get all breach data for your configured watchlist |
| **Get Exposed Identity Data** | Get exposed identity data from recent breaches and malware |
| **Get Compass Devices List** | List infected devices from malware data |
| **Get Compass Device Data** | Get detailed data for a specific infected device |
| **Get Compass Applications Data** | Get malware-stolen credential data by application |
| **Get Compass Data** | Get all compass malware intelligence data |

<a name="deployment"></a>

## Deployment Instructions

Deploy the custom connector before deploying any playbooks that use it.

1. Click **Deploy to Azure** below
2. Fill in the required parameters:
   - **Connector Name**: Name for the custom connector (default: SpyCloud-Identity-Exposure-Intelligence)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FSolutions%2FSpyCloud%2520Identity%2520Exposure%2520Intelligence%2FPlaybooks%2FCustom%2520Connector%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FSolutions%2FSpyCloud%2520Identity%2520Exposure%2520Intelligence%2FPlaybooks%2FCustom%2520Connector%2Fazuredeploy.json)

<a name="authentication"></a>

## Authentication

This connector uses API Key authentication. Obtain your API key from [SpyCloud Portal](https://portal.spycloud.com).

When creating a connection in a Logic App, you will be prompted to enter your SpyCloud API Key.
