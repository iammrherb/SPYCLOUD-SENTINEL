# SpyCloud-Monitor-Watchlist-Data

![SpyCloud](images/logo.png)

## Summary

Runs on a daily schedule to fetch watchlist data from SpyCloud API, parse results, and save to custom log table for monitoring.

## Prerequisites

1. **SpyCloud Custom Connector** must be deployed in the same resource group
2. **SpyCloud API Key** from [portal.spycloud.com](https://portal.spycloud.com)
3. **Microsoft Sentinel** workspace

## Deployment Instructions

1. Click **Deploy to Azure** below
2. Select your subscription, resource group, and region
3. Enter the playbook name and SpyCloud connector name
4. Click **Review + Create**, then **Create**

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FSolutions%2FSpyCloud%2520Identity%2520Exposure%2520Intelligence%2FPlaybooks%2FSpyCloud-Monitor-Watchlist-Data%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FSolutions%2FSpyCloud%2520Identity%2520Exposure%2520Intelligence%2FPlaybooks%2FSpyCloud-Monitor-Watchlist-Data%2Fazuredeploy.json)

## Post-Deployment

1. Open the Logic App in the Azure portal
2. Edit the Logic App and authorize the SpyCloud connector connection with your API key
3. Authorize the Microsoft Sentinel connection
4. Save the Logic App
5. The playbook will run automatically on the configured schedule
6. Monitor the `SpyCloudBreachWatchlist_CL` table for incoming data
