# Azure Service Principal Setup for GitHub Actions

## Create a Service Principal

```bash
az ad sp create-for-rbac \
  --name "spycloud-sentinel-deployer" \
  --role Contributor \
  --scopes /subscriptions/YOUR-SUBSCRIPTION-ID \
  --sdk-auth
```

## Copy the JSON Output

The command outputs JSON like:

```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

## Add as GitHub Secret

1. Go to your fork → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `AZURE_CREDENTIALS`
4. Value: paste the entire JSON output above
5. Click **Add secret**

## Also Add the SpyCloud API Key

1. **New repository secret**
2. Name: `SPYCLOUD_API_KEY`
3. Value: your SpyCloud Enterprise API key
4. Click **Add secret**

## Required Permissions

The service principal needs:
- **Contributor** on the target subscription (for resource deployment)
- **User Access Administrator** on the target subscription (for RBAC assignments)

```bash
# Add User Access Administrator if needed
az role assignment create \
  --assignee "CLIENT-ID-FROM-ABOVE" \
  --role "User Access Administrator" \
  --scope /subscriptions/YOUR-SUBSCRIPTION-ID
```
