# Troubleshooting

Common issues and solutions for PermitVet.

## Authentication Errors

### AWS

**Error:** `Unable to locate credentials`

```
Error: Could not load credentials from any providers
```

**Solution:**

1. Configure AWS credentials:
```bash
# Option 1: AWS CLI
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# Option 3: Use profile
permitvet scan aws --profile myprofile
```

2. Verify credentials work:
```bash
aws sts get-caller-identity
```

---

### Azure

**Error:** `DefaultAzureCredential failed`

```
Error: DefaultAzureCredential authentication failed
```

**Solution:**

1. Login with Azure CLI:
```bash
az login
az account set --subscription YOUR_SUBSCRIPTION_ID
```

2. Or use environment variables:
```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
```

---

### GCP

**Error:** `Could not load the default credentials`

```
Error: Could not load the default credentials
```

**Solution:**

1. Login with gcloud:
```bash
gcloud auth application-default login
```

2. Or use service account:
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

3. Set project:
```bash
permitvet scan gcp --project my-project-id
```

## Permission Errors

### AWS

**Error:** `AccessDenied`

```
AccessDeniedException: User is not authorized to perform: iam:ListUsers
```

**Required permissions:**
- `iam:List*`
- `iam:Get*`
- `access-analyzer:List*` (for enhanced checks)
- `organizations:Describe*` (for SCP checks)

**Solution:** Attach the `SecurityAudit` managed policy or create a custom policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "access-analyzer:List*",
        "organizations:Describe*",
        "organizations:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### Azure

**Error:** `AuthorizationFailed`

```
AuthorizationFailed: does not have authorization to perform action
```

**Required roles:**
- `Reader` on subscription
- `Security Reader` for advanced checks
- `Management Group Reader` for tenant-wide scans

**Solution:**
```bash
# Assign Reader role
az role assignment create \
  --assignee YOUR_PRINCIPAL_ID \
  --role "Reader" \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID
```

---

### GCP

**Error:** `PERMISSION_DENIED`

```
PERMISSION_DENIED: Permission 'iam.serviceAccounts.list' denied
```

**Required permissions:**
- `resourcemanager.projects.getIamPolicy`
- `iam.serviceAccounts.list`
- `iam.serviceAccountKeys.list`
- `iam.roles.list`

**Solution:** Grant the `Security Reviewer` role or custom role with required permissions.

## SDK Errors

### Missing SDK

**Error:** `Cannot find module '@aws-sdk/client-iam'`

**Solution:**
```bash
npm install @aws-sdk/client-iam @aws-sdk/client-organizations @aws-sdk/client-accessanalyzer
```

For Azure:
```bash
npm install @azure/identity @azure/arm-authorization @azure/arm-managementgroups
```

For GCP:
```bash
npm install googleapis @google-cloud/iam-credentials
```

## Network Errors

### Timeout

**Error:** `TimeoutError` or `ETIMEDOUT`

**Solution:**

1. Check network connectivity to cloud provider APIs
2. If behind proxy:
```bash
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
```

3. Increase timeout (if supported by SDK)

### Rate Limiting

**Error:** `Throttling` or `Rate Exceeded`

**Solution:**

1. PermitVet includes automatic retry with backoff
2. If persists, try scanning during off-peak hours
3. Split large scans into smaller batches

## Output Errors

### SARIF Generation

**Error:** `Cannot generate SARIF`

**Solution:** Ensure findings array is not empty and has correct schema:

```bash
# Debug: output JSON first
permitvet scan aws --format json --output debug.json
# Then try SARIF
permitvet scan aws --format sarif --output report.sarif
```

### HTML Report

**Error:** `Cannot write HTML report`

**Solution:** Check file path permissions:

```bash
# Use absolute path
permitvet scan aws --format html --output /tmp/report.html
```

## Common Issues

### No Findings

**Symptom:** Scan completes but returns 0 findings

**Possible causes:**
1. Permissions too restrictive (check for access denied errors)
2. No resources in scanned scope (empty account/project)
3. Enhanced checks skipped (add `--enhanced` or remove `--no-enhanced`)

**Debug:**
```bash
# Run with debug info
DEBUG=* permitvet scan aws
```

### Slow Scans

**Symptom:** Scan takes very long time

**Possible causes:**
1. Large number of resources
2. API rate limiting (check for throttling errors)
3. Network latency

**Solutions:**
1. Use `--quiet` to reduce output overhead
2. Use `--no-enhanced` to skip slower checks
3. Scan specific resources instead of entire account

### Version Mismatch

**Error:** Unexpected behavior after update

**Solution:**
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Or reinstall globally
npm uninstall -g @permitvet/cli
npm install -g @permitvet/cli
```

## Getting Help

1. **Check documentation:** [docs/](./docs/)
2. **Search issues:** [GitHub Issues](https://github.com/taku-tez/PermitVet/issues)
3. **Create issue:** Include:
   - PermitVet version (`permitvet --version`)
   - Node.js version (`node --version`)
   - Full error message
   - Steps to reproduce
