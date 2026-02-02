# Azure Scanner

Scans Azure RBAC and Entra ID for security issues.

## Quick Start

```bash
# Scan subscription
permitvet scan azure --subscription YOUR_SUBSCRIPTION_ID

# Auto-detect subscription
permitvet scan azure

# Tenant-wide scan
permitvet scan azure --tenant YOUR_TENANT_ID

# Scan all subscriptions
permitvet scan azure --all-subscriptions

# Management group scan
permitvet scan azure --management-group mg-root --all-subscriptions
```

## Authentication

### Azure CLI (Recommended)

```bash
# Login
az login

# Set subscription
az account set --subscription YOUR_SUBSCRIPTION_ID

# Scan
permitvet scan azure
```

### Service Principal

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...

permitvet scan azure
```

### Managed Identity

When running in Azure (VM, AKS, Functions), uses Managed Identity automatically.

## Required Permissions

### Basic Scan (Subscription Level)

- `Reader` role on subscription

### Enhanced Scan (Entra ID)

- `Directory.Read.All` (Microsoft Graph)
- `RoleManagement.Read.All` (for PIM)

### Tenant-Wide Scan

- `Management Group Reader` at root management group

### Recommended Setup

```bash
# Assign Reader on subscription
az role assignment create \
  --assignee YOUR_PRINCIPAL_ID \
  --role "Reader" \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID

# For management group access
az role assignment create \
  --assignee YOUR_PRINCIPAL_ID \
  --role "Management Group Reader" \
  --scope /providers/Microsoft.Management/managementGroups/YOUR_ROOT_MG
```

## Checks Performed

### Basic Checks (azure.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| azure-owner-role | critical | Direct Owner role assignment |
| azure-contributor-role | warning | Contributor role assignment |
| azure-user-access-admin | warning | User Access Administrator role |
| azure-custom-role-privileged | warning | Custom role with privileged actions |
| azure-no-condition | info | Role assignment without conditions |
| azure-inactive-assignment | info | Unused role assignment |

### Entra ID Checks (azure-entra.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| azure-global-admin | critical | Global Administrator role |
| azure-privileged-role-admin | warning | Privileged Role Administrator |
| azure-no-pim | warning | Privileged role without PIM |
| azure-mfa-not-enforced | warning | MFA not enforced for admin |
| azure-guest-admin | critical | Guest user with admin role |

### Management Group Checks (azure-advanced.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| azure-no-management-groups | info | No MG hierarchy configured |
| azure-mg-deep-hierarchy | info | MG hierarchy > 6 levels |
| azure-mg-many-direct-subs | info | Many subscriptions under MG |
| azure-inherited-privileged-from-mg | warning | Privileged role inherited from MG |
| azure-many-inherited-roles | info | High ratio of inherited roles |
| azure-no-deny-assignments | info | No deny assignments |

### Tenant Checks (azure-tenant.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| azure-mg-owner | critical | Owner at management group level |
| azure-mg-sp-privileged | warning | Service Principal with MG privileges |
| azure-mg-too-many-privileged | warning | Many principals with privileged MG roles |
| azure-tenant-role-dangerous | warning | Custom role with dangerous actions |
| azure-cross-sub-privileged | warning | Principal with cross-subscription access |
| azure-sp-multi-sub | warning | SP with multi-subscription access |

### Privilege Escalation (privesc-detector.js)

Detects 8+ Azure privilege escalation techniques:

- roleAssignments/write (self-escalation)
- roleDefinitions/write
- managedIdentities/assign
- keyVault/secrets access
- And more...

## Output Examples

### Table

```
🦅 PermitVet v0.11.0

━━━ Azure ━━━
  Checking RBAC assignments...
  Checking custom roles...
  Running enhanced checks (Entra ID + PIM)...

┌──────────┬─────────────────────┬────────────────────────────────┬──────────────────────────────┐
│ Severity │ Resource            │ Issue                          │ Recommendation               │
├──────────┼─────────────────────┼────────────────────────────────┼──────────────────────────────┤
│ critical │ User/admin@test.com │ Has Global Administrator role  │ Use PIM for JIT access       │
│ warning  │ SP/app-123          │ Has Contributor on subscription│ Use least privilege          │
└──────────┴─────────────────────┴────────────────────────────────┴──────────────────────────────┘
```

## Tenant-Wide Scanning

New in v0.11.0: Scan across your entire Azure tenant.

```bash
# Scan root management group
permitvet scan azure --tenant YOUR_TENANT_ID

# Scan specific management group
permitvet scan azure --management-group mg-production

# Scan management group + all subscriptions
permitvet scan azure --management-group mg-root --all-subscriptions

# Scan all accessible subscriptions
permitvet scan azure --all-subscriptions
```

### What Tenant Scan Covers

1. **Management Group Role Assignments** - Who has Owner/Contributor at MG level
2. **MG Hierarchy Analysis** - Deep hierarchies, subscription distribution
3. **Tenant Custom Roles** - Dangerous permissions in custom roles
4. **Cross-Subscription Analysis** - Principals with access to multiple subscriptions
5. **Service Principal Sprawl** - SPs with multi-subscription access

## Best Practices

1. **Use Managed Identity** when running in Azure
2. **Enable PIM** for privileged roles
3. **Review MG permissions** regularly
4. **Use Conditions** on role assignments where possible
5. **Monitor Guest access** to sensitive roles

## Troubleshooting

See [troubleshooting.md](../troubleshooting.md) for common issues.

### Common Errors

**AuthorizationFailed:**
```bash
# Check your identity
az account show

# Verify role assignments
az role assignment list --assignee YOUR_PRINCIPAL_ID
```

**Cannot access Entra ID:**
```bash
# Graph API permissions required
# Check in Azure Portal > App Registrations > API Permissions
```

**Management Group access denied:**
```bash
# Need Management Group Reader at appropriate scope
az role assignment list --scope /providers/Microsoft.Management/managementGroups/YOUR_MG
```
