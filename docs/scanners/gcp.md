# GCP Scanner

Scans GCP IAM for security issues based on CIS Benchmarks and best practices.

## Quick Start

```bash
# Scan project
permitvet scan gcp --project my-project-id

# Organization-level scan
permitvet scan gcp --organization 123456789012

# Scan all projects in organization
permitvet scan gcp --organization 123456789012 --all-projects

# Folder-level scan
permitvet scan gcp --folder 987654321 --all-projects
```

## Authentication

### gcloud CLI (Recommended)

```bash
# Login
gcloud auth application-default login

# Set project
export GOOGLE_CLOUD_PROJECT=my-project-id

# Scan
permitvet scan gcp
```

### Service Account

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
permitvet scan gcp --project my-project-id
```

### Workload Identity (GKE)

When running in GKE with Workload Identity, authentication is automatic.

## Required Permissions

### Basic Scan (Project Level)

```yaml
# Custom role or use Security Reviewer
- resourcemanager.projects.getIamPolicy
- iam.serviceAccounts.list
- iam.serviceAccountKeys.list
- iam.roles.list
- iam.roles.get
```

### Enhanced Scan (IAM Recommender + Org Policies)

```yaml
- recommender.iamPolicyRecommendations.list
- orgpolicy.policy.get
- cloudresourcemanager.projects.get
```

### Organization-Level Scan

```yaml
- resourcemanager.organizations.getIamPolicy
- resourcemanager.folders.list
- resourcemanager.folders.getIamPolicy
- resourcemanager.projects.list
- iam.roles.list (at org level)
```

**Recommended:** Use the predefined role `roles/iam.securityReviewer`.

## Checks Performed

### Basic Checks (gcp.js)

| Check ID | Severity | Description | CIS |
|----------|----------|-------------|-----|
| gcp-primitive-role | warning | User has Owner/Editor role | 1.3 |
| gcp-public-access | critical | Role granted to allUsers | - |
| gcp-authenticated-users | critical | Role granted to allAuthenticatedUsers | - |
| gcp-service-account-impersonation | warning | SA can impersonate other SAs | 1.6 |
| gcp-user-managed-keys | warning | SA has user-managed keys | 1.4 |
| gcp-key-old | warning | SA key older than 90 days | 1.7 |
| gcp-disabled-sa-with-keys | info | Disabled SA still has keys | - |
| gcp-public-sa-impersonation | critical | SA can be impersonated publicly | - |
| gcp-custom-role-wildcard | warning | Custom role uses wildcards | - |
| gcp-privesc-* | critical | Custom role enables privilege escalation | - |

### Organization Policy Checks (gcp-advanced.js)

| Check ID | Severity | Description | CIS |
|----------|----------|-------------|-----|
| gcp-orgpolicy-iam-disableServiceAccountKeyCreation | warning | SA key creation not disabled | 1.4 |
| gcp-orgpolicy-iam-allowedPolicyMemberDomains | warning | Domain restriction not set | - |
| gcp-orgpolicy-storage-uniformBucketLevelAccess | warning | Uniform bucket access not enforced | 5.2 |
| gcp-inherited-privileged-role | warning | Privileged role inherited from parent | - |
| gcp-workload-identity-no-condition | warning | WI provider without conditions | - |

### Organization-Level Checks (gcp-organization.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| gcp-org-primitive-role | critical | Owner/Editor at org level |
| gcp-org-admin-count | warning/info | Number of Organization Admins |
| gcp-org-folder-admin | warning | Folder Admin at org level |
| gcp-org-security-admin | warning | Security Admin at org level |
| gcp-org-sa-privileged | critical | SA with org-level privileged role |
| gcp-org-role-critical-perms | critical | Org custom role with critical permissions |
| gcp-org-role-wildcards | warning | Org custom role with wildcards |
| gcp-folder-primitive-role | warning | Owner/Editor at folder level |
| gcp-folder-public-access | critical | Public access at folder level |
| gcp-cross-project-privileged | warning | Principal in 5+ projects |
| gcp-sa-multi-project | warning | SA with access to multiple projects |

### IAM Recommender Checks (gcp-recommender.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| gcp-recommender-remove-role | warning | Unused role should be removed |
| gcp-recommender-replace-role | info | Role can be replaced with more specific |

### Privilege Escalation (privesc-detector.js)

Detects 10+ GCP privilege escalation techniques:

- serviceAccountKeys.create
- serviceAccounts.actAs
- setIamPolicy (project/folder/org)
- deploymentmanager.deployments.create
- cloudfunctions.functions.create + actAs
- And more...

## Output Examples

### Organization Scan

```
🦅 PermitVet v0.11.0

━━━ GCP ━━━
  Scanning organization: 123456789012...
  Checking organization IAM policy...
  Scanning organization custom roles...
  Analyzing folder hierarchy...
  Scanning all projects in organization...
  Found 25 projects...

┌──────────┬───────────────────────────┬────────────────────────────────────────┐
│ Severity │ Resource                  │ Issue                                  │
├──────────┼───────────────────────────┼────────────────────────────────────────┤
│ critical │ Organization/123456789012 │ 2 principal(s) have roles/owner        │
│ warning  │ sa@project.iam...         │ SA has privileged access to 8 projects │
└──────────┴───────────────────────────┴────────────────────────────────────────┘
```

## Organization Scanning

New in v0.10.0: Scan across your entire GCP organization.

```bash
# Scan organization IAM only
permitvet scan gcp --organization 123456789012

# Scan organization + all projects
permitvet scan gcp --organization 123456789012 --all-projects

# Scan specific folder + projects
permitvet scan gcp --folder 987654321 --all-projects
```

### What Organization Scan Covers

1. **Organization IAM Policy** - Who has Owner/Editor/Admin at org level
2. **Organization Custom Roles** - Dangerous permissions in org-level roles
3. **Folder Hierarchy** - Recursive analysis of folder IAM policies
4. **Cross-Project Analysis** - Principals with access to many projects
5. **Service Account Sprawl** - SAs with multi-project access

## Best Practices

1. **Avoid primitive roles** (Owner/Editor) - use predefined roles
2. **Disable SA key creation** via org policy
3. **Use Workload Identity** instead of SA keys
4. **Set domain restriction** to prevent external access
5. **Review IAM Recommender** suggestions regularly

## Troubleshooting

See [troubleshooting.md](../troubleshooting.md) for common issues.

### Common Errors

**PERMISSION_DENIED:**
```bash
# Check your identity
gcloud auth list

# Verify IAM permissions
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:YOUR_EMAIL"
```

**Project not found:**
```bash
# List accessible projects
gcloud projects list

# Set project explicitly
permitvet scan gcp --project my-project-id
```

**Organization access denied:**
```bash
# Need Organization Viewer or higher
gcloud organizations get-iam-policy ORG_ID
```
