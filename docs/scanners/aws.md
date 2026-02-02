# AWS Scanner

Scans AWS IAM for security issues based on CIS Benchmarks and best practices.

## Quick Start

```bash
# Basic scan
permitvet scan aws

# With specific profile
permitvet scan aws --profile production

# Skip enhanced checks
permitvet scan aws --no-enhanced
```

## Required Permissions

Minimum permissions for basic scan:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroups",
        "iam:ListGroupPolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    }
  ]
}
```

### For Enhanced Checks

Additional permissions for Access Analyzer and SCPs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "organizations:DescribeOrganization",
        "organizations:ListPolicies",
        "organizations:DescribePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

**Recommended:** Use the AWS managed policy `SecurityAudit` for comprehensive access.

## Checks Performed

### Basic Checks (aws.js)

| Check ID | Severity | Description | CIS |
|----------|----------|-------------|-----|
| aws-root-mfa | critical | Root account MFA not enabled | 1.5 |
| aws-root-access-keys | critical | Root account has access keys | 1.4 |
| aws-iam-user-mfa | warning | IAM user without MFA | 1.10 |
| aws-iam-user-inactive | warning | Inactive IAM user | 1.12 |
| aws-access-key-old | warning | Access key older than 90 days | 1.14 |
| aws-access-key-unused | info | Unused access key | 1.11 |
| aws-password-policy | warning | Weak password policy | 1.8-1.9 |
| aws-user-inline-policy | info | User has inline policy | - |
| aws-admin-policy | warning | User/role has AdministratorAccess | - |
| aws-wildcard-resource | warning | Policy allows * resource | - |
| aws-wildcard-action | critical | Policy allows * action | - |

### Enhanced Checks (aws-advanced.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| aws-no-scp | info | No SCPs configured |
| aws-scp-full-admin | warning | SCP allows full admin |
| aws-no-permission-boundary | info | No permission boundaries |
| aws-boundary-overly-permissive | warning | Permission boundary too broad |
| aws-cross-account-trust | warning | Role trusts external account |
| aws-trust-any-principal | critical | Role trusts any AWS principal |

### Access Analyzer (aws-access-analyzer.js)

| Check ID | Severity | Description |
|----------|----------|-------------|
| aws-analyzer-finding | varies | Access Analyzer finding (IAM resources only) |
| aws-no-analyzer | info | No Access Analyzer configured |

### Privilege Escalation (privesc-detector.js)

Detects 30+ AWS privilege escalation techniques including:

- CreatePolicyVersion
- SetDefaultPolicyVersion
- PassRole + Lambda/EC2/ECS/etc.
- AttachUserPolicy/AttachRolePolicy/AttachGroupPolicy
- PutUserPolicy/PutRolePolicy/PutGroupPolicy
- CreateAccessKey
- CreateLoginProfile
- UpdateLoginProfile
- UpdateAssumeRolePolicy
- And more...

## Output Examples

### Table (default)

```
🦅 PermitVet v0.11.0

━━━ AWS ━━━
  Checking IAM users...
  Checking IAM groups...
  Checking IAM roles...
  Running enhanced checks (Access Analyzer)...

┌──────────┬──────────┬────────────────────────────────┬────────────────────────────────────────┐
│ Severity │ Resource │ Issue                          │ Recommendation                         │
├──────────┼──────────┼────────────────────────────────┼────────────────────────────────────────┤
│ warning  │ IAM/admin│ MFA not enabled                │ Enable MFA for all IAM users           │
│ warning  │ IAM/admin│ Access key is 95 days old      │ Rotate access keys every 90 days       │
└──────────┴──────────┴────────────────────────────────┴────────────────────────────────────────┘

Summary: 0 critical, 2 warning, 10 info
```

### JSON

```json
{
  "total": 12,
  "critical": 0,
  "warning": 2,
  "info": 10,
  "findings": [
    {
      "id": "aws-iam-user-mfa",
      "severity": "warning",
      "resource": "IAMUser/admin",
      "message": "IAM user does not have MFA enabled",
      "recommendation": "Enable MFA for all IAM users",
      "cis": "1.10"
    }
  ]
}
```

## Best Practices

1. **Use profiles** for different AWS accounts
2. **Run regularly** in CI/CD pipelines
3. **Enable Access Analyzer** for external access detection
4. **Review SCPs** if using AWS Organizations
5. **Export SARIF** for GitHub Security integration

## Troubleshooting

See [troubleshooting.md](../troubleshooting.md) for common issues.

### Common Errors

**AccessDenied on ListUsers:**
```bash
# Check your identity
aws sts get-caller-identity

# Verify permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/scanner \
  --action-names iam:ListUsers
```

**No MFA findings for root:**
```bash
# Root MFA check requires GetAccountSummary permission
aws iam get-account-summary
```
