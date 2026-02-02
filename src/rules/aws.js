/**
 * AWS IAM Security Rules
 */

const rules = [
  {
    id: 'aws-admin-policy',
    severity: 'critical',
    description: 'Policy grants full administrator access (*:*)',
    recommendation: 'Apply least privilege principle - restrict actions and resources',
  },
  {
    id: 'aws-open-trust-policy',
    severity: 'critical',
    description: 'Role trust policy allows anyone to assume (Principal: *)',
    recommendation: 'Restrict trust policy to specific AWS accounts or services',
  },
  {
    id: 'aws-old-access-key',
    severity: 'warning',
    description: 'Access key older than 90 days',
    recommendation: 'Rotate access keys regularly (every 90 days recommended)',
  },
  {
    id: 'aws-unused-access-key',
    severity: 'warning',
    description: 'Access key has never been used',
    recommendation: 'Remove unused access keys to reduce attack surface',
  },
  {
    id: 'aws-dangerous-action',
    severity: 'warning',
    description: 'Policy includes potentially dangerous IAM actions',
    recommendation: 'Review if this permission is necessary for the use case',
  },
  {
    id: 'aws-wildcard-resource',
    severity: 'warning',
    description: 'Policy uses wildcard (*) for resources',
    recommendation: 'Restrict to specific resource ARNs when possible',
  },
  {
    id: 'aws-inactive-user',
    severity: 'info',
    description: 'IAM user has not logged in for 90+ days',
    recommendation: 'Consider disabling or removing inactive users',
  },
  {
    id: 'aws-mfa-disabled',
    severity: 'warning',
    description: 'IAM user does not have MFA enabled',
    recommendation: 'Enable MFA for all IAM users with console access',
  },
  {
    id: 'aws-cross-account-trust',
    severity: 'info',
    description: 'Role allows cross-account access',
    recommendation: 'Verify the trusted account is expected',
  },
  {
    id: 'aws-service-linked-role',
    severity: 'info',
    description: 'Service-linked role detected',
    recommendation: 'These are managed by AWS services - review if service is needed',
  },
];

module.exports = { rules };
