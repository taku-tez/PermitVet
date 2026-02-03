/**
 * AWS IAM Security Rules
 * Based on CIS AWS Foundations Benchmark v1.4.0 and security best practices
 */

import type { Severity } from '../types';

export interface Rule {
  id: string;
  severity: Severity;
  cis?: string;
  description: string;
  recommendation: string;
}

export interface RulesCollection {
  rootAccount: Rule[];
  passwordPolicy: Rule[];
  mfa: Rule[];
  credentials: Rule[];
  policyAttachment: Rule[];
  dangerousPermissions: Rule[];
  trustPolicy: Rule[];
  privEscalation: Rule[];
  resourcePolicies: Rule[];
  organizations: Rule[];
}

export const rules: RulesCollection = {
  // ===========================================
  // Root Account (CIS 1.4 - 1.7)
  // ===========================================
  rootAccount: [
    {
      id: 'aws-root-access-key',
      severity: 'critical',
      cis: '1.4',
      description: 'Root account has active access keys',
      recommendation: 'Delete root account access keys. Use IAM users instead.',
    },
    {
      id: 'aws-root-mfa-disabled',
      severity: 'critical',
      cis: '1.5',
      description: 'Root account does not have MFA enabled',
      recommendation: 'Enable hardware MFA for the root account',
    },
    {
      id: 'aws-root-used-recently',
      severity: 'warning',
      cis: '1.7',
      description: 'Root account was used in the last 90 days',
      recommendation: 'Avoid using root account for daily tasks. Use IAM users.',
    },
  ],

  // ===========================================
  // Password Policy (CIS 1.8 - 1.9)
  // ===========================================
  passwordPolicy: [
    {
      id: 'aws-password-length',
      severity: 'warning',
      cis: '1.8',
      description: 'Password policy requires less than 14 characters',
      recommendation: 'Set minimum password length to 14 or more',
    },
    {
      id: 'aws-password-reuse',
      severity: 'warning',
      cis: '1.9',
      description: 'Password policy allows password reuse',
      recommendation: 'Prevent password reuse (24 passwords recommended)',
    },
    {
      id: 'aws-password-no-uppercase',
      severity: 'info',
      description: 'Password policy does not require uppercase letters',
      recommendation: 'Require at least one uppercase letter',
    },
    {
      id: 'aws-password-no-lowercase',
      severity: 'info',
      description: 'Password policy does not require lowercase letters',
      recommendation: 'Require at least one lowercase letter',
    },
    {
      id: 'aws-password-no-numbers',
      severity: 'info',
      description: 'Password policy does not require numbers',
      recommendation: 'Require at least one number',
    },
    {
      id: 'aws-password-no-symbols',
      severity: 'info',
      description: 'Password policy does not require symbols',
      recommendation: 'Require at least one symbol',
    },
  ],

  // ===========================================
  // MFA (CIS 1.10)
  // ===========================================
  mfa: [
    {
      id: 'aws-user-mfa-disabled',
      severity: 'warning',
      cis: '1.10',
      description: 'IAM user with console access does not have MFA enabled',
      recommendation: 'Enable MFA for all users with console access',
    },
    {
      id: 'aws-user-no-hardware-mfa',
      severity: 'info',
      description: 'IAM user uses virtual MFA instead of hardware MFA',
      recommendation: 'Consider hardware MFA for privileged users',
    },
  ],

  // ===========================================
  // Credentials (CIS 1.12 - 1.14)
  // ===========================================
  credentials: [
    {
      id: 'aws-user-inactive',
      severity: 'warning',
      cis: '1.12',
      description: 'IAM user has not logged in for 90+ days',
      recommendation: 'Disable or remove inactive users',
    },
    {
      id: 'aws-access-key-old',
      severity: 'warning',
      cis: '1.14',
      description: 'Access key is older than 90 days',
      recommendation: 'Rotate access keys every 90 days',
    },
    {
      id: 'aws-access-key-unused',
      severity: 'warning',
      description: 'Access key has never been used',
      recommendation: 'Remove unused access keys',
    },
    {
      id: 'aws-multiple-access-keys',
      severity: 'info',
      description: 'User has multiple active access keys',
      recommendation: 'Limit to one active access key per user',
    },
  ],

  // ===========================================
  // Policy Attachment (CIS 1.15 - 1.16)
  // ===========================================
  policyAttachment: [
    {
      id: 'aws-policy-attached-to-user',
      severity: 'warning',
      cis: '1.15',
      description: 'IAM policy is directly attached to a user',
      recommendation: 'Attach policies to groups or roles, not users',
    },
    {
      id: 'aws-inline-policy-user',
      severity: 'warning',
      cis: '1.16',
      description: 'User has inline policy instead of managed policy',
      recommendation: 'Use managed policies for easier management',
    },
    {
      id: 'aws-inline-policy-role',
      severity: 'info',
      description: 'Role has inline policy instead of managed policy',
      recommendation: 'Consider using managed policies',
    },
  ],

  // ===========================================
  // Dangerous Permissions
  // ===========================================
  dangerousPermissions: [
    {
      id: 'aws-admin-access',
      severity: 'critical',
      description: 'Policy grants full administrator access (*:*)',
      recommendation: 'Apply least privilege - specify exact actions and resources',
    },
    {
      id: 'aws-iam-full-access',
      severity: 'critical',
      description: 'Policy grants full IAM access (iam:*)',
      recommendation: 'IAM access enables privilege escalation. Restrict carefully.',
    },
    {
      id: 'aws-sts-assume-any-role',
      severity: 'critical',
      description: 'Policy allows assuming any role (sts:AssumeRole with *)',
      recommendation: 'Restrict to specific role ARNs',
    },
    {
      id: 'aws-pass-role-any',
      severity: 'critical',
      description: 'Policy allows passing any role (iam:PassRole with *)',
      recommendation: 'iam:PassRole enables privilege escalation. Restrict to specific roles.',
    },
    {
      id: 'aws-create-policy-version',
      severity: 'warning',
      description: 'Policy allows iam:CreatePolicyVersion',
      recommendation: 'Can be used to escalate privileges by modifying policies',
    },
    {
      id: 'aws-attach-policy',
      severity: 'warning',
      description: 'Policy allows iam:AttachUserPolicy/AttachRolePolicy',
      recommendation: 'Can attach admin policies to self. Restrict carefully.',
    },
    {
      id: 'aws-put-role-policy',
      severity: 'warning',
      description: 'Policy allows iam:PutUserPolicy/PutRolePolicy',
      recommendation: 'Can create inline policies. Privilege escalation risk.',
    },
    {
      id: 'aws-create-access-key',
      severity: 'warning',
      description: 'Policy allows iam:CreateAccessKey for other users',
      recommendation: 'Can create keys for other users. Restrict to self only.',
    },
    {
      id: 'aws-lambda-invoke-any',
      severity: 'warning',
      description: 'Policy allows invoking any Lambda function',
      recommendation: 'Restrict to specific function ARNs',
    },
    {
      id: 'aws-s3-full-access',
      severity: 'warning',
      description: 'Policy grants full S3 access (s3:*)',
      recommendation: 'Restrict to specific buckets and actions',
    },
    {
      id: 'aws-ec2-full-access',
      severity: 'warning',
      description: 'Policy grants full EC2 access (ec2:*)',
      recommendation: 'Restrict to specific actions and resources',
    },
  ],

  // ===========================================
  // Trust Policy Issues
  // ===========================================
  trustPolicy: [
    {
      id: 'aws-open-trust-policy',
      severity: 'critical',
      description: 'Role can be assumed by anyone (Principal: *)',
      recommendation: 'Restrict trust policy to specific AWS accounts or services',
    },
    {
      id: 'aws-cross-account-trust',
      severity: 'info',
      description: 'Role allows cross-account access',
      recommendation: 'Verify the trusted account is expected',
    },
    {
      id: 'aws-external-id-missing',
      severity: 'warning',
      description: 'Cross-account role without ExternalId condition',
      recommendation: 'Use ExternalId to prevent confused deputy attacks',
    },
    {
      id: 'aws-trust-any-service',
      severity: 'warning',
      description: 'Role trusts a broad service principal',
      recommendation: 'Restrict to specific services when possible',
    },
  ],

  // ===========================================
  // Privilege Escalation Paths
  // ===========================================
  privEscalation: [
    {
      id: 'aws-privesc-create-user',
      severity: 'critical',
      description: 'User can create new IAM users (potential privilege escalation)',
      recommendation: 'Creating users + attaching policies = admin access',
    },
    {
      id: 'aws-privesc-create-role',
      severity: 'critical',
      description: 'User can create new IAM roles (potential privilege escalation)',
      recommendation: 'Creating roles + PassRole = assume any permissions',
    },
    {
      id: 'aws-privesc-lambda-passrole',
      severity: 'critical',
      description: 'User can create Lambda with PassRole (privilege escalation)',
      recommendation: 'Lambda + PassRole = execute code as any role',
    },
    {
      id: 'aws-privesc-cloudformation',
      severity: 'warning',
      description: 'User can create CloudFormation stacks with IAM resources',
      recommendation: 'CloudFormation can create IAM resources with elevated permissions',
    },
    {
      id: 'aws-privesc-ec2-passrole',
      severity: 'warning',
      description: 'User can launch EC2 with instance profile',
      recommendation: 'EC2 + PassRole = execute code as instance role',
    },
    {
      id: 'aws-privesc-ssm',
      severity: 'warning',
      description: 'User can run SSM commands on instances',
      recommendation: 'SSM access = execute commands as instance role',
    },
  ],

  // ===========================================
  // Resource-Based Policies
  // ===========================================
  resourcePolicies: [
    {
      id: 'aws-s3-public-policy',
      severity: 'critical',
      description: 'S3 bucket policy allows public access',
      recommendation: 'Remove public access unless explicitly required',
    },
    {
      id: 'aws-kms-key-public',
      severity: 'critical',
      description: 'KMS key policy allows public access',
      recommendation: 'Restrict KMS key access to specific principals',
    },
    {
      id: 'aws-sqs-public-policy',
      severity: 'warning',
      description: 'SQS queue policy allows public access',
      recommendation: 'Restrict queue access to specific principals',
    },
    {
      id: 'aws-sns-public-policy',
      severity: 'warning',
      description: 'SNS topic policy allows public access',
      recommendation: 'Restrict topic access to specific principals',
    },
  ],

  // ===========================================
  // Service Control Policies (Organizations)
  // ===========================================
  organizations: [
    {
      id: 'aws-no-scp',
      severity: 'info',
      description: 'AWS Organizations not using Service Control Policies',
      recommendation: 'Use SCPs to enforce guardrails across accounts',
    },
    {
      id: 'aws-scp-allow-all',
      severity: 'warning',
      description: 'SCP allows all actions (FullAWSAccess only)',
      recommendation: 'Define restrictive SCPs for security guardrails',
    },
  ],
};

// Flatten rules for easy iteration
export const allRules: Rule[] = Object.values(rules).flat();
