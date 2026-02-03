/**
 * AWS Advanced IAM Scanner
 * Organizations SCPs, Permission Boundaries, Net-Effective Permissions
 * CIS AWS Foundations Benchmark v3.0+ controls
 */

import type { Finding, ScanOptions } from '../types';
// Utils imported as needed

interface SCPStatement {
  Effect: 'Allow' | 'Deny';
  Action?: string | string[];
  Resource?: string | string[];
  Condition?: Record<string, Record<string, string>>;
}

interface SCPContent {
  Statement?: SCPStatement[];
}

interface TrustPolicyStatement {
  Effect: string;
  Principal?:
    | string
    | { AWS?: string | string[]; Service?: string | string[]; Federated?: string | string[] };
  Condition?: {
    StringEquals?: Record<string, string>;
    StringLike?: Record<string, string>;
  };
}

interface TrustPolicy {
  Statement?: TrustPolicyStatement[];
}

interface OrganizationsClient {
  send: (command: unknown) => Promise<unknown>;
}

interface IAMClient {
  send: (command: unknown) => Promise<unknown>;
}

/**
 * Scan AWS Organizations and advanced IAM features
 */
export async function scanAWSAdvanced(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { IAMClient } = await import('@aws-sdk/client-iam');
    const { OrganizationsClient } = await import('@aws-sdk/client-organizations');

    const config = options.profile ? { profile: options.profile } : {};

    const iamClient = new IAMClient(config) as any;

    const orgClient = new OrganizationsClient(config) as any;

    // 1. Organizations SCP Analysis
    console.log('  Analyzing Organizations SCPs...');
    const scpFindings = await analyzeOrganizationsSCPs(orgClient);
    findings.push(...scpFindings);

    // 2. Permission Boundaries Analysis
    console.log('  Analyzing Permission Boundaries...');
    const boundaryFindings = await analyzePermissionBoundaries(iamClient);
    findings.push(...boundaryFindings);

    // 3. Cross-Account Role Analysis
    console.log('  Analyzing cross-account roles...');
    const crossAccountFindings = await analyzeCrossAccountRoles(iamClient);
    findings.push(...crossAccountFindings);

    // 4. Effective Permissions Analysis
    console.log('  Analyzing effective permissions...');
    const effectiveFindings = await analyzeEffectivePermissions(iamClient);
    findings.push(...effectiveFindings);
  } catch (error) {
    const err = error as Error & { code?: string; name?: string };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed.');
    } else if (err.name === 'AWSOrganizationsNotInUseException') {
      // Not using Organizations - skip
    } else if (err.name === 'AccessDeniedException') {
      findings.push({
        id: 'aws-advanced-permission-denied',
        severity: 'info',
        resource: 'Account',
        message: 'Unable to access advanced IAM features',
        recommendation: 'Ensure scanner has organizations:* and iam:* permissions',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Analyze Organizations Service Control Policies
 */
async function analyzeOrganizationsSCPs(orgClient: OrganizationsClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ListPoliciesCommand, DescribePolicyCommand } =
      await import('@aws-sdk/client-organizations');

    // List all SCPs
    const policiesResponse = (await orgClient.send(
      new ListPoliciesCommand({
        Filter: 'SERVICE_CONTROL_POLICY',
      })
    )) as { Policies?: Array<{ Id: string; Name: string }> };

    const policies = policiesResponse.Policies || [];

    if (policies.length === 0) {
      findings.push({
        id: 'aws-no-scps',
        severity: 'info',
        resource: 'Organizations',
        message: 'No Service Control Policies configured',
        recommendation: 'Consider using SCPs to enforce guardrails across accounts',
      });
      return findings;
    }

    // Analyze each SCP
    for (const policy of policies) {
      if (policy.Name === 'FullAWSAccess') continue; // Skip default

      const policyDetail = (await orgClient.send(
        new DescribePolicyCommand({
          PolicyId: policy.Id,
        })
      )) as { Policy?: { Content?: string } };

      const content: SCPContent = JSON.parse(policyDetail.Policy?.Content || '{}');

      for (const statement of content.Statement || []) {
        // Check for overly permissive Allow statements
        if (statement.Effect === 'Allow') {
          const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
          const resources = Array.isArray(statement.Resource)
            ? statement.Resource
            : [statement.Resource];

          if (actions.includes('*') && resources.includes('*')) {
            findings.push({
              id: 'aws-scp-too-permissive',
              severity: 'warning',
              resource: `SCP/${policy.Name}`,
              message: 'SCP allows all actions on all resources',
              recommendation: 'SCPs should deny dangerous actions, not allow everything',
            });
          }
        }

        // Check for good deny patterns - no finding needed for good SCPs
      }
    }

    // Check for recommended deny SCPs
    const allScpContent = await Promise.all(
      policies.map(async p => {
        try {
          const detail = (await orgClient.send(new DescribePolicyCommand({ PolicyId: p.Id }))) as {
            Policy?: { Content?: string };
          };
          return detail.Policy?.Content || '';
        } catch {
          return '';
        }
      })
    );

    const combinedContent = allScpContent.join(' ');

    // Check for critical deny patterns
    const criticalDenyPatterns = [
      {
        pattern: 'cloudtrail:DeleteTrail',
        id: 'aws-scp-no-cloudtrail-protection',
        msg: 'No SCP prevents CloudTrail deletion',
      },
      {
        pattern: 'cloudtrail:StopLogging',
        id: 'aws-scp-no-logging-protection',
        msg: 'No SCP prevents CloudTrail logging stop',
      },
      {
        pattern: 'organizations:LeaveOrganization',
        id: 'aws-scp-no-leave-protection',
        msg: 'No SCP prevents accounts from leaving organization',
      },
      {
        pattern: 's3:DeleteBucket',
        id: 'aws-scp-no-s3-protection',
        msg: 'Consider SCP to prevent critical S3 bucket deletion',
      },
    ];

    for (const check of criticalDenyPatterns) {
      if (!combinedContent.includes(check.pattern)) {
        findings.push({
          id: check.id,
          severity: 'info',
          resource: 'Organizations/SCP',
          message: check.msg,
          recommendation: `Add SCP to deny ${check.pattern}`,
        });
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AWSOrganizationsNotInUseException' && err.name !== 'AccessDeniedException') {
      throw error;
    }
  }

  return findings;
}

/**
 * Analyze Permission Boundaries
 */
async function analyzePermissionBoundaries(iamClient: IAMClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ListUsersCommand, ListRolesCommand, GetUserCommand, GetRoleCommand } =
      await import('@aws-sdk/client-iam');

    // Check users without permission boundaries
    const usersResponse = (await iamClient.send(new ListUsersCommand({}))) as {
      Users?: Array<{ UserName: string }>;
    };
    let usersWithoutBoundary = 0;

    for (const user of usersResponse.Users || []) {
      const userDetail = (await iamClient.send(
        new GetUserCommand({ UserName: user.UserName })
      )) as { User?: { PermissionsBoundary?: unknown } };
      if (!userDetail.User?.PermissionsBoundary) {
        usersWithoutBoundary++;
      }
    }

    const totalUsers = usersResponse.Users?.length || 0;
    if (usersWithoutBoundary > 0 && totalUsers > 5) {
      const percentage = Math.round((usersWithoutBoundary / totalUsers) * 100);
      findings.push({
        id: 'aws-users-without-boundary',
        severity: percentage > 50 ? 'warning' : 'info',
        resource: 'IAM/Users',
        message: `${usersWithoutBoundary}/${totalUsers} users (${percentage}%) have no permission boundary`,
        recommendation: 'Use permission boundaries to limit maximum permissions for IAM entities',
      });
    }

    // Check roles created by users (should have boundaries)
    const rolesResponse = (await iamClient.send(new ListRolesCommand({}))) as {
      Roles?: Array<{ RoleName: string; Path?: string; Arn?: string }>;
    };
    let customRolesWithoutBoundary = 0;

    for (const role of rolesResponse.Roles || []) {
      // Skip service-linked and AWS-created roles
      if (
        role.Path?.startsWith('/aws-service-role/') ||
        role.Path?.startsWith('/service-role/') ||
        role.Arn?.includes(':role/aws-')
      ) {
        continue;
      }

      const roleDetail = (await iamClient.send(
        new GetRoleCommand({ RoleName: role.RoleName })
      )) as { Role?: { PermissionsBoundary?: unknown } };
      if (!roleDetail.Role?.PermissionsBoundary) {
        customRolesWithoutBoundary++;
      }
    }

    if (customRolesWithoutBoundary > 5) {
      findings.push({
        id: 'aws-roles-without-boundary',
        severity: 'info',
        resource: 'IAM/Roles',
        message: `${customRolesWithoutBoundary} custom roles have no permission boundary`,
        recommendation: 'Consider using permission boundaries for delegated role creation',
      });
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Analyze cross-account role trust relationships
 */
async function analyzeCrossAccountRoles(iamClient: IAMClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ListRolesCommand } = await import('@aws-sdk/client-iam');
    const { STSClient, GetCallerIdentityCommand } = await import('@aws-sdk/client-sts');

    const stsClient = new STSClient({});
    const identity = (await stsClient.send(new GetCallerIdentityCommand({}))) as {
      Account?: string;
    };
    const currentAccountId = identity.Account;

    const rolesResponse = (await iamClient.send(new ListRolesCommand({}))) as {
      Roles?: Array<{ RoleName: string; Path?: string; AssumeRolePolicyDocument?: string }>;
    };

    const externalAccounts = new Set<string>();

    for (const role of rolesResponse.Roles || []) {
      // Skip AWS service roles
      if (role.Path?.startsWith('/aws-service-role/')) continue;

      try {
        const trustPolicy: TrustPolicy = JSON.parse(
          decodeURIComponent(role.AssumeRolePolicyDocument || '{}')
        );

        for (const statement of trustPolicy.Statement || []) {
          if (statement.Effect !== 'Allow') continue;

          const principals = extractAWSPrincipals(statement.Principal);

          for (const principal of principals) {
            // Extract account ID from ARN
            const accountMatch = principal.match(/arn:aws[^:]*:[^:]*:(\d{12}):/);
            if (accountMatch && accountMatch[1] !== currentAccountId) {
              externalAccounts.add(accountMatch[1]);

              // Check for missing ExternalId condition
              const hasExternalId =
                statement.Condition?.StringEquals?.['sts:ExternalId'] ||
                statement.Condition?.StringLike?.['sts:ExternalId'];

              if (!hasExternalId && !principal.includes(':role/')) {
                findings.push({
                  id: 'aws-cross-account-no-external-id',
                  severity: 'warning',
                  resource: `Role/${role.RoleName}`,
                  message: `Cross-account trust to ${accountMatch[1]} without ExternalId`,
                  recommendation: 'Use ExternalId condition to prevent confused deputy attacks',
                });
              }
            }

            // Check for :root principal (overly permissive)
            if (principal.includes(':root')) {
              findings.push({
                id: 'aws-cross-account-root-trust',
                severity: 'warning',
                resource: `Role/${role.RoleName}`,
                message: 'Trust policy allows entire account (root), not specific role/user',
                recommendation: 'Restrict trust to specific IAM principals, not account root',
              });
            }
          }
        }
      } catch {
        // Skip roles with invalid trust policies
      }
    }

    // Summary finding for many cross-account relationships
    if (externalAccounts.size > 10) {
      findings.push({
        id: 'aws-many-cross-account-trusts',
        severity: 'info',
        resource: 'IAM',
        message: `Multiple roles trust ${externalAccounts.size} external accounts`,
        recommendation: 'Regularly review cross-account trust relationships',
      });
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Analyze effective permissions (simplified net-effective calculation)
 */
async function analyzeEffectivePermissions(iamClient: IAMClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ListUsersCommand, SimulatePrincipalPolicyCommand } =
      await import('@aws-sdk/client-iam');

    // Get users and analyze their effective permissions
    const usersResponse = (await iamClient.send(new ListUsersCommand({}))) as {
      Users?: Array<{ UserName: string; Arn: string }>;
    };

    // Critical actions to check
    const criticalActions = [
      'iam:CreateUser',
      'iam:CreateAccessKey',
      'iam:AttachUserPolicy',
      'iam:PutUserPolicy',
      'sts:AssumeRole',
      's3:DeleteBucket',
      'ec2:TerminateInstances',
      'rds:DeleteDBInstance',
      'lambda:InvokeFunction',
      'secretsmanager:GetSecretValue',
    ];

    // Sample a few users (full analysis would be too slow)
    const sampleSize = Math.min(5, usersResponse.Users?.length || 0);
    const sampledUsers = usersResponse.Users?.slice(0, sampleSize) || [];

    for (const user of sampledUsers) {
      try {
        // Use IAM Policy Simulator for effective permissions
        const simResult = (await iamClient.send(
          new SimulatePrincipalPolicyCommand({
            PolicySourceArn: user.Arn,
            ActionNames: criticalActions,
            ResourceArns: ['*'],
          })
        )) as { EvaluationResults?: Array<{ EvalDecision: string; EvalActionName: string }> };

        const allowedCriticalActions =
          simResult.EvaluationResults?.filter(r => r.EvalDecision === 'allowed') || [];

        if (allowedCriticalActions.length > 5) {
          findings.push({
            id: 'aws-user-many-critical-permissions',
            severity: 'warning',
            resource: `User/${user.UserName}`,
            message: `User has ${allowedCriticalActions.length} critical permissions allowed`,
            recommendation: 'Review if all these permissions are necessary',
            details: {
              allowedActions: allowedCriticalActions.map(a => a.EvalActionName),
            },
          });
        }

        // Check for dangerous combinations
        const canCreateUsers = allowedCriticalActions.some(
          a => a.EvalActionName === 'iam:CreateUser'
        );
        const canAttachPolicies = allowedCriticalActions.some(
          a => a.EvalActionName === 'iam:AttachUserPolicy'
        );

        if (canCreateUsers && canAttachPolicies) {
          findings.push({
            id: 'aws-user-privesc-risk',
            severity: 'critical',
            resource: `User/${user.UserName}`,
            message: 'User can create users AND attach policies (privilege escalation risk)',
            recommendation: 'This combination allows creating admin users - review immediately',
          });
        }
      } catch {
        // Simulation might fail for some users
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Extract AWS principals from IAM principal object
 */
function extractAWSPrincipals(principal: TrustPolicyStatement['Principal']): string[] {
  if (!principal) return [];
  if (typeof principal === 'string') return principal === '*' ? ['*'] : [principal];

  const principals: string[] = [];
  if (principal.AWS) {
    const aws = Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS];
    principals.push(...aws);
  }

  return principals;
}
