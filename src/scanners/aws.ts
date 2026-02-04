/**
 * AWS IAM Scanner
 * Scans IAM configurations for security issues based on CIS benchmarks
 */

import type { Finding, ScanOptions, Severity } from '../types';
import { createFinding, handleScanError, logProgress, logError, logDebug } from '../utils';

interface DangerousPattern {
  pattern: RegExp;
  resource?: string;
  id: string;
  severity: Severity;
  msg: string;
}

interface CredentialReportUser {
  user: string;
  arn?: string;
  user_creation_time?: string;
  password_enabled?: string;
  password_last_used?: string;
  password_last_changed?: string;
  password_next_rotation?: string;
  mfa_active?: string;
  access_key_1_active?: string;
  access_key_1_last_rotated?: string;
  access_key_1_last_used_date?: string;
  access_key_2_active?: string;
  access_key_2_last_rotated?: string;
  access_key_2_last_used_date?: string;
  [key: string]: string | undefined;
}

/**
 * Scan AWS IAM for permission issues
 */
export async function scanAWS(_options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { IAMClient, ListUsersCommand, ListRolesCommand, ListPoliciesCommand } =
      await import('@aws-sdk/client-iam');

    // Profile support via AWS_PROFILE env or SDK default credential chain
    const client = new IAMClient({});

    // 1. Account Summary (Root account checks)
    logProgress('Checking account summary...');
    const summaryFindings = await scanAccountSummary(client);
    findings.push(...summaryFindings);

    // 2. Password Policy
    logProgress('Checking password policy...');
    const passwordFindings = await scanPasswordPolicy(client);
    findings.push(...passwordFindings);

    // 3. Credential Report
    logProgress('Generating credential report...');
    const credentialFindings = await scanCredentialReport(client);
    findings.push(...credentialFindings);

    // 4. Users (with pagination)
    logProgress('Scanning IAM users...');
    const users: Array<{ UserName?: string; UserId?: string; Arn?: string; CreateDate?: Date }> =
      [];
    let usersMarker: string | undefined;
    do {
      const usersResponse = await client.send(new ListUsersCommand({ Marker: usersMarker }));
      users.push(...(usersResponse.Users || []));
      usersMarker = usersResponse.IsTruncated ? usersResponse.Marker : undefined;
    } while (usersMarker);
    logProgress(`Found ${users.length} IAM users`);

    for (const user of users) {
      const userFindings = await scanUser(client, user);
      findings.push(...userFindings);
    }

    // 5. Roles (with pagination)
    logProgress('Scanning IAM roles...');
    const roles: Array<{
      RoleName?: string;
      RoleId?: string;
      Arn?: string;
      AssumeRolePolicyDocument?: string;
    }> = [];
    let rolesMarker: string | undefined;
    do {
      const rolesResponse = await client.send(new ListRolesCommand({ Marker: rolesMarker }));
      roles.push(...(rolesResponse.Roles || []));
      rolesMarker = rolesResponse.IsTruncated ? rolesResponse.Marker : undefined;
    } while (rolesMarker);
    logProgress(`Found ${roles.length} IAM roles`);

    for (const role of roles) {
      const roleFindings = await scanRole(client, role);
      findings.push(...roleFindings);
    }

    // 6. Customer Managed Policies (with pagination)
    logProgress('Scanning IAM policies...');
    const policies: Array<{
      PolicyName?: string;
      PolicyId?: string;
      Arn?: string;
      DefaultVersionId?: string;
    }> = [];
    let policiesMarker: string | undefined;
    do {
      const policiesResponse = await client.send(
        new ListPoliciesCommand({ Scope: 'Local', Marker: policiesMarker })
      );
      policies.push(...(policiesResponse.Policies || []));
      policiesMarker = policiesResponse.IsTruncated ? policiesResponse.Marker : undefined;
    } while (policiesMarker);
    logProgress(`Found ${policies.length} customer managed policies`);

    for (const policy of policies) {
      const policyFindings = await scanPolicy(client, policy);
      findings.push(...policyFindings);
    }
  } catch (error) {
    const result = handleScanError(error, { provider: 'aws' });
    if (result.shouldThrow) {
      throw error;
    }
    logError(result.message);
  }

  return findings;
}

/**
 * Scan account summary for root account issues
 */
async function scanAccountSummary(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { GetAccountSummaryCommand } = await import('@aws-sdk/client-iam');
    const response = await client.send(new GetAccountSummaryCommand({}));
    const summary = response.SummaryMap || {};

    // Check for root access keys (CIS 1.4)
    if ((summary.AccountAccessKeysPresent || 0) > 0) {
      findings.push(
        createFinding(
          'aws-root-access-key',
          'Account/Root',
          'Root account has active access keys',
          'critical',
          'Delete root account access keys. Use IAM users instead.',
          { cis: '1.4' }
        )
      );
    }

    // Check for root MFA (CIS 1.5)
    if ((summary.AccountMFAEnabled || 0) === 0) {
      findings.push(
        createFinding(
          'aws-root-mfa-disabled',
          'Account/Root',
          'Root account does not have MFA enabled',
          'critical',
          'Enable hardware MFA for the root account',
          { cis: '1.5' }
        )
      );
    }
  } catch (_e) {
    logDebug('Permission denied - skip', _e);
  }

  return findings;
}

/**
 * Scan password policy (CIS 1.8 - 1.9)
 */
async function scanPasswordPolicy(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { GetAccountPasswordPolicyCommand } = await import('@aws-sdk/client-iam');
    const response = await client.send(new GetAccountPasswordPolicyCommand({}));
    const policy = response.PasswordPolicy;

    if (!policy) return findings;

    // Minimum length (CIS 1.8)
    if ((policy.MinimumPasswordLength || 0) < 14) {
      findings.push(
        createFinding(
          'aws-password-length',
          'Account/PasswordPolicy',
          `Password policy requires only ${policy.MinimumPasswordLength} characters (should be 14+)`,
          'warning',
          'Set minimum password length to 14 or more',
          { cis: '1.8' }
        )
      );
    }

    // Password reuse (CIS 1.9)
    if (!policy.PasswordReusePrevention || policy.PasswordReusePrevention < 24) {
      findings.push(
        createFinding(
          'aws-password-reuse',
          'Account/PasswordPolicy',
          `Password reuse prevention: ${policy.PasswordReusePrevention || 0} (should be 24)`,
          'warning',
          'Prevent password reuse for last 24 passwords',
          { cis: '1.9' }
        )
      );
    }

    // Complexity requirements
    if (!policy.RequireUppercaseCharacters) {
      findings.push(
        createFinding(
          'aws-password-no-uppercase',
          'Account/PasswordPolicy',
          'Password policy does not require uppercase letters',
          'info',
          'Require at least one uppercase letter'
        )
      );
    }

    if (!policy.RequireLowercaseCharacters) {
      findings.push(
        createFinding(
          'aws-password-no-lowercase',
          'Account/PasswordPolicy',
          'Password policy does not require lowercase letters',
          'info',
          'Require at least one lowercase letter'
        )
      );
    }

    if (!policy.RequireNumbers) {
      findings.push({
        id: 'aws-password-no-numbers',
        severity: 'info',
        resource: 'Account/PasswordPolicy',
        message: 'Password policy does not require numbers',
        recommendation: 'Require at least one number',
      });
    }

    if (!policy.RequireSymbols) {
      findings.push({
        id: 'aws-password-no-symbols',
        severity: 'info',
        resource: 'Account/PasswordPolicy',
        message: 'Password policy does not require symbols',
        recommendation: 'Require at least one symbol',
      });
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name === 'NoSuchEntityException') {
      findings.push({
        id: 'aws-no-password-policy',
        severity: 'warning',
        resource: 'Account/PasswordPolicy',
        message: 'No custom password policy configured',
        recommendation: 'Configure a strong password policy',
      });
    }
  }

  return findings;
}

/**
 * Scan credential report for inactive users and old keys
 */
async function scanCredentialReport(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { GenerateCredentialReportCommand, GetCredentialReportCommand } =
      await import('@aws-sdk/client-iam');

    // Generate report
    let reportReady = false;
    for (let i = 0; i < 10 && !reportReady; i++) {
      const genResponse = await client.send(new GenerateCredentialReportCommand({}));
      if (genResponse.State === 'COMPLETE') {
        reportReady = true;
      } else {
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    if (!reportReady) return findings;

    // Get report
    const response = await client.send(new GetCredentialReportCommand({}));
    if (!response.Content) return findings;

    const reportCsv = Buffer.from(response.Content).toString('utf-8');
    const lines = reportCsv.split('\n');
    const headers = lines[0].split(',');

    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].trim()) continue;

      const values = lines[i].split(',');
      const user: CredentialReportUser = { user: '' };
      headers.forEach((h, idx) => {
        user[h] = values[idx];
      });

      // Skip root for user-specific checks
      if (user.user === '<root_account>') {
        // Check root last used (CIS 1.7)
        if (
          user.password_last_used &&
          user.password_last_used !== 'no_information' &&
          user.password_last_used !== 'N/A'
        ) {
          const lastUsed = new Date(user.password_last_used);
          const daysSince = (Date.now() - lastUsed.getTime()) / (1000 * 60 * 60 * 24);
          if (daysSince < 90) {
            findings.push({
              id: 'aws-root-used-recently',
              severity: 'warning',
              resource: 'Account/Root',
              message: `Root account was used ${Math.floor(daysSince)} days ago`,
              recommendation: 'Avoid using root account. Use IAM users.',
              cis: '1.7',
            });
          }
        }
        continue;
      }

      // Check user inactivity (CIS 1.12)
      if (
        user.password_enabled === 'true' &&
        user.password_last_used &&
        user.password_last_used !== 'no_information'
      ) {
        const lastUsed = new Date(user.password_last_used);
        const daysSince = (Date.now() - lastUsed.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSince > 90) {
          findings.push({
            id: 'aws-user-inactive',
            severity: 'warning',
            resource: `User/${user.user}`,
            message: `User has not logged in for ${Math.floor(daysSince)} days`,
            recommendation: 'Disable or remove inactive users',
            cis: '1.12',
          });
        }
      }

      // Check MFA for console users (CIS 1.10)
      if (user.password_enabled === 'true' && user.mfa_active === 'false') {
        findings.push({
          id: 'aws-user-mfa-disabled',
          severity: 'warning',
          resource: `User/${user.user}`,
          message: 'User with console access does not have MFA enabled',
          recommendation: 'Enable MFA for all users with console access',
          cis: '1.10',
        });
      }

      // Check access key age (CIS 1.14)
      for (const keyNum of ['1', '2']) {
        if (user[`access_key_${keyNum}_active`] === 'true') {
          const lastRotated = user[`access_key_${keyNum}_last_rotated`];
          if (lastRotated) {
            const rotatedDate = new Date(lastRotated);
            const daysSince = (Date.now() - rotatedDate.getTime()) / (1000 * 60 * 60 * 24);
            if (daysSince > 90) {
              findings.push({
                id: 'aws-access-key-old',
                severity: 'warning',
                resource: `User/${user.user}/AccessKey${keyNum}`,
                message: `Access key is ${Math.floor(daysSince)} days old`,
                recommendation: 'Rotate access keys every 90 days',
                cis: '1.14',
              });
            }
          }
        }
      }
    }
  } catch (_e) {
    logDebug('', _e);
  }

  return findings;
}

/**
 * Scan individual user
 */
async function scanUser(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>,
  user: { UserName?: string }
): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (!user.UserName) return findings;

  try {
    const {
      ListAttachedUserPoliciesCommand,
      ListUserPoliciesCommand,
      ListAccessKeysCommand,
      GetAccessKeyLastUsedCommand,
    } = await import('@aws-sdk/client-iam');

    // Check for policies attached directly to user (CIS 1.15)
    const attachedResponse = await client.send(
      new ListAttachedUserPoliciesCommand({ UserName: user.UserName })
    );
    if ((attachedResponse.AttachedPolicies?.length || 0) > 0) {
      findings.push({
        id: 'aws-policy-attached-to-user',
        severity: 'warning',
        resource: `User/${user.UserName}`,
        message: `User has ${attachedResponse.AttachedPolicies?.length} policies directly attached`,
        recommendation: 'Attach policies to groups, not users',
        cis: '1.15',
      });
    }

    // Check for inline policies (CIS 1.16)
    const inlineResponse = await client.send(
      new ListUserPoliciesCommand({ UserName: user.UserName })
    );
    if ((inlineResponse.PolicyNames?.length || 0) > 0) {
      findings.push({
        id: 'aws-inline-policy-user',
        severity: 'warning',
        resource: `User/${user.UserName}`,
        message: `User has ${inlineResponse.PolicyNames?.length} inline policies`,
        recommendation: 'Use managed policies instead of inline policies',
        cis: '1.16',
      });
    }

    // Check for multiple access keys
    const keysResponse = await client.send(new ListAccessKeysCommand({ UserName: user.UserName }));
    const activeKeys = keysResponse.AccessKeyMetadata?.filter(k => k.Status === 'Active') || [];

    if (activeKeys.length > 1) {
      findings.push({
        id: 'aws-multiple-access-keys',
        severity: 'info',
        resource: `User/${user.UserName}`,
        message: `User has ${activeKeys.length} active access keys`,
        recommendation: 'Limit to one active access key per user',
      });
    }

    // Check for unused access keys
    for (const key of activeKeys) {
      if (!key.AccessKeyId) continue;
      const lastUsedResponse = await client.send(
        new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId })
      );
      if (!lastUsedResponse.AccessKeyLastUsed?.LastUsedDate) {
        findings.push({
          id: 'aws-access-key-unused',
          severity: 'warning',
          resource: `User/${user.UserName}/AccessKey/${key.AccessKeyId}`,
          message: 'Access key has never been used',
          recommendation: 'Remove unused access keys',
        });
      }
    }
  } catch (_e) {
    logDebug('', _e);
  }

  return findings;
}

/**
 * Scan individual role
 */
async function scanRole(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>,
  role: { RoleName?: string; Path?: string; AssumeRolePolicyDocument?: string }
): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (!role.RoleName) return findings;

  // Skip service-linked roles
  if (role.Path?.startsWith('/aws-service-role/')) {
    return findings;
  }

  try {
    const { ListAttachedRolePoliciesCommand, ListRolePoliciesCommand } =
      await import('@aws-sdk/client-iam');

    // Analyze trust policy
    const trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument || '{}'));

    for (const statement of trustPolicy.Statement || []) {
      // Open trust policy (Principal: *)
      if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
        findings.push({
          id: 'aws-open-trust-policy',
          severity: 'critical',
          resource: `Role/${role.RoleName}`,
          message: 'Role can be assumed by anyone (Principal: *)',
          recommendation: 'Restrict trust policy to specific principals',
        });
      }

      // Cross-account trust
      const awsPrincipal = statement.Principal?.AWS;
      if (awsPrincipal && awsPrincipal !== '*') {
        const principals = Array.isArray(awsPrincipal) ? awsPrincipal : [awsPrincipal];
        for (const principal of principals) {
          if (principal.includes(':root') || /^\d{12}$/.test(principal)) {
            // Check for ExternalId condition
            const hasExternalId = statement.Condition?.StringEquals?.['sts:ExternalId'];
            if (!hasExternalId) {
              findings.push({
                id: 'aws-external-id-missing',
                severity: 'warning',
                resource: `Role/${role.RoleName}`,
                message: 'Cross-account role without ExternalId condition',
                recommendation: 'Use ExternalId to prevent confused deputy attacks',
              });
            }

            findings.push({
              id: 'aws-cross-account-trust',
              severity: 'info',
              resource: `Role/${role.RoleName}`,
              message: `Role allows cross-account access from ${principal}`,
              recommendation: 'Verify the trusted account is expected',
            });
          }
        }
      }
    }

    // Check inline policies
    const inlineResponse = await client.send(
      new ListRolePoliciesCommand({ RoleName: role.RoleName })
    );
    if ((inlineResponse.PolicyNames?.length || 0) > 0) {
      findings.push({
        id: 'aws-inline-policy-role',
        severity: 'info',
        resource: `Role/${role.RoleName}`,
        message: `Role has ${inlineResponse.PolicyNames?.length} inline policies`,
        recommendation: 'Consider using managed policies',
      });
    }

    // Analyze attached policies for dangerous permissions
    const attachedResponse = await client.send(
      new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName })
    );
    for (const policy of attachedResponse.AttachedPolicies || []) {
      // Skip AWS managed policies (they start with arn:aws:iam::aws:)
      if (policy.PolicyArn?.startsWith('arn:aws:iam::aws:')) continue;

      // Analyze customer managed policies
      if (policy.PolicyArn) {
        const policyFindings = await analyzePolicyDocument(
          client,
          policy.PolicyArn,
          `Role/${role.RoleName}`
        );
        findings.push(...policyFindings);
      }
    }
  } catch (_e) {
    logDebug('', _e);
  }

  return findings;
}

/**
 * Scan individual policy
 */
async function scanPolicy(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>,
  policy: { Arn?: string; PolicyName?: string }
): Promise<Finding[]> {
  if (!policy.Arn) return [];
  return analyzePolicyDocument(client, policy.Arn, `Policy/${policy.PolicyName}`);
}

/**
 * Analyze a policy document for dangerous permissions
 */
async function analyzePolicyDocument(
  client: InstanceType<typeof import('@aws-sdk/client-iam').IAMClient>,
  policyArn: string,
  resourcePrefix: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { GetPolicyCommand, GetPolicyVersionCommand } = await import('@aws-sdk/client-iam');

    // Get policy version
    const policyResponse = await client.send(new GetPolicyCommand({ PolicyArn: policyArn }));
    if (!policyResponse.Policy?.DefaultVersionId) return findings;

    const versionResponse = await client.send(
      new GetPolicyVersionCommand({
        PolicyArn: policyArn,
        VersionId: policyResponse.Policy.DefaultVersionId,
      })
    );

    const policyDoc = JSON.parse(
      decodeURIComponent(versionResponse.PolicyVersion?.Document || '{}')
    );

    for (const statement of policyDoc.Statement || []) {
      if (statement.Effect !== 'Allow') continue;

      const actions: string[] = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      const resources: string[] = Array.isArray(statement.Resource)
        ? statement.Resource
        : [statement.Resource];

      // Full admin access (*:*)
      if (actions.includes('*') && resources.includes('*')) {
        findings.push({
          id: 'aws-admin-access',
          severity: 'critical',
          resource: resourcePrefix,
          message: 'Policy grants full administrator access (*:*)',
          recommendation: 'Apply least privilege - restrict actions and resources',
        });
        continue; // No need to check other rules
      }

      // Check for dangerous actions
      const dangerousPatterns: DangerousPattern[] = [
        {
          pattern: /^iam:\*$/,
          id: 'aws-iam-full-access',
          severity: 'critical',
          msg: 'Full IAM access (iam:*)',
        },
        {
          pattern: /^sts:AssumeRole$/,
          resource: '*',
          id: 'aws-sts-assume-any-role',
          severity: 'critical',
          msg: 'Can assume any role',
        },
        {
          pattern: /^iam:PassRole$/,
          resource: '*',
          id: 'aws-pass-role-any',
          severity: 'critical',
          msg: 'Can pass any role',
        },
        {
          pattern: /^iam:CreatePolicyVersion$/,
          id: 'aws-create-policy-version',
          severity: 'warning',
          msg: 'Can create policy versions',
        },
        {
          pattern: /^iam:(Attach|Put)(User|Role|Group)Policy$/,
          id: 'aws-attach-policy',
          severity: 'warning',
          msg: 'Can attach policies',
        },
        {
          pattern: /^iam:CreateAccessKey$/,
          id: 'aws-create-access-key',
          severity: 'warning',
          msg: 'Can create access keys',
        },
        {
          pattern: /^s3:\*$/,
          id: 'aws-s3-full-access',
          severity: 'warning',
          msg: 'Full S3 access',
        },
        {
          pattern: /^ec2:\*$/,
          id: 'aws-ec2-full-access',
          severity: 'warning',
          msg: 'Full EC2 access',
        },
        {
          pattern: /^lambda:InvokeFunction$/,
          resource: '*',
          id: 'aws-lambda-invoke-any',
          severity: 'warning',
          msg: 'Can invoke any Lambda',
        },
      ];

      for (const action of actions) {
        for (const dp of dangerousPatterns) {
          if (dp.pattern.test(action)) {
            // Check resource constraint if required
            if (dp.resource && !resources.includes(dp.resource)) continue;

            findings.push({
              id: dp.id,
              severity: dp.severity,
              resource: resourcePrefix,
              message: dp.msg,
              recommendation: `Review if ${action} is necessary`,
            });
          }
        }
      }

      // Check for privilege escalation paths
      const canCreateUser = actions.some(a => /^iam:CreateUser$/.test(a));
      const canAttachPolicy = actions.some(a =>
        /^iam:(Attach|Put)(User|Role|Group)Policy$/.test(a)
      );
      const canPassRole = actions.some(a => /^iam:PassRole$/.test(a));
      const canCreateRole = actions.some(a => /^iam:CreateRole$/.test(a));
      const canCreateLambda = actions.some(a => /^lambda:CreateFunction$/.test(a));

      if (canCreateUser && canAttachPolicy) {
        findings.push({
          id: 'aws-privesc-create-user',
          severity: 'critical',
          resource: resourcePrefix,
          message: 'Can create users and attach policies (privilege escalation)',
          recommendation: 'This combination allows creating admin users',
        });
      }

      if (canCreateRole && canPassRole) {
        findings.push({
          id: 'aws-privesc-create-role',
          severity: 'critical',
          resource: resourcePrefix,
          message: 'Can create roles and pass them (privilege escalation)',
          recommendation: 'This combination allows assuming any permissions',
        });
      }

      if (canCreateLambda && canPassRole) {
        findings.push({
          id: 'aws-privesc-lambda-passrole',
          severity: 'critical',
          resource: resourcePrefix,
          message: 'Can create Lambda with PassRole (privilege escalation)',
          recommendation: 'Lambda + PassRole = execute code as any role',
        });
      }
    }
  } catch (_e) {
    logDebug('', _e);
  }

  return findings;
}
