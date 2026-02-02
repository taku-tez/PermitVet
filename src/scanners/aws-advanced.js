/**
 * AWS Advanced IAM Scanner
 * Organizations SCPs, Permission Boundaries, Net-Effective Permissions
 * CIS AWS Foundations Benchmark v3.0+ controls
 */

/**
 * Scan AWS Organizations and advanced IAM features
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanAWSAdvanced(options = {}) {
  const findings = [];

  try {
    const { IAMClient } = require('@aws-sdk/client-iam');
    const { OrganizationsClient, ListPoliciesCommand, DescribePolicyCommand, ListRootsCommand, ListOrganizationalUnitsForParentCommand, ListAccountsForParentCommand, ListPoliciesForTargetCommand } = require('@aws-sdk/client-organizations');
    const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
    
    const config = options.profile ? { profile: options.profile } : {};
    const iamClient = new IAMClient(config);
    const orgClient = new OrganizationsClient(config);

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
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed.');
    } else if (error.name === 'AWSOrganizationsNotInUseException') {
      // Not using Organizations - skip
    } else if (error.name === 'AccessDeniedException') {
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
async function analyzeOrganizationsSCPs(orgClient) {
  const findings = [];
  
  try {
    const { ListPoliciesCommand, DescribePolicyCommand, ListRootsCommand } = require('@aws-sdk/client-organizations');
    
    // List all SCPs
    const policiesResponse = await orgClient.send(new ListPoliciesCommand({
      Filter: 'SERVICE_CONTROL_POLICY',
    }));
    
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
      
      const policyDetail = await orgClient.send(new DescribePolicyCommand({
        PolicyId: policy.Id,
      }));
      
      const content = JSON.parse(policyDetail.Policy?.Content || '{}');
      
      for (const statement of content.Statement || []) {
        // Check for overly permissive Allow statements
        if (statement.Effect === 'Allow') {
          const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
          const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
          
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
        
        // Check for good deny patterns
        if (statement.Effect === 'Deny') {
          const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
          
          // Good patterns to look for
          const goodDenyPatterns = [
            'organizations:LeaveOrganization',
            'account:CloseAccount',
            'iam:CreateUser',
            'cloudtrail:DeleteTrail',
            'cloudtrail:StopLogging',
          ];
          
          // Track which patterns are denied
          const deniedPatterns = goodDenyPatterns.filter(p => 
            actions.some(a => a === p || a === '*' || p.startsWith(a.replace('*', '')))
          );
          
          // This is informational - good SCPs
          if (deniedPatterns.length > 0) {
            // No finding - this is good!
          }
        }
      }
    }
    
    // Check for recommended deny SCPs
    const allScpContent = await Promise.all(
      policies.map(async p => {
        try {
          const detail = await orgClient.send(new DescribePolicyCommand({ PolicyId: p.Id }));
          return detail.Policy?.Content || '';
        } catch { return ''; }
      })
    );
    
    const combinedContent = allScpContent.join(' ');
    
    // Check for critical deny patterns
    const criticalDenyPatterns = [
      { pattern: 'cloudtrail:DeleteTrail', id: 'aws-scp-no-cloudtrail-protection', msg: 'No SCP prevents CloudTrail deletion' },
      { pattern: 'cloudtrail:StopLogging', id: 'aws-scp-no-logging-protection', msg: 'No SCP prevents CloudTrail logging stop' },
      { pattern: 'organizations:LeaveOrganization', id: 'aws-scp-no-leave-protection', msg: 'No SCP prevents accounts from leaving organization' },
      { pattern: 's3:DeleteBucket', id: 'aws-scp-no-s3-protection', msg: 'Consider SCP to prevent critical S3 bucket deletion' },
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
    if (error.name !== 'AWSOrganizationsNotInUseException' && 
        error.name !== 'AccessDeniedException') {
      throw error;
    }
  }
  
  return findings;
}

/**
 * Analyze Permission Boundaries
 */
async function analyzePermissionBoundaries(iamClient) {
  const findings = [];
  
  try {
    const { ListUsersCommand, ListRolesCommand, GetUserCommand, GetRoleCommand } = require('@aws-sdk/client-iam');
    
    // Check users without permission boundaries
    const usersResponse = await iamClient.send(new ListUsersCommand({}));
    let usersWithoutBoundary = 0;
    
    for (const user of usersResponse.Users || []) {
      const userDetail = await iamClient.send(new GetUserCommand({ UserName: user.UserName }));
      if (!userDetail.User?.PermissionsBoundary) {
        usersWithoutBoundary++;
      }
    }
    
    if (usersWithoutBoundary > 0 && (usersResponse.Users?.length || 0) > 5) {
      const percentage = Math.round((usersWithoutBoundary / usersResponse.Users.length) * 100);
      findings.push({
        id: 'aws-users-without-boundary',
        severity: percentage > 50 ? 'warning' : 'info',
        resource: 'IAM/Users',
        message: `${usersWithoutBoundary}/${usersResponse.Users.length} users (${percentage}%) have no permission boundary`,
        recommendation: 'Use permission boundaries to limit maximum permissions for IAM entities',
      });
    }
    
    // Check roles created by users (should have boundaries)
    const rolesResponse = await iamClient.send(new ListRolesCommand({}));
    let customRolesWithoutBoundary = 0;
    
    for (const role of rolesResponse.Roles || []) {
      // Skip service-linked and AWS-created roles
      if (role.Path?.startsWith('/aws-service-role/') || 
          role.Path?.startsWith('/service-role/') ||
          role.Arn?.includes(':role/aws-')) continue;
      
      const roleDetail = await iamClient.send(new GetRoleCommand({ RoleName: role.RoleName }));
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
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Analyze cross-account role trust relationships
 */
async function analyzeCrossAccountRoles(iamClient) {
  const findings = [];
  
  try {
    const { ListRolesCommand } = require('@aws-sdk/client-iam');
    const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
    
    const stsClient = new STSClient({});
    const identity = await stsClient.send(new GetCallerIdentityCommand({}));
    const currentAccountId = identity.Account;
    
    const rolesResponse = await iamClient.send(new ListRolesCommand({}));
    
    const crossAccountRoles = [];
    const externalAccounts = new Set();
    
    for (const role of rolesResponse.Roles || []) {
      // Skip AWS service roles
      if (role.Path?.startsWith('/aws-service-role/')) continue;
      
      try {
        const trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument || '{}'));
        
        for (const statement of trustPolicy.Statement || []) {
          if (statement.Effect !== 'Allow') continue;
          
          const principals = extractAWSPrincipals(statement.Principal);
          
          for (const principal of principals) {
            // Extract account ID from ARN
            const accountMatch = principal.match(/arn:aws[^:]*:[^:]*:(\d{12}):/);
            if (accountMatch && accountMatch[1] !== currentAccountId) {
              externalAccounts.add(accountMatch[1]);
              
              // Check for missing ExternalId condition
              const hasExternalId = statement.Condition?.StringEquals?.['sts:ExternalId'] ||
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
              
              crossAccountRoles.push({
                role: role.RoleName,
                externalAccount: accountMatch[1],
                hasExternalId,
              });
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
      } catch (e) {
        // Skip roles with invalid trust policies
      }
    }
    
    // Summary finding for many cross-account relationships
    if (externalAccounts.size > 10) {
      findings.push({
        id: 'aws-many-cross-account-trusts',
        severity: 'info',
        resource: 'IAM',
        message: `${crossAccountRoles.length} roles trust ${externalAccounts.size} external accounts`,
        recommendation: 'Regularly review cross-account trust relationships',
      });
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Analyze effective permissions (simplified net-effective calculation)
 */
async function analyzeEffectivePermissions(iamClient) {
  const findings = [];
  
  try {
    const { 
      ListUsersCommand, 
      ListGroupsForUserCommand, 
      ListAttachedUserPoliciesCommand,
      ListAttachedGroupPoliciesCommand,
      ListUserPoliciesCommand,
      ListGroupPoliciesCommand,
      SimulatePrincipalPolicyCommand,
    } = require('@aws-sdk/client-iam');
    
    // Get users and analyze their effective permissions
    const usersResponse = await iamClient.send(new ListUsersCommand({}));
    
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
        const simResult = await iamClient.send(new SimulatePrincipalPolicyCommand({
          PolicySourceArn: user.Arn,
          ActionNames: criticalActions,
          ResourceArns: ['*'],
        }));
        
        const allowedCriticalActions = simResult.EvaluationResults?.filter(
          r => r.EvalDecision === 'allowed'
        ) || [];
        
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
        const canCreateUsers = allowedCriticalActions.some(a => a.EvalActionName === 'iam:CreateUser');
        const canAttachPolicies = allowedCriticalActions.some(a => a.EvalActionName === 'iam:AttachUserPolicy');
        
        if (canCreateUsers && canAttachPolicies) {
          findings.push({
            id: 'aws-user-privesc-risk',
            severity: 'critical',
            resource: `User/${user.UserName}`,
            message: 'User can create users AND attach policies (privilege escalation risk)',
            recommendation: 'This combination allows creating admin users - review immediately',
          });
        }
        
      } catch (e) {
        // Simulation might fail for some users
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Extract AWS principals from IAM principal object
 */
function extractAWSPrincipals(principal) {
  if (!principal) return [];
  if (typeof principal === 'string') return principal === '*' ? ['*'] : [principal];
  
  const principals = [];
  if (principal.AWS) {
    const aws = Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS];
    principals.push(...aws);
  }
  
  return principals;
}

module.exports = { scanAWSAdvanced };
