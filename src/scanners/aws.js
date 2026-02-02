/**
 * AWS IAM Scanner
 */

const rules = require('../rules/aws.js');

/**
 * Scan AWS IAM for permission issues
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanAWS(options = {}) {
  const findings = [];

  try {
    // Check if AWS SDK is available
    const { IAMClient, ListUsersCommand, ListRolesCommand, ListPoliciesCommand } = require('@aws-sdk/client-iam');
    
    const config = options.profile ? { profile: options.profile } : {};
    const client = new IAMClient(config);

    // Scan users
    console.log('  Scanning IAM users...');
    const usersResponse = await client.send(new ListUsersCommand({}));
    const users = usersResponse.Users || [];
    
    for (const user of users) {
      const userFindings = await scanUser(client, user, rules);
      findings.push(...userFindings);
    }

    // Scan roles
    console.log('  Scanning IAM roles...');
    const rolesResponse = await client.send(new ListRolesCommand({}));
    const roles = rolesResponse.Roles || [];
    
    for (const role of roles) {
      const roleFindings = await scanRole(client, role, rules);
      findings.push(...roleFindings);
    }

    // Scan policies
    console.log('  Scanning IAM policies...');
    const policiesResponse = await client.send(new ListPoliciesCommand({ Scope: 'Local' }));
    const policies = policiesResponse.Policies || [];
    
    for (const policy of policies) {
      const policyFindings = await scanPolicy(client, policy, rules);
      findings.push(...policyFindings);
    }

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed. Run: npm install');
    } else if (error.name === 'CredentialsProviderError') {
      console.error('AWS credentials not configured. Run: aws configure');
    } else {
      throw error;
    }
  }

  return findings;
}

async function scanUser(client, user, rules) {
  const findings = [];
  
  // Check for old access keys
  try {
    const { ListAccessKeysCommand, GetAccessKeyLastUsedCommand } = require('@aws-sdk/client-iam');
    
    const keysResponse = await client.send(new ListAccessKeysCommand({ UserName: user.UserName }));
    const keys = keysResponse.AccessKeyMetadata || [];
    
    for (const key of keys) {
      const age = Date.now() - new Date(key.CreateDate).getTime();
      const daysOld = Math.floor(age / (1000 * 60 * 60 * 24));
      
      if (daysOld > 90) {
        findings.push({
          id: 'aws-old-access-key',
          severity: 'warning',
          resource: `User/${user.UserName}/AccessKey/${key.AccessKeyId}`,
          message: `Access key is ${daysOld} days old`,
          recommendation: 'Rotate access keys every 90 days',
        });
      }
      
      // Check last used
      const lastUsedResponse = await client.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }));
      if (!lastUsedResponse.AccessKeyLastUsed?.LastUsedDate) {
        findings.push({
          id: 'aws-unused-access-key',
          severity: 'warning',
          resource: `User/${user.UserName}/AccessKey/${key.AccessKeyId}`,
          message: 'Access key has never been used',
          recommendation: 'Remove unused access keys',
        });
      }
    }
  } catch (error) {
    // Skip if permission denied
  }

  return findings;
}

async function scanRole(client, role, rules) {
  const findings = [];
  
  // Check for overly permissive trust policies
  try {
    const trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument || '{}'));
    
    for (const statement of trustPolicy.Statement || []) {
      if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
        findings.push({
          id: 'aws-open-trust-policy',
          severity: 'critical',
          resource: `Role/${role.RoleName}`,
          message: 'Role can be assumed by anyone (Principal: *)',
          recommendation: 'Restrict trust policy to specific principals',
        });
      }
    }
  } catch (error) {
    // Skip if parsing fails
  }

  return findings;
}

async function scanPolicy(client, policy, rules) {
  const findings = [];
  
  try {
    const { GetPolicyVersionCommand } = require('@aws-sdk/client-iam');
    
    const versionResponse = await client.send(new GetPolicyVersionCommand({
      PolicyArn: policy.Arn,
      VersionId: policy.DefaultVersionId,
    }));
    
    const policyDoc = JSON.parse(decodeURIComponent(versionResponse.PolicyVersion?.Document || '{}'));
    
    for (const statement of policyDoc.Statement || []) {
      // Check for admin access
      if (statement.Effect === 'Allow' && 
          statement.Action === '*' && 
          statement.Resource === '*') {
        findings.push({
          id: 'aws-admin-policy',
          severity: 'critical',
          resource: `Policy/${policy.PolicyName}`,
          message: 'Policy grants full admin access (*:*)',
          recommendation: 'Apply least privilege - restrict actions and resources',
        });
      }
      
      // Check for dangerous actions
      const dangerousActions = ['iam:*', 'sts:AssumeRole', 'organizations:*'];
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      
      for (const action of actions) {
        if (dangerousActions.some(d => action === d || action.match(new RegExp(`^${d.replace('*', '.*')}$`)))) {
          findings.push({
            id: 'aws-dangerous-action',
            severity: 'warning',
            resource: `Policy/${policy.PolicyName}`,
            message: `Policy includes dangerous action: ${action}`,
            recommendation: 'Review if this permission is necessary',
          });
        }
      }
    }
  } catch (error) {
    // Skip if permission denied
  }

  return findings;
}

module.exports = { scanAWS };
