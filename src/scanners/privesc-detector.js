/**
 * Privilege Escalation Path Detector
 * PMapper/Pacu-level detection for AWS, Azure, GCP
 * Based on: https://pathfinding.cloud and Rhino Security research
 */

/**
 * Known privilege escalation techniques
 * Each technique has: name, permissions required, severity, and remediation
 */
const AWS_PRIVESC_TECHNIQUES = [
  // IAM Permission Manipulation
  {
    id: 'CreateNewPolicyVersion',
    name: 'Create New Policy Version',
    permissions: ['iam:CreatePolicyVersion'],
    description: 'Attacker can create a new version of a managed policy with elevated permissions',
    severity: 'critical',
    remediation: 'Restrict iam:CreatePolicyVersion to trusted admins only',
    mitre: 'T1098.001',
  },
  {
    id: 'SetExistingDefaultPolicyVersion',
    name: 'Set Default Policy Version',
    permissions: ['iam:SetDefaultPolicyVersion'],
    description: 'Attacker can revert a policy to an older version with more permissions',
    severity: 'critical',
    remediation: 'Restrict iam:SetDefaultPolicyVersion; delete old policy versions',
    mitre: 'T1098.001',
  },
  {
    id: 'CreateAccessKey',
    name: 'Create Access Key',
    permissions: ['iam:CreateAccessKey'],
    description: 'Attacker can create access keys for other users to impersonate them',
    severity: 'critical',
    remediation: 'Restrict iam:CreateAccessKey to self only with condition',
    mitre: 'T1098.001',
  },
  {
    id: 'CreateLoginProfile',
    name: 'Create Login Profile',
    permissions: ['iam:CreateLoginProfile'],
    description: 'Attacker can create console password for users without one',
    severity: 'warning',
    remediation: 'Restrict iam:CreateLoginProfile',
    mitre: 'T1098.001',
  },
  {
    id: 'UpdateLoginProfile',
    name: 'Update Login Profile',
    permissions: ['iam:UpdateLoginProfile'],
    description: 'Attacker can change passwords for other users',
    severity: 'critical',
    remediation: 'Restrict iam:UpdateLoginProfile to self only',
    mitre: 'T1098.001',
  },
  {
    id: 'AttachUserPolicy',
    name: 'Attach User Policy',
    permissions: ['iam:AttachUserPolicy'],
    description: 'Attacker can attach admin policy to their user',
    severity: 'critical',
    remediation: 'Restrict iam:AttachUserPolicy; use SCPs to deny AdministratorAccess',
    mitre: 'T1098.001',
  },
  {
    id: 'AttachGroupPolicy',
    name: 'Attach Group Policy',
    permissions: ['iam:AttachGroupPolicy'],
    description: 'Attacker can attach admin policy to a group they belong to',
    severity: 'critical',
    remediation: 'Restrict iam:AttachGroupPolicy',
    mitre: 'T1098.001',
  },
  {
    id: 'AttachRolePolicy',
    name: 'Attach Role Policy',
    permissions: ['iam:AttachRolePolicy', 'sts:AssumeRole'],
    description: 'Attacker can attach policy to a role they can assume',
    severity: 'critical',
    remediation: 'Restrict iam:AttachRolePolicy and limit assumable roles',
    mitre: 'T1098.001',
  },
  {
    id: 'PutUserPolicy',
    name: 'Put User Inline Policy',
    permissions: ['iam:PutUserPolicy'],
    description: 'Attacker can add inline policy with admin permissions to their user',
    severity: 'critical',
    remediation: 'Restrict iam:PutUserPolicy',
    mitre: 'T1098.001',
  },
  {
    id: 'PutGroupPolicy',
    name: 'Put Group Inline Policy',
    permissions: ['iam:PutGroupPolicy'],
    description: 'Attacker can add inline policy to a group they belong to',
    severity: 'critical',
    remediation: 'Restrict iam:PutGroupPolicy',
    mitre: 'T1098.001',
  },
  {
    id: 'PutRolePolicy',
    name: 'Put Role Inline Policy',
    permissions: ['iam:PutRolePolicy', 'sts:AssumeRole'],
    description: 'Attacker can add inline policy to a role they can assume',
    severity: 'critical',
    remediation: 'Restrict iam:PutRolePolicy',
    mitre: 'T1098.001',
  },
  {
    id: 'AddUserToGroup',
    name: 'Add User to Group',
    permissions: ['iam:AddUserToGroup'],
    description: 'Attacker can add themselves to an admin group',
    severity: 'critical',
    remediation: 'Restrict iam:AddUserToGroup',
    mitre: 'T1098.001',
  },
  {
    id: 'UpdateAssumeRolePolicy',
    name: 'Update Assume Role Policy',
    permissions: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
    description: 'Attacker can modify trust policy to allow themselves to assume high-privilege roles',
    severity: 'critical',
    remediation: 'Restrict iam:UpdateAssumeRolePolicy',
    mitre: 'T1098.001',
  },
  
  // Role Assumption Chains
  {
    id: 'PassRole_EC2',
    name: 'PassRole + EC2',
    permissions: ['iam:PassRole', 'ec2:RunInstances'],
    description: 'Attacker can launch EC2 with high-privilege role and access from instance metadata',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole with conditions; use IMDSv2 requirement',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_Lambda',
    name: 'PassRole + Lambda',
    permissions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    description: 'Attacker can create Lambda with high-privilege role and execute arbitrary code',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and lambda:CreateFunction',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_Glue',
    name: 'PassRole + Glue',
    permissions: ['iam:PassRole', 'glue:CreateDevEndpoint'],
    description: 'Attacker can create Glue dev endpoint with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and glue:CreateDevEndpoint',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_CloudFormation',
    name: 'PassRole + CloudFormation',
    permissions: ['iam:PassRole', 'cloudformation:CreateStack'],
    description: 'Attacker can create CloudFormation stack with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and cloudformation:CreateStack',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_DataPipeline',
    name: 'PassRole + Data Pipeline',
    permissions: ['iam:PassRole', 'datapipeline:CreatePipeline', 'datapipeline:PutPipelineDefinition', 'datapipeline:ActivatePipeline'],
    description: 'Attacker can create Data Pipeline with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and datapipeline:* permissions',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_SageMaker',
    name: 'PassRole + SageMaker',
    permissions: ['iam:PassRole', 'sagemaker:CreateNotebookInstance', 'sagemaker:CreatePresignedNotebookInstanceUrl'],
    description: 'Attacker can create SageMaker notebook with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and sagemaker:CreateNotebookInstance',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_CodeBuild',
    name: 'PassRole + CodeBuild',
    permissions: ['iam:PassRole', 'codebuild:CreateProject', 'codebuild:StartBuild'],
    description: 'Attacker can create CodeBuild project with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and codebuild:CreateProject',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_CodeStar',
    name: 'PassRole + CodeStar',
    permissions: ['iam:PassRole', 'codestar:CreateProject'],
    description: 'Attacker can create CodeStar project with high-privilege role',
    severity: 'warning',
    remediation: 'Restrict iam:PassRole and codestar:CreateProject',
    mitre: 'T1098.001',
  },
  {
    id: 'PassRole_ECS',
    name: 'PassRole + ECS',
    permissions: ['iam:PassRole', 'ecs:RegisterTaskDefinition', 'ecs:RunTask'],
    description: 'Attacker can register ECS task with high-privilege role and run it',
    severity: 'critical',
    remediation: 'Restrict iam:PassRole and ecs:RegisterTaskDefinition',
    mitre: 'T1098.001',
  },
  
  // SSM Exploitation
  {
    id: 'SSM_SendCommand',
    name: 'SSM Send Command',
    permissions: ['ssm:SendCommand'],
    description: 'Attacker can execute commands on any EC2 instance with SSM agent',
    severity: 'critical',
    remediation: 'Restrict ssm:SendCommand with instance tag conditions',
    mitre: 'T1059',
  },
  {
    id: 'SSM_StartSession',
    name: 'SSM Start Session',
    permissions: ['ssm:StartSession'],
    description: 'Attacker can start interactive session on instances',
    severity: 'warning',
    remediation: 'Restrict ssm:StartSession with conditions',
    mitre: 'T1059',
  },
  
  // Secrets Access
  {
    id: 'SecretsManager_GetSecretValue',
    name: 'Secrets Manager Access',
    permissions: ['secretsmanager:GetSecretValue'],
    description: 'Attacker can retrieve all secrets if not resource-restricted',
    severity: 'warning',
    remediation: 'Restrict secretsmanager:GetSecretValue by resource ARN',
    mitre: 'T1552.001',
  },
  {
    id: 'SSM_GetParameter',
    name: 'SSM Parameter Store Access',
    permissions: ['ssm:GetParameter', 'ssm:GetParameters'],
    description: 'Attacker can retrieve all SSM parameters including secrets',
    severity: 'warning',
    remediation: 'Restrict ssm:GetParameter* by resource path',
    mitre: 'T1552.001',
  },
  
  // STS Abuse
  {
    id: 'STS_AssumeRole_Star',
    name: 'Assume Any Role',
    permissions: ['sts:AssumeRole'],
    resource: '*',
    description: 'Attacker can assume any role in the account (and potentially cross-account)',
    severity: 'critical',
    remediation: 'Restrict sts:AssumeRole by role ARN pattern',
    mitre: 'T1550.001',
  },
  {
    id: 'STS_GetFederationToken',
    name: 'Get Federation Token',
    permissions: ['sts:GetFederationToken'],
    description: 'Attacker can create federated tokens for any user',
    severity: 'warning',
    remediation: 'Restrict sts:GetFederationToken',
    mitre: 'T1550.001',
  },
  
  // EC2 Metadata Abuse
  {
    id: 'EC2_ModifyInstanceAttribute',
    name: 'Modify EC2 Instance Attribute',
    permissions: ['ec2:ModifyInstanceAttribute'],
    description: 'Attacker can change IAM role attached to running instances',
    severity: 'critical',
    remediation: 'Restrict ec2:ModifyInstanceAttribute',
    mitre: 'T1098',
  },
  
  // Lambda Abuse
  {
    id: 'Lambda_UpdateFunctionCode',
    name: 'Update Lambda Code',
    permissions: ['lambda:UpdateFunctionCode'],
    description: 'Attacker can inject malicious code into existing Lambda functions',
    severity: 'critical',
    remediation: 'Restrict lambda:UpdateFunctionCode by function ARN',
    mitre: 'T1059',
  },
  {
    id: 'Lambda_AddPermission',
    name: 'Lambda Add Permission',
    permissions: ['lambda:AddPermission'],
    description: 'Attacker can grant external access to Lambda functions',
    severity: 'warning',
    remediation: 'Restrict lambda:AddPermission',
    mitre: 'T1098',
  },
  
  // KMS Abuse
  {
    id: 'KMS_CreateGrant',
    name: 'KMS Create Grant',
    permissions: ['kms:CreateGrant'],
    description: 'Attacker can grant themselves access to KMS keys',
    severity: 'warning',
    remediation: 'Restrict kms:CreateGrant with conditions',
    mitre: 'T1098',
  },
  {
    id: 'KMS_PutKeyPolicy',
    name: 'KMS Put Key Policy',
    permissions: ['kms:PutKeyPolicy'],
    description: 'Attacker can modify key policies to grant themselves access',
    severity: 'critical',
    remediation: 'Restrict kms:PutKeyPolicy',
    mitre: 'T1098',
  },
];

const AZURE_PRIVESC_TECHNIQUES = [
  {
    id: 'RoleAssignment_Write',
    name: 'Role Assignment Write',
    permissions: ['Microsoft.Authorization/roleAssignments/write'],
    description: 'Attacker can assign themselves Owner or other privileged roles',
    severity: 'critical',
    remediation: 'Restrict roleAssignments/write to PIM or trusted admins',
  },
  {
    id: 'RoleDefinition_Write',
    name: 'Role Definition Write',
    permissions: ['Microsoft.Authorization/roleDefinitions/write'],
    description: 'Attacker can create custom roles with any permissions',
    severity: 'critical',
    remediation: 'Restrict roleDefinitions/write to trusted admins only',
  },
  {
    id: 'VMExtension_Write',
    name: 'VM Extension Write',
    permissions: ['Microsoft.Compute/virtualMachines/extensions/write'],
    description: 'Attacker can execute arbitrary code on VMs via extensions',
    severity: 'critical',
    remediation: 'Restrict extensions/write; use Azure Policy to limit extension types',
  },
  {
    id: 'VMRunCommand',
    name: 'VM Run Command',
    permissions: ['Microsoft.Compute/virtualMachines/runCommand/action'],
    description: 'Attacker can execute arbitrary commands on VMs',
    severity: 'critical',
    remediation: 'Restrict runCommand/action',
  },
  {
    id: 'KeyVault_GetSecrets',
    name: 'Key Vault Get Secrets',
    permissions: ['Microsoft.KeyVault/vaults/secrets/*/read'],
    description: 'Attacker can read all secrets from Key Vault',
    severity: 'warning',
    remediation: 'Use RBAC with specific secret permissions',
  },
  {
    id: 'Automation_RunAsAccount',
    name: 'Automation Run As Account',
    permissions: ['Microsoft.Automation/automationAccounts/*/write'],
    description: 'Attacker can abuse Automation Run As accounts with high privileges',
    severity: 'critical',
    remediation: 'Use managed identities instead of Run As accounts',
  },
  {
    id: 'LogicApps_ManagedIdentity',
    name: 'Logic Apps Managed Identity',
    permissions: ['Microsoft.Logic/workflows/write'],
    description: 'Attacker can create Logic Apps using managed identities',
    severity: 'warning',
    remediation: 'Restrict workflows/write; limit managed identity assignments',
  },
  {
    id: 'AzureAD_AppRegistration',
    name: 'App Registration Abuse',
    permissions: ['Microsoft.Graph/applications/write'],
    description: 'Attacker can create app registrations with high API permissions',
    severity: 'warning',
    remediation: 'Require admin consent for high-privilege API permissions',
  },
];

const GCP_PRIVESC_TECHNIQUES = [
  {
    id: 'SetIamPolicy',
    name: 'Set IAM Policy',
    permissions: ['resourcemanager.projects.setIamPolicy'],
    description: 'Attacker can modify project IAM policy to grant themselves Owner',
    severity: 'critical',
    remediation: 'Restrict setIamPolicy to trusted admins; use organization policies',
  },
  {
    id: 'CreateServiceAccountKey',
    name: 'Create Service Account Key',
    permissions: ['iam.serviceAccountKeys.create'],
    description: 'Attacker can create keys for any service account they have access to',
    severity: 'critical',
    remediation: 'Disable user-managed keys via organization policy',
  },
  {
    id: 'ActAs_ServiceAccount',
    name: 'Act As Service Account',
    permissions: ['iam.serviceAccounts.actAs'],
    description: 'Attacker can impersonate service accounts',
    severity: 'critical',
    remediation: 'Restrict actAs to specific service accounts',
  },
  {
    id: 'GetAccessToken',
    name: 'Get Access Token',
    permissions: ['iam.serviceAccounts.getAccessToken'],
    description: 'Attacker can get access tokens for service accounts',
    severity: 'critical',
    remediation: 'Restrict getAccessToken; prefer workload identity',
  },
  {
    id: 'CloudFunction_ActAs',
    name: 'Cloud Function + actAs',
    permissions: ['cloudfunctions.functions.create', 'iam.serviceAccounts.actAs'],
    description: 'Attacker can deploy functions with high-privilege service accounts',
    severity: 'critical',
    remediation: 'Restrict cloudfunctions.functions.create and actAs',
  },
  {
    id: 'CloudRun_ActAs',
    name: 'Cloud Run + actAs',
    permissions: ['run.services.create', 'iam.serviceAccounts.actAs'],
    description: 'Attacker can deploy Cloud Run services with high-privilege service accounts',
    severity: 'critical',
    remediation: 'Restrict run.services.create and actAs',
  },
  {
    id: 'ComputeInstance_SetServiceAccount',
    name: 'Compute Set Service Account',
    permissions: ['compute.instances.setServiceAccount'],
    description: 'Attacker can change service account on running VMs',
    severity: 'critical',
    remediation: 'Restrict setServiceAccount',
  },
  {
    id: 'ComputeInstance_SetMetadata',
    name: 'Compute Set Metadata',
    permissions: ['compute.instances.setMetadata'],
    description: 'Attacker can inject SSH keys via instance metadata',
    severity: 'critical',
    remediation: 'Restrict setMetadata; use OS Login instead of metadata SSH keys',
  },
  {
    id: 'DeploymentManager',
    name: 'Deployment Manager Abuse',
    permissions: ['deploymentmanager.deployments.create'],
    description: 'Attacker can create deployments with elevated service account',
    severity: 'critical',
    remediation: 'Restrict deploymentmanager.deployments.create',
  },
  {
    id: 'CloudBuild_Builds',
    name: 'Cloud Build Abuse',
    permissions: ['cloudbuild.builds.create'],
    description: 'Attacker can run builds with Cloud Build service account',
    severity: 'warning',
    remediation: 'Restrict cloudbuild.builds.create; limit Cloud Build SA permissions',
  },
];

/**
 * Analyze permissions for privilege escalation paths
 * @param {string} provider - Cloud provider (aws, azure, gcp)
 * @param {array} permissions - List of permissions the principal has
 * @param {object} options - Additional options
 * @returns {array} Detected privilege escalation paths
 */
function detectPrivescPaths(provider, permissions, options = {}) {
  const findings = [];
  const permSet = new Set(permissions.map(p => p.toLowerCase()));
  
  let techniques;
  switch (provider.toLowerCase()) {
    case 'aws':
      techniques = AWS_PRIVESC_TECHNIQUES;
      break;
    case 'azure':
      techniques = AZURE_PRIVESC_TECHNIQUES;
      break;
    case 'gcp':
      techniques = GCP_PRIVESC_TECHNIQUES;
      break;
    default:
      return findings;
  }
  
  for (const technique of techniques) {
    const requiredPerms = technique.permissions.map(p => p.toLowerCase());
    const hasAllPerms = requiredPerms.every(p => {
      // Check for exact match or wildcard match
      if (permSet.has(p)) return true;
      if (permSet.has('*')) return true;
      
      // Check for service wildcard (e.g., iam:* matches iam:CreateUser)
      const service = p.split(':')[0] || p.split('/')[0];
      if (permSet.has(`${service}:*`) || permSet.has(`${service}/*`)) return true;
      
      // Check for action wildcard patterns
      for (const perm of permSet) {
        if (perm.endsWith('*') && p.startsWith(perm.slice(0, -1))) return true;
      }
      
      return false;
    });
    
    if (hasAllPerms) {
      // Check resource constraint if specified
      if (technique.resource && options.resource && options.resource !== '*') {
        if (technique.resource === '*' && options.resource !== '*') {
          continue; // This technique requires wildcard resource
        }
      }
      
      findings.push({
        id: `privesc-${provider.toLowerCase()}-${technique.id}`,
        technique: technique.name,
        severity: technique.severity,
        resource: options.principalArn || options.resource || 'Unknown',
        message: technique.description,
        recommendation: technique.remediation,
        requiredPermissions: technique.permissions,
        mitre: technique.mitre,
      });
    }
  }
  
  return findings;
}

/**
 * Build attack graph from IAM configuration
 * @param {object} iamData - IAM configuration data
 * @returns {object} Attack graph
 */
function buildAttackGraph(iamData) {
  const graph = {
    nodes: [],
    edges: [],
  };
  
  // Add principals as nodes
  for (const user of iamData.users || []) {
    graph.nodes.push({
      id: user.arn,
      type: 'user',
      name: user.name,
    });
  }
  
  for (const role of iamData.roles || []) {
    graph.nodes.push({
      id: role.arn,
      type: 'role',
      name: role.name,
    });
    
    // Add edges for trust relationships
    const trustPolicy = role.trustPolicy;
    if (trustPolicy) {
      for (const statement of trustPolicy.Statement || []) {
        if (statement.Effect !== 'Allow') continue;
        
        const principals = extractPrincipals(statement.Principal);
        for (const principal of principals) {
          graph.edges.push({
            from: principal,
            to: role.arn,
            type: 'can_assume',
            conditions: statement.Condition,
          });
        }
      }
    }
  }
  
  // Add edges for privilege escalation
  for (const node of graph.nodes) {
    const permissions = iamData.effectivePermissions?.[node.id] || [];
    const privescPaths = detectPrivescPaths('aws', permissions, { principalArn: node.id });
    
    for (const path of privescPaths) {
      // Find potential targets
      if (path.id.includes('AssumeRole') || path.id.includes('PassRole')) {
        // Can potentially reach any role
        for (const role of iamData.roles || []) {
          graph.edges.push({
            from: node.id,
            to: role.arn,
            type: 'privesc',
            technique: path.technique,
          });
        }
      }
    }
  }
  
  return graph;
}

/**
 * Extract principal ARNs from IAM principal object
 */
function extractPrincipals(principal) {
  if (!principal) return [];
  if (typeof principal === 'string') return [principal];
  
  const principals = [];
  if (principal.AWS) {
    const aws = Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS];
    principals.push(...aws);
  }
  if (principal.Service) {
    const svc = Array.isArray(principal.Service) ? principal.Service : [principal.Service];
    principals.push(...svc.map(s => `Service:${s}`));
  }
  if (principal.Federated) {
    const fed = Array.isArray(principal.Federated) ? principal.Federated : [principal.Federated];
    principals.push(...fed.map(f => `Federated:${f}`));
  }
  
  return principals;
}

module.exports = {
  detectPrivescPaths,
  buildAttackGraph,
  AWS_PRIVESC_TECHNIQUES,
  AZURE_PRIVESC_TECHNIQUES,
  GCP_PRIVESC_TECHNIQUES,
};
