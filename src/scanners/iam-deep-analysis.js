/**
 * IAM Deep Analysis Module
 * Advanced IAM security checks beyond basic CIS benchmarks
 * Rhino Security Labs research + additional techniques
 */

/**
 * Additional AWS privilege escalation techniques (Rhino Security expanded)
 */
const ADDITIONAL_AWS_TECHNIQUES = [
  // Lambda Layers abuse
  {
    id: 'Lambda_PublishLayerVersion',
    name: 'Lambda Layer Poisoning',
    permissions: ['lambda:PublishLayerVersion', 'lambda:UpdateFunctionConfiguration'],
    description: 'Attacker can poison Lambda layers to inject code into multiple functions',
    severity: 'critical',
    remediation: 'Restrict lambda:PublishLayerVersion and use layer version pinning',
    mitre: 'T1195.002',
  },
  {
    id: 'Lambda_CreateEventSourceMapping',
    name: 'Lambda Event Source Mapping',
    permissions: ['lambda:CreateEventSourceMapping', 'iam:PassRole'],
    description: 'Attacker can trigger Lambda with high-privilege role via event sources',
    severity: 'warning',
    remediation: 'Restrict lambda:CreateEventSourceMapping and PassRole',
    mitre: 'T1098.001',
  },
  
  // SageMaker Notebook abuse (Rhino Security)
  {
    id: 'SageMaker_CreatePresignedUrl',
    name: 'SageMaker Presigned URL',
    permissions: ['sagemaker:CreatePresignedNotebookInstanceUrl'],
    description: 'Attacker can get presigned URL to access existing notebooks',
    severity: 'warning',
    remediation: 'Restrict sagemaker:CreatePresignedNotebookInstanceUrl',
    mitre: 'T1059',
  },
  
  // Step Functions abuse
  {
    id: 'StepFunctions_PassRole',
    name: 'Step Functions + PassRole',
    permissions: ['states:CreateStateMachine', 'iam:PassRole', 'states:StartExecution'],
    description: 'Attacker can create state machine with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict states:CreateStateMachine and PassRole',
    mitre: 'T1098.001',
  },
  
  // AppRunner abuse
  {
    id: 'AppRunner_PassRole',
    name: 'App Runner + PassRole',
    permissions: ['apprunner:CreateService', 'iam:PassRole'],
    description: 'Attacker can deploy App Runner service with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict apprunner:CreateService and PassRole',
    mitre: 'T1098.001',
  },
  
  // Batch abuse
  {
    id: 'Batch_PassRole',
    name: 'Batch + PassRole',
    permissions: ['batch:SubmitJob', 'iam:PassRole'],
    description: 'Attacker can submit batch job with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict batch:SubmitJob and PassRole',
    mitre: 'T1098.001',
  },
  
  // CloudWatch Events/EventBridge
  {
    id: 'Events_PutRule',
    name: 'EventBridge Rule Creation',
    permissions: ['events:PutRule', 'events:PutTargets', 'iam:PassRole'],
    description: 'Attacker can create event rules targeting high-privilege resources',
    severity: 'warning',
    remediation: 'Restrict events:Put* and PassRole',
    mitre: 'T1098.001',
  },
  
  // Backup service abuse
  {
    id: 'Backup_PassRole',
    name: 'Backup Service Abuse',
    permissions: ['backup:StartBackupJob', 'iam:PassRole'],
    description: 'Attacker can start backup jobs with high-privilege role',
    severity: 'warning',
    remediation: 'Restrict backup:StartBackupJob and PassRole',
    mitre: 'T1098.001',
  },
  
  // Athena workgroup abuse
  {
    id: 'Athena_CreateWorkGroup',
    name: 'Athena Workgroup S3 Access',
    permissions: ['athena:CreateWorkGroup', 'athena:StartQueryExecution'],
    description: 'Attacker can create workgroup to access S3 data',
    severity: 'warning',
    remediation: 'Restrict athena:CreateWorkGroup',
    mitre: 'T1530',
  },
  
  // EMR abuse
  {
    id: 'EMR_PassRole',
    name: 'EMR Cluster + PassRole',
    permissions: ['elasticmapreduce:RunJobFlow', 'iam:PassRole'],
    description: 'Attacker can create EMR cluster with high-privilege role',
    severity: 'critical',
    remediation: 'Restrict elasticmapreduce:RunJobFlow and PassRole',
    mitre: 'T1098.001',
  },
  
  // Redshift abuse
  {
    id: 'Redshift_GetClusterCredentials',
    name: 'Redshift Credential Access',
    permissions: ['redshift:GetClusterCredentials'],
    description: 'Attacker can get temporary credentials for Redshift clusters',
    severity: 'warning',
    remediation: 'Restrict redshift:GetClusterCredentials by cluster',
    mitre: 'T1552.001',
  },
  
  // RDS IAM auth abuse
  {
    id: 'RDS_Connect',
    name: 'RDS IAM Authentication',
    permissions: ['rds-db:connect'],
    description: 'Attacker can connect to RDS using IAM credentials',
    severity: 'info',
    remediation: 'Restrict rds-db:connect by database resource',
    mitre: 'T1078.004',
  },
  
  // Cognito abuse
  {
    id: 'Cognito_SetUserPoolMfaConfig',
    name: 'Cognito MFA Disable',
    permissions: ['cognito-idp:SetUserPoolMfaConfig'],
    description: 'Attacker can disable MFA for Cognito user pools',
    severity: 'critical',
    remediation: 'Restrict cognito-idp:SetUserPoolMfaConfig',
    mitre: 'T1556',
  },
  {
    id: 'Cognito_AdminSetUserPassword',
    name: 'Cognito Password Reset',
    permissions: ['cognito-idp:AdminSetUserPassword'],
    description: 'Attacker can reset passwords for Cognito users',
    severity: 'critical',
    remediation: 'Restrict cognito-idp:AdminSetUserPassword',
    mitre: 'T1098.001',
  },
  
  // Organizations abuse
  {
    id: 'Organizations_CreateAccount',
    name: 'Create Organization Account',
    permissions: ['organizations:CreateAccount'],
    description: 'Attacker can create new AWS accounts in the organization',
    severity: 'critical',
    remediation: 'Restrict organizations:CreateAccount to trusted admins',
    mitre: 'T1136.003',
  },
  {
    id: 'Organizations_InviteAccount',
    name: 'Invite External Account',
    permissions: ['organizations:InviteAccountToOrganization'],
    description: 'Attacker can invite external accounts to organization',
    severity: 'critical',
    remediation: 'Restrict organizations:InviteAccountToOrganization',
    mitre: 'T1136.003',
  },
  
  // Control Tower abuse
  {
    id: 'ControlTower_Disable',
    name: 'Control Tower Disable',
    permissions: ['controltower:DisableControl'],
    description: 'Attacker can disable Control Tower guardrails',
    severity: 'critical',
    remediation: 'Restrict controltower:DisableControl via SCP',
    mitre: 'T1562.001',
  },
  
  // GuardDuty/Security Hub disable
  {
    id: 'GuardDuty_Disable',
    name: 'GuardDuty Disable',
    permissions: ['guardduty:DeleteDetector'],
    description: 'Attacker can disable GuardDuty threat detection',
    severity: 'critical',
    remediation: 'Deny guardduty:Delete* via SCP',
    mitre: 'T1562.001',
  },
  {
    id: 'SecurityHub_Disable',
    name: 'Security Hub Disable',
    permissions: ['securityhub:DisableSecurityHub'],
    description: 'Attacker can disable Security Hub',
    severity: 'critical',
    remediation: 'Deny securityhub:Disable* via SCP',
    mitre: 'T1562.001',
  },
  
  // CloudTrail tampering
  {
    id: 'CloudTrail_StopLogging',
    name: 'CloudTrail Stop Logging',
    permissions: ['cloudtrail:StopLogging'],
    description: 'Attacker can stop CloudTrail logging to hide activity',
    severity: 'critical',
    remediation: 'Deny cloudtrail:StopLogging via SCP',
    mitre: 'T1562.008',
  },
  {
    id: 'CloudTrail_DeleteTrail',
    name: 'CloudTrail Delete',
    permissions: ['cloudtrail:DeleteTrail'],
    description: 'Attacker can delete CloudTrail trails',
    severity: 'critical',
    remediation: 'Deny cloudtrail:DeleteTrail via SCP',
    mitre: 'T1562.008',
  },
  {
    id: 'CloudTrail_PutEventSelectors',
    name: 'CloudTrail Event Selectors',
    permissions: ['cloudtrail:PutEventSelectors'],
    description: 'Attacker can modify event selectors to exclude events',
    severity: 'warning',
    remediation: 'Restrict cloudtrail:PutEventSelectors',
    mitre: 'T1562.008',
  },
  
  // Config tampering
  {
    id: 'Config_StopRecorder',
    name: 'Config Recorder Stop',
    permissions: ['config:StopConfigurationRecorder'],
    description: 'Attacker can stop AWS Config recording',
    severity: 'critical',
    remediation: 'Deny config:Stop* via SCP',
    mitre: 'T1562.001',
  },
  
  // VPC Flow Logs tampering
  {
    id: 'EC2_DeleteFlowLogs',
    name: 'VPC Flow Logs Delete',
    permissions: ['ec2:DeleteFlowLogs'],
    description: 'Attacker can delete VPC flow logs',
    severity: 'warning',
    remediation: 'Restrict ec2:DeleteFlowLogs',
    mitre: 'T1562.008',
  },
];

/**
 * Additional Azure privilege escalation techniques
 */
const ADDITIONAL_AZURE_TECHNIQUES = [
  {
    id: 'AzureAD_AddOwner',
    name: 'Add App Owner',
    permissions: ['microsoft.directory/applications/owners/update'],
    description: 'Attacker can add themselves as app owner to gain control',
    severity: 'critical',
    remediation: 'Restrict application owner management',
  },
  {
    id: 'AzureAD_ResetPassword',
    name: 'Reset User Password',
    permissions: ['microsoft.directory/users/password/update'],
    description: 'Attacker can reset other users passwords',
    severity: 'critical',
    remediation: 'Restrict password reset to Helpdesk roles only',
  },
  {
    id: 'AzureAD_AddGroupMember',
    name: 'Add Group Member',
    permissions: ['microsoft.directory/groups/members/update'],
    description: 'Attacker can add themselves to privileged groups',
    severity: 'critical',
    remediation: 'Use PIM for group membership',
  },
  {
    id: 'Azure_StorageAccountKey',
    name: 'Storage Account Key List',
    permissions: ['Microsoft.Storage/storageAccounts/listKeys/action'],
    description: 'Attacker can get storage account keys for full access',
    severity: 'warning',
    remediation: 'Use Azure AD auth instead of shared keys',
  },
  {
    id: 'Azure_KeyVaultPurge',
    name: 'Key Vault Purge',
    permissions: ['Microsoft.KeyVault/vaults/delete', 'Microsoft.KeyVault/locations/deletedVaults/purge/action'],
    description: 'Attacker can permanently delete Key Vaults',
    severity: 'critical',
    remediation: 'Enable soft delete and purge protection',
  },
  {
    id: 'Azure_DeploymentScript',
    name: 'Deployment Script Execution',
    permissions: ['Microsoft.Resources/deploymentScripts/write'],
    description: 'Attacker can run arbitrary scripts via ARM deployments',
    severity: 'critical',
    remediation: 'Restrict deploymentScripts/write',
  },
  {
    id: 'Azure_CustomScriptExtension',
    name: 'Custom Script Extension',
    permissions: ['Microsoft.Compute/virtualMachines/extensions/write'],
    description: 'Attacker can install custom script extension on VMs',
    severity: 'critical',
    remediation: 'Use Azure Policy to restrict extension types',
  },
];

/**
 * Additional GCP privilege escalation techniques
 */
const ADDITIONAL_GCP_TECHNIQUES = [
  {
    id: 'GCP_SetProjectIAMPolicy',
    name: 'Set Project IAM Policy',
    permissions: ['resourcemanager.projects.setIamPolicy'],
    description: 'Attacker can modify project IAM to grant themselves owner',
    severity: 'critical',
    remediation: 'Restrict setIamPolicy via org policy',
  },
  {
    id: 'GCP_CreateServiceAccountKey',
    name: 'Create SA Key',
    permissions: ['iam.serviceAccountKeys.create'],
    description: 'Attacker can create keys for service accounts',
    severity: 'critical',
    remediation: 'Disable SA key creation via org policy',
  },
  {
    id: 'GCP_ServiceAccountSignBlob',
    name: 'SA Sign Blob',
    permissions: ['iam.serviceAccounts.signBlob'],
    description: 'Attacker can sign blobs as service account for auth',
    severity: 'warning',
    remediation: 'Restrict signBlob permission',
  },
  {
    id: 'GCP_ServiceAccountSignJwt',
    name: 'SA Sign JWT',
    permissions: ['iam.serviceAccounts.signJwt'],
    description: 'Attacker can create JWTs as service account',
    severity: 'warning',
    remediation: 'Restrict signJwt permission',
  },
  {
    id: 'GCP_OrgPolicyAdmin',
    name: 'Org Policy Admin',
    permissions: ['orgpolicy.policy.set'],
    description: 'Attacker can modify org policies to remove guardrails',
    severity: 'critical',
    remediation: 'Restrict org policy modification',
  },
  {
    id: 'GCP_CloudShellAttach',
    name: 'Cloud Shell Attach',
    permissions: ['cloudshell.environments.get'],
    description: 'Attacker can attach to existing Cloud Shell sessions',
    severity: 'warning',
    remediation: 'Disable Cloud Shell if not needed',
  },
  {
    id: 'GCP_CloudBuildWorkerPool',
    name: 'Cloud Build Worker Pool',
    permissions: ['cloudbuild.workerPools.create'],
    description: 'Attacker can create worker pools in VPCs for lateral movement',
    severity: 'warning',
    remediation: 'Restrict workerPools.create',
  },
];

/**
 * Dangerous IAM action patterns
 * Used for quick policy analysis without full simulation
 */
const DANGEROUS_IAM_PATTERNS = {
  aws: [
    // Full admin
    { pattern: '*', severity: 'critical', category: 'admin' },
    { pattern: 'iam:*', severity: 'critical', category: 'iam-admin' },
    { pattern: 'sts:*', severity: 'critical', category: 'sts-admin' },
    
    // Privilege escalation enablers
    { pattern: 'iam:Create*', severity: 'warning', category: 'iam-create' },
    { pattern: 'iam:Attach*', severity: 'critical', category: 'iam-attach' },
    { pattern: 'iam:Put*', severity: 'critical', category: 'iam-put' },
    { pattern: 'iam:Update*', severity: 'warning', category: 'iam-update' },
    { pattern: 'iam:PassRole', severity: 'critical', category: 'passrole' },
    
    // Data exfiltration
    { pattern: 's3:GetObject', severity: 'info', category: 'data-read' },
    { pattern: 's3:*', severity: 'warning', category: 's3-admin' },
    { pattern: 'secretsmanager:GetSecretValue', severity: 'warning', category: 'secrets' },
    { pattern: 'ssm:GetParameter*', severity: 'warning', category: 'secrets' },
    { pattern: 'kms:Decrypt', severity: 'warning', category: 'crypto' },
    
    // Persistence
    { pattern: 'lambda:CreateFunction', severity: 'warning', category: 'persistence' },
    { pattern: 'lambda:UpdateFunctionCode', severity: 'warning', category: 'persistence' },
    { pattern: 'events:PutRule', severity: 'info', category: 'persistence' },
    
    // Defense evasion
    { pattern: 'cloudtrail:*', severity: 'critical', category: 'logging' },
    { pattern: 'guardduty:*', severity: 'critical', category: 'detection' },
    { pattern: 'securityhub:*', severity: 'critical', category: 'detection' },
    { pattern: 'config:*', severity: 'warning', category: 'compliance' },
  ],
  
  azure: [
    { pattern: '*/write', severity: 'warning', category: 'write' },
    { pattern: '*/delete', severity: 'warning', category: 'delete' },
    { pattern: '*', severity: 'critical', category: 'admin' },
    { pattern: 'Microsoft.Authorization/*', severity: 'critical', category: 'rbac' },
    { pattern: 'Microsoft.KeyVault/vaults/secrets/*', severity: 'warning', category: 'secrets' },
    { pattern: 'Microsoft.Compute/virtualMachines/extensions/*', severity: 'critical', category: 'execution' },
  ],
  
  gcp: [
    { pattern: '*', severity: 'critical', category: 'admin' },
    { pattern: 'iam.*', severity: 'critical', category: 'iam' },
    { pattern: '*.setIamPolicy', severity: 'critical', category: 'iam' },
    { pattern: 'resourcemanager.*', severity: 'warning', category: 'org' },
    { pattern: 'secretmanager.secrets.*', severity: 'warning', category: 'secrets' },
  ],
};

/**
 * Analyze IAM policy document for security issues
 * @param {object} policy - IAM policy document
 * @param {string} provider - Cloud provider
 * @returns {array} Security findings
 */
function analyzePolicy(policy, provider = 'aws') {
  const findings = [];
  const patterns = DANGEROUS_IAM_PATTERNS[provider] || [];
  
  const statements = policy.Statement || policy.statements || [];
  
  for (const statement of statements) {
    if (statement.Effect !== 'Allow') continue;
    
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
    
    for (const action of actions) {
      for (const pattern of patterns) {
        if (matchPattern(action, pattern.pattern)) {
          // Check if resource is wildcarded (more dangerous)
          const hasWildcardResource = resources.some(r => r === '*');
          const severity = hasWildcardResource ? pattern.severity : 
            (pattern.severity === 'critical' ? 'warning' : 'info');
          
          findings.push({
            action,
            pattern: pattern.pattern,
            category: pattern.category,
            severity,
            resources,
            hasCondition: !!statement.Condition,
          });
        }
      }
    }
  }
  
  return findings;
}

/**
 * Match action against pattern (supports wildcards)
 */
function matchPattern(action, pattern) {
  if (pattern === '*') return action === '*';
  if (action === '*') return true;
  
  // Convert pattern to regex
  const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
  return regex.test(action);
}

/**
 * Calculate policy risk score
 * @param {array} findings - Policy analysis findings
 * @returns {object} Risk score and breakdown
 */
function calculateRiskScore(findings) {
  let score = 0;
  const breakdown = {
    critical: 0,
    warning: 0,
    info: 0,
    categories: {},
  };
  
  for (const finding of findings) {
    switch (finding.severity) {
      case 'critical':
        score += 100;
        breakdown.critical++;
        break;
      case 'warning':
        score += 25;
        breakdown.warning++;
        break;
      case 'info':
        score += 5;
        breakdown.info++;
        break;
    }
    
    breakdown.categories[finding.category] = 
      (breakdown.categories[finding.category] || 0) + 1;
  }
  
  // Cap at 1000
  score = Math.min(score, 1000);
  
  return {
    score,
    level: score >= 500 ? 'critical' : score >= 200 ? 'high' : score >= 50 ? 'medium' : 'low',
    breakdown,
  };
}

/**
 * Get all privesc techniques
 */
function getAllTechniques() {
  return {
    aws: ADDITIONAL_AWS_TECHNIQUES,
    azure: ADDITIONAL_AZURE_TECHNIQUES,
    gcp: ADDITIONAL_GCP_TECHNIQUES,
  };
}

module.exports = {
  ADDITIONAL_AWS_TECHNIQUES,
  ADDITIONAL_AZURE_TECHNIQUES,
  ADDITIONAL_GCP_TECHNIQUES,
  DANGEROUS_IAM_PATTERNS,
  analyzePolicy,
  calculateRiskScore,
  getAllTechniques,
};
