/**
 * RBAC Analyzer
 * Deep RBAC analysis including role utilization, unused permission detection,
 * and session-based temporary permission recommendations
 */

/**
 * Analyze RBAC configuration for optimization opportunities
 * @param {string} provider - Cloud provider (aws, azure, gcp)
 * @param {object} options - Analysis options
 * @returns {object} RBAC analysis results
 */
async function analyzeRBAC(provider, options = {}) {
  const results = {
    roleUtilization: [],
    unusedPermissions: [],
    temporaryAccessRecommendations: [],
    summary: {
      totalRoles: 0,
      underutilizedRoles: 0,
      unusedPermissionCount: 0,
      jitCandidates: 0,
    },
  };

  switch (provider.toLowerCase()) {
    case 'aws':
      return analyzeAWSRBAC(options);
    case 'azure':
      return analyzeAzureRBAC(options);
    case 'gcp':
      return analyzeGCPRBAC(options);
    default:
      throw new Error(`RBAC analysis not supported for provider: ${provider}`);
  }
}

/**
 * AWS RBAC Analysis
 * Uses IAM Access Analyzer and CloudTrail for utilization analysis
 */
async function analyzeAWSRBAC(options = {}) {
  const results = {
    roleUtilization: [],
    unusedPermissions: [],
    temporaryAccessRecommendations: [],
    summary: {
      totalRoles: 0,
      underutilizedRoles: 0,
      unusedPermissionCount: 0,
      jitCandidates: 0,
    },
  };

  try {
    const {
      IAMClient,
      ListRolesCommand,
      GetRoleCommand,
      ListAttachedRolePoliciesCommand,
      ListRolePoliciesCommand,
      GetRolePolicyCommand,
      GetPolicyCommand,
      GetPolicyVersionCommand,
    } = require('@aws-sdk/client-iam');
    const {
      AccessAnalyzerClient,
      ListAccessPreviewFindingsCommand,
    } = require('@aws-sdk/client-accessanalyzer');

    const config = options.profile ? { profile: options.profile } : {};
    const iamClient = new IAMClient(config);
    const _accessAnalyzerClient = new AccessAnalyzerClient(config);

    console.log('  Analyzing AWS RBAC configuration...');

    // 1. List all roles
    const rolesResponse = await iamClient.send(new ListRolesCommand({}));
    const roles = rolesResponse.Roles || [];
    results.summary.totalRoles = roles.length;

    console.log(`  Found ${roles.length} roles...`);

    for (const role of roles) {
      // Skip AWS service-linked roles
      if (role.Path?.startsWith('/aws-service-role/')) continue;

      const roleAnalysis = {
        roleName: role.RoleName,
        roleArn: role.Arn,
        lastUsed: null,
        daysSinceLastUse: null,
        utilizationLevel: 'unknown',
        attachedPolicies: [],
        unusedPermissions: [],
        jitRecommendation: null,
      };

      // Get role details including last used
      try {
        const roleDetails = await iamClient.send(new GetRoleCommand({ RoleName: role.RoleName }));
        const lastUsed = roleDetails.Role?.RoleLastUsed?.LastUsedDate;

        if (lastUsed) {
          roleAnalysis.lastUsed = lastUsed;
          roleAnalysis.daysSinceLastUse = Math.floor(
            (Date.now() - new Date(lastUsed).getTime()) / (1000 * 60 * 60 * 24)
          );

          // Classify utilization
          if (roleAnalysis.daysSinceLastUse > 90) {
            roleAnalysis.utilizationLevel = 'unused';
            results.summary.underutilizedRoles++;
          } else if (roleAnalysis.daysSinceLastUse > 30) {
            roleAnalysis.utilizationLevel = 'low';
            results.summary.underutilizedRoles++;
          } else if (roleAnalysis.daysSinceLastUse > 7) {
            roleAnalysis.utilizationLevel = 'moderate';
          } else {
            roleAnalysis.utilizationLevel = 'high';
          }
        } else {
          roleAnalysis.utilizationLevel = 'never_used';
          results.summary.underutilizedRoles++;
        }
      } catch (_err) {
        // Skip if unable to get role details
      }

      // Get attached policies and analyze permissions
      try {
        const attachedPoliciesResponse = await iamClient.send(
          new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName })
        );
        roleAnalysis.attachedPolicies = attachedPoliciesResponse.AttachedPolicies || [];

        // Analyze each attached policy
        for (const policy of roleAnalysis.attachedPolicies) {
          if (policy.PolicyArn?.includes('aws-service-role')) continue;

          try {
            const policyDetails = await iamClient.send(
              new GetPolicyCommand({ PolicyArn: policy.PolicyArn })
            );
            const policyVersion = await iamClient.send(
              new GetPolicyVersionCommand({
                PolicyArn: policy.PolicyArn,
                VersionId: policyDetails.Policy?.DefaultVersionId,
              })
            );

            const policyDoc = JSON.parse(
              decodeURIComponent(policyVersion.PolicyVersion?.Document || '{}')
            );

            // Check for overly broad permissions
            for (const statement of policyDoc.Statement || []) {
              if (statement.Effect === 'Allow') {
                const actions = Array.isArray(statement.Action)
                  ? statement.Action
                  : [statement.Action];
                const resources = Array.isArray(statement.Resource)
                  ? statement.Resource
                  : [statement.Resource];

                // Flag wildcard actions
                if (actions.includes('*') || actions.some(a => a?.endsWith(':*'))) {
                  roleAnalysis.unusedPermissions.push({
                    type: 'overly_broad_action',
                    policy: policy.PolicyName,
                    actions,
                    resources,
                    recommendation:
                      'Replace wildcard actions with specific actions based on actual usage',
                  });
                  results.summary.unusedPermissionCount++;
                }

                // Flag wildcard resources with sensitive actions
                const sensitiveActions = [
                  'iam:*',
                  's3:*',
                  'ec2:*',
                  'lambda:*',
                  'secretsmanager:*',
                  'kms:*',
                ];
                if (
                  resources.includes('*') &&
                  actions.some(a => sensitiveActions.some(sa => a?.startsWith(sa.replace('*', ''))))
                ) {
                  roleAnalysis.unusedPermissions.push({
                    type: 'overly_broad_resource',
                    policy: policy.PolicyName,
                    actions,
                    resources,
                    recommendation: 'Restrict resources to specific ARNs',
                  });
                  results.summary.unusedPermissionCount++;
                }
              }
            }
          } catch (_err) {
            // Skip if unable to get policy details
          }
        }

        // Check inline policies
        const inlinePoliciesResponse = await iamClient.send(
          new ListRolePoliciesCommand({ RoleName: role.RoleName })
        );

        for (const policyName of inlinePoliciesResponse.PolicyNames || []) {
          try {
            const inlinePolicy = await iamClient.send(
              new GetRolePolicyCommand({ RoleName: role.RoleName, PolicyName: policyName })
            );
            const policyDoc = JSON.parse(decodeURIComponent(inlinePolicy.PolicyDocument || '{}'));

            // Similar analysis for inline policies
            for (const statement of policyDoc.Statement || []) {
              if (statement.Effect === 'Allow' && statement.Action === '*') {
                roleAnalysis.unusedPermissions.push({
                  type: 'admin_inline_policy',
                  policy: policyName,
                  inline: true,
                  recommendation: 'Convert to managed policy with least privilege',
                });
                results.summary.unusedPermissionCount++;
              }
            }
          } catch (_err) {
            // Skip
          }
        }
      } catch (_err) {
        // Skip if unable to analyze policies
      }

      // Generate JIT/temporary access recommendation
      if (roleAnalysis.utilizationLevel === 'low' || roleAnalysis.utilizationLevel === 'unused') {
        // Check for privileged permissions
        const hasPrivilegedAccess = roleAnalysis.attachedPolicies.some(
          p =>
            p.PolicyName?.includes('Admin') ||
            p.PolicyArn?.includes('AdministratorAccess') ||
            p.PolicyArn?.includes('PowerUser')
        );

        if (hasPrivilegedAccess) {
          roleAnalysis.jitRecommendation = {
            type: 'aws_sso_jit',
            message: 'Convert to AWS IAM Identity Center (SSO) with time-limited sessions',
            currentUsage: `Last used ${roleAnalysis.daysSinceLastUse || 'never'} days ago`,
            recommendation: [
              'Create equivalent permission set in IAM Identity Center',
              'Set session duration (e.g., 1-4 hours)',
              'Require MFA for assuming the role',
              'Consider AWS Organizations SCP to enforce JIT only',
            ],
          };
          results.summary.jitCandidates++;
        }
      }

      results.roleUtilization.push(roleAnalysis);
    }

    // Generate deletion recommendations for unused roles
    results.unusedPermissions = results.roleUtilization
      .filter(r => r.utilizationLevel === 'never_used' || r.daysSinceLastUse > 90)
      .map(r => ({
        roleArn: r.roleArn,
        roleName: r.roleName,
        daysSinceLastUse: r.daysSinceLastUse,
        recommendation: 'delete',
        command: `aws iam delete-role --role-name ${r.roleName}`,
        warning: 'Ensure no workloads depend on this role before deletion',
      }));

    // Generate temporary access recommendations
    results.temporaryAccessRecommendations = results.roleUtilization
      .filter(r => r.jitRecommendation)
      .map(r => ({
        roleArn: r.roleArn,
        roleName: r.roleName,
        ...r.jitRecommendation,
      }));
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed.');
    } else {
      throw error;
    }
  }

  return results;
}

/**
 * Azure RBAC Analysis
 * Uses Azure PIM and Activity Logs for utilization analysis
 */
async function analyzeAzureRBAC(options = {}) {
  const results = {
    roleUtilization: [],
    unusedPermissions: [],
    temporaryAccessRecommendations: [],
    summary: {
      totalRoles: 0,
      underutilizedRoles: 0,
      unusedPermissionCount: 0,
      jitCandidates: 0,
    },
  };

  try {
    const { DefaultAzureCredential } = require('@azure/identity');
    const { AuthorizationManagementClient } = require('@azure/arm-authorization');

    const credential = new DefaultAzureCredential();
    const subscriptionId = options.subscription || process.env.AZURE_SUBSCRIPTION_ID;

    if (!subscriptionId) {
      console.error('No Azure subscription specified.');
      return results;
    }

    const authClient = new AuthorizationManagementClient(credential, subscriptionId);

    console.log('  Analyzing Azure RBAC configuration...');

    // List role assignments
    const assignments = [];
    for await (const assignment of authClient.roleAssignments.listForSubscription()) {
      assignments.push(assignment);
    }

    results.summary.totalRoles = assignments.length;
    console.log(`  Found ${assignments.length} role assignments...`);

    // Privileged role IDs
    const privilegedRoles = {
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
      'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
    };

    for (const assignment of assignments) {
      const roleDefId = assignment.roleDefinitionId?.split('/').pop();
      const roleName = privilegedRoles[roleDefId];

      // Check for privileged permanent assignments
      if (roleName && assignment.principalType === 'User') {
        results.temporaryAccessRecommendations.push({
          assignmentId: assignment.id,
          principalId: assignment.principalId,
          principalType: assignment.principalType,
          roleName,
          scope: assignment.scope,
          recommendation: 'azure_pim',
          message: `Convert ${roleName} assignment to Azure PIM eligible assignment`,
          steps: [
            `Open Azure Portal > Entra ID > Privileged Identity Management`,
            `Navigate to Azure resources > ${assignment.scope}`,
            `Convert active assignment to eligible`,
            'Set activation duration (e.g., 8 hours max)',
            'Require MFA and approval for activation',
          ],
        });
        results.summary.jitCandidates++;
      }
    }

    // Generate unused role detection findings
    // Note: Full activity log analysis would require additional API access
    results.unusedPermissions = assignments
      .filter(a => a.principalType === 'ServicePrincipal')
      .slice(0, 10) // Limit for now
      .map(a => ({
        assignmentId: a.id,
        principalId: a.principalId,
        principalType: a.principalType,
        roleDefinitionId: a.roleDefinitionId,
        scope: a.scope,
        recommendation: 'review_service_principal',
        message: 'Review Service Principal role assignment for least privilege',
        command: `az role assignment list --assignee ${a.principalId} --all`,
      }));
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('Azure SDK not installed.');
    } else if (error.statusCode !== 403) {
      throw error;
    }
  }

  return results;
}

/**
 * GCP RBAC Analysis
 * Uses IAM Recommender for utilization analysis
 */
async function analyzeGCPRBAC(options = {}) {
  const results = {
    roleUtilization: [],
    unusedPermissions: [],
    temporaryAccessRecommendations: [],
    summary: {
      totalRoles: 0,
      underutilizedRoles: 0,
      unusedPermissionCount: 0,
      jitCandidates: 0,
    },
  };

  try {
    const { google } = require('googleapis');

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });

    const projectId =
      options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;

    if (!projectId) {
      console.error('No GCP project specified.');
      return results;
    }

    const recommender = google.recommender({ version: 'v1', auth });
    const iam = google.iam({ version: 'v1', auth });
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v1', auth });

    console.log('  Analyzing GCP RBAC configuration...');

    // Get IAM policy
    const policyResponse = await cloudresourcemanager.projects.getIamPolicy({
      resource: projectId,
      requestBody: {},
    });

    const policy = policyResponse.data;
    results.summary.totalRoles = policy.bindings?.length || 0;

    console.log(`  Found ${results.summary.totalRoles} role bindings...`);

    // Get IAM recommendations
    try {
      const recommendationsResponse =
        await recommender.projects.locations.recommenders.recommendations.list({
          parent: `projects/${projectId}/locations/global/recommenders/google.iam.policy.Recommender`,
        });

      const recommendations = recommendationsResponse.data.recommendations || [];

      for (const rec of recommendations) {
        if (rec.recommenderSubtype === 'REMOVE_ROLE') {
          results.unusedPermissions.push({
            id: rec.name,
            targetMember:
              rec.content?.operationGroups?.[0]?.operations?.[0]?.pathFilters?.[
                '/iamPolicy/bindings/*/members/*'
              ],
            targetRole:
              rec.content?.operationGroups?.[0]?.operations?.[0]?.pathFilters?.[
                '/iamPolicy/bindings/*/role'
              ],
            priority: rec.priority,
            recommendation: 'remove_role',
            message: rec.description,
            stateInfo: rec.stateInfo?.state,
          });
          results.summary.unusedPermissionCount++;
          results.summary.underutilizedRoles++;
        } else if (rec.recommenderSubtype === 'REPLACE_ROLE') {
          results.unusedPermissions.push({
            id: rec.name,
            targetMember:
              rec.content?.operationGroups?.[0]?.operations?.[0]?.pathFilters?.[
                '/iamPolicy/bindings/*/members/*'
              ],
            currentRole:
              rec.content?.operationGroups?.[0]?.operations?.[0]?.pathFilters?.[
                '/iamPolicy/bindings/*/role'
              ],
            recommendedRole:
              rec.content?.operationGroups?.[1]?.operations?.[0]?.pathFilters?.[
                '/iamPolicy/bindings/*/role'
              ],
            priority: rec.priority,
            recommendation: 'replace_role',
            message: rec.description,
          });
        }
      }
    } catch (_err) {
      // IAM Recommender may not be available
      console.log('  IAM Recommender not available or no recommendations.');
    }

    // Check for primitive roles that should use JIT
    const primitiveRoles = ['roles/owner', 'roles/editor'];
    for (const binding of policy.bindings || []) {
      if (primitiveRoles.includes(binding.role)) {
        for (const member of binding.members || []) {
          if (member.startsWith('user:')) {
            results.temporaryAccessRecommendations.push({
              member,
              role: binding.role,
              recommendation: 'gcp_pam',
              message: 'Convert to Privileged Access Manager (PAM) for just-in-time access',
              steps: [
                'Create PAM entitlement for the role',
                'Set max session duration (e.g., 4 hours)',
                'Require justification for access requests',
                'Configure approval workflow',
                'Remove permanent role binding',
              ],
            });
            results.summary.jitCandidates++;
          }
        }
      }
    }

    // Analyze service accounts
    const saResponse = await iam.projects.serviceAccounts.list({
      name: `projects/${projectId}`,
    });

    const serviceAccounts = saResponse.data.accounts || [];

    for (const sa of serviceAccounts) {
      // Skip Google-managed SAs
      if (
        sa.email?.includes('gserviceaccount.com') &&
        (sa.email.includes('developer.gserviceaccount.com') ||
          sa.email.includes('compute@') ||
          sa.email.includes('cloudservices.gserviceaccount.com'))
      ) {
        continue;
      }

      // Check for unused service accounts
      if (sa.disabled) {
        results.unusedPermissions.push({
          type: 'disabled_service_account',
          email: sa.email,
          recommendation: 'delete_service_account',
          message: 'Service account is disabled but not deleted',
          command: `gcloud iam service-accounts delete ${sa.email} --project=${projectId}`,
        });
        results.summary.unusedPermissionCount++;
      }
    }
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('GCP SDK not installed.');
    } else if (error.code !== 403) {
      throw error;
    }
  }

  return results;
}

/**
 * Generate RBAC optimization report
 * @param {object} results - RBAC analysis results
 * @returns {string} Formatted report
 */
function generateRBACReport(results) {
  let report = '\n📊 RBAC Analysis Report\n';
  report += '═'.repeat(50) + '\n\n';

  // Summary
  report += '📈 Summary\n';
  report += `  Total Roles/Assignments: ${results.summary.totalRoles}\n`;
  report += `  Underutilized: ${results.summary.underutilizedRoles}\n`;
  report += `  Unused Permissions: ${results.summary.unusedPermissionCount}\n`;
  report += `  JIT Candidates: ${results.summary.jitCandidates}\n\n`;

  // Unused Permissions
  if (results.unusedPermissions.length > 0) {
    report += '🗑️ Unused/Overly Broad Permissions\n';
    for (const item of results.unusedPermissions.slice(0, 10)) {
      report += `  • ${item.roleName || item.email || item.targetMember || 'Unknown'}\n`;
      report += `    Recommendation: ${item.recommendation}\n`;
      if (item.command) {
        report += `    Command: ${item.command}\n`;
      }
      report += '\n';
    }
  }

  // JIT Recommendations
  if (results.temporaryAccessRecommendations.length > 0) {
    report += '⏱️ Just-In-Time Access Recommendations\n';
    for (const rec of results.temporaryAccessRecommendations.slice(0, 5)) {
      report += `  • ${rec.roleName || rec.role || 'Privileged Role'}\n`;
      report += `    ${rec.message}\n`;
      if (rec.steps) {
        report += '    Steps:\n';
        for (const step of rec.steps.slice(0, 3)) {
          report += `      - ${step}\n`;
        }
      }
      report += '\n';
    }
  }

  return report;
}

module.exports = {
  analyzeRBAC,
  analyzeAWSRBAC,
  analyzeAzureRBAC,
  analyzeGCPRBAC,
  generateRBACReport,
};
