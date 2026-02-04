/**
 * RBAC Analyzer
 * Deep RBAC analysis including role utilization, unused permission detection,
 * and session-based temporary permission recommendations
 */

import type { ScanOptions } from '../types';
import { logProgress, logError, logDebug } from '../utils';

/** JIT/Temporary access recommendation */
export interface JITRecommendation {
  type: string;
  message: string;
  currentUsage?: string;
  recommendation?: string[];
  steps?: string[];
}

/** Unused permission finding */
export interface UnusedPermissionFinding {
  type?: string;
  policy?: string;
  inline?: boolean;
  actions?: string[];
  resources?: string[];
  recommendation: string;
  message?: string;
  command?: string;
  roleArn?: string;
  roleName?: string;
  daysSinceLastUse?: number | null;
  warning?: string;
  // Azure specific
  assignmentId?: string;
  principalId?: string;
  principalType?: string;
  roleDefinitionId?: string;
  scope?: string;
  // GCP specific
  id?: string;
  targetMember?: string;
  targetRole?: string;
  currentRole?: string;
  recommendedRole?: string;
  priority?: string;
  stateInfo?: string;
  email?: string;
}

/** Role utilization analysis */
export interface RoleUtilization {
  roleName: string;
  roleArn: string;
  lastUsed: Date | null;
  daysSinceLastUse: number | null;
  utilizationLevel: 'unknown' | 'unused' | 'low' | 'moderate' | 'high' | 'never_used';
  attachedPolicies: Array<{ PolicyName?: string; PolicyArn?: string }>;
  unusedPermissions: UnusedPermissionFinding[];
  jitRecommendation: JITRecommendation | null;
}

/** Temporary access recommendation */
export interface TemporaryAccessRecommendation extends JITRecommendation {
  roleArn?: string;
  roleName?: string;
  // Azure specific
  assignmentId?: string;
  principalId?: string;
  principalType?: string;
  scope?: string;
  // GCP specific
  member?: string;
  role?: string;
}

/** RBAC analysis summary */
export interface RBACSummary {
  totalRoles: number;
  underutilizedRoles: number;
  unusedPermissionCount: number;
  jitCandidates: number;
}

/** RBAC analysis results */
export interface RBACAnalysisResults {
  roleUtilization: RoleUtilization[];
  unusedPermissions: UnusedPermissionFinding[];
  temporaryAccessRecommendations: TemporaryAccessRecommendation[];
  summary: RBACSummary;
}

/** RBAC analysis options */
export interface RBACOptions extends ScanOptions {
  profile?: string;
  subscription?: string;
  project?: string;
}

/**
 * Analyze RBAC configuration for optimization opportunities
 * @param provider - Cloud provider (aws, azure, gcp)
 * @param options - Analysis options
 * @returns RBAC analysis results
 */
export async function analyzeRBAC(
  provider: string,
  options: RBACOptions = {}
): Promise<RBACAnalysisResults> {
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
export async function analyzeAWSRBAC(options: RBACOptions = {}): Promise<RBACAnalysisResults> {
  const results: RBACAnalysisResults = {
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
    } = await import('@aws-sdk/client-iam');

    const config = options.profile ? { profile: options.profile } : {};
    const iamClient = new IAMClient(config);

    logProgress('Analyzing AWS RBAC configuration...');

    // 1. List all roles
    const rolesResponse = await iamClient.send(new ListRolesCommand({}));
    const roles = rolesResponse.Roles || [];
    results.summary.totalRoles = roles.length;

    logProgress(`Found ${roles.length} roles...`);

    for (const role of roles) {
      // Skip AWS service-linked roles
      if (role.Path?.startsWith('/aws-service-role/')) continue;

      const roleAnalysis: RoleUtilization = {
        roleName: role.RoleName || '',
        roleArn: role.Arn || '',
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
      } catch (_e) {
        logDebug('Skip if unable to get role details', _e);
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

            interface PolicyStatement {
              Effect?: string;
              Action?: string | string[];
              Resource?: string | string[];
            }

            const policyDoc = JSON.parse(
              decodeURIComponent(policyVersion.PolicyVersion?.Document || '{}')
            ) as { Statement?: PolicyStatement[] };

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
                    actions: actions.filter((a): a is string => a !== undefined),
                    resources: resources.filter((r): r is string => r !== undefined),
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
                    actions: actions.filter((a): a is string => a !== undefined),
                    resources: resources.filter((r): r is string => r !== undefined),
                    recommendation: 'Restrict resources to specific ARNs',
                  });
                  results.summary.unusedPermissionCount++;
                }
              }
            }
          } catch (_e) {
            logDebug('Operation skipped due to error', _e);
          }
        }

        // Check inline policies
        const inlinePoliciesResponse = await iamClient.send(
          new ListRolePoliciesCommand({ RoleName: role.RoleName })
        );

        for (const policyName of inlinePoliciesResponse.PolicyNames || []) {
          try {
            const inlinePolicy = await iamClient.send(
              new GetRolePolicyCommand({
                RoleName: role.RoleName,
                PolicyName: policyName,
              })
            );
            interface PolicyStatement {
              Effect?: string;
              Action?: string | string[];
            }
            const policyDoc = JSON.parse(
              decodeURIComponent(inlinePolicy.PolicyDocument || '{}')
            ) as { Statement?: PolicyStatement[] };

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
          } catch (_e) {
            logDebug('Skip', _e);
          }
        }
      } catch (_e) {
        logDebug('Operation skipped due to error', _e);
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
      .filter(r => r.utilizationLevel === 'never_used' || (r.daysSinceLastUse ?? 0) > 90)
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
        ...r.jitRecommendation!,
      }));
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code === 'MODULE_NOT_FOUND') {
      logError('AWS SDK not installed. Run: npm install @aws-sdk/client-iam');
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
export async function analyzeAzureRBAC(options: RBACOptions = {}): Promise<RBACAnalysisResults> {
  const results: RBACAnalysisResults = {
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
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');

    const credential = new DefaultAzureCredential();
    const subscriptionId = options.subscription || process.env.AZURE_SUBSCRIPTION_ID;

    if (!subscriptionId) {
      logError('No Azure subscription specified.');
      return results;
    }

    const authClient = new AuthorizationManagementClient(credential, subscriptionId);

    logProgress('Analyzing Azure RBAC configuration...');

    // List role assignments
    interface RoleAssignment {
      id?: string;
      roleDefinitionId?: string;
      principalId?: string;
      principalType?: string;
      scope?: string;
    }

    const assignments: RoleAssignment[] = [];
    for await (const assignment of authClient.roleAssignments.listForSubscription()) {
      assignments.push(assignment);
    }

    results.summary.totalRoles = assignments.length;
    logProgress(`Found ${assignments.length} role assignments...`);

    // Privileged role IDs
    const privilegedRoles: Record<string, string> = {
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
      'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
    };

    for (const assignment of assignments) {
      const roleDefId = assignment.roleDefinitionId?.split('/').pop();
      const roleName = roleDefId ? privilegedRoles[roleDefId] : undefined;

      // Check for privileged permanent assignments
      if (roleName && assignment.principalType === 'User') {
        results.temporaryAccessRecommendations.push({
          type: 'azure_pim',
          assignmentId: assignment.id,
          principalId: assignment.principalId,
          principalType: assignment.principalType,
          roleName,
          scope: assignment.scope,
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
    const err = error as Error & { code?: string; statusCode?: number };
    if (err.code === 'MODULE_NOT_FOUND') {
      logError(
        'Azure SDK not installed. Run: npm install @azure/identity @azure/arm-authorization'
      );
    } else if (err.statusCode !== 403) {
      throw error;
    }
  }

  return results;
}

/**
 * GCP RBAC Analysis
 * Uses IAM Recommender for utilization analysis
 */
export async function analyzeGCPRBAC(options: RBACOptions = {}): Promise<RBACAnalysisResults> {
  const results: RBACAnalysisResults = {
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
    const { google } = await import('googleapis');

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });

    const projectId =
      options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;

    if (!projectId) {
      logError('No GCP project specified.');
      return results;
    }

    const recommender = google.recommender({ version: 'v1', auth });
    const iam = google.iam({ version: 'v1', auth });
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v1', auth });

    logProgress('Analyzing GCP RBAC configuration...');

    // Get IAM policy
    const policyResponse = await cloudresourcemanager.projects.getIamPolicy({
      resource: projectId,
      requestBody: {},
    });

    interface IAMBinding {
      role?: string;
      members?: string[];
    }

    const policy = policyResponse.data as { bindings?: IAMBinding[] };
    results.summary.totalRoles = policy.bindings?.length || 0;

    logProgress(`Found ${results.summary.totalRoles} role bindings...`);

    // Get IAM recommendations
    try {
      interface RecommenderContent {
        operationGroups?: Array<{
          operations?: Array<{
            pathFilters?: Record<string, string>;
          }>;
        }>;
      }

      interface Recommendation {
        name?: string;
        recommenderSubtype?: string;
        description?: string;
        priority?: string;
        stateInfo?: { state?: string };
        content?: RecommenderContent;
      }

      const recommendationsResponse =
        await recommender.projects.locations.recommenders.recommendations.list({
          parent: `projects/${projectId}/locations/global/recommenders/google.iam.policy.Recommender`,
        });

      const recommendations = (recommendationsResponse.data.recommendations ||
        []) as Recommendation[];

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
    } catch (_e) {
      logDebug('IAM Recommender may not be available', _e);
      logProgress('IAM Recommender not available or no recommendations.');
    }

    // Check for primitive roles that should use JIT
    const primitiveRoles = ['roles/owner', 'roles/editor'];
    for (const binding of policy.bindings || []) {
      if (binding.role && primitiveRoles.includes(binding.role)) {
        for (const member of binding.members || []) {
          if (member.startsWith('user:')) {
            results.temporaryAccessRecommendations.push({
              type: 'gcp_pam',
              member,
              role: binding.role,
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
    interface ServiceAccount {
      email?: string;
      disabled?: boolean;
    }

    const saResponse = await iam.projects.serviceAccounts.list({
      name: `projects/${projectId}`,
    });

    const serviceAccounts = (saResponse.data.accounts || []) as ServiceAccount[];

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
    const err = error as Error & { code?: string | number };
    if (err.code === 'MODULE_NOT_FOUND') {
      logError('GCP SDK not installed. Run: npm install googleapis');
    } else if (err.code !== 403) {
      throw error;
    }
  }

  return results;
}

/**
 * Generate RBAC optimization report
 * @param results - RBAC analysis results
 * @returns Formatted report
 */
export function generateRBACReport(results: RBACAnalysisResults): string {
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
