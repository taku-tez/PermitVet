/**
 * Azure Advanced RBAC Scanner
 * Management Group inheritance, Inherited Roles, Deny Assignments
 */

import type { Finding, ScanOptions } from '../types';
import { createFinding, handleScanError, logProgress, logError, logDebug } from '../utils';

// Azure SDK types
interface ManagementGroup {
  name?: string;
  properties?: {
    details?: {
      parent?: {
        id?: string;
      };
    };
    children?: ManagementGroupChild[];
  };
}

interface ManagementGroupChild {
  name?: string;
  type?: string;
}

interface RoleAssignment {
  roleDefinitionId?: string;
  principalId?: string;
  principalType?: string;
  scope?: string;
}

interface DenyAssignment {
  name?: string;
  denyAssignmentName?: string;
  scope?: string;
  isSystemProtected?: boolean;
}

/**
 * Scan Azure advanced RBAC features
 */
export async function scanAzureAdvanced(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { DefaultAzureCredential } = await import('@azure/identity');

    const credential = new DefaultAzureCredential();

    // Get subscription
    const subscriptionId = options.subscription || process.env.AZURE_SUBSCRIPTION_ID;

    if (!subscriptionId) {
      logProgress('No subscription specified, scanning management groups only...');
    }

    // 1. Management Group Analysis
    logProgress('Analyzing Management Groups...');
    const mgFindings = await analyzeManagementGroups(credential, subscriptionId);
    findings.push(...mgFindings);

    // 2. Inherited Role Assignments
    if (subscriptionId) {
      logProgress('Checking inherited role assignments...');
      const inheritedFindings = await checkInheritedRoles(credential, subscriptionId);
      findings.push(...inheritedFindings);
    }

    // 3. Deny Assignments
    if (subscriptionId) {
      logProgress('Checking Deny Assignments...');
      const denyFindings = await checkDenyAssignments(credential, subscriptionId);
      findings.push(...denyFindings);
    }
  } catch (error) {
    const result = handleScanError(error, { provider: 'azure', operation: 'advanced scan' });
    if (result.type === 'sdk_not_installed') {
      logError(result.message);
    } else if (result.type === 'permission_denied') {
      findings.push(
        createFinding(
          'azure-advanced-permission-denied',
          'Azure',
          'Unable to access advanced Azure features',
          'info',
          'Ensure scanner has Management Group Reader role'
        )
      );
    } else if (result.shouldThrow) {
      throw error;
    }
  }

  return findings;
}

/**
 * Analyze Management Group hierarchy
 */
async function analyzeManagementGroups(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  _subscriptionId?: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ManagementGroupsAPI } = await import('@azure/arm-managementgroups');
    const mgClient = new ManagementGroupsAPI(credential);

    // List all management groups
    const managementGroups: ManagementGroup[] = [];
    for await (const mg of mgClient.managementGroups.list()) {
      managementGroups.push(mg as ManagementGroup);
    }

    if (managementGroups.length === 0) {
      findings.push(
        createFinding(
          'azure-no-management-groups',
          'Azure',
          'No management group hierarchy configured',
          'info',
          'Use management groups for centralized governance at scale'
        )
      );
      return findings;
    }

    // Analyze each management group
    for (const mg of managementGroups) {
      try {
        // Get detailed info including children
        const mgDetail = (await mgClient.managementGroups.get(mg.name!, {
          expand: 'children',
          recurse: true,
        })) as ManagementGroup;

        // Check hierarchy depth
        let depth = 0;
        const current = mgDetail;
        while (current.properties?.details?.parent) {
          depth++;
          if (depth > 6) {
            findings.push(
              createFinding(
                'azure-mg-deep-hierarchy',
                `ManagementGroup/${mg.name}`,
                'Management group hierarchy is very deep (>6 levels)',
                'info',
                'Consider flattening the hierarchy for simpler governance'
              )
            );
            break;
          }
          break; // Only checking immediate parent
        }

        // Check for subscriptions directly under root
        if (
          mgDetail.properties?.details?.parent?.id?.includes(
            '/providers/Microsoft.Management/managementGroups/'
          ) === false
        ) {
          const children = mgDetail.properties?.children || [];
          const directSubs = children.filter(c => c.type === '/subscriptions');

          if (directSubs.length > 10) {
            findings.push(
              createFinding(
                'azure-mg-many-direct-subs',
                `ManagementGroup/${mg.name}`,
                `${directSubs.length} subscriptions directly under management group`,
                'info',
                'Consider organizing subscriptions into child management groups'
              )
            );
          }
        }
      } catch (e) {
        logDebug("Skip if can't get details", e);
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Check inherited role assignments
 */
async function checkInheritedRoles(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  subscriptionId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');
    const authClient = new AuthorizationManagementClient(credential, subscriptionId);

    // Get all role assignments including inherited
    const assignments: RoleAssignment[] = [];
    for await (const assignment of authClient.roleAssignments.listForSubscription()) {
      assignments.push(assignment as RoleAssignment);
    }

    // Separate inherited vs direct assignments
    const inheritedAssignments = assignments.filter(
      a =>
        !a.scope?.startsWith(`/subscriptions/${subscriptionId}`) ||
        a.scope === `/subscriptions/${subscriptionId}`
    );

    // Check for privileged inherited roles
    const privilegedRoleIds = [
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', // Owner
      'b24988ac-6180-42a0-ab88-20f7382dd24c', // Contributor
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', // User Access Administrator
    ];

    for (const assignment of inheritedAssignments) {
      const roleId = assignment.roleDefinitionId?.split('/').pop();

      if (roleId && privilegedRoleIds.includes(roleId)) {
        // Check if inherited from management group
        if (assignment.scope?.includes('/providers/Microsoft.Management/managementGroups/')) {
          const mgName = assignment.scope.split('/managementGroups/')[1];

          findings.push(
            createFinding(
              'azure-inherited-privileged-from-mg',
              `Subscription/${subscriptionId}`,
              `Privileged role inherited from Management Group: ${mgName}`,
              'warning',
              'Review inherited permissions. Consider subscription-level assignments for better control.',
              {
                details: {
                  roleDefinitionId: assignment.roleDefinitionId,
                  principalId: assignment.principalId,
                  scope: assignment.scope,
                },
              }
            )
          );
        }
      }
    }

    // Count inherited vs direct
    const inheritedCount = inheritedAssignments.length;
    const directCount = assignments.length - inheritedCount;

    if (inheritedCount > directCount * 2) {
      findings.push(
        createFinding(
          'azure-many-inherited-roles',
          `Subscription/${subscriptionId}`,
          `${inheritedCount} inherited vs ${directCount} direct role assignments`,
          'info',
          'High ratio of inherited roles may indicate overly broad MG policies'
        )
      );
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Check Deny Assignments (used by Blueprints and managed apps)
 */
async function checkDenyAssignments(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  subscriptionId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');

    const authClient = new AuthorizationManagementClient(credential, subscriptionId) as any;

    // List deny assignments
    const denyAssignments: DenyAssignment[] = [];
    for await (const deny of authClient.denyAssignments.listForSubscription()) {
      denyAssignments.push(deny as DenyAssignment);
    }

    if (denyAssignments.length === 0) {
      // This is just informational
      findings.push(
        createFinding(
          'azure-no-deny-assignments',
          `Subscription/${subscriptionId}`,
          'No deny assignments configured',
          'info',
          'Consider using Azure Blueprints for immutable resource protection'
        )
      );
      return findings;
    }

    // Analyze deny assignments
    for (const deny of denyAssignments) {
      // Check for system-managed deny assignments (from Blueprints)
      if (deny.isSystemProtected) {
        findings.push(
          createFinding(
            'azure-blueprint-deny',
            deny.scope || 'Unknown',
            `System-protected deny assignment: ${deny.denyAssignmentName}`,
            'info',
            'This is managed by Azure Blueprints - modification requires Blueprint update'
          )
        );
      }

      // Check scope of deny assignment
      if (deny.scope === `/subscriptions/${subscriptionId}`) {
        findings.push(
          createFinding(
            'azure-subscription-deny',
            `Subscription/${subscriptionId}`,
            `Subscription-level deny assignment: ${deny.denyAssignmentName}`,
            'info',
            'Review deny assignment scope and excluded principals'
          )
        );
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}
