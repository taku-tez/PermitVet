/**
 * Azure RBAC Scanner
 * Scans Azure Role-Based Access Control for security issues based on CIS benchmarks
 */

import type { Finding, ScanOptions, Severity } from '../types';
import { createFinding, handleScanError, logProgress, logError } from '../utils';

// Azure SDK types
interface RoleAssignment {
  name?: string;
  roleDefinitionId?: string;
  principalId?: string;
  principalType?: string;
  scope?: string;
}

interface RoleDefinition {
  id?: string;
  roleName?: string;
  permissions?: Permission[];
  assignableScopes?: string[];
}

interface Permission {
  actions?: string[];
  notActions?: string[];
  dataActions?: string[];
}

interface ClassicAdministrator {
  role?: string;
}

interface DangerousRole {
  name: string;
  severity: Severity;
  cis: string | null;
}

/**
 * Scan Azure RBAC for permission issues
 */
export async function scanAzure(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');
    const { SubscriptionClient } = await import('@azure/arm-subscriptions');

    const credential = new DefaultAzureCredential();

    // Get subscription ID from options or environment
    let subscriptionId = options.subscription || process.env.AZURE_SUBSCRIPTION_ID;

    // If no subscription specified, list available ones
    if (!subscriptionId) {
      const subClient = new SubscriptionClient(credential) as any;
      const subscriptions: Array<{ subscriptionId?: string; displayName?: string }> = [];
      for await (const sub of subClient.subscriptions.list()) {
        subscriptions.push(sub);
      }

      if (subscriptions.length === 0) {
        logError('No Azure subscriptions found. Check your credentials.');
        return findings;
      }

      // Use first subscription if only one, otherwise ask
      if (subscriptions.length === 1) {
        subscriptionId = subscriptions[0].subscriptionId;
        logProgress(`Using subscription: ${subscriptions[0].displayName}`);
      } else {
        logError('Multiple subscriptions found. Use --subscription to specify one:');
        for (const sub of subscriptions) {
          logError(`  - ${sub.subscriptionId} (${sub.displayName})`);
        }
        return findings;
      }
    }

    const authClient = new AuthorizationManagementClient(credential, subscriptionId!);

    // 1. Scan Role Assignments
    logProgress('Scanning role assignments...');
    const assignmentFindings = await scanRoleAssignments(authClient, subscriptionId!);
    findings.push(...assignmentFindings);

    // 2. Scan Custom Role Definitions
    logProgress('Scanning custom roles...');
    const roleFindings = await scanCustomRoles(authClient, subscriptionId!);
    findings.push(...roleFindings);

    // 3. Scan Classic Administrators (deprecated)
    logProgress('Checking classic administrators...');
    const classicFindings = await scanClassicAdmins(authClient, subscriptionId!);
    findings.push(...classicFindings);
  } catch (error) {
    const result = handleScanError(error, { provider: 'azure' });
    if (result.shouldThrow) {
      throw error;
    }
    logError(result.message);
  }

  return findings;
}

/**
 * Scan Role Assignments for risky configurations
 */
async function scanRoleAssignments(
  authClient: InstanceType<typeof import('@azure/arm-authorization').AuthorizationManagementClient>,
  subscriptionId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get all role assignments at subscription scope
    const assignments: RoleAssignment[] = [];
    for await (const assignment of authClient.roleAssignments.listForSubscription()) {
      assignments.push(assignment as RoleAssignment);
    }

    // Get role definitions for lookup
    const roleDefinitions = new Map<string, RoleDefinition>();
    for await (const role of authClient.roleDefinitions.list(`/subscriptions/${subscriptionId}`)) {
      roleDefinitions.set(role.id!, role as RoleDefinition);
    }

    // Built-in dangerous role IDs
    const dangerousRoles: Record<string, DangerousRole> = {
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': { name: 'Owner', severity: 'warning', cis: '1.21' },
      'b24988ac-6180-42a0-ab88-20f7382dd24c': { name: 'Contributor', severity: 'info', cis: null },
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': {
        name: 'User Access Administrator',
        severity: 'warning',
        cis: null,
      },
    };

    for (const assignment of assignments) {
      const roleDefId = assignment.roleDefinitionId;
      const roleDef = roleDefinitions.get(roleDefId!);
      const roleName = roleDef?.roleName || roleDefId?.split('/').pop();
      const principalId = assignment.principalId;
      const principalType = assignment.principalType || 'Unknown';
      const scope = assignment.scope;

      // Check for subscription-level Owner assignments (CIS 1.21)
      const roleId = roleDefId?.split('/').pop();
      if (roleId && dangerousRoles[roleId]) {
        const danger = dangerousRoles[roleId];

        // Subscription-scope assignments are more concerning
        if (scope === `/subscriptions/${subscriptionId}`) {
          findings.push({
            id: `azure-sub-${danger.name.toLowerCase().replace(/ /g, '-')}`,
            severity: danger.severity,
            resource: `Subscription/${subscriptionId}`,
            message: `${principalType} ${principalId} has ${danger.name} role at subscription level`,
            recommendation: `Review if ${danger.name} access is necessary. Apply least privilege.`,
            cis: danger.cis || undefined,
          });
        }
      }

      // Check for wildcard scope (Management Group root or very broad)
      if (scope === '/' || scope?.startsWith('/providers/Microsoft.Management/managementGroups/')) {
        findings.push({
          id: 'azure-broad-scope',
          severity: 'warning',
          resource: `Scope/${scope}`,
          message: `${principalType} ${principalId} has ${roleName} at broad scope`,
          recommendation: 'Prefer subscription or resource group level assignments',
        });
      }

      // Check for external guest users (CIS 1.3)
      if (principalType === 'Guest') {
        findings.push({
          id: 'azure-guest-rbac',
          severity: 'warning',
          resource: `RoleAssignment/${assignment.name}`,
          message: `Guest user ${principalId} has ${roleName} role`,
          recommendation:
            'Review guest user access regularly. Remove unnecessary guest assignments.',
          cis: '1.3',
        });
      }

      // Check for service principals with high-privilege roles
      if (principalType === 'ServicePrincipal' && roleId && dangerousRoles[roleId]) {
        findings.push({
          id: 'azure-sp-high-privilege',
          severity: 'warning',
          resource: `ServicePrincipal/${principalId}`,
          message: `Service Principal has ${roleName} role`,
          recommendation: 'Use least-privilege custom roles for service principals',
        });
      }
    }

    // Check for too many Owners (CIS 1.22, 1.23)
    const owners = assignments.filter(a =>
      a.roleDefinitionId?.endsWith('8e3af657-a8ff-443c-a75c-2fe8c4bcb635')
    );
    if (owners.length > 3) {
      findings.push({
        id: 'azure-too-many-owners',
        severity: 'warning',
        resource: `Subscription/${subscriptionId}`,
        message: `Subscription has ${owners.length} Owners (recommended: 3 or fewer)`,
        recommendation: 'Limit Owner assignments to reduce blast radius',
        cis: '1.22',
      });
    }

    if (owners.length < 2) {
      findings.push({
        id: 'azure-single-owner',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'Subscription has fewer than 2 Owners',
        recommendation: 'Have at least 2 Owners for redundancy',
        cis: '1.23',
      });
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode === 403) {
      findings.push({
        id: 'azure-permission-denied',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'Unable to list role assignments',
        recommendation:
          'Ensure scanner has Microsoft.Authorization/roleAssignments/read permission',
      });
    }
  }

  return findings;
}

/**
 * Scan Custom Role Definitions for dangerous permissions
 */
async function scanCustomRoles(
  authClient: InstanceType<typeof import('@azure/arm-authorization').AuthorizationManagementClient>,
  subscriptionId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List custom roles (type = CustomRole)
    const roles: RoleDefinition[] = [];
    for await (const role of authClient.roleDefinitions.list(`/subscriptions/${subscriptionId}`, {
      filter: "type eq 'CustomRole'",
    })) {
      roles.push(role as RoleDefinition);
    }

    // Dangerous actions that enable privilege escalation
    const dangerousActions: Array<{ action: string; severity: Severity; msg: string }> = [
      { action: '*', severity: 'critical', msg: 'Wildcard permissions (full access)' },
      { action: '*/write', severity: 'critical', msg: 'Broad write access' },
      { action: '*/delete', severity: 'warning', msg: 'Broad delete access' },
      {
        action: 'Microsoft.Authorization/*',
        severity: 'critical',
        msg: 'Full authorization control',
      },
      { action: 'Microsoft.Authorization/*/write', severity: 'critical', msg: 'Can modify RBAC' },
      {
        action: 'Microsoft.Authorization/roleAssignments/write',
        severity: 'critical',
        msg: 'Can assign roles',
      },
      {
        action: 'Microsoft.Authorization/roleDefinitions/write',
        severity: 'critical',
        msg: 'Can create roles',
      },
      {
        action: 'Microsoft.Authorization/elevateAccess/Action',
        severity: 'critical',
        msg: 'Can elevate to User Access Admin',
      },
      {
        action: 'Microsoft.Compute/virtualMachines/extensions/write',
        severity: 'warning',
        msg: 'Can install VM extensions (code execution)',
      },
      {
        action: 'Microsoft.Compute/virtualMachines/runCommand/action',
        severity: 'warning',
        msg: 'Can run commands on VMs',
      },
      {
        action: 'Microsoft.KeyVault/vaults/secrets/*',
        severity: 'warning',
        msg: 'Full secrets access',
      },
      {
        action: 'Microsoft.Storage/storageAccounts/listKeys/action',
        severity: 'warning',
        msg: 'Can list storage account keys',
      },
      {
        action: 'Microsoft.Web/sites/publishxml/action',
        severity: 'warning',
        msg: 'Can get publish credentials',
      },
      {
        action: 'Microsoft.ContainerRegistry/registries/credentials/action',
        severity: 'warning',
        msg: 'Can get container registry creds',
      },
    ];

    for (const role of roles) {
      const roleName = role.roleName;
      const permissions = role.permissions || [];

      for (const perm of permissions) {
        const actions = perm.actions || [];
        const notActions = perm.notActions || [];
        const dataActions = perm.dataActions || [];

        // Check for dangerous actions
        for (const action of [...actions, ...dataActions]) {
          for (const da of dangerousActions) {
            // Wildcard match
            if (
              action === da.action ||
              (da.action.includes('*') && matchWildcard(action, da.action)) ||
              (action.includes('*') && matchWildcard(da.action, action))
            ) {
              // Check if blocked by notActions
              const blocked = notActions.some(na => matchWildcard(action, na));
              if (blocked) continue;

              findings.push({
                id: `azure-custom-role-${da.action.replace(/[/*]/g, '-')}`,
                severity: da.severity,
                resource: `CustomRole/${roleName}`,
                message: `Custom role has action: ${action} - ${da.msg}`,
                recommendation: 'Review if this permission is necessary',
              });
            }
          }
        }

        // Check for assignable scopes
        const assignableScopes = role.assignableScopes || [];
        for (const scope of assignableScopes) {
          if (scope === '/' || scope === '/subscriptions') {
            findings.push({
              id: 'azure-custom-role-broad-scope',
              severity: 'warning',
              resource: `CustomRole/${roleName}`,
              message: 'Custom role can be assigned at root or all subscriptions',
              recommendation:
                'Limit assignable scopes to specific subscriptions or resource groups',
            });
          }
        }

        // Privilege escalation detection
        const canAssignRoles = actions.some(
          a => a === '*' || a === 'Microsoft.Authorization/*' || a.includes('roleAssignments/write')
        );

        const canCreateRoles = actions.some(
          a => a === '*' || a === 'Microsoft.Authorization/*' || a.includes('roleDefinitions/write')
        );

        if (canAssignRoles && !roleName?.toLowerCase().includes('admin')) {
          findings.push({
            id: 'azure-privesc-role-assignment',
            severity: 'critical',
            resource: `CustomRole/${roleName}`,
            message: 'Non-admin custom role can assign roles (privilege escalation)',
            recommendation: 'Role assignment permissions should be tightly controlled',
          });
        }

        if (canCreateRoles) {
          findings.push({
            id: 'azure-privesc-role-creation',
            severity: 'critical',
            resource: `CustomRole/${roleName}`,
            message: 'Custom role can create/modify role definitions (privilege escalation)',
            recommendation: 'Role definition permissions should be tightly controlled',
          });
        }
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode === 403) {
      findings.push({
        id: 'azure-roles-permission-denied',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'Unable to list custom role definitions',
        recommendation:
          'Ensure scanner has Microsoft.Authorization/roleDefinitions/read permission',
      });
    }
  }

  return findings;
}

/**
 * Scan Classic Administrators (deprecated, but still in use)
 */
async function scanClassicAdmins(
  authClient: InstanceType<typeof import('@azure/arm-authorization').AuthorizationManagementClient>,
  subscriptionId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const admins: ClassicAdministrator[] = [];
    for await (const admin of authClient.classicAdministrators.list()) {
      admins.push(admin as ClassicAdministrator);
    }

    // Classic admins should be migrated to RBAC
    if (admins.length > 0) {
      findings.push({
        id: 'azure-classic-admins-exist',
        severity: 'warning',
        resource: `Subscription/${subscriptionId}`,
        message: `${admins.length} classic administrator(s) found`,
        recommendation:
          'Migrate classic administrators to RBAC. Classic admin roles are deprecated.',
        cis: '1.24',
      });

      // Check for co-administrators
      const coAdmins = admins.filter(a => a.role === 'CoAdministrator');
      if (coAdmins.length > 0) {
        findings.push({
          id: 'azure-co-administrators',
          severity: 'warning',
          resource: `Subscription/${subscriptionId}`,
          message: `${coAdmins.length} Co-Administrator(s) found`,
          recommendation: 'Remove Co-Administrators and use RBAC roles instead',
        });
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    // Classic admin API may not be available in all subscriptions
    if (err.statusCode !== 404 && err.statusCode !== 403) {
      throw error;
    }
  }

  return findings;
}

/**
 * Match wildcard patterns
 */
function matchWildcard(str: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return str === pattern;

  const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
  return regex.test(str);
}
