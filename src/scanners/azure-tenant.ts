/**
 * Azure Tenant Scanner
 * Tenant-wide IAM analysis, Management Group hierarchy, cross-subscription permissions
 */

import type { Finding, ScanOptions, Severity } from '../types';

// Azure SDK types
interface ManagementGroup {
  name?: string;
  children?: ManagementGroupChild[];
}

interface ManagementGroupChild {
  name?: string;
  type?: string;
}

interface RoleAssignmentResponse {
  value?: RoleAssignment[];
}

interface RoleAssignment {
  properties?: {
    roleDefinitionId?: string;
    principalId?: string;
    principalType?: string;
  };
}

interface RoleDefinitionResponse {
  value?: RoleDefinition[];
}

interface RoleDefinition {
  properties?: {
    roleName?: string;
    permissions?: Permission[];
  };
}

interface Permission {
  actions?: string[];
  dataActions?: string[];
}

interface Subscription {
  id?: string;
  subscriptionId?: string;
  displayName?: string;
}

interface SubscriptionAccess {
  subscription: string;
  displayName?: string;
  role: string;
}

/**
 * Scan Azure Tenant for IAM issues
 */
export async function scanAzureTenant(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { DefaultAzureCredential } = await import('@azure/identity');

    const credential = new DefaultAzureCredential();

    const tenantId = options.tenant;
    const managementGroupId = options.managementGroup;
    const allSubscriptions = options.allSubscriptions;

    if (tenantId || managementGroupId) {
      // Tenant/Management Group scan
      const mgId = managementGroupId || tenantId; // Root MG often has tenant ID
      console.log(`  Scanning management group: ${mgId}...`);

      // 1. Management Group IAM Policy
      console.log('  Checking management group role assignments...');
      const mgIamFindings = await scanManagementGroupIAM(credential, mgId!);
      findings.push(...mgIamFindings);

      // 2. Management Group Hierarchy Analysis
      console.log('  Analyzing management group hierarchy...');
      const hierarchyFindings = await analyzeManagementGroupHierarchy(credential, mgId!);
      findings.push(...hierarchyFindings);

      // 3. Tenant-level Custom Role Definitions
      console.log('  Scanning tenant custom roles...');
      const roleFindings = await scanTenantCustomRoles(credential, mgId!);
      findings.push(...roleFindings);

      // 4. All subscriptions (if requested)
      if (allSubscriptions) {
        console.log('  Scanning all subscriptions...');
        const subFindings = await scanAllSubscriptions(credential, mgId!);
        findings.push(...subFindings);
      }
    } else if (allSubscriptions) {
      // Scan all accessible subscriptions without MG context
      console.log('  Scanning all accessible subscriptions...');
      const subFindings = await scanAccessibleSubscriptions(credential);
      findings.push(...subFindings);
    } else {
      findings.push({
        id: 'azure-tenant-no-target',
        severity: 'info',
        resource: 'Azure',
        message: 'Specify --tenant, --management-group, or --all-subscriptions',
        recommendation: 'Use --tenant <id> for full tenant scan',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: string; statusCode?: number };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error(
        'Azure SDK not installed. Run: npm install @azure/identity @azure/arm-managementgroups @azure/arm-authorization @azure/arm-subscriptions'
      );
    } else if (err.statusCode === 403 || err.code === 'AuthorizationFailed') {
      findings.push({
        id: 'azure-tenant-permission-denied',
        severity: 'warning',
        resource: 'Tenant',
        message: 'Unable to access tenant-level resources',
        recommendation: 'Ensure scanner has Management Group Reader role at root',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Management Group Role Assignments
 */
async function scanManagementGroupIAM(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  managementGroupId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const token = await credential.getToken('https://management.azure.com/.default');

    const mgScope = `/providers/Microsoft.Management/managementGroups/${managementGroupId}`;
    const url = `https://management.azure.com${mgScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token.token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 403) {
        findings.push({
          id: 'azure-mg-iam-denied',
          severity: 'info',
          resource: `ManagementGroup/${managementGroupId}`,
          message: 'Unable to read management group role assignments',
          recommendation: 'Need Microsoft.Authorization/roleAssignments/read at MG scope',
        });
        return findings;
      }
      throw new Error(`API error: ${response.status}`);
    }

    const data = (await response.json()) as RoleAssignmentResponse;
    const assignments = data.value || [];

    // Privileged role definition IDs
    const privilegedRoles: Record<string, string> = {
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
      'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
      'fb1c8493-542b-48eb-b624-b4c8fea62acd': 'Security Admin',
    };

    const roleCounts: Record<string, number> = {};

    for (const assignment of assignments) {
      const roleDefId = assignment.properties?.roleDefinitionId?.split('/').pop();
      const roleName = roleDefId ? privilegedRoles[roleDefId] : undefined;
      const principalType = assignment.properties?.principalType;
      const principalId = assignment.properties?.principalId;

      // Track role counts
      if (roleName) {
        roleCounts[roleName] = (roleCounts[roleName] || 0) + 1;
      }

      // Critical: Owner at MG level
      if (roleName === 'Owner') {
        findings.push({
          id: 'azure-mg-owner',
          severity: 'critical',
          resource: `ManagementGroup/${managementGroupId}`,
          message: `${principalType} has Owner role at management group level`,
          recommendation: 'Avoid Owner role at MG level. Use more specific roles.',
          details: { principalId, principalType },
        });
      }

      // Service Principal with elevated MG permissions
      if (principalType === 'ServicePrincipal' && roleName) {
        findings.push({
          id: 'azure-mg-sp-privileged',
          severity: 'warning',
          resource: `ManagementGroup/${managementGroupId}`,
          message: `Service Principal has ${roleName} at management group level`,
          recommendation: 'Service Principals should not have MG-level privileged roles',
          details: { principalId },
        });
      }
    }

    // Summary of privileged role counts at MG
    for (const [role, count] of Object.entries(roleCounts)) {
      if (count > 3 && role !== 'Contributor') {
        findings.push({
          id: 'azure-mg-too-many-privileged',
          severity: 'warning',
          resource: `ManagementGroup/${managementGroupId}`,
          message: `${count} principals have ${role} role`,
          recommendation: 'Review if all principals need MG-level access',
        });
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Analyze Management Group Hierarchy
 */
async function analyzeManagementGroupHierarchy(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  rootMgId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ManagementGroupsAPI } = await import('@azure/arm-managementgroups');
    const mgClient = new ManagementGroupsAPI(credential);

    // Get MG with expanded children
    const mgDetail = (await mgClient.managementGroups.get(rootMgId, {
      expand: 'children',
      recurse: true,
    })) as ManagementGroup;

    // Analyze hierarchy
    const analyzeNode = async (node: ManagementGroup, depth = 0): Promise<void> => {
      if (depth > 6) {
        findings.push({
          id: 'azure-mg-too-deep',
          severity: 'info',
          resource: `ManagementGroup/${node.name}`,
          message: `Management group hierarchy depth exceeds 6 levels`,
          recommendation: 'Consider flattening hierarchy for simpler governance',
        });
        return;
      }

      const children = node.children || [];
      const subscriptions = children.filter(c => c.type === '/subscriptions');
      const childMGs = children.filter(c => c.type?.includes('managementGroups'));

      // Too many direct subscriptions
      if (subscriptions.length > 20) {
        findings.push({
          id: 'azure-mg-many-subs',
          severity: 'info',
          resource: `ManagementGroup/${node.name}`,
          message: `${subscriptions.length} subscriptions directly under management group`,
          recommendation: 'Consider organizing into child management groups',
        });
      }

      // Check each child MG's role assignments
      for (const childMG of childMGs) {
        const childFindings = await scanManagementGroupIAM(credential, childMG.name!);
        findings.push(...childFindings);

        // Recurse
        try {
          const childDetail = (await mgClient.managementGroups.get(childMG.name!, {
            expand: 'children',
            recurse: false,
          })) as ManagementGroup;
          await analyzeNode(childDetail, depth + 1);
        } catch {
          // Skip if can't access child
        }
      }
    };

    await analyzeNode(mgDetail);
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan Tenant Custom Role Definitions
 */
async function scanTenantCustomRoles(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  managementGroupId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const token = await credential.getToken('https://management.azure.com/.default');

    // List custom role definitions at MG scope
    const mgScope = `/providers/Microsoft.Management/managementGroups/${managementGroupId}`;
    const url = `https://management.azure.com${mgScope}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=type eq 'CustomRole'`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token.token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 403) return findings;
      throw new Error(`API error: ${response.status}`);
    }

    const data = (await response.json()) as RoleDefinitionResponse;
    const roles = data.value || [];

    // Dangerous permissions/actions
    const dangerousActions = [
      '*/write',
      '*/delete',
      'Microsoft.Authorization/*/write',
      'Microsoft.Authorization/roleAssignments/write',
      'Microsoft.Authorization/roleDefinitions/write',
      'Microsoft.ManagedIdentity/*/write',
      'Microsoft.KeyVault/vaults/secrets/*',
    ];

    for (const role of roles) {
      const roleName = role.properties?.roleName;
      const permissions = role.properties?.permissions || [];

      for (const perm of permissions) {
        const actions = [...(perm.actions || []), ...(perm.dataActions || [])];

        // Check for dangerous actions
        const dangerous = actions.filter(a =>
          dangerousActions.some(d => a.includes(d.replace('*', '')))
        );

        if (dangerous.length > 0) {
          findings.push({
            id: 'azure-tenant-role-dangerous',
            severity: 'warning',
            resource: `CustomRole/${roleName}`,
            message: `Tenant-level custom role has ${dangerous.length} dangerous action(s)`,
            recommendation: 'Review dangerous permissions in tenant-level custom roles',
            details: { dangerousActions: dangerous.slice(0, 5) },
          });
        }

        // Check for wildcard actions at resource provider level
        const wildcardRPs = actions.filter(a => a.match(/^[^/]+\/\*$/));
        if (wildcardRPs.length > 0) {
          findings.push({
            id: 'azure-tenant-role-wildcard-rp',
            severity: 'warning',
            resource: `CustomRole/${roleName}`,
            message: `Custom role grants full access to ${wildcardRPs.length} resource provider(s)`,
            recommendation: 'Avoid wildcard permissions on resource providers',
          });
        }
      }
    }

    // Role count summary
    if (roles.length > 30) {
      findings.push({
        id: 'azure-tenant-many-custom-roles',
        severity: 'info',
        resource: `ManagementGroup/${managementGroupId}`,
        message: `${roles.length} custom roles defined at tenant/MG level`,
        recommendation: 'Review if all tenant-level roles are necessary',
      });
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan All Subscriptions under Management Group
 */
async function scanAllSubscriptions(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>,
  managementGroupId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { ManagementGroupsAPI } = await import('@azure/arm-managementgroups');
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');

    const mgClient = new ManagementGroupsAPI(credential);

    // Get all descendants (subscriptions)
    const descendants: Subscription[] = [];
    for await (const desc of mgClient.managementGroupSubscriptions.listSubscriptionsUnderManagementGroup(
      managementGroupId
    )) {
      descendants.push(desc as Subscription);
    }

    console.log(`  Found ${descendants.length} subscriptions...`);

    // Cross-subscription analysis
    const principalAccess = new Map<string, SubscriptionAccess[]>();

    for (const sub of descendants) {
      const subscriptionId = sub.id?.split('/').pop();
      if (!subscriptionId) continue;

      try {
        const authClient = new AuthorizationManagementClient(credential, subscriptionId);

        // Get role assignments
        for await (const assignment of authClient.roleAssignments.listForSubscription()) {
          const roleDefId = (assignment as { roleDefinitionId?: string }).roleDefinitionId
            ?.split('/')
            .pop();
          const principalId = (assignment as { principalId?: string }).principalId;
          const principalType = (assignment as { principalType?: string }).principalType;

          // Track privileged access
          const privilegedRoleIds = [
            '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', // Owner
            'b24988ac-6180-42a0-ab88-20f7382dd24c', // Contributor
          ];

          if (roleDefId && privilegedRoleIds.includes(roleDefId)) {
            const key = `${principalType}:${principalId}`;
            if (!principalAccess.has(key)) {
              principalAccess.set(key, []);
            }
            principalAccess.get(key)!.push({
              subscription: subscriptionId,
              role: roleDefId === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' ? 'Owner' : 'Contributor',
            });
          }
        }
      } catch {
        // Skip subscriptions we can't access
      }
    }

    // Analyze cross-subscription permissions
    for (const [principal, access] of principalAccess) {
      const [principalType, principalId] = principal.split(':');

      if (access.length > 5) {
        findings.push({
          id: 'azure-cross-sub-privileged',
          severity: 'warning',
          resource: principal,
          message: `${principalType} has privileged access to ${access.length} subscriptions`,
          recommendation: 'Review if cross-subscription privileged access is necessary',
          details: {
            principalType,
            subscriptionCount: access.length,
            subscriptions: access.slice(0, 5).map(a => a.subscription),
          },
        });
      }

      // Service Principals with multi-subscription access
      if (principalType === 'ServicePrincipal' && access.length > 3) {
        findings.push({
          id: 'azure-sp-multi-sub',
          severity: 'warning',
          resource: principalId,
          message: `Service Principal has privileged access to ${access.length} subscriptions`,
          recommendation: 'Service Principals should be scoped to minimal subscriptions',
        });
      }
    }

    // Subscription count summary
    findings.push({
      id: 'azure-subscription-count',
      severity: 'info',
      resource: `ManagementGroup/${managementGroupId}`,
      message: `${descendants.length} subscriptions scanned`,
      recommendation: '',
    });
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan all accessible subscriptions (without MG context)
 */
async function scanAccessibleSubscriptions(
  credential: InstanceType<typeof import('@azure/identity').DefaultAzureCredential>
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { SubscriptionClient } = await import('@azure/arm-subscriptions');
    const { AuthorizationManagementClient } = await import('@azure/arm-authorization');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const subClient = new SubscriptionClient(credential) as any;

    const subscriptions: Subscription[] = [];
    for await (const sub of subClient.subscriptions.list()) {
      subscriptions.push(sub as Subscription);
    }

    console.log(`  Found ${subscriptions.length} accessible subscriptions...`);

    const principalAccess = new Map<string, SubscriptionAccess[]>();

    for (const sub of subscriptions) {
      try {
        const authClient = new AuthorizationManagementClient(credential, sub.subscriptionId!);

        for await (const assignment of authClient.roleAssignments.listForSubscription()) {
          const roleDefId = (assignment as { roleDefinitionId?: string }).roleDefinitionId
            ?.split('/')
            .pop();
          const principalId = (assignment as { principalId?: string }).principalId;
          const principalType = (assignment as { principalType?: string }).principalType;

          const privilegedRoleIds = [
            '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
            'b24988ac-6180-42a0-ab88-20f7382dd24c',
          ];

          if (roleDefId && privilegedRoleIds.includes(roleDefId)) {
            const key = `${principalType}:${principalId}`;
            if (!principalAccess.has(key)) {
              principalAccess.set(key, []);
            }
            principalAccess.get(key)!.push({
              subscription: sub.subscriptionId!,
              displayName: sub.displayName,
              role: roleDefId === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' ? 'Owner' : 'Contributor',
            });
          }
        }
      } catch {
        // Skip
      }
    }

    // Analyze
    for (const [principal, access] of principalAccess) {
      if (access.length > 5) {
        const [principalType] = principal.split(':');
        findings.push({
          id: 'azure-cross-sub-privileged',
          severity: 'warning',
          resource: principal,
          message: `${principalType} has privileged access to ${access.length} subscriptions`,
          recommendation: 'Review cross-subscription privileged access',
        });
      }
    }

    findings.push({
      id: 'azure-subscription-count',
      severity: 'info',
      resource: 'Tenant',
      message: `${subscriptions.length} subscriptions scanned`,
      recommendation: '',
    });
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}
