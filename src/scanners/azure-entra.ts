/**
 * Azure Entra ID (Azure AD) + PIM Scanner
 * Scans Entra ID for privileged roles, risky configurations, and PIM settings
 */

import type { Finding, ScanOptions, Severity } from '../types';

// Graph API types
interface DirectoryRole {
  roleTemplateId?: string;
  displayName?: string;
  members?: DirectoryMember[];
}

interface DirectoryMember {
  '@odata.type'?: string;
  userPrincipalName?: string;
  userType?: string;
  displayName?: string;
}

interface RoleAssignment {
  roleDefinitionId?: string;
  principalId?: string;
  endDateTime?: string;
  assignmentType?: string;
  startDateTime?: string;
}

interface RoleManagementPolicy {
  id?: string;
}

interface PolicyRule {
  '@odata.type'?: string;
  isExpirationRequired?: boolean;
  maximumDuration?: string;
  isEnabled?: boolean;
  setting?: {
    isApprovalRequired?: boolean;
  };
}

interface AppRegistration {
  id?: string;
  displayName?: string;
  requiredResourceAccess?: ResourceAccess[];
  passwordCredentials?: Credential[];
  keyCredentials?: Credential[];
}

interface ResourceAccess {
  resourceAppId?: string;
  resourceAccess?: Array<{
    id?: string;
    type?: string;
  }>;
}

interface Credential {
  startDateTime?: string;
  endDateTime?: string;
}

interface ServicePrincipal {
  id?: string;
  displayName?: string;
  appRoleAssignments?: unknown[];
}

interface ConditionalAccessPolicy {
  state?: string;
  grantControls?: {
    builtInControls?: string[];
  };
  conditions?: {
    clientAppTypes?: string[];
    signInRiskLevels?: string[];
  };
}

interface GuestUser {
  id?: string;
  displayName?: string;
  userPrincipalName?: string;
  createdDateTime?: string;
  signInActivity?: {
    lastSignInDateTime?: string;
  };
}

interface GraphClient {
  api(path: string): GraphRequest;
}

interface GraphRequest {
  expand(field: string): GraphRequest;
  select(fields: string): GraphRequest;
  filter(query: string): GraphRequest;
  top(count: number): GraphRequest;
  get(): Promise<{ value?: unknown[]; data?: unknown }>;
}

/**
 * Scan Azure Entra ID for security issues
 */
export async function scanEntraID(_options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { Client } = await import('@microsoft/microsoft-graph-client');
    const { TokenCredentialAuthenticationProvider } =
      await import('@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials');

    // Initialize Graph client
    const credential = new DefaultAzureCredential();
    const authProvider = new TokenCredentialAuthenticationProvider(credential, {
      scopes: ['https://graph.microsoft.com/.default'],
    });

    const graphClient = Client.initWithMiddleware({ authProvider }) as GraphClient;

    // 1. Scan Directory Roles (Global Admin, etc.)
    console.log('  Scanning Entra ID directory roles...');
    const roleFindings = await scanDirectoryRoles(graphClient);
    findings.push(...roleFindings);

    // 2. Scan PIM Role Assignments
    console.log('  Scanning PIM role assignments...');
    const pimFindings = await scanPIMRoleAssignments(graphClient);
    findings.push(...pimFindings);

    // 3. Scan PIM Settings
    console.log('  Scanning PIM settings...');
    const pimSettingsFindings = await scanPIMSettings(graphClient);
    findings.push(...pimSettingsFindings);

    // 4. Scan App Registrations
    console.log('  Scanning app registrations...');
    const appFindings = await scanAppRegistrations(graphClient);
    findings.push(...appFindings);

    // 5. Scan Service Principals
    console.log('  Scanning service principals...');
    const spFindings = await scanServicePrincipals(graphClient);
    findings.push(...spFindings);

    // 6. Scan Conditional Access Policies
    console.log('  Scanning conditional access policies...');
    const caFindings = await scanConditionalAccess(graphClient);
    findings.push(...caFindings);

    // 7. Scan Guest Users
    console.log('  Scanning guest users...');
    const guestFindings = await scanGuestUsers(graphClient);
    findings.push(...guestFindings);
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error(
        'Microsoft Graph SDK not installed. Run: npm install @microsoft/microsoft-graph-client @azure/identity'
      );
    } else if (err.code === 'Authorization_RequestDenied') {
      findings.push({
        id: 'azure-entra-permission-denied',
        severity: 'info',
        resource: 'EntraID',
        message: 'Unable to access Entra ID. Ensure app has Directory.Read.All permission.',
        recommendation: 'Grant Directory.Read.All and RoleManagement.Read.All to the scanner app',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Directory Roles for privileged assignments
 */
async function scanDirectoryRoles(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Critical roles to monitor
  const criticalRoles: Record<string, string> = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
    'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
    '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
  };

  try {
    // Get all directory roles with members
    const roles = await graphClient.api('/directoryRoles').expand('members').get();

    for (const role of (roles.value || []) as DirectoryRole[]) {
      const roleTemplateId = role.roleTemplateId;
      const roleName = role.displayName;
      const members = role.members || [];

      // Check if this is a critical role
      if (roleTemplateId && criticalRoles[roleTemplateId]) {
        // Too many Global Admins
        if (roleTemplateId === '62e90394-69f5-4237-9190-012177145e10') {
          if (members.length > 5) {
            findings.push({
              id: 'azure-too-many-global-admins',
              severity: 'warning',
              resource: 'EntraID/GlobalAdministrators',
              message: `${members.length} Global Administrators (recommended: 2-5)`,
              recommendation: 'Reduce Global Administrators. Use specific admin roles instead.',
              cis: '1.1.1',
            });
          }
          if (members.length < 2) {
            findings.push({
              id: 'azure-single-global-admin',
              severity: 'info',
              resource: 'EntraID/GlobalAdministrators',
              message: 'Only 1 Global Administrator configured',
              recommendation: 'Have at least 2 Global Administrators for redundancy',
              cis: '1.1.2',
            });
          }
        }

        // Check each member of critical roles
        for (const member of members) {
          // Guest users in privileged roles
          if (member.userType === 'Guest') {
            findings.push({
              id: 'azure-guest-privileged-role',
              severity: 'critical',
              resource: `EntraID/${roleName}/${member.userPrincipalName}`,
              message: `Guest user ${member.userPrincipalName} has ${roleName} role`,
              recommendation: 'Remove guest users from privileged roles',
              cis: '1.3',
            });
          }

          // Service principals in Global Admin (risky)
          if (
            member['@odata.type'] === '#microsoft.graph.servicePrincipal' &&
            roleTemplateId === '62e90394-69f5-4237-9190-012177145e10'
          ) {
            findings.push({
              id: 'azure-sp-global-admin',
              severity: 'critical',
              resource: `EntraID/GlobalAdministrator/${member.displayName}`,
              message: `Service Principal ${member.displayName} has Global Administrator role`,
              recommendation: 'Use more specific roles for service principals',
            });
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan PIM Role Assignments
 */
async function scanPIMRoleAssignments(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get active role assignments
    const activeAssignments = await graphClient
      .api('/roleManagement/directory/roleAssignmentScheduleInstances')
      .get();

    // Get eligible role assignments
    const eligibleAssignments = await graphClient
      .api('/roleManagement/directory/roleEligibilityScheduleInstances')
      .get();

    // Check for permanent (non-PIM) assignments to privileged roles
    for (const assignment of (activeAssignments.value || []) as RoleAssignment[]) {
      // Permanent assignments (no end date)
      if (!assignment.endDateTime && assignment.assignmentType === 'Assigned') {
        findings.push({
          id: 'azure-permanent-privileged-assignment',
          severity: 'warning',
          resource: `EntraID/PIM/${assignment.roleDefinitionId}`,
          message: `Permanent (non-expiring) role assignment to ${assignment.principalId}`,
          recommendation: 'Use PIM eligible assignments instead of permanent active assignments',
          cis: '1.1.4',
        });
      }
    }

    // Check for stale eligible assignments (not activated in 90+ days)
    const now = new Date();
    for (const assignment of (eligibleAssignments.value || []) as RoleAssignment[]) {
      // This would need audit log analysis for actual activation times
      // For now, flag assignments older than 1 year
      if (assignment.startDateTime) {
        const startDate = new Date(assignment.startDateTime);
        const daysSinceStart = (now.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24);

        if (daysSinceStart > 365) {
          findings.push({
            id: 'azure-stale-eligible-assignment',
            severity: 'info',
            resource: `EntraID/PIM/${assignment.roleDefinitionId}`,
            message: `Eligible assignment created ${Math.floor(daysSinceStart)} days ago`,
            recommendation: 'Review if this eligible assignment is still needed',
          });
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan PIM Settings for weak configurations
 */
async function scanPIMSettings(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get role management policies
    const policies = await graphClient.api('/policies/roleManagementPolicies').get();

    for (const policy of (policies.value || []) as RoleManagementPolicy[]) {
      // Get policy rules
      const rules = await graphClient
        .api(`/policies/roleManagementPolicies/${policy.id}/rules`)
        .get();

      for (const rule of (rules.value || []) as PolicyRule[]) {
        // Check activation rules
        if (rule['@odata.type'] === '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule') {
          // Maximum activation duration
          if (rule.isExpirationRequired === false) {
            findings.push({
              id: 'azure-pim-no-expiration',
              severity: 'warning',
              resource: `EntraID/PIM/Policy/${policy.id}`,
              message: 'PIM role has no activation expiration requirement',
              recommendation: 'Require activation expiration for privileged roles',
            });
          }

          // Long activation duration (> 8 hours)
          if (rule.maximumDuration) {
            const duration = parseDuration(rule.maximumDuration);
            if (duration > 8 * 60 * 60 * 1000) {
              // 8 hours in ms
              findings.push({
                id: 'azure-pim-long-activation',
                severity: 'info',
                resource: `EntraID/PIM/Policy/${policy.id}`,
                message: `PIM activation duration is ${rule.maximumDuration} (recommended: 1-8 hours)`,
                recommendation: 'Reduce maximum activation duration',
              });
            }
          }
        }

        // Check MFA requirement
        if (
          rule['@odata.type'] ===
          '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'
        ) {
          if (!rule.isEnabled) {
            findings.push({
              id: 'azure-pim-no-mfa',
              severity: 'warning',
              resource: `EntraID/PIM/Policy/${policy.id}`,
              message: 'PIM role does not require MFA for activation',
              recommendation: 'Require MFA for all privileged role activations',
              cis: '1.1.3',
            });
          }
        }

        // Check approval requirement
        if (rule['@odata.type'] === '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule') {
          if (!rule.setting?.isApprovalRequired) {
            // Only flag for critical roles
            findings.push({
              id: 'azure-pim-no-approval',
              severity: 'info',
              resource: `EntraID/PIM/Policy/${policy.id}`,
              message: 'PIM role does not require approval for activation',
              recommendation: 'Consider requiring approval for critical roles',
            });
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan App Registrations for risky permissions
 */
async function scanAppRegistrations(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Dangerous Microsoft Graph permissions
  const dangerousPermissions: Record<string, { name: string; severity: Severity }> = {
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9': {
      name: 'Application.ReadWrite.All',
      severity: 'critical',
    },
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7': {
      name: 'Directory.ReadWrite.All',
      severity: 'critical',
    },
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8': {
      name: 'RoleManagement.ReadWrite.Directory',
      severity: 'critical',
    },
    'e12dae10-5a57-4817-b79d-dfbec5c3b589': { name: 'Mail.ReadWrite', severity: 'warning' },
    '75359482-378d-4052-8f01-80520e7db3cd': { name: 'Files.ReadWrite.All', severity: 'warning' },
    '01d4889c-1287-42c6-ac1f-5d1e02578ef6': { name: 'Files.Read.All', severity: 'info' },
  };

  try {
    const apps = await graphClient
      .api('/applications')
      .select('id,displayName,requiredResourceAccess,passwordCredentials,keyCredentials')
      .get();

    for (const app of (apps.value || []) as AppRegistration[]) {
      // Check for dangerous permissions
      for (const resource of app.requiredResourceAccess || []) {
        // Microsoft Graph permissions
        if (resource.resourceAppId === '00000003-0000-0000-c000-000000000000') {
          for (const access of resource.resourceAccess || []) {
            if (access.id && dangerousPermissions[access.id]) {
              const perm = dangerousPermissions[access.id];
              const isAppPermission = access.type === 'Role';

              findings.push({
                id: `azure-app-${perm.severity}-permission`,
                severity: isAppPermission ? perm.severity : 'info',
                resource: `EntraID/App/${app.displayName}`,
                message: `App has ${perm.name} (${isAppPermission ? 'Application' : 'Delegated'})`,
                recommendation: 'Review if this permission is necessary',
              });
            }
          }
        }
      }

      // Check for expiring/expired credentials
      for (const cred of [...(app.passwordCredentials || []), ...(app.keyCredentials || [])]) {
        if (cred.endDateTime) {
          const endDate = new Date(cred.endDateTime);
          const now = new Date();
          const daysUntilExpiry = (endDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

          if (daysUntilExpiry < 0) {
            findings.push({
              id: 'azure-app-expired-credential',
              severity: 'warning',
              resource: `EntraID/App/${app.displayName}`,
              message: `App has expired credential (expired ${Math.abs(Math.floor(daysUntilExpiry))} days ago)`,
              recommendation: 'Remove expired credentials',
            });
          } else if (daysUntilExpiry < 30) {
            findings.push({
              id: 'azure-app-expiring-credential',
              severity: 'info',
              resource: `EntraID/App/${app.displayName}`,
              message: `App credential expires in ${Math.floor(daysUntilExpiry)} days`,
              recommendation: 'Rotate credential before expiry',
            });
          }
        }

        // Check for long-lived credentials (> 2 years)
        if (cred.startDateTime && cred.endDateTime) {
          const duration =
            new Date(cred.endDateTime).getTime() - new Date(cred.startDateTime).getTime();
          const years = duration / (1000 * 60 * 60 * 24 * 365);

          if (years > 2) {
            findings.push({
              id: 'azure-app-long-credential',
              severity: 'info',
              resource: `EntraID/App/${app.displayName}`,
              message: `App credential has ${Math.floor(years)} year validity`,
              recommendation: 'Use shorter credential lifetimes (< 1 year)',
            });
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan Service Principals
 */
async function scanServicePrincipals(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get service principals with app role assignments
    const servicePrincipals = await graphClient
      .api('/servicePrincipals')
      .filter("servicePrincipalType eq 'Application'")
      .select('id,displayName,appRoleAssignments')
      .top(100)
      .get();

    for (const sp of (servicePrincipals.value || []) as ServicePrincipal[]) {
      if ((sp.appRoleAssignments?.length || 0) > 10) {
        findings.push({
          id: 'azure-sp-many-permissions',
          severity: 'info',
          resource: `EntraID/ServicePrincipal/${sp.displayName}`,
          message: `Service Principal has ${sp.appRoleAssignments!.length} app role assignments`,
          recommendation: 'Review if all assignments are necessary',
        });
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan Conditional Access Policies
 */
async function scanConditionalAccess(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const policies = await graphClient.api('/identity/conditionalAccess/policies').get();

    // Check if no CA policies exist
    if (!policies.value || policies.value.length === 0) {
      findings.push({
        id: 'azure-no-conditional-access',
        severity: 'critical',
        resource: 'EntraID/ConditionalAccess',
        message: 'No Conditional Access policies configured',
        recommendation: 'Implement Conditional Access policies for Zero Trust security',
      });
      return findings;
    }

    // Check for specific policy requirements
    let hasMFAPolicy = false;
    let hasBlockLegacyAuth = false;
    let hasRiskySignInPolicy = false;

    for (const policy of policies.value as ConditionalAccessPolicy[]) {
      if (policy.state !== 'enabled') continue;

      const grantControls = policy.grantControls;
      const conditions = policy.conditions;

      // MFA requirement
      if (grantControls?.builtInControls?.includes('mfa')) {
        hasMFAPolicy = true;
      }

      // Block legacy authentication
      if (
        grantControls?.builtInControls?.includes('block') &&
        conditions?.clientAppTypes?.includes('other')
      ) {
        hasBlockLegacyAuth = true;
      }

      // Sign-in risk policy
      if (conditions?.signInRiskLevels && conditions.signInRiskLevels.length > 0) {
        hasRiskySignInPolicy = true;
      }
    }

    if (!hasMFAPolicy) {
      findings.push({
        id: 'azure-no-mfa-policy',
        severity: 'warning',
        resource: 'EntraID/ConditionalAccess',
        message: 'No Conditional Access policy requiring MFA',
        recommendation: 'Create a policy requiring MFA for all users',
        cis: '1.1.3',
      });
    }

    if (!hasBlockLegacyAuth) {
      findings.push({
        id: 'azure-legacy-auth-allowed',
        severity: 'warning',
        resource: 'EntraID/ConditionalAccess',
        message: 'Legacy authentication is not blocked',
        recommendation: 'Create a policy to block legacy authentication protocols',
        cis: '1.1.6',
      });
    }

    if (!hasRiskySignInPolicy) {
      findings.push({
        id: 'azure-no-risk-policy',
        severity: 'info',
        resource: 'EntraID/ConditionalAccess',
        message: 'No sign-in risk-based Conditional Access policy',
        recommendation: 'Create policies that respond to risky sign-ins',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Scan Guest Users
 */
async function scanGuestUsers(graphClient: GraphClient): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const guests = await graphClient
      .api('/users')
      .filter("userType eq 'Guest'")
      .select('id,displayName,userPrincipalName,createdDateTime,signInActivity')
      .get();

    const now = new Date();

    for (const guest of (guests.value || []) as GuestUser[]) {
      // Check for stale guest accounts (no sign-in in 90+ days)
      if (guest.signInActivity?.lastSignInDateTime) {
        const lastSignIn = new Date(guest.signInActivity.lastSignInDateTime);
        const daysSinceSignIn = (now.getTime() - lastSignIn.getTime()) / (1000 * 60 * 60 * 24);

        if (daysSinceSignIn > 90) {
          findings.push({
            id: 'azure-stale-guest',
            severity: 'info',
            resource: `EntraID/Guest/${guest.userPrincipalName}`,
            message: `Guest user has not signed in for ${Math.floor(daysSinceSignIn)} days`,
            recommendation: 'Review and remove inactive guest accounts',
          });
        }
      }

      // Check for old guest accounts without activity
      if (guest.createdDateTime) {
        const created = new Date(guest.createdDateTime);
        const daysSinceCreation = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);

        if (daysSinceCreation > 365 && !guest.signInActivity?.lastSignInDateTime) {
          findings.push({
            id: 'azure-old-unused-guest',
            severity: 'warning',
            resource: `EntraID/Guest/${guest.userPrincipalName}`,
            message: `Guest user created ${Math.floor(daysSinceCreation)} days ago with no sign-in activity`,
            recommendation: 'Remove unused guest accounts',
          });
        }
      }
    }

    // Too many guest users warning
    if (guests.value && guests.value.length > 100) {
      findings.push({
        id: 'azure-many-guests',
        severity: 'info',
        resource: 'EntraID/Guests',
        message: `${guests.value.length} guest users in directory`,
        recommendation: 'Regularly review and clean up guest accounts',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: string };
    if (err.code !== 'Authorization_RequestDenied') throw error;
  }

  return findings;
}

/**
 * Parse ISO 8601 duration to milliseconds
 */
function parseDuration(duration: string): number {
  const match = duration.match(/PT(\d+H)?(\d+M)?(\d+S)?/);
  if (!match) return 0;

  let ms = 0;
  if (match[1]) ms += parseInt(match[1], 10) * 60 * 60 * 1000;
  if (match[2]) ms += parseInt(match[2], 10) * 60 * 1000;
  if (match[3]) ms += parseInt(match[3], 10) * 1000;

  return ms;
}
