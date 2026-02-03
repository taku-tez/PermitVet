/**
 * Oracle Cloud Infrastructure (OCI) IAM Scanner
 * Scans OCI for IAM security issues based on best practices
 */

import type { Finding, ScanOptions, Severity } from '../types';
import { createFinding, handleScanError, logProgress, logError } from '../utils';

interface OCIUser {
  id: string;
  name: string;
  description?: string;
  isMfaActivated?: boolean;
  lastSuccessfulLoginTime?: Date;
  lifecycleState: string;
}

interface OCIGroup {
  id: string;
  name: string;
}

interface OCIPolicy {
  name: string;
  statements: string[];
}

interface OCICompartment {
  id: string;
  name: string;
  compartmentId: string;
  lifecycleState: string;
}

interface OCIApiKey {
  fingerprint?: string;
  timeCreated?: string;
  lifecycleState: string;
}

interface OCIAuthToken {
  timeCreated?: string;
}

interface OCIIdentityProvider {
  name: string;
  lifecycleState: string;
}

interface IdentityClient {
  listUsers: (request: { compartmentId: string }) => Promise<{ items?: OCIUser[] }>;
  listGroups: (request: { compartmentId: string }) => Promise<{ items?: OCIGroup[] }>;
  listUserGroupMemberships: (request: {
    compartmentId: string;
    groupId?: string;
  }) => Promise<{ items?: unknown[] }>;
  listPolicies: (request: { compartmentId: string }) => Promise<{ items?: OCIPolicy[] }>;
  listCompartments: (request: {
    compartmentId: string;
    compartmentIdInSubtree?: boolean;
  }) => Promise<{ items?: OCICompartment[] }>;
  listApiKeys: (request: { userId: string }) => Promise<{ items?: OCIApiKey[] }>;
  listAuthTokens: (request: { userId: string }) => Promise<{ items?: OCIAuthToken[] }>;
  listIdentityProviders: (request: {
    compartmentId: string;
    protocol: string;
  }) => Promise<{ items?: OCIIdentityProvider[] }>;
}

// AuthProvider interface removed - using dynamic import

interface DangerousPattern {
  pattern: RegExp;
  severity: Severity;
  msg: string;
}

/**
 * Scan OCI IAM for security issues
 */
export async function scanOCI(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const oci = await import('oci-sdk');
    const common = await import('oci-common');

    // Initialize OCI provider

    let provider: any;
    if (options.configPath) {
      provider = new common.ConfigFileAuthenticationDetailsProvider(
        options.configPath,
        options.profile || 'DEFAULT'
      );
    } else {
      provider = new common.ConfigFileAuthenticationDetailsProvider();
    }

    const identityClient = new oci.identity.IdentityClient({
      authenticationDetailsProvider: provider,
    }) as any;

    // Get tenancy info
    const tenancyId = provider.getTenantId();
    logProgress(`Scanning OCI tenancy: ${tenancyId}...`);

    // 1. Scan Users
    logProgress('Scanning users...');
    const userFindings = await scanUsers(identityClient, tenancyId);
    findings.push(...userFindings);

    // 2. Scan Groups
    logProgress('Scanning groups...');
    const groupFindings = await scanGroups(identityClient, tenancyId);
    findings.push(...groupFindings);

    // 3. Scan Policies
    logProgress('Scanning policies...');
    const policyFindings = await scanPolicies(identityClient, tenancyId);
    findings.push(...policyFindings);

    // 4. Scan Compartments
    logProgress('Scanning compartments...');
    const compartmentFindings = await scanCompartments(identityClient, tenancyId);
    findings.push(...compartmentFindings);

    // 5. Scan API Keys and Auth Tokens
    logProgress('Scanning API keys...');
    const keyFindings = await scanAPIKeys(identityClient, tenancyId);
    findings.push(...keyFindings);

    // 6. Scan Identity Domains (if available)
    logProgress('Scanning identity domains...');
    const domainFindings = await scanIdentityDomains(identityClient, tenancyId);
    findings.push(...domainFindings);
  } catch (error) {
    const result = handleScanError(error, { provider: 'oci', operation: 'tenancy scan' });
    if (result.type === 'sdk_not_installed') {
      logError(result.message);
    } else if (result.type === 'auth_failed') {
      findings.push(
        createFinding(
          'oci-auth-failed',
          'OCI',
          'OCI authentication failed',
          'info',
          'Configure ~/.oci/config with valid credentials'
        )
      );
    } else if (result.shouldThrow) {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan OCI Users
 */
async function scanUsers(identityClient: IdentityClient, tenancyId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const request = {
      compartmentId: tenancyId,
    };

    const response = await identityClient.listUsers(request);
    const users = response.items || [];

    for (const user of users) {
      // Check for users without MFA
      if (!user.isMfaActivated) {
        findings.push(
          createFinding(
            'oci-user-no-mfa',
            `User/${user.name}`,
            'User does not have MFA enabled',
            'warning',
            'Enable MFA for all users with console access'
          )
        );
      }

      // Check for inactive users (no login in 90 days)
      if (user.lastSuccessfulLoginTime) {
        const lastLogin = user.lastSuccessfulLoginTime;
        const daysSinceLogin = (Date.now() - lastLogin.getTime()) / (1000 * 60 * 60 * 24);

        if (daysSinceLogin > 90) {
          findings.push(
            createFinding(
              'oci-user-inactive',
              `User/${user.name}`,
              `User has not logged in for ${Math.floor(daysSinceLogin)} days`,
              'warning',
              'Review and disable inactive users'
            )
          );
        }
      }

      // Check lifecycle state
      if (user.lifecycleState !== 'ACTIVE') {
        findings.push(
          createFinding(
            'oci-user-not-active',
            `User/${user.name}`,
            `User is in ${user.lifecycleState} state`,
            'info',
            'Review users not in ACTIVE state'
          )
        );
      }

      // Check for users who can manage all resources (via description/name pattern)
      if (
        user.description?.toLowerCase().includes('admin') ||
        user.name?.toLowerCase().includes('admin')
      ) {
        // Note: This is a heuristic, actual permissions need policy analysis
        findings.push(
          createFinding(
            'oci-potential-admin-user',
            `User/${user.name}`,
            'User appears to be an administrator (name/description)',
            'info',
            'Verify admin users have appropriate MFA and access controls'
          )
        );
      }
    }

    // Check total user count
    if (users.length > 100) {
      findings.push(
        createFinding(
          'oci-many-users',
          'OCI/Users',
          `${users.length} users in tenancy`,
          'info',
          'Consider using identity federation for large user bases'
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
 * Scan OCI Groups
 */
async function scanGroups(identityClient: IdentityClient, tenancyId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const request = {
      compartmentId: tenancyId,
    };

    const response = await identityClient.listGroups(request);
    const groups = response.items || [];

    // Check for default Administrators group
    const adminGroup = groups.find(g => g.name === 'Administrators');

    if (adminGroup) {
      // Get group members
      const membersResponse = await identityClient.listUserGroupMemberships({
        compartmentId: tenancyId,
        groupId: adminGroup.id,
      });

      const memberCount = membersResponse.items?.length || 0;

      if (memberCount > 5) {
        findings.push(
          createFinding(
            'oci-too-many-admins',
            'Group/Administrators',
            `${memberCount} members in Administrators group (recommended: ≤5)`,
            'warning',
            'Reduce Administrators group membership. Use specific groups.'
          )
        );
      }

      if (memberCount < 2) {
        findings.push(
          createFinding(
            'oci-single-admin',
            'Group/Administrators',
            'Only 1 member in Administrators group',
            'info',
            'Have at least 2 administrators for redundancy'
          )
        );
      }
    }

    // Check for empty groups
    for (const group of groups) {
      const membersResponse = await identityClient.listUserGroupMemberships({
        compartmentId: tenancyId,
        groupId: group.id,
      });

      if (!membersResponse.items || membersResponse.items.length === 0) {
        findings.push(
          createFinding(
            'oci-empty-group',
            `Group/${group.name}`,
            'Group has no members',
            'info',
            'Remove unused groups or add members'
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

/**
 * Scan OCI Policies
 */
async function scanPolicies(identityClient: IdentityClient, tenancyId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get policies at tenancy level
    const request = {
      compartmentId: tenancyId,
    };

    const response = await identityClient.listPolicies(request);
    const policies = response.items || [];

    // Dangerous policy patterns
    const dangerousPatterns: DangerousPattern[] = [
      {
        pattern: /allow .+ to manage all-resources in tenancy/i,
        severity: 'critical',
        msg: 'Full tenancy admin access',
      },
      {
        pattern: /allow any-user to/i,
        severity: 'warning',
        msg: 'Policy grants access to any user',
      },
      {
        pattern: /allow any-group to/i,
        severity: 'warning',
        msg: 'Policy grants access to any group',
      },
      {
        pattern: /allow .+ to manage users in tenancy/i,
        severity: 'warning',
        msg: 'Can manage all users',
      },
      {
        pattern: /allow .+ to manage groups in tenancy/i,
        severity: 'warning',
        msg: 'Can manage all groups',
      },
      {
        pattern: /allow .+ to manage policies in tenancy/i,
        severity: 'critical',
        msg: 'Can modify policies (privilege escalation)',
      },
      {
        pattern: /allow .+ to manage compartments in tenancy/i,
        severity: 'warning',
        msg: 'Can manage all compartments',
      },
      {
        pattern: /allow .+ to manage vaults in tenancy/i,
        severity: 'warning',
        msg: 'Can manage all vaults (secrets)',
      },
      {
        pattern: /allow .+ to manage secrets in tenancy/i,
        severity: 'warning',
        msg: 'Can manage all secrets',
      },
    ];

    for (const policy of policies) {
      const statements = policy.statements || [];

      for (const statement of statements) {
        for (const dangerous of dangerousPatterns) {
          if (dangerous.pattern.test(statement)) {
            findings.push(
              createFinding(
                `oci-policy-${dangerous.severity}`,
                `Policy/${policy.name}`,
                dangerous.msg,
                dangerous.severity,
                'Review and restrict this policy statement',
                { details: { statement } }
              )
            );
            break; // One finding per statement
          }
        }

        // Check for missing conditions
        if (
          statement.toLowerCase().includes('manage') &&
          !statement.toLowerCase().includes('where')
        ) {
          findings.push(
            createFinding(
              'oci-policy-no-condition',
              `Policy/${policy.name}`,
              'Policy with manage verb has no conditions',
              'info',
              'Add conditions to restrict policy scope',
              { details: { statement } }
            )
          );
        }
      }
    }

    // Check for policy count at tenancy level
    if (policies.length > 50) {
      findings.push(
        createFinding(
          'oci-many-tenancy-policies',
          'OCI/Policies',
          `${policies.length} policies at tenancy level`,
          'info',
          'Consider moving policies to compartment level for better organization'
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
 * Scan OCI Compartments
 */
async function scanCompartments(
  identityClient: IdentityClient,
  tenancyId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const request = {
      compartmentId: tenancyId,
      compartmentIdInSubtree: true,
    };

    const response = await identityClient.listCompartments(request);
    const compartments = response.items || [];

    // Check compartment hierarchy depth
    const compartmentMap = new Map<string, OCICompartment>();
    for (const comp of compartments) {
      compartmentMap.set(comp.id, comp);
    }

    for (const comp of compartments) {
      // Calculate depth
      let depth = 0;
      let current: OCICompartment | undefined = comp;
      while (current && current.compartmentId !== tenancyId) {
        depth++;
        current = compartmentMap.get(current.compartmentId);
        if (!current || depth > 6) break;
      }

      if (depth > 5) {
        findings.push(
          createFinding(
            'oci-deep-compartment-hierarchy',
            `Compartment/${comp.name}`,
            `Compartment is ${depth} levels deep`,
            'info',
            'Deep hierarchies can complicate policy management'
          )
        );
      }

      // Check for deleted compartments
      if (comp.lifecycleState === 'DELETED' || comp.lifecycleState === 'DELETING') {
        findings.push(
          createFinding(
            'oci-deleted-compartment',
            `Compartment/${comp.name}`,
            `Compartment is in ${comp.lifecycleState} state`,
            'info',
            'Verify resources have been moved or deleted'
          )
        );
      }
    }

    // Check for root compartment (tenancy) resources
    findings.push(
      createFinding(
        'oci-compartment-check',
        'OCI/Compartments',
        `${compartments.length} compartments in tenancy`,
        'info',
        'Use compartments to organize resources and apply policies'
      )
    );
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan OCI API Keys
 */
async function scanAPIKeys(identityClient: IdentityClient, tenancyId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List all users and their API keys
    const usersResponse = await identityClient.listUsers({
      compartmentId: tenancyId,
    });

    for (const user of usersResponse.items || []) {
      // Get API keys for user
      const keysResponse = await identityClient.listApiKeys({
        userId: user.id,
      });

      for (const key of keysResponse.items || []) {
        // Check key age (OCI doesn't have last used, use creation time)
        if (key.timeCreated) {
          const created = new Date(key.timeCreated);
          const daysSinceCreation = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);

          if (daysSinceCreation > 365) {
            findings.push(
              createFinding(
                'oci-old-api-key',
                `User/${user.name}/APIKey/${key.fingerprint?.substring(0, 16) || 'unknown'}`,
                `API key is ${Math.floor(daysSinceCreation)} days old`,
                'warning',
                'Rotate API keys regularly (at least annually)'
              )
            );
          }
        }

        // Check for inactive keys
        if (key.lifecycleState !== 'ACTIVE') {
          findings.push(
            createFinding(
              'oci-inactive-api-key',
              `User/${user.name}/APIKey`,
              `API key is in ${key.lifecycleState} state`,
              'info',
              'Remove inactive API keys'
            )
          );
        }
      }

      // Check for too many API keys per user
      const keyCount = keysResponse.items?.length || 0;
      if (keyCount > 2) {
        findings.push(
          createFinding(
            'oci-many-api-keys',
            `User/${user.name}`,
            `User has ${keyCount} API keys`,
            'info',
            'Limit API keys per user and rotate regularly'
          )
        );
      }

      // Get auth tokens
      const tokensResponse = await identityClient.listAuthTokens({
        userId: user.id,
      });

      for (const token of tokensResponse.items || []) {
        if (token.timeCreated) {
          const created = new Date(token.timeCreated);
          const daysSinceCreation = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);

          if (daysSinceCreation > 90) {
            findings.push(
              createFinding(
                'oci-old-auth-token',
                `User/${user.name}/AuthToken`,
                `Auth token is ${Math.floor(daysSinceCreation)} days old`,
                'warning',
                'Rotate auth tokens every 90 days'
              )
            );
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan OCI Identity Domains (newer identity management)
 */
async function scanIdentityDomains(
  identityClient: IdentityClient,
  tenancyId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Note: Identity Domains API might be separate
    // This is a placeholder for when we add full domain support

    // Check if using federated identity
    const idpResponse = await identityClient.listIdentityProviders({
      compartmentId: tenancyId,
      protocol: 'SAML2',
    });

    if (!idpResponse.items || idpResponse.items.length === 0) {
      findings.push(
        createFinding(
          'oci-no-identity-federation',
          'OCI/Identity',
          'No SAML identity providers configured',
          'info',
          'Consider using identity federation for enterprise SSO'
        )
      );
    }

    for (const idp of idpResponse.items || []) {
      if (idp.lifecycleState !== 'ACTIVE') {
        findings.push(
          createFinding(
            'oci-inactive-idp',
            `IdentityProvider/${idp.name}`,
            `Identity provider is in ${idp.lifecycleState} state`,
            'info',
            'Review inactive identity providers'
          )
        );
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403 && err.statusCode !== 404) throw error;
  }

  return findings;
}
