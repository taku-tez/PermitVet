/**
 * Oracle Cloud Infrastructure (OCI) IAM Scanner
 * Scans OCI for IAM security issues based on best practices
 */

/**
 * Scan OCI IAM for security issues
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanOCI(options = {}) {
  const findings = [];

  try {
    const oci = require('oci-sdk');
    const common = require('oci-common');
    
    // Initialize OCI provider
    let provider;
    if (options.configFile) {
      provider = new common.ConfigFileAuthenticationDetailsProvider(
        options.configFile,
        options.profile || 'DEFAULT'
      );
    } else {
      provider = new common.ConfigFileAuthenticationDetailsProvider();
    }
    
    const identityClient = new oci.identity.IdentityClient({
      authenticationDetailsProvider: provider,
    });
    
    // Get tenancy info
    const tenancyId = provider.getTenantId();
    console.log(`  Scanning OCI tenancy: ${tenancyId}...`);

    // 1. Scan Users
    console.log('  Scanning users...');
    const userFindings = await scanUsers(identityClient, tenancyId);
    findings.push(...userFindings);

    // 2. Scan Groups
    console.log('  Scanning groups...');
    const groupFindings = await scanGroups(identityClient, tenancyId);
    findings.push(...groupFindings);

    // 3. Scan Policies
    console.log('  Scanning policies...');
    const policyFindings = await scanPolicies(identityClient, tenancyId);
    findings.push(...policyFindings);

    // 4. Scan Compartments
    console.log('  Scanning compartments...');
    const compartmentFindings = await scanCompartments(identityClient, tenancyId);
    findings.push(...compartmentFindings);

    // 5. Scan API Keys and Auth Tokens
    console.log('  Scanning API keys...');
    const keyFindings = await scanAPIKeys(identityClient, tenancyId);
    findings.push(...keyFindings);

    // 6. Scan Identity Domains (if available)
    console.log('  Scanning identity domains...');
    const domainFindings = await scanIdentityDomains(identityClient, tenancyId);
    findings.push(...domainFindings);

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('OCI SDK not installed. Run: npm install oci-sdk');
    } else if (error.statusCode === 401 || error.statusCode === 403) {
      findings.push({
        id: 'oci-auth-failed',
        severity: 'info',
        resource: 'OCI',
        message: 'OCI authentication failed',
        recommendation: 'Configure ~/.oci/config with valid credentials',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan OCI Users
 */
async function scanUsers(identityClient, tenancyId) {
  const findings = [];
  
  try {
    const request = {
      compartmentId: tenancyId,
    };
    
    const response = await identityClient.listUsers(request);
    const users = response.items || [];
    
    for (const user of users) {
      // Check for users without MFA
      if (!user.isMfaActivated) {
        findings.push({
          id: 'oci-user-no-mfa',
          severity: 'warning',
          resource: `User/${user.name}`,
          message: 'User does not have MFA enabled',
          recommendation: 'Enable MFA for all users with console access',
        });
      }
      
      // Check for inactive users (no login in 90 days)
      if (user.lastSuccessfulLoginTime) {
        const lastLogin = new Date(user.lastSuccessfulLoginTime);
        const daysSinceLogin = (Date.now() - lastLogin.getTime()) / (1000 * 60 * 60 * 24);
        
        if (daysSinceLogin > 90) {
          findings.push({
            id: 'oci-user-inactive',
            severity: 'warning',
            resource: `User/${user.name}`,
            message: `User has not logged in for ${Math.floor(daysSinceLogin)} days`,
            recommendation: 'Review and disable inactive users',
          });
        }
      }
      
      // Check lifecycle state
      if (user.lifecycleState !== 'ACTIVE') {
        findings.push({
          id: 'oci-user-not-active',
          severity: 'info',
          resource: `User/${user.name}`,
          message: `User is in ${user.lifecycleState} state`,
          recommendation: 'Review users not in ACTIVE state',
        });
      }
      
      // Check for users who can manage all resources (via description/name pattern)
      if (user.description?.toLowerCase().includes('admin') || 
          user.name?.toLowerCase().includes('admin')) {
        // Note: This is a heuristic, actual permissions need policy analysis
        findings.push({
          id: 'oci-potential-admin-user',
          severity: 'info',
          resource: `User/${user.name}`,
          message: 'User appears to be an administrator (name/description)',
          recommendation: 'Verify admin users have appropriate MFA and access controls',
        });
      }
    }
    
    // Check total user count
    if (users.length > 100) {
      findings.push({
        id: 'oci-many-users',
        severity: 'info',
        resource: 'OCI/Users',
        message: `${users.length} users in tenancy`,
        recommendation: 'Consider using identity federation for large user bases',
      });
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Scan OCI Groups
 */
async function scanGroups(identityClient, tenancyId) {
  const findings = [];
  
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
        findings.push({
          id: 'oci-too-many-admins',
          severity: 'warning',
          resource: 'Group/Administrators',
          message: `${memberCount} members in Administrators group (recommended: ≤5)`,
          recommendation: 'Reduce Administrators group membership. Use specific groups.',
        });
      }
      
      if (memberCount < 2) {
        findings.push({
          id: 'oci-single-admin',
          severity: 'info',
          resource: 'Group/Administrators',
          message: 'Only 1 member in Administrators group',
          recommendation: 'Have at least 2 administrators for redundancy',
        });
      }
    }
    
    // Check for empty groups
    for (const group of groups) {
      const membersResponse = await identityClient.listUserGroupMemberships({
        compartmentId: tenancyId,
        groupId: group.id,
      });
      
      if (!membersResponse.items || membersResponse.items.length === 0) {
        findings.push({
          id: 'oci-empty-group',
          severity: 'info',
          resource: `Group/${group.name}`,
          message: 'Group has no members',
          recommendation: 'Remove unused groups or add members',
        });
      }
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Scan OCI Policies
 */
async function scanPolicies(identityClient, tenancyId) {
  const findings = [];
  
  try {
    // Get policies at tenancy level
    const request = {
      compartmentId: tenancyId,
    };
    
    const response = await identityClient.listPolicies(request);
    const policies = response.items || [];
    
    // Dangerous policy patterns
    const dangerousPatterns = [
      { pattern: /allow .+ to manage all-resources in tenancy/i, severity: 'critical', msg: 'Full tenancy admin access' },
      { pattern: /allow any-user to/i, severity: 'warning', msg: 'Policy grants access to any user' },
      { pattern: /allow any-group to/i, severity: 'warning', msg: 'Policy grants access to any group' },
      { pattern: /allow .+ to manage users in tenancy/i, severity: 'warning', msg: 'Can manage all users' },
      { pattern: /allow .+ to manage groups in tenancy/i, severity: 'warning', msg: 'Can manage all groups' },
      { pattern: /allow .+ to manage policies in tenancy/i, severity: 'critical', msg: 'Can modify policies (privilege escalation)' },
      { pattern: /allow .+ to manage compartments in tenancy/i, severity: 'warning', msg: 'Can manage all compartments' },
      { pattern: /allow .+ to manage vaults in tenancy/i, severity: 'warning', msg: 'Can manage all vaults (secrets)' },
      { pattern: /allow .+ to manage secrets in tenancy/i, severity: 'warning', msg: 'Can manage all secrets' },
    ];
    
    for (const policy of policies) {
      const statements = policy.statements || [];
      
      for (const statement of statements) {
        for (const dangerous of dangerousPatterns) {
          if (dangerous.pattern.test(statement)) {
            findings.push({
              id: `oci-policy-${dangerous.severity}`,
              severity: dangerous.severity,
              resource: `Policy/${policy.name}`,
              message: dangerous.msg,
              recommendation: 'Review and restrict this policy statement',
              details: {
                statement,
              },
            });
            break; // One finding per statement
          }
        }
        
        // Check for missing conditions
        if (statement.toLowerCase().includes('manage') && 
            !statement.toLowerCase().includes('where')) {
          findings.push({
            id: 'oci-policy-no-condition',
            severity: 'info',
            resource: `Policy/${policy.name}`,
            message: 'Policy with manage verb has no conditions',
            recommendation: 'Add conditions to restrict policy scope',
            details: {
              statement,
            },
          });
        }
      }
    }
    
    // Check for policy count at tenancy level
    if (policies.length > 50) {
      findings.push({
        id: 'oci-many-tenancy-policies',
        severity: 'info',
        resource: 'OCI/Policies',
        message: `${policies.length} policies at tenancy level`,
        recommendation: 'Consider moving policies to compartment level for better organization',
      });
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Scan OCI Compartments
 */
async function scanCompartments(identityClient, tenancyId) {
  const findings = [];
  
  try {
    const request = {
      compartmentId: tenancyId,
      compartmentIdInSubtree: true,
    };
    
    const response = await identityClient.listCompartments(request);
    const compartments = response.items || [];
    
    // Check compartment hierarchy depth
    const compartmentMap = new Map();
    for (const comp of compartments) {
      compartmentMap.set(comp.id, comp);
    }
    
    for (const comp of compartments) {
      // Calculate depth
      let depth = 0;
      let current = comp;
      while (current.compartmentId !== tenancyId) {
        depth++;
        current = compartmentMap.get(current.compartmentId);
        if (!current || depth > 6) break;
      }
      
      if (depth > 5) {
        findings.push({
          id: 'oci-deep-compartment-hierarchy',
          severity: 'info',
          resource: `Compartment/${comp.name}`,
          message: `Compartment is ${depth} levels deep`,
          recommendation: 'Deep hierarchies can complicate policy management',
        });
      }
      
      // Check for deleted compartments
      if (comp.lifecycleState === 'DELETED' || comp.lifecycleState === 'DELETING') {
        findings.push({
          id: 'oci-deleted-compartment',
          severity: 'info',
          resource: `Compartment/${comp.name}`,
          message: `Compartment is in ${comp.lifecycleState} state`,
          recommendation: 'Verify resources have been moved or deleted',
        });
      }
    }
    
    // Check for root compartment (tenancy) resources
    findings.push({
      id: 'oci-compartment-check',
      severity: 'info',
      resource: 'OCI/Compartments',
      message: `${compartments.length} compartments in tenancy`,
      recommendation: 'Use compartments to organize resources and apply policies',
    });
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Scan OCI API Keys
 */
async function scanAPIKeys(identityClient, tenancyId) {
  const findings = [];
  
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
            findings.push({
              id: 'oci-old-api-key',
              severity: 'warning',
              resource: `User/${user.name}/APIKey/${key.fingerprint?.substring(0, 16)}`,
              message: `API key is ${Math.floor(daysSinceCreation)} days old`,
              recommendation: 'Rotate API keys regularly (at least annually)',
            });
          }
        }
        
        // Check for inactive keys
        if (key.lifecycleState !== 'ACTIVE') {
          findings.push({
            id: 'oci-inactive-api-key',
            severity: 'info',
            resource: `User/${user.name}/APIKey`,
            message: `API key is in ${key.lifecycleState} state`,
            recommendation: 'Remove inactive API keys',
          });
        }
      }
      
      // Check for too many API keys per user
      if ((keysResponse.items?.length || 0) > 2) {
        findings.push({
          id: 'oci-many-api-keys',
          severity: 'info',
          resource: `User/${user.name}`,
          message: `User has ${keysResponse.items.length} API keys`,
          recommendation: 'Limit API keys per user and rotate regularly',
        });
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
            findings.push({
              id: 'oci-old-auth-token',
              severity: 'warning',
              resource: `User/${user.name}/AuthToken`,
              message: `Auth token is ${Math.floor(daysSinceCreation)} days old`,
              recommendation: 'Rotate auth tokens every 90 days',
            });
          }
        }
      }
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Scan OCI Identity Domains (newer identity management)
 */
async function scanIdentityDomains(identityClient, tenancyId) {
  const findings = [];
  
  try {
    // Note: Identity Domains API might be separate
    // This is a placeholder for when we add full domain support
    
    // Check if using federated identity
    const idpResponse = await identityClient.listIdentityProviders({
      compartmentId: tenancyId,
      protocol: 'SAML2',
    });
    
    if (!idpResponse.items || idpResponse.items.length === 0) {
      findings.push({
        id: 'oci-no-identity-federation',
        severity: 'info',
        resource: 'OCI/Identity',
        message: 'No SAML identity providers configured',
        recommendation: 'Consider using identity federation for enterprise SSO',
      });
    }
    
    for (const idp of idpResponse.items || []) {
      if (idp.lifecycleState !== 'ACTIVE') {
        findings.push({
          id: 'oci-inactive-idp',
          severity: 'info',
          resource: `IdentityProvider/${idp.name}`,
          message: `Identity provider is in ${idp.lifecycleState} state`,
          recommendation: 'Review inactive identity providers',
        });
      }
    }
    
  } catch (error) {
    if (error.statusCode !== 403 && error.statusCode !== 404) throw error;
  }
  
  return findings;
}

module.exports = { scanOCI };
