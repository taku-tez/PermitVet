/**
 * Azure Advanced RBAC Scanner
 * Management Group inheritance, Resource Locks, Blueprints
 */

/**
 * Scan Azure advanced features
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanAzureAdvanced(options = {}) {
  const findings = [];

  try {
    const { DefaultAzureCredential } = require('@azure/identity');
    const { ManagementGroupsAPI } = require('@azure/arm-managementgroups');
    const { ResourceManagementClient } = require('@azure/arm-resources');
    const { AuthorizationManagementClient } = require('@azure/arm-authorization');
    const { PolicyClient } = require('@azure/arm-policy');
    
    const credential = new DefaultAzureCredential();
    
    // Get subscription
    let subscriptionId = options.subscription || process.env.AZURE_SUBSCRIPTION_ID;
    
    if (!subscriptionId) {
      console.log('  No subscription specified, scanning management groups only...');
    }

    // 1. Management Group Analysis
    console.log('  Analyzing Management Groups...');
    const mgFindings = await analyzeManagementGroups(credential, subscriptionId);
    findings.push(...mgFindings);

    // 2. Inherited Role Assignments
    if (subscriptionId) {
      console.log('  Checking inherited role assignments...');
      const inheritedFindings = await checkInheritedRoles(credential, subscriptionId);
      findings.push(...inheritedFindings);
    }

    // 3. Azure Policy Compliance
    if (subscriptionId) {
      console.log('  Checking Azure Policy...');
      const policyFindings = await checkAzurePolicy(credential, subscriptionId);
      findings.push(...policyFindings);
    }

    // 4. Resource Locks
    if (subscriptionId) {
      console.log('  Checking Resource Locks...');
      const lockFindings = await checkResourceLocks(credential, subscriptionId);
      findings.push(...lockFindings);
    }

    // 5. Deny Assignments
    if (subscriptionId) {
      console.log('  Checking Deny Assignments...');
      const denyFindings = await checkDenyAssignments(credential, subscriptionId);
      findings.push(...denyFindings);
    }

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('Azure SDK not installed.');
    } else if (error.statusCode === 403) {
      findings.push({
        id: 'azure-advanced-permission-denied',
        severity: 'info',
        resource: 'Azure',
        message: 'Unable to access advanced Azure features',
        recommendation: 'Ensure scanner has Management Group Reader role',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Analyze Management Group hierarchy
 */
async function analyzeManagementGroups(credential, subscriptionId) {
  const findings = [];
  
  try {
    const { ManagementGroupsAPI } = require('@azure/arm-managementgroups');
    const mgClient = new ManagementGroupsAPI(credential);
    
    // List all management groups
    const managementGroups = [];
    for await (const mg of mgClient.managementGroups.list()) {
      managementGroups.push(mg);
    }
    
    if (managementGroups.length === 0) {
      findings.push({
        id: 'azure-no-management-groups',
        severity: 'info',
        resource: 'Azure',
        message: 'No management group hierarchy configured',
        recommendation: 'Use management groups for centralized governance at scale',
      });
      return findings;
    }
    
    // Analyze each management group
    for (const mg of managementGroups) {
      try {
        // Get detailed info including children
        const mgDetail = await mgClient.managementGroups.get(mg.name, {
          expand: 'children',
          recurse: true,
        });
        
        // Check for role assignments at MG level
        const { AuthorizationManagementClient } = require('@azure/arm-authorization');
        // Note: Need to use resourceId for MG-level queries
        
        // Check hierarchy depth
        let depth = 0;
        let current = mgDetail;
        while (current.properties?.details?.parent) {
          depth++;
          if (depth > 6) {
            findings.push({
              id: 'azure-mg-deep-hierarchy',
              severity: 'info',
              resource: `ManagementGroup/${mg.name}`,
              message: 'Management group hierarchy is very deep (>6 levels)',
              recommendation: 'Consider flattening the hierarchy for simpler governance',
            });
            break;
          }
          break; // Only checking immediate parent
        }
        
        // Check for subscriptions directly under root
        if (mgDetail.properties?.details?.parent?.id?.includes('/providers/Microsoft.Management/managementGroups/') === false) {
          const children = mgDetail.properties?.children || [];
          const directSubs = children.filter(c => c.type === '/subscriptions');
          
          if (directSubs.length > 10) {
            findings.push({
              id: 'azure-mg-many-direct-subs',
              severity: 'info',
              resource: `ManagementGroup/${mg.name}`,
              message: `${directSubs.length} subscriptions directly under management group`,
              recommendation: 'Consider organizing subscriptions into child management groups',
            });
          }
        }
        
      } catch (e) {
        // Skip if can't get details
      }
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Check inherited role assignments
 */
async function checkInheritedRoles(credential, subscriptionId) {
  const findings = [];
  
  try {
    const { AuthorizationManagementClient } = require('@azure/arm-authorization');
    const authClient = new AuthorizationManagementClient(credential, subscriptionId);
    
    // Get all role assignments including inherited
    const assignments = [];
    for await (const assignment of authClient.roleAssignments.listForSubscription()) {
      assignments.push(assignment);
    }
    
    // Separate inherited vs direct assignments
    const inheritedAssignments = assignments.filter(a => 
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
      
      if (privilegedRoleIds.includes(roleId)) {
        // Check if inherited from management group
        if (assignment.scope?.includes('/providers/Microsoft.Management/managementGroups/')) {
          const mgName = assignment.scope.split('/managementGroups/')[1];
          
          findings.push({
            id: 'azure-inherited-privileged-from-mg',
            severity: 'warning',
            resource: `Subscription/${subscriptionId}`,
            message: `Privileged role inherited from Management Group: ${mgName}`,
            recommendation: 'Review inherited permissions. Consider subscription-level assignments for better control.',
            details: {
              roleDefinitionId: assignment.roleDefinitionId,
              principalId: assignment.principalId,
              scope: assignment.scope,
            },
          });
        }
      }
    }
    
    // Count inherited vs direct
    const inheritedCount = inheritedAssignments.length;
    const directCount = assignments.length - inheritedCount;
    
    if (inheritedCount > directCount * 2) {
      findings.push({
        id: 'azure-many-inherited-roles',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: `${inheritedCount} inherited vs ${directCount} direct role assignments`,
        recommendation: 'High ratio of inherited roles may indicate overly broad MG policies',
      });
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

/**
 * Check Azure Policy compliance
 */
async function checkAzurePolicy(credential, subscriptionId) {
  const findings = [];
  
  try {
    const { PolicyClient } = require('@azure/arm-policy');
    const policyClient = new PolicyClient(credential, subscriptionId);
    
    // List policy assignments
    const assignments = [];
    for await (const assignment of policyClient.policyAssignments.list()) {
      assignments.push(assignment);
    }
    
    if (assignments.length === 0) {
      findings.push({
        id: 'azure-no-policy-assignments',
        severity: 'warning',
        resource: `Subscription/${subscriptionId}`,
        message: 'No Azure Policy assignments configured',
        recommendation: 'Use Azure Policy to enforce security standards',
      });
      return findings;
    }
    
    // Check for important security initiatives
    const securityInitiatives = [
      'Azure Security Benchmark',
      'CIS Microsoft Azure Foundations',
      'NIST SP 800-53',
      'ISO 27001',
    ];
    
    const assignmentNames = assignments.map(a => a.displayName?.toLowerCase() || '');
    const hasSecurityInitiative = securityInitiatives.some(si => 
      assignmentNames.some(an => an.includes(si.toLowerCase()))
    );
    
    if (!hasSecurityInitiative) {
      findings.push({
        id: 'azure-no-security-initiative',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'No security benchmark initiative assigned',
        recommendation: 'Assign Azure Security Benchmark or CIS initiative',
      });
    }
    
    // Check for disabled policies
    const disabledAssignments = assignments.filter(a => 
      a.enforcementMode === 'DoNotEnforce'
    );
    
    if (disabledAssignments.length > 0) {
      findings.push({
        id: 'azure-disabled-policies',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: `${disabledAssignments.length} policy assignments in DoNotEnforce mode`,
        recommendation: 'Review and enable policies after testing',
      });
    }
    
  } catch (error) {
    if (error.statusCode !== 403 && error.code !== 'MODULE_NOT_FOUND') throw error;
  }
  
  return findings;
}

/**
 * Check Resource Locks
 */
async function checkResourceLocks(credential, subscriptionId) {
  const findings = [];
  
  try {
    const { ManagementLockClient } = require('@azure/arm-locks');
    const lockClient = new ManagementLockClient(credential, subscriptionId);
    
    // List subscription-level locks
    const locks = [];
    for await (const lock of lockClient.managementLocks.listAtSubscriptionLevel()) {
      locks.push(lock);
    }
    
    // Check for CanNotDelete or ReadOnly locks at subscription level
    const subLevelLocks = locks.filter(l => 
      l.level === 'CanNotDelete' || l.level === 'ReadOnly'
    );
    
    if (subLevelLocks.length === 0) {
      findings.push({
        id: 'azure-no-subscription-lock',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'No resource locks at subscription level',
        recommendation: 'Consider adding locks to prevent accidental deletion of critical resources',
      });
    }
    
    // Check for ReadOnly locks (might cause issues)
    const readOnlyLocks = locks.filter(l => l.level === 'ReadOnly');
    if (readOnlyLocks.length > 5) {
      findings.push({
        id: 'azure-many-readonly-locks',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: `${readOnlyLocks.length} ReadOnly locks (may impact operations)`,
        recommendation: 'ReadOnly locks can prevent legitimate changes - use carefully',
      });
    }
    
  } catch (error) {
    if (error.statusCode !== 403 && error.code !== 'MODULE_NOT_FOUND') throw error;
  }
  
  return findings;
}

/**
 * Check Deny Assignments (used by Blueprints and managed apps)
 */
async function checkDenyAssignments(credential, subscriptionId) {
  const findings = [];
  
  try {
    const { AuthorizationManagementClient } = require('@azure/arm-authorization');
    const authClient = new AuthorizationManagementClient(credential, subscriptionId);
    
    // List deny assignments
    const denyAssignments = [];
    for await (const deny of authClient.denyAssignments.listForSubscription()) {
      denyAssignments.push(deny);
    }
    
    if (denyAssignments.length === 0) {
      // This is just informational
      findings.push({
        id: 'azure-no-deny-assignments',
        severity: 'info',
        resource: `Subscription/${subscriptionId}`,
        message: 'No deny assignments configured',
        recommendation: 'Consider using Azure Blueprints for immutable resource protection',
      });
      return findings;
    }
    
    // Analyze deny assignments
    for (const deny of denyAssignments) {
      // Check for system-managed deny assignments (from Blueprints)
      if (deny.isSystemProtected) {
        findings.push({
          id: 'azure-blueprint-deny',
          severity: 'info',
          resource: deny.scope,
          message: `System-protected deny assignment: ${deny.denyAssignmentName}`,
          recommendation: 'This is managed by Azure Blueprints - modification requires Blueprint update',
        });
      }
      
      // Check scope of deny assignment
      if (deny.scope === `/subscriptions/${subscriptionId}`) {
        findings.push({
          id: 'azure-subscription-deny',
          severity: 'info',
          resource: `Subscription/${subscriptionId}`,
          message: `Subscription-level deny assignment: ${deny.denyAssignmentName}`,
          recommendation: 'Review deny assignment scope and excluded principals',
        });
      }
    }
    
  } catch (error) {
    if (error.statusCode !== 403) throw error;
  }
  
  return findings;
}

module.exports = { scanAzureAdvanced };
