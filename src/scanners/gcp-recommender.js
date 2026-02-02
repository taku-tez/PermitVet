/**
 * GCP IAM Recommender Integration
 * Leverages Google's Policy Intelligence for unused permission detection
 */

/**
 * Scan using GCP IAM Recommender
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanGCPRecommender(options = {}) {
  const findings = [];

  try {
    const { google } = require('googleapis');
    
    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    
    const projectId = options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
    
    if (!projectId) {
      console.error('No GCP project specified. Use --project or set GOOGLE_CLOUD_PROJECT');
      return findings;
    }
    
    const recommender = google.recommender({ version: 'v1', auth });

    // 1. Get IAM role recommendations (unused permissions)
    console.log('  Fetching IAM role recommendations...');
    const roleFindings = await getRoleRecommendations(recommender, projectId);
    findings.push(...roleFindings);

    // 2. Get policy insights (over-privileged access)
    console.log('  Fetching policy insights...');
    const policyFindings = await getPolicyInsights(recommender, projectId);
    findings.push(...policyFindings);

    // 3. Get service account insights (unused service accounts)
    console.log('  Fetching service account insights...');
    const saFindings = await getServiceAccountInsights(recommender, projectId);
    findings.push(...saFindings);

    // 4. Get lateral movement insights
    console.log('  Fetching lateral movement insights...');
    const lateralFindings = await getLateralMovementInsights(recommender, projectId);
    findings.push(...lateralFindings);

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('GCP SDK not installed. Run: npm install googleapis');
    } else if (error.code === 403) {
      findings.push({
        id: 'gcp-recommender-denied',
        severity: 'info',
        resource: `Project/${options.project}`,
        message: 'Unable to access IAM Recommender',
        recommendation: 'Ensure scanner has recommender.* permissions',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Get IAM role recommendations for unused permissions
 */
async function getRoleRecommendations(recommender, projectId) {
  const findings = [];
  
  try {
    const parent = `projects/${projectId}/locations/global/recommenders/google.iam.policy.Recommender`;
    
    const response = await recommender.projects.locations.recommenders.recommendations.list({
      parent,
    });
    
    for (const rec of response.data.recommendations || []) {
      const content = rec.content?.operationGroups?.[0]?.operations?.[0];
      const targetResource = content?.resource;
      const targetMember = content?.pathFilters?.['/iamPolicy/bindings/*/members/*'];
      const targetRole = content?.pathFilters?.['/iamPolicy/bindings/*/role'];
      
      // Determine severity based on priority
      let severity = 'info';
      if (rec.priority === 'P1') severity = 'critical';
      else if (rec.priority === 'P2') severity = 'warning';
      
      // Parse recommendation type
      let message = rec.description || 'IAM role recommendation';
      let id = 'gcp-iam-recommendation';
      
      if (rec.recommenderSubtype === 'REMOVE_ROLE') {
        id = 'gcp-unused-role-binding';
        message = `Role binding can be removed: ${targetMember} → ${targetRole}`;
      } else if (rec.recommenderSubtype === 'REPLACE_ROLE') {
        id = 'gcp-overprivileged-role';
        const suggestedRole = content?.value?.roles?.[0];
        message = `Role ${targetRole} can be replaced with ${suggestedRole || 'a more restrictive role'}`;
      }
      
      findings.push({
        id,
        severity,
        resource: targetResource || rec.name,
        message,
        recommendation: rec.description,
        details: {
          priority: rec.priority,
          etag: rec.etag,
          stateInfo: rec.stateInfo,
          associatedInsights: rec.associatedInsights,
        },
      });
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Get policy insights for over-privileged access
 */
async function getPolicyInsights(recommender, projectId) {
  const findings = [];
  
  try {
    const parent = `projects/${projectId}/locations/global/insightTypes/google.iam.policy.Insight`;
    
    const response = await recommender.projects.locations.insightTypes.insights.list({
      parent,
    });
    
    for (const insight of response.data.insights || []) {
      const content = insight.content || {};
      const member = content.member;
      const role = content.role;
      const exercisedPermissions = content.exercisedPermissions || [];
      const inferredPermissions = content.inferredPermissions || [];
      const totalPermissions = content.currentTotalPermissionsCount || 0;
      const usedPermissions = exercisedPermissions.length;
      
      // Calculate usage percentage
      const usagePercent = totalPermissions > 0 ? (usedPermissions / totalPermissions * 100).toFixed(1) : 0;
      
      // Severity based on how many permissions are unused
      let severity = 'info';
      if (usagePercent < 10) severity = 'warning';
      if (usagePercent < 5) severity = 'warning';
      
      findings.push({
        id: 'gcp-policy-insight',
        severity,
        resource: `${member} → ${role}`,
        message: `Only ${usagePercent}% of permissions used (${usedPermissions}/${totalPermissions})`,
        recommendation: 'Consider replacing with a more restrictive role or custom role',
        details: {
          member,
          role,
          exercisedPermissions: exercisedPermissions.slice(0, 10), // First 10
          inferredPermissions: inferredPermissions.slice(0, 10),
          totalPermissions,
          observationPeriod: insight.observationPeriod,
        },
      });
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Get service account insights for unused service accounts
 */
async function getServiceAccountInsights(recommender, projectId) {
  const findings = [];
  
  try {
    const parent = `projects/${projectId}/locations/global/insightTypes/google.iam.serviceAccount.Insight`;
    
    const response = await recommender.projects.locations.insightTypes.insights.list({
      parent,
    });
    
    for (const insight of response.data.insights || []) {
      const content = insight.content || {};
      const serviceAccount = content.email || insight.targetResources?.[0];
      const lastAuthenticated = content.lastAuthenticatedTime;
      const lastAuthenticatedDate = lastAuthenticated ? new Date(lastAuthenticated) : null;
      
      let severity = 'info';
      let message = 'Service account insight';
      
      // Determine insight type
      if (insight.insightSubtype === 'SERVICE_ACCOUNT_NOT_USED') {
        severity = 'warning';
        const daysSinceAuth = lastAuthenticatedDate 
          ? Math.floor((Date.now() - lastAuthenticatedDate.getTime()) / (1000 * 60 * 60 * 24))
          : 'never';
        message = `Service account has not been used in ${daysSinceAuth} days`;
      } else if (insight.insightSubtype === 'REDUNDANT_SERVICE_ACCOUNT_KEY') {
        severity = 'info';
        message = 'Service account has redundant keys';
      }
      
      findings.push({
        id: `gcp-sa-insight-${insight.insightSubtype?.toLowerCase() || 'unknown'}`,
        severity,
        resource: serviceAccount,
        message,
        recommendation: insight.description || 'Review and remediate service account',
        details: {
          insightSubtype: insight.insightSubtype,
          lastAuthenticated,
          observationPeriod: insight.observationPeriod,
        },
      });
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Get lateral movement insights
 */
async function getLateralMovementInsights(recommender, projectId) {
  const findings = [];
  
  try {
    const parent = `projects/${projectId}/locations/global/insightTypes/google.iam.policy.LateralMovementInsight`;
    
    const response = await recommender.projects.locations.insightTypes.insights.list({
      parent,
    });
    
    for (const insight of response.data.insights || []) {
      const content = insight.content || {};
      const sourceAccount = content.sourceServiceAccount;
      const targetAccount = content.targetServiceAccount;
      const impersonationPermission = content.permission;
      
      findings.push({
        id: 'gcp-lateral-movement',
        severity: 'warning',
        resource: sourceAccount,
        message: `${sourceAccount} can impersonate ${targetAccount} via ${impersonationPermission}`,
        recommendation: 'Review if this impersonation is necessary. Consider removing the permission.',
        details: {
          sourceServiceAccount: sourceAccount,
          targetServiceAccount: targetAccount,
          permission: impersonationPermission,
        },
      });
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

module.exports = { scanGCPRecommender };
