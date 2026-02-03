/**
 * GCP IAM Recommender Integration
 * Leverages Google's Policy Intelligence for unused permission detection
 */

import type { Finding, ScanOptions, Severity } from '../types';

interface RecommenderClient {
  projects: {
    locations: {
      recommenders: {
        recommendations: {
          list: (params: {
            parent: string;
          }) => Promise<{ data: { recommendations?: Recommendation[] } }>;
        };
      };
      insightTypes: {
        insights: {
          list: (params: { parent: string }) => Promise<{ data: { insights?: Insight[] } }>;
        };
      };
    };
  };
}

interface Recommendation {
  name?: string;
  description?: string;
  priority?: string;
  recommenderSubtype?: string;
  etag?: string;
  stateInfo?: unknown;
  associatedInsights?: unknown[];
  content?: {
    operationGroups?: Array<{
      operations?: Array<{
        resource?: string;
        pathFilters?: Record<string, string>;
        value?: { roles?: string[] };
      }>;
    }>;
  };
}

interface Insight {
  name?: string;
  description?: string;
  insightSubtype?: string;
  observationPeriod?: unknown;
  targetResources?: string[];
  content?: {
    member?: string;
    role?: string;
    email?: string;
    exercisedPermissions?: string[];
    inferredPermissions?: string[];
    currentTotalPermissionsCount?: number;
    lastAuthenticatedTime?: string;
    sourceServiceAccount?: string;
    targetServiceAccount?: string;
    permission?: string;
  };
}

/**
 * Scan using GCP IAM Recommender
 */
export async function scanGCPRecommender(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });

    const projectId =
      options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;

    if (!projectId) {
      console.error('No GCP project specified. Use --project or set GOOGLE_CLOUD_PROJECT');
      return findings;
    }

    const recommender = google.recommender({ version: 'v1', auth }) as unknown as RecommenderClient;

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
    const err = error as Error & { code?: number | string };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error('GCP SDK not installed. Run: npm install googleapis');
    } else if (err.code === 403) {
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
async function getRoleRecommendations(
  recommender: RecommenderClient,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

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
      let severity: Severity = 'info';
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
        resource: targetResource || rec.name || 'unknown',
        message,
        recommendation: rec.description || 'Review IAM role binding',
        details: {
          priority: rec.priority,
          etag: rec.etag,
          stateInfo: rec.stateInfo,
          associatedInsights: rec.associatedInsights,
        },
      });
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}

/**
 * Get policy insights for over-privileged access
 */
async function getPolicyInsights(
  recommender: RecommenderClient,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

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
      const totalPermissions = content.currentTotalPermissionsCount || 0;
      const usedPermissions = exercisedPermissions.length;

      // Calculate usage percentage
      const usagePercent =
        totalPermissions > 0 ? ((usedPermissions / totalPermissions) * 100).toFixed(1) : '0';

      // Severity based on how many permissions are unused
      let severity: Severity = 'info';
      const usageNum = parseFloat(usagePercent);
      if (usageNum < 10) severity = 'warning';

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
          inferredPermissions: (content.inferredPermissions || []).slice(0, 10),
          totalPermissions,
          observationPeriod: insight.observationPeriod,
        },
      });
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}

/**
 * Get service account insights for unused service accounts
 */
async function getServiceAccountInsights(
  recommender: RecommenderClient,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const parent = `projects/${projectId}/locations/global/insightTypes/google.iam.serviceAccount.Insight`;

    const response = await recommender.projects.locations.insightTypes.insights.list({
      parent,
    });

    for (const insight of response.data.insights || []) {
      const content = insight.content || {};
      const serviceAccount = content.email || insight.targetResources?.[0] || 'unknown';
      const lastAuthenticated = content.lastAuthenticatedTime;
      const lastAuthenticatedDate = lastAuthenticated ? new Date(lastAuthenticated) : null;

      let severity: Severity = 'info';
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
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}

/**
 * Get lateral movement insights
 */
async function getLateralMovementInsights(
  recommender: RecommenderClient,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const parent = `projects/${projectId}/locations/global/insightTypes/google.iam.policy.LateralMovementInsight`;

    const response = await recommender.projects.locations.insightTypes.insights.list({
      parent,
    });

    for (const insight of response.data.insights || []) {
      const content = insight.content || {};
      const sourceAccount = content.sourceServiceAccount || 'unknown';
      const targetAccount = content.targetServiceAccount || 'unknown';
      const impersonationPermission = content.permission || 'unknown';

      findings.push({
        id: 'gcp-lateral-movement',
        severity: 'warning',
        resource: sourceAccount,
        message: `${sourceAccount} can impersonate ${targetAccount} via ${impersonationPermission}`,
        recommendation:
          'Review if this impersonation is necessary. Consider removing the permission.',
        details: {
          sourceServiceAccount: sourceAccount,
          targetServiceAccount: targetAccount,
          permission: impersonationPermission,
        },
      });
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}
