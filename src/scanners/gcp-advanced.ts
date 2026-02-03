/**
 * GCP Advanced IAM Scanner
 * Organization Policies (IAM), Hierarchy Analysis, Workload Identity
 */

import type { Finding, ScanOptions, Severity } from '../types';
import { createFinding, handleScanError, logProgress, logError } from '../utils';

// GCP types
interface OrgPolicy {
  name?: string;
  spec?: {
    rules?: Array<{
      enforce?: boolean;
    }>;
  };
}

interface Project {
  parent?: string;
}

interface IAMPolicy {
  bindings?: IAMBinding[];
}

interface IAMBinding {
  role?: string;
  members?: string[];
}

interface WorkloadIdentityPool {
  name?: string;
  disabled?: boolean;
}

interface WorkloadIdentityProvider {
  name?: string;
  attributeCondition?: string;
  aws?: Record<string, unknown>;
  oidc?: {
    allowedAudiences?: string[];
  };
}

interface SecurityPolicyConfig {
  expected?: boolean;
  checkDomains?: boolean;
  severity: Severity;
  msg: string;
  recommendation: string;
  cis?: string;
}

/**
 * Scan GCP advanced security features
 */
export async function scanGCPAdvanced(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });

    const projectId =
      options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;

    if (!projectId) {
      logError('No GCP project specified.');
      return findings;
    }

    // 1. Organization Policies (IAM-related)
    logProgress('Checking Organization Policies...');
    const orgPolicyFindings = await scanOrganizationPolicies(auth, projectId);
    findings.push(...orgPolicyFindings);

    // 2. Resource Hierarchy Inheritance
    logProgress('Analyzing IAM hierarchy...');
    const hierarchyFindings = await analyzeIAMHierarchy(auth, projectId);
    findings.push(...hierarchyFindings);

    // 3. Workload Identity Federation
    logProgress('Checking Workload Identity...');
    const workloadFindings = await checkWorkloadIdentity(auth, projectId);
    findings.push(...workloadFindings);
  } catch (error) {
    const result = handleScanError(error, { provider: 'gcp', operation: 'advanced scan' });
    if (result.type === 'permission_denied') {
      findings.push(
        createFinding(
          'gcp-advanced-permission-denied',
          `Project/${options.project}`,
          'Unable to access advanced GCP features',
          'info',
          'Ensure scanner has orgpolicy.* and accesscontextmanager.* permissions'
        )
      );
    } else if (result.type !== 'sdk_not_installed' && result.shouldThrow) {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Organization Policies
 */
async function scanOrganizationPolicies(auth: any, projectId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const orgpolicy = google.orgpolicy({ version: 'v2', auth }) as any;

    // List all organization policies for the project
    const response = await orgpolicy.projects.policies.list({
      parent: `projects/${projectId}`,
    });

    const policies = (response.data.policies || []) as OrgPolicy[];

    // IAM-related organization policies to check (CIEM focus)
    const securityPolicies: Record<string, SecurityPolicyConfig> = {
      'constraints/iam.disableServiceAccountKeyCreation': {
        expected: true,
        severity: 'warning',
        msg: 'Service account key creation should be disabled',
        recommendation: 'Use Workload Identity instead of SA keys',
        cis: '1.4',
      },
      'constraints/iam.disableServiceAccountKeyUpload': {
        expected: true,
        severity: 'info',
        msg: 'Service account key upload should be disabled',
        recommendation: 'Prevent uploading external keys',
      },
      'constraints/iam.allowedPolicyMemberDomains': {
        checkDomains: true,
        severity: 'warning',
        msg: 'Domain restriction policy should be set',
        recommendation: 'Restrict IAM members to specific domains',
      },
      'constraints/iam.disableWorkloadIdentityClusterCreation': {
        expected: false, // We want WI enabled, so this should NOT be set
        severity: 'info',
        msg: 'Workload Identity cluster creation is disabled',
        recommendation: 'Enable Workload Identity for GKE clusters',
      },
      'constraints/storage.uniformBucketLevelAccess': {
        expected: true,
        severity: 'warning',
        msg: 'Uniform bucket-level access should be enabled (IAM over ACLs)',
        recommendation: 'Use IAM policies instead of ACLs for access control',
        cis: '5.2',
      },
    };

    // Check which policies are set
    const setPolicies = new Set(policies.map(p => p.name?.split('/').pop()));

    for (const [constraint, config] of Object.entries(securityPolicies)) {
      const policyName = constraint.replace('constraints/', '');

      if (!setPolicies.has(policyName)) {
        findings.push(
          createFinding(
            `gcp-orgpolicy-${policyName.replace(/\./g, '-')}`,
            `Project/${projectId}`,
            config.msg,
            config.severity,
            config.recommendation,
            config.cis ? { cis: config.cis } : undefined
          )
        );
      }
    }

    // Check specific policy configurations
    for (const policy of policies) {
      const constraintName = policy.name?.split('/').pop();

      // Check if boolean constraints are enforced
      if (policy.spec?.rules?.[0]?.enforce === false) {
        const config = securityPolicies[`constraints/${constraintName}`];
        if (config?.expected) {
          findings.push(
            createFinding(
              `gcp-orgpolicy-not-enforced-${constraintName?.replace(/\./g, '-')}`,
              `Project/${projectId}`,
              `${constraintName} is set but not enforced`,
              config.severity,
              config.recommendation
            )
          );
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}

/**
 * Analyze IAM hierarchy inheritance
 */
async function analyzeIAMHierarchy(auth: any, projectId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v3', auth }) as any;

    // Get project info
    const projectResponse = await cloudresourcemanager.projects.get({
      name: `projects/${projectId}`,
    });

    const project = projectResponse.data as Project;
    const parent = project.parent;

    if (!parent) {
      findings.push(
        createFinding(
          'gcp-project-no-org',
          `Project/${projectId}`,
          'Project is not part of an organization',
          'info',
          'Move project to an organization for centralized governance'
        )
      );
      return findings;
    }

    // Get parent (folder or organization) IAM policy
    let parentPolicy: IAMPolicy | undefined;
    if (parent.startsWith('folders/')) {
      const folderResponse = await cloudresourcemanager.folders.getIamPolicy({
        resource: parent,
        requestBody: {},
      });
      parentPolicy = folderResponse.data as IAMPolicy;
    } else if (parent.startsWith('organizations/')) {
      const orgResponse = await cloudresourcemanager.organizations.getIamPolicy({
        resource: parent,
        requestBody: {},
      });
      parentPolicy = orgResponse.data as IAMPolicy;
    }

    if (parentPolicy) {
      // Check for inherited privileged roles
      for (const binding of parentPolicy.bindings || []) {
        const role = binding.role;
        const members = binding.members || [];

        // Dangerous inherited roles
        const inheritedDangerousRoles = ['roles/owner', 'roles/editor', 'roles/iam.securityAdmin'];

        if (role && inheritedDangerousRoles.includes(role)) {
          findings.push(
            createFinding(
              'gcp-inherited-privileged-role',
              `Project/${projectId}`,
              `Project inherits ${role} from ${parent}`,
              'warning',
              'Review inherited permissions. Prefer project-level assignments.',
              {
                details: {
                  parent,
                  role,
                  memberCount: members.length,
                },
              }
            )
          );
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}

/**
 * Check Workload Identity configuration
 */
async function checkWorkloadIdentity(auth: any, projectId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const iam = google.iam({ version: 'v1', auth }) as any;

    // List workload identity pools
    const poolsResponse = await iam.projects.locations.workloadIdentityPools.list({
      parent: `projects/${projectId}/locations/global`,
    });

    const pools = (poolsResponse.data.workloadIdentityPools || []) as WorkloadIdentityPool[];

    // If no pools but project has GKE or external workloads, suggest WI
    if (pools.length === 0) {
      // This is just informational
      findings.push(
        createFinding(
          'gcp-no-workload-identity',
          `Project/${projectId}`,
          'No Workload Identity pools configured',
          'info',
          'Use Workload Identity for GKE and external workloads'
        )
      );
      return findings;
    }

    for (const pool of pools) {
      // Check if pool is disabled
      if (pool.disabled) {
        findings.push(
          createFinding(
            'gcp-workload-identity-disabled',
            pool.name || 'Unknown',
            'Workload Identity pool is disabled',
            'info',
            'Remove disabled pools if not needed'
          )
        );
        continue;
      }

      // List providers in the pool
      const providersResponse = await iam.projects.locations.workloadIdentityPools.providers.list({
        parent: pool.name!,
      });

      const providers = (providersResponse.data.workloadIdentityPoolProviders ||
        []) as WorkloadIdentityProvider[];

      for (const provider of providers) {
        // Check for overly permissive attribute conditions
        if (!provider.attributeCondition) {
          findings.push(
            createFinding(
              'gcp-workload-identity-no-condition',
              provider.name || 'Unknown',
              'Workload Identity provider has no attribute condition',
              'warning',
              'Add attribute conditions to restrict which identities can authenticate'
            )
          );
        }

        // Check AWS provider configuration
        if (provider.aws) {
          if (!provider.attributeCondition?.includes('aws.arn')) {
            findings.push(
              createFinding(
                'gcp-workload-identity-aws-no-arn-filter',
                provider.name || 'Unknown',
                'AWS Workload Identity provider not filtering by ARN',
                'warning',
                'Add attribute condition on aws.arn to restrict access'
              )
            );
          }
        }

        // Check OIDC provider configuration
        if (provider.oidc) {
          // Check allowed audiences
          if (!provider.oidc.allowedAudiences?.length) {
            findings.push(
              createFinding(
                'gcp-workload-identity-oidc-no-audience',
                provider.name || 'Unknown',
                'OIDC Workload Identity provider has no audience restriction',
                'info',
                'Specify allowed audiences for OIDC tokens'
              )
            );
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403 && err.code !== 404) throw error;
  }

  return findings;
}
