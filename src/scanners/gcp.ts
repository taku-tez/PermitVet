/**
 * GCP IAM Scanner
 * Scans GCP IAM configurations for security issues based on CIS benchmarks
 */

import type { Finding, ScanOptions, Severity } from '../types';

// GCP types
interface IAMPolicy {
  bindings?: IAMBinding[];
}

interface IAMBinding {
  role?: string;
  members?: string[];
}

interface ServiceAccount {
  email?: string;
  disabled?: boolean;
}

interface ServiceAccountKey {
  name?: string;
  keyType?: string;
  validAfterTime?: string;
}

interface CustomRole {
  name?: string;
  deleted?: boolean;
  includedPermissions?: string[];
}

interface DangerousPermission {
  perm: string;
  severity: Severity;
  msg: string;
}

/**
 * Scan GCP IAM for permission issues
 */
export async function scanGCP(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    // Initialize clients
    const auth = new google.auth.GoogleAuth({
      scopes: [
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/iam',
      ],
    });

    const projectId =
      options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;

    if (!projectId) {
      console.error('No GCP project specified. Use --project or set GOOGLE_CLOUD_PROJECT');
      return findings;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const iam = google.iam({ version: 'v1', auth }) as any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v1', auth }) as any;

    // 1. Scan Project IAM Policy
    console.log('  Checking project IAM policy...');
    const policyFindings = await scanProjectIAMPolicy(cloudresourcemanager, projectId);
    findings.push(...policyFindings);

    // 2. Scan Service Accounts
    console.log('  Scanning service accounts...');
    const saFindings = await scanServiceAccounts(iam, projectId);
    findings.push(...saFindings);

    // 3. Scan Custom Roles
    console.log('  Scanning custom roles...');
    const roleFindings = await scanCustomRoles(iam, projectId);
    findings.push(...roleFindings);
  } catch (error) {
    const err = error as Error & { code?: string | number };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error(
        'GCP SDK not installed. Run: npm install googleapis @google-cloud/iam-credentials @google-cloud/resource-manager'
      );
    } else if (err.code === 401 || err.code === 403) {
      console.error('GCP authentication failed. Run: gcloud auth application-default login');
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Project IAM Policy for risky bindings
 */
async function scanProjectIAMPolicy(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cloudresourcemanager: any,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await cloudresourcemanager.projects.getIamPolicy({
      resource: projectId,
      requestBody: {},
    });

    const policy = response.data as IAMPolicy;

    for (const binding of policy.bindings || []) {
      const role = binding.role;
      const members = binding.members || [];

      // Check for primitive roles (CIS 1.3)
      if (role === 'roles/owner' || role === 'roles/editor') {
        for (const member of members) {
          // Skip organization-level service accounts
          if (member.includes('gserviceaccount.com') && !member.includes('@' + projectId)) {
            continue;
          }

          findings.push({
            id: 'gcp-primitive-role',
            severity: 'warning',
            resource: `Project/${projectId}`,
            message: `${member} has primitive role: ${role}`,
            recommendation: 'Use predefined or custom roles instead of Owner/Editor',
            cis: '1.3',
          });
        }
      }

      // Check for allUsers or allAuthenticatedUsers (public access)
      if (members.includes('allUsers')) {
        findings.push({
          id: 'gcp-public-access',
          severity: 'critical',
          resource: `Project/${projectId}`,
          message: `Role ${role} granted to allUsers (public)`,
          recommendation: 'Remove public access unless absolutely required',
        });
      }

      if (members.includes('allAuthenticatedUsers')) {
        findings.push({
          id: 'gcp-authenticated-users',
          severity: 'critical',
          resource: `Project/${projectId}`,
          message: `Role ${role} granted to allAuthenticatedUsers`,
          recommendation:
            'This grants access to any Google account - restrict to specific principals',
        });
      }

      // Check for domain-wide delegation capable roles
      const delegationRoles = [
        'roles/iam.serviceAccountTokenCreator',
        'roles/iam.serviceAccountUser',
        'roles/iam.serviceAccountAdmin',
      ];

      if (role && delegationRoles.includes(role)) {
        for (const member of members) {
          if (!member.startsWith('serviceAccount:')) continue;

          findings.push({
            id: 'gcp-service-account-impersonation',
            severity: 'warning',
            resource: `Project/${projectId}`,
            message: `${member} has ${role} - can impersonate other service accounts`,
            recommendation: 'Limit service account impersonation permissions',
            cis: '1.6',
          });
        }
      }

      // Check for dangerous permissions
      const dangerousRoles: Array<{ role: string; severity: Severity; msg: string }> = [
        { role: 'roles/owner', severity: 'critical', msg: 'Full project owner access' },
        {
          role: 'roles/editor',
          severity: 'warning',
          msg: 'Project editor access (can modify most resources)',
        },
        {
          role: 'roles/iam.securityAdmin',
          severity: 'warning',
          msg: 'Can manage all IAM policies',
        },
        {
          role: 'roles/resourcemanager.projectIamAdmin',
          severity: 'warning',
          msg: 'Can manage project IAM',
        },
        { role: 'roles/storage.admin', severity: 'info', msg: 'Full Cloud Storage admin' },
        { role: 'roles/compute.admin', severity: 'info', msg: 'Full Compute Engine admin' },
        { role: 'roles/cloudfunctions.admin', severity: 'info', msg: 'Full Cloud Functions admin' },
      ];

      for (const dr of dangerousRoles) {
        if (role === dr.role) {
          for (const member of members) {
            if (member.startsWith('serviceAccount:')) {
              findings.push({
                id: `gcp-sa-${dr.role.split('/')[1]}`,
                severity: dr.severity,
                resource: `Project/${projectId}`,
                message: `Service account ${member} has ${dr.msg}`,
                recommendation: 'Apply least privilege to service accounts',
              });
            }
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code === 403) {
      findings.push({
        id: 'gcp-permission-denied',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'Unable to read project IAM policy',
        recommendation: 'Ensure scanner has resourcemanager.projects.getIamPolicy permission',
      });
    }
  }

  return findings;
}

/**
 * Scan Service Accounts for security issues
 */
async function scanServiceAccounts(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  iam: any,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List all service accounts
    const response = await iam.projects.serviceAccounts.list({
      name: `projects/${projectId}`,
    });

    const serviceAccounts = (response.data.accounts || []) as ServiceAccount[];

    for (const sa of serviceAccounts) {
      // Skip Google-managed service accounts
      if (
        sa.email?.includes('gserviceaccount.com') &&
        (sa.email.includes('developer.gserviceaccount.com') ||
          sa.email.includes('compute@') ||
          sa.email.includes('cloudservices.gserviceaccount.com'))
      ) {
        continue;
      }

      // Check service account keys
      const keysResponse = await iam.projects.serviceAccounts.keys.list({
        name: `projects/${projectId}/serviceAccounts/${sa.email}`,
      });

      const keys = (keysResponse.data.keys || []) as ServiceAccountKey[];
      const userManagedKeys = keys.filter(k => k.keyType === 'USER_MANAGED');

      // CIS 1.4: Avoid user-managed service account keys
      if (userManagedKeys.length > 0) {
        findings.push({
          id: 'gcp-user-managed-keys',
          severity: 'warning',
          resource: `ServiceAccount/${sa.email}`,
          message: `Service account has ${userManagedKeys.length} user-managed key(s)`,
          recommendation: 'Use GCP-managed keys or Workload Identity instead of user-managed keys',
          cis: '1.4',
        });

        // Check key age (CIS 1.7)
        for (const key of userManagedKeys) {
          const keyId = key.name?.split('/').pop();
          const validAfterTime = new Date(key.validAfterTime!);
          const daysSince = (Date.now() - validAfterTime.getTime()) / (1000 * 60 * 60 * 24);

          if (daysSince > 90) {
            findings.push({
              id: 'gcp-key-old',
              severity: 'warning',
              resource: `ServiceAccount/${sa.email}/Key/${keyId}`,
              message: `Service account key is ${Math.floor(daysSince)} days old`,
              recommendation: 'Rotate service account keys every 90 days',
              cis: '1.7',
            });
          }
        }
      }

      // Check for disabled service accounts with keys
      if (sa.disabled && userManagedKeys.length > 0) {
        findings.push({
          id: 'gcp-disabled-sa-with-keys',
          severity: 'info',
          resource: `ServiceAccount/${sa.email}`,
          message: 'Disabled service account still has user-managed keys',
          recommendation: 'Delete keys for disabled service accounts',
        });
      }

      // Get IAM policy on the service account itself (who can impersonate it)
      try {
        const saPolicy = await iam.projects.serviceAccounts.getIamPolicy({
          resource: `projects/${projectId}/serviceAccounts/${sa.email}`,
        });

        for (const binding of (saPolicy.data.bindings || []) as IAMBinding[]) {
          const role = binding.role;
          const members = binding.members || [];

          // Check for broad impersonation rights
          if (
            role === 'roles/iam.serviceAccountUser' ||
            role === 'roles/iam.serviceAccountTokenCreator'
          ) {
            for (const member of members) {
              if (member === 'allUsers' || member === 'allAuthenticatedUsers') {
                findings.push({
                  id: 'gcp-public-sa-impersonation',
                  severity: 'critical',
                  resource: `ServiceAccount/${sa.email}`,
                  message: `Service account can be impersonated by ${member}`,
                  recommendation: 'Remove public impersonation permissions immediately',
                });
              }
            }
          }
        }
      } catch {
        // Skip if unable to get SA policy
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code === 403) {
      findings.push({
        id: 'gcp-sa-permission-denied',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'Unable to list service accounts',
        recommendation: 'Ensure scanner has iam.serviceAccounts.list permission',
      });
    }
  }

  return findings;
}

/**
 * Scan Custom Roles for dangerous permissions
 */
async function scanCustomRoles(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  iam: any,
  projectId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List custom roles at project level
    const response = await iam.projects.roles.list({
      parent: `projects/${projectId}`,
    });

    const roles = (response.data.roles || []) as CustomRole[];

    // Dangerous permissions that enable privilege escalation
    const dangerousPermissions: DangerousPermission[] = [
      {
        perm: 'iam.serviceAccountKeys.create',
        severity: 'critical',
        msg: 'Can create service account keys',
      },
      {
        perm: 'iam.serviceAccountTokenCreator',
        severity: 'critical',
        msg: 'Can create tokens for service accounts',
      },
      {
        perm: 'iam.serviceAccounts.actAs',
        severity: 'warning',
        msg: 'Can act as service accounts',
      },
      {
        perm: 'iam.serviceAccounts.getAccessToken',
        severity: 'critical',
        msg: 'Can get access tokens',
      },
      {
        perm: 'iam.serviceAccounts.signBlob',
        severity: 'warning',
        msg: 'Can sign blobs as service accounts',
      },
      {
        perm: 'iam.serviceAccounts.signJwt',
        severity: 'warning',
        msg: 'Can sign JWTs as service accounts',
      },
      {
        perm: 'resourcemanager.projects.setIamPolicy',
        severity: 'critical',
        msg: 'Can modify project IAM policies',
      },
      {
        perm: 'deploymentmanager.deployments.create',
        severity: 'warning',
        msg: 'Can create deployments (potential code execution)',
      },
      {
        perm: 'cloudfunctions.functions.create',
        severity: 'warning',
        msg: 'Can create Cloud Functions (code execution)',
      },
      {
        perm: 'cloudfunctions.functions.setIamPolicy',
        severity: 'warning',
        msg: 'Can set Cloud Functions IAM',
      },
      {
        perm: 'compute.instances.setServiceAccount',
        severity: 'warning',
        msg: 'Can change VM service accounts',
      },
      { perm: 'run.services.setIamPolicy', severity: 'warning', msg: 'Can set Cloud Run IAM' },
      {
        perm: 'storage.buckets.setIamPolicy',
        severity: 'warning',
        msg: 'Can set bucket IAM policies',
      },
    ];

    for (const role of roles) {
      // Skip deleted roles
      if (role.deleted) continue;

      // Get full role details including permissions
      const roleDetails = await iam.projects.roles.get({
        name: role.name!,
      });

      const permissions = (roleDetails.data.includedPermissions || []) as string[];

      // Check for wildcard permissions
      if (permissions.some(p => p.endsWith('*'))) {
        findings.push({
          id: 'gcp-custom-role-wildcard',
          severity: 'warning',
          resource: `CustomRole/${role.name?.split('/').pop()}`,
          message: 'Custom role uses wildcard permissions',
          recommendation: 'Specify exact permissions instead of wildcards',
        });
      }

      // Check for dangerous permissions
      for (const dp of dangerousPermissions) {
        if (permissions.includes(dp.perm)) {
          findings.push({
            id: `gcp-custom-role-${dp.perm.replace(/\./g, '-')}`,
            severity: dp.severity,
            resource: `CustomRole/${role.name?.split('/').pop()}`,
            message: `Custom role has permission: ${dp.perm} - ${dp.msg}`,
            recommendation: 'Review if this permission is necessary',
          });
        }
      }

      // Check for privilege escalation combinations
      const canSetIAM = permissions.some(p => p.includes('setIamPolicy'));
      const canActAs = permissions.includes('iam.serviceAccounts.actAs');
      const canCreateFunction = permissions.includes('cloudfunctions.functions.create');

      if (canActAs && canCreateFunction) {
        findings.push({
          id: 'gcp-privesc-function-actAs',
          severity: 'critical',
          resource: `CustomRole/${role.name?.split('/').pop()}`,
          message: 'Can create functions and actAs service accounts (privilege escalation)',
          recommendation: 'This combination allows executing code as other service accounts',
        });
      }

      if (canSetIAM && !role.name?.includes('admin')) {
        findings.push({
          id: 'gcp-privesc-setIamPolicy',
          severity: 'critical',
          resource: `CustomRole/${role.name?.split('/').pop()}`,
          message: 'Non-admin role can modify IAM policies (privilege escalation)',
          recommendation: 'setIamPolicy permissions should be tightly controlled',
        });
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code === 403) {
      findings.push({
        id: 'gcp-roles-permission-denied',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'Unable to list custom roles',
        recommendation: 'Ensure scanner has iam.roles.list permission',
      });
    }
  }

  return findings;
}
