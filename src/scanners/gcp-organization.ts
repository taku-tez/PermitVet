/**
 * GCP Organization Scanner
 * Organization-level IAM analysis, folder hierarchy, cross-project permissions
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

interface CustomRole {
  name?: string;
  deleted?: boolean;
}

interface CustomRoleDetails {
  includedPermissions?: string[];
}

interface Folder {
  name?: string;
  displayName?: string;
}

interface Project {
  name?: string;
  projectId?: string;
  state?: string;
}

interface ProjectAccess {
  project: string;
  role: string;
}

/**
 * Scan GCP Organization for IAM issues
 */
export async function scanGCPOrganization(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { google } = await import('googleapis');

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });

    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v3', auth }) as any;

    const iam = google.iam({ version: 'v1', auth }) as any;

    const organizationId = options.organization;
    const folderId = options.folder;
    const allProjects = options.allProjects;

    if (organizationId) {
      // Organization-level scan
      console.log(`  Scanning organization: ${organizationId}...`);

      // 1. Organization IAM Policy
      console.log('  Checking organization IAM policy...');
      const orgIamFindings = await scanOrganizationIAM(cloudresourcemanager, organizationId);
      findings.push(...orgIamFindings);

      // 2. Organization-level Custom Roles
      console.log('  Scanning organization custom roles...');
      const orgRoleFindings = await scanOrganizationRoles(iam, organizationId);
      findings.push(...orgRoleFindings);

      // 3. Folder hierarchy analysis
      console.log('  Analyzing folder hierarchy...');
      const folderFindings = await analyzeFolderHierarchy(
        cloudresourcemanager,
        `organizations/${organizationId}`
      );
      findings.push(...folderFindings);

      // 4. All projects in organization (if requested)
      if (allProjects) {
        console.log('  Scanning all projects in organization...');
        const projectFindings = await scanAllProjects(
          cloudresourcemanager,
          `organizations/${organizationId}`
        );
        findings.push(...projectFindings);
      }
    } else if (folderId) {
      // Folder-level scan
      console.log(`  Scanning folder: ${folderId}...`);

      // 1. Folder IAM Policy
      console.log('  Checking folder IAM policy...');
      const folderIamFindings = await scanFolderIAM(cloudresourcemanager, folderId);
      findings.push(...folderIamFindings);

      // 2. Sub-folder hierarchy
      console.log('  Analyzing sub-folder hierarchy...');
      const subFolderFindings = await analyzeFolderHierarchy(
        cloudresourcemanager,
        `folders/${folderId}`
      );
      findings.push(...subFolderFindings);

      // 3. All projects in folder (if requested)
      if (allProjects) {
        console.log('  Scanning all projects in folder...');
        const projectFindings = await scanAllProjects(cloudresourcemanager, `folders/${folderId}`);
        findings.push(...projectFindings);
      }
    } else if (allProjects) {
      // Need organization or folder for all-projects scan
      console.error('  --all-projects requires --organization or --folder');
      findings.push({
        id: 'gcp-org-missing-parent',
        severity: 'info',
        resource: 'GCP',
        message: '--all-projects requires --organization or --folder',
        recommendation: 'Specify organization ID or folder ID',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: string | number };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error('GCP SDK not installed.');
    } else if (err.code === 403) {
      findings.push({
        id: 'gcp-org-permission-denied',
        severity: 'warning',
        resource: 'Organization',
        message: 'Unable to access organization-level resources',
        recommendation: 'Ensure scanner has resourcemanager.organizations.* permissions',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Folder IAM Policy
 */
async function scanFolderIAM(cloudresourcemanager: any, folderId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await cloudresourcemanager.folders.getIamPolicy({
      resource: `folders/${folderId}`,
      requestBody: {},
    });

    const bindings = response.data?.bindings || [];

    for (const binding of bindings) {
      const role = binding.role;
      const members = binding.members || [];

      // Check for public access
      if (members.includes('allUsers') || members.includes('allAuthenticatedUsers')) {
        findings.push({
          id: 'gcp-folder-public-access',
          severity: 'critical',
          resource: `Folder/${folderId}`,
          message: `Role ${role} granted to ${members.includes('allUsers') ? 'allUsers' : 'allAuthenticatedUsers'}`,
          recommendation: 'Remove public access from folder IAM policy',
        });
      }

      // Check for broad domain access
      for (const member of members) {
        if (member.startsWith('domain:')) {
          findings.push({
            id: 'gcp-folder-domain-access',
            severity: 'warning',
            resource: `Folder/${folderId}`,
            message: `Role ${role} granted to entire domain: ${member}`,
            recommendation: 'Consider restricting to specific users or groups',
          });
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code === 403) {
      findings.push({
        id: 'gcp-folder-permission-denied',
        severity: 'info',
        resource: `Folder/${folderId}`,
        message: 'Unable to read folder IAM policy',
        recommendation: 'Ensure scanner has resourcemanager.folders.getIamPolicy permission',
      });
    }
  }

  return findings;
}

/**
 * Scan Organization IAM Policy
 */
async function scanOrganizationIAM(
  cloudresourcemanager: any,
  organizationId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await cloudresourcemanager.organizations.getIamPolicy({
      resource: `organizations/${organizationId}`,
      requestBody: {},
    });

    const policy = response.data as IAMPolicy;

    for (const binding of policy.bindings || []) {
      const role = binding.role;
      const members = binding.members || [];

      // Critical: Organization-level Owner/Editor
      if (role === 'roles/owner' || role === 'roles/editor') {
        findings.push({
          id: 'gcp-org-primitive-role',
          severity: 'critical',
          resource: `Organization/${organizationId}`,
          message: `${members.length} principal(s) have ${role} at organization level`,
          recommendation:
            'Avoid primitive roles at org level. Use folder/project-level assignments.',
          details: { role, memberCount: members.length },
        });
      }

      // Organization Admin
      if (role === 'roles/resourcemanager.organizationAdmin') {
        findings.push({
          id: 'gcp-org-admin-count',
          severity: members.length > 5 ? 'warning' : 'info',
          resource: `Organization/${organizationId}`,
          message: `${members.length} Organization Admin(s)`,
          recommendation: 'Limit Organization Admins to essential personnel only',
          details: { memberCount: members.length },
        });
      }

      // Folder Admin at org level (can manage all folders)
      if (role === 'roles/resourcemanager.folderAdmin') {
        findings.push({
          id: 'gcp-org-folder-admin',
          severity: 'warning',
          resource: `Organization/${organizationId}`,
          message: `${members.length} principal(s) have Folder Admin at org level`,
          recommendation: 'Assign Folder Admin at folder level, not organization',
        });
      }

      // IAM Security Admin at org level
      if (role === 'roles/iam.securityAdmin') {
        findings.push({
          id: 'gcp-org-security-admin',
          severity: 'warning',
          resource: `Organization/${organizationId}`,
          message: `${members.length} Security Admin(s) at organization level`,
          recommendation: 'Review if org-wide Security Admin is necessary',
        });
      }

      // Service Account with org-level permissions
      for (const member of members) {
        if (member.startsWith('serviceAccount:')) {
          const dangerousOrgRoles = [
            'roles/owner',
            'roles/editor',
            'roles/resourcemanager.organizationAdmin',
            'roles/iam.securityAdmin',
            'roles/resourcemanager.folderAdmin',
          ];

          if (role && dangerousOrgRoles.includes(role)) {
            findings.push({
              id: 'gcp-org-sa-privileged',
              severity: 'critical',
              resource: `Organization/${organizationId}`,
              message: `Service account ${member} has ${role} at org level`,
              recommendation: 'Service accounts should not have org-level privileged roles',
            });
          }
        }
      }

      // External/Guest users at org level
      for (const member of members) {
        if (member.startsWith('user:') && member.includes('@')) {
          // Check if user is from a different domain (would need org domain info)
          // For now, flag any user with high privileges
          if (role === 'roles/owner' || role === 'roles/resourcemanager.organizationAdmin') {
            findings.push({
              id: 'gcp-org-user-privileged',
              severity: 'warning',
              resource: `Organization/${organizationId}`,
              message: `User ${member} has ${role} at org level`,
              recommendation: 'Review if user requires org-level privileges',
            });
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code === 403) {
      findings.push({
        id: 'gcp-org-iam-denied',
        severity: 'info',
        resource: `Organization/${organizationId}`,
        message: 'Unable to read organization IAM policy',
        recommendation: 'Need resourcemanager.organizations.getIamPolicy permission',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Organization-level Custom Roles
 */
async function scanOrganizationRoles(iam: any, organizationId: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await iam.organizations.roles.list({
      parent: `organizations/${organizationId}`,
    });

    const roles = (response.data.roles || []) as CustomRole[];

    // Dangerous permissions at org level
    const criticalPermissions = [
      'resourcemanager.organizations.setIamPolicy',
      'resourcemanager.folders.setIamPolicy',
      'resourcemanager.projects.setIamPolicy',
      'iam.serviceAccountKeys.create',
      'iam.serviceAccounts.actAs',
      'resourcemanager.organizations.delete',
      'resourcemanager.folders.delete',
    ];

    for (const role of roles) {
      if (role.deleted) continue;

      try {
        const roleDetails = await iam.organizations.roles.get({
          name: role.name!,
        });

        const permissions = (roleDetails.data as CustomRoleDetails).includedPermissions || [];

        // Check for critical permissions
        const hasCritical = permissions.filter(p => criticalPermissions.includes(p));
        if (hasCritical.length > 0) {
          findings.push({
            id: 'gcp-org-role-critical-perms',
            severity: 'critical',
            resource: `OrgRole/${role.name?.split('/').pop()}`,
            message: `Org-level custom role has ${hasCritical.length} critical permission(s)`,
            recommendation: 'Review critical permissions in organization-level custom roles',
            details: { criticalPermissions: hasCritical },
          });
        }

        // Check for wildcard permissions
        const wildcards = permissions.filter(p => p.endsWith('*'));
        if (wildcards.length > 0) {
          findings.push({
            id: 'gcp-org-role-wildcards',
            severity: 'warning',
            resource: `OrgRole/${role.name?.split('/').pop()}`,
            message: `Org-level custom role uses ${wildcards.length} wildcard permission(s)`,
            recommendation: 'Avoid wildcards in organization-level roles',
          });
        }
      } catch {
        // Skip if can't get role details
      }
    }

    // Report org role count
    if (roles.length > 20) {
      findings.push({
        id: 'gcp-org-many-custom-roles',
        severity: 'info',
        resource: `Organization/${organizationId}`,
        message: `${roles.length} custom roles defined at organization level`,
        recommendation: 'Review if all org-level roles are necessary',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403) throw error;
  }

  return findings;
}

/**
 * Analyze Folder Hierarchy
 */
async function analyzeFolderHierarchy(
  cloudresourcemanager: any,
  parent: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List all folders under parent
    const response = await cloudresourcemanager.folders.list({
      parent,
    });

    const folders = (response.data.folders || []) as Folder[];

    for (const folder of folders) {
      // Check folder IAM policy
      try {
        const policyResponse = await cloudresourcemanager.folders.getIamPolicy({
          resource: folder.name!,
          requestBody: {},
        });

        const policy = policyResponse.data as IAMPolicy;

        for (const binding of policy.bindings || []) {
          const role = binding.role;
          const members = binding.members || [];

          // Primitive roles at folder level
          if (role === 'roles/owner' || role === 'roles/editor') {
            findings.push({
              id: 'gcp-folder-primitive-role',
              severity: 'warning',
              resource: `Folder/${folder.displayName}`,
              message: `${members.length} principal(s) have ${role} at folder level`,
              recommendation: 'Prefer project-level role assignments over folder-level',
            });
          }

          // Check for allUsers/allAuthenticatedUsers
          if (members.includes('allUsers') || members.includes('allAuthenticatedUsers')) {
            findings.push({
              id: 'gcp-folder-public-access',
              severity: 'critical',
              resource: `Folder/${folder.displayName}`,
              message: `Public access granted at folder level: ${role}`,
              recommendation: 'Remove public access from folders immediately',
            });
          }
        }
      } catch {
        // Skip if can't read folder policy
      }

      // Recursively check sub-folders
      const subFindings = await analyzeFolderHierarchy(cloudresourcemanager, folder.name!);
      findings.push(...subFindings);
    }

    // Check folder count
    if (folders.length > 50) {
      findings.push({
        id: 'gcp-many-folders',
        severity: 'info',
        resource: parent,
        message: `${folders.length} direct child folders`,
        recommendation: 'Consider consolidating folder structure if too complex',
      });
    }
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403) throw error;
  }

  return findings;
}

/**
 * Scan All Projects under a parent
 */
async function scanAllProjects(cloudresourcemanager: any, parent: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // List all projects under parent
    const response = await cloudresourcemanager.projects.list({
      parent,
    });

    const projects = (response.data.projects || []) as Project[];

    console.log(`  Found ${projects.length} projects...`);

    // Cross-project analysis
    const projectPermissions = new Map<string, ProjectAccess[]>(); // member -> [projects with owner/editor]

    for (const project of projects) {
      if (project.state !== 'ACTIVE') continue;

      try {
        // Get project IAM policy
        const policyResponse = await cloudresourcemanager.projects.getIamPolicy({
          resource: project.name!,
          requestBody: {},
        });

        const policy = policyResponse.data as IAMPolicy;

        for (const binding of policy.bindings || []) {
          const role = binding.role;

          // Track cross-project privileged access
          if (role === 'roles/owner' || role === 'roles/editor') {
            for (const member of binding.members || []) {
              if (!projectPermissions.has(member)) {
                projectPermissions.set(member, []);
              }
              projectPermissions.get(member)!.push({
                project: project.projectId!,
                role: role!,
              });
            }
          }
        }
      } catch {
        // Skip projects we can't access
      }
    }

    // Analyze cross-project permissions
    for (const [member, projectAccess] of projectPermissions) {
      if (projectAccess.length > 5) {
        findings.push({
          id: 'gcp-cross-project-privileged',
          severity: 'warning',
          resource: member,
          message: `Principal has Owner/Editor in ${projectAccess.length} projects`,
          recommendation: 'Review if cross-project privileged access is necessary',
          details: {
            projectCount: projectAccess.length,
            projects: projectAccess.slice(0, 5).map(p => p.project),
          },
        });
      }
    }

    // Service accounts with access to multiple projects
    const serviceAccounts = [...projectPermissions.entries()].filter(([member]) =>
      member.startsWith('serviceAccount:')
    );

    for (const [sa, access] of serviceAccounts) {
      if (access.length > 3) {
        findings.push({
          id: 'gcp-sa-multi-project',
          severity: 'warning',
          resource: sa,
          message: `Service account has privileged access to ${access.length} projects`,
          recommendation: 'Service accounts should be scoped to single projects',
        });
      }
    }

    // Project count summary
    findings.push({
      id: 'gcp-project-count',
      severity: 'info',
      resource: parent,
      message: `${projects.length} projects scanned`,
      recommendation: '',
    });
  } catch (error) {
    const err = error as Error & { code?: number };
    if (err.code !== 403) throw error;
  }

  return findings;
}
