/**
 * GCP Advanced IAM Scanner
 * Organization Policies, VPC Service Controls, Hierarchy Analysis
 */

/**
 * Scan GCP advanced security features
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanGCPAdvanced(options = {}) {
  const findings = [];

  try {
    const { google } = require('googleapis');
    
    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    
    const projectId = options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
    
    if (!projectId) {
      console.error('No GCP project specified.');
      return findings;
    }

    // 1. Organization Policies
    console.log('  Checking Organization Policies...');
    const orgPolicyFindings = await scanOrganizationPolicies(auth, projectId);
    findings.push(...orgPolicyFindings);

    // 2. VPC Service Controls
    console.log('  Checking VPC Service Controls...');
    const vpcscFindings = await scanVPCServiceControls(auth, projectId);
    findings.push(...vpcscFindings);

    // 3. Resource Hierarchy Inheritance
    console.log('  Analyzing IAM hierarchy...');
    const hierarchyFindings = await analyzeIAMHierarchy(auth, projectId);
    findings.push(...hierarchyFindings);

    // 4. Workload Identity Federation
    console.log('  Checking Workload Identity...');
    const workloadFindings = await checkWorkloadIdentity(auth, projectId);
    findings.push(...workloadFindings);

  } catch (error) {
    if (error.code === 403) {
      findings.push({
        id: 'gcp-advanced-permission-denied',
        severity: 'info',
        resource: `Project/${options.project}`,
        message: 'Unable to access advanced GCP features',
        recommendation: 'Ensure scanner has orgpolicy.* and accesscontextmanager.* permissions',
      });
    } else if (error.code !== 'MODULE_NOT_FOUND') {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Organization Policies
 */
async function scanOrganizationPolicies(auth, projectId) {
  const findings = [];
  
  try {
    const orgpolicy = google.orgpolicy({ version: 'v2', auth });
    
    // List all organization policies for the project
    const response = await orgpolicy.projects.policies.list({
      parent: `projects/${projectId}`,
    });
    
    const policies = response.data.policies || [];
    
    // Important security policies to check
    const securityPolicies = {
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
      'constraints/compute.requireOsLogin': {
        expected: true,
        severity: 'warning',
        msg: 'OS Login should be required for compute instances',
        recommendation: 'Use OS Login instead of SSH keys in metadata',
        cis: '4.4',
      },
      'constraints/compute.disableSerialPortAccess': {
        expected: true,
        severity: 'info',
        msg: 'Serial port access should be disabled',
        recommendation: 'Disable serial port for production workloads',
      },
      'constraints/compute.requireShieldedVm': {
        expected: true,
        severity: 'info',
        msg: 'Shielded VMs should be required',
        recommendation: 'Enable Shielded VM for enhanced security',
      },
      'constraints/storage.uniformBucketLevelAccess': {
        expected: true,
        severity: 'warning',
        msg: 'Uniform bucket-level access should be enabled',
        recommendation: 'Use uniform access instead of ACLs',
        cis: '5.2',
      },
      'constraints/sql.restrictPublicIp': {
        expected: true,
        severity: 'warning',
        msg: 'Public IP for Cloud SQL should be restricted',
        recommendation: 'Use private IP for Cloud SQL instances',
      },
      'constraints/iam.allowedPolicyMemberDomains': {
        checkDomains: true,
        severity: 'info',
        msg: 'Domain restriction policy should be set',
        recommendation: 'Restrict IAM members to specific domains',
      },
    };
    
    // Check which policies are set
    const setPolicies = new Set(policies.map(p => p.name?.split('/').pop()));
    
    for (const [constraint, config] of Object.entries(securityPolicies)) {
      const policyName = constraint.replace('constraints/', '');
      
      if (!setPolicies.has(policyName)) {
        findings.push({
          id: `gcp-orgpolicy-${policyName.replace(/\./g, '-')}`,
          severity: config.severity,
          resource: `Project/${projectId}`,
          message: config.msg,
          recommendation: config.recommendation,
          cis: config.cis,
        });
      }
    }
    
    // Check specific policy configurations
    for (const policy of policies) {
      const constraintName = policy.name?.split('/').pop();
      
      // Check if boolean constraints are enforced
      if (policy.spec?.rules?.[0]?.enforce === false) {
        const config = securityPolicies[`constraints/${constraintName}`];
        if (config?.expected) {
          findings.push({
            id: `gcp-orgpolicy-not-enforced-${constraintName.replace(/\./g, '-')}`,
            severity: config.severity,
            resource: `Project/${projectId}`,
            message: `${constraintName} is set but not enforced`,
            recommendation: config.recommendation,
          });
        }
      }
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Scan VPC Service Controls
 */
async function scanVPCServiceControls(auth, projectId) {
  const findings = [];
  
  try {
    const accesscontextmanager = google.accesscontextmanager({ version: 'v1', auth });
    
    // List access policies
    const policiesResponse = await accesscontextmanager.accessPolicies.list({});
    const policies = policiesResponse.data.accessPolicies || [];
    
    if (policies.length === 0) {
      findings.push({
        id: 'gcp-no-vpc-service-controls',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'No VPC Service Controls configured',
        recommendation: 'Consider using VPC Service Controls for data exfiltration prevention',
      });
      return findings;
    }
    
    for (const policy of policies) {
      // List service perimeters
      const perimetersResponse = await accesscontextmanager.accessPolicies.servicePerimeters.list({
        parent: policy.name,
      });
      
      const perimeters = perimetersResponse.data.servicePerimeters || [];
      
      if (perimeters.length === 0) {
        findings.push({
          id: 'gcp-no-service-perimeters',
          severity: 'info',
          resource: policy.name,
          message: 'Access Policy exists but has no service perimeters',
          recommendation: 'Create service perimeters to protect sensitive resources',
        });
        continue;
      }
      
      for (const perimeter of perimeters) {
        const config = perimeter.status || perimeter.spec;
        
        // Check for dry-run only perimeters
        if (perimeter.useExplicitDryRunSpec && !perimeter.status) {
          findings.push({
            id: 'gcp-perimeter-dry-run-only',
            severity: 'info',
            resource: perimeter.name,
            message: 'Service perimeter is in dry-run mode only',
            recommendation: 'Enable enforcement after testing',
          });
        }
        
        // Check for overly permissive ingress/egress
        const ingressPolicies = config?.ingressPolicies || [];
        const egressPolicies = config?.egressPolicies || [];
        
        for (const ingress of ingressPolicies) {
          // Check for any identity allowed
          if (ingress.ingressFrom?.identities?.includes('*') ||
              ingress.ingressFrom?.identityType === 'ANY_IDENTITY') {
            findings.push({
              id: 'gcp-perimeter-any-ingress',
              severity: 'warning',
              resource: perimeter.name,
              message: 'Service perimeter allows ingress from any identity',
              recommendation: 'Restrict ingress to specific identities',
            });
          }
          
          // Check for all services allowed
          if (ingress.ingressTo?.resources?.includes('*')) {
            findings.push({
              id: 'gcp-perimeter-all-resources-ingress',
              severity: 'info',
              resource: perimeter.name,
              message: 'Service perimeter allows ingress to all resources',
              recommendation: 'Restrict ingress to specific resources',
            });
          }
        }
        
        // Check restricted services
        const restrictedServices = config?.restrictedServices || [];
        const criticalServices = [
          'storage.googleapis.com',
          'bigquery.googleapis.com',
          'secretmanager.googleapis.com',
        ];
        
        const missingServices = criticalServices.filter(s => !restrictedServices.includes(s));
        if (missingServices.length > 0 && restrictedServices.length > 0) {
          findings.push({
            id: 'gcp-perimeter-missing-services',
            severity: 'info',
            resource: perimeter.name,
            message: `Critical services not in perimeter: ${missingServices.join(', ')}`,
            recommendation: 'Add data-sensitive services to the perimeter',
          });
        }
      }
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Analyze IAM hierarchy inheritance
 */
async function analyzeIAMHierarchy(auth, projectId) {
  const findings = [];
  
  try {
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v3', auth });
    
    // Get project info
    const projectResponse = await cloudresourcemanager.projects.get({
      name: `projects/${projectId}`,
    });
    
    const project = projectResponse.data;
    const parent = project.parent;
    
    if (!parent) {
      findings.push({
        id: 'gcp-project-no-org',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'Project is not part of an organization',
        recommendation: 'Move project to an organization for centralized governance',
      });
      return findings;
    }
    
    // Get parent (folder or organization) IAM policy
    let parentPolicy;
    if (parent.startsWith('folders/')) {
      const folderResponse = await cloudresourcemanager.folders.getIamPolicy({
        resource: parent,
        requestBody: {},
      });
      parentPolicy = folderResponse.data;
    } else if (parent.startsWith('organizations/')) {
      const orgResponse = await cloudresourcemanager.organizations.getIamPolicy({
        resource: parent,
        requestBody: {},
      });
      parentPolicy = orgResponse.data;
    }
    
    if (parentPolicy) {
      // Check for inherited privileged roles
      for (const binding of parentPolicy.bindings || []) {
        const role = binding.role;
        const members = binding.members || [];
        
        // Dangerous inherited roles
        const inheritedDangerousRoles = ['roles/owner', 'roles/editor', 'roles/iam.securityAdmin'];
        
        if (inheritedDangerousRoles.includes(role)) {
          findings.push({
            id: 'gcp-inherited-privileged-role',
            severity: 'warning',
            resource: `Project/${projectId}`,
            message: `Project inherits ${role} from ${parent}`,
            recommendation: 'Review inherited permissions. Prefer project-level assignments.',
            details: {
              parent,
              role,
              memberCount: members.length,
            },
          });
        }
      }
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

/**
 * Check Workload Identity configuration
 */
async function checkWorkloadIdentity(auth, projectId) {
  const findings = [];
  
  try {
    const iam = google.iam({ version: 'v1', auth });
    
    // List workload identity pools
    const poolsResponse = await iam.projects.locations.workloadIdentityPools.list({
      parent: `projects/${projectId}/locations/global`,
    });
    
    const pools = poolsResponse.data.workloadIdentityPools || [];
    
    // If no pools but project has GKE or external workloads, suggest WI
    if (pools.length === 0) {
      // This is just informational
      findings.push({
        id: 'gcp-no-workload-identity',
        severity: 'info',
        resource: `Project/${projectId}`,
        message: 'No Workload Identity pools configured',
        recommendation: 'Use Workload Identity for GKE and external workloads',
      });
      return findings;
    }
    
    for (const pool of pools) {
      // Check if pool is disabled
      if (pool.disabled) {
        findings.push({
          id: 'gcp-workload-identity-disabled',
          severity: 'info',
          resource: pool.name,
          message: 'Workload Identity pool is disabled',
          recommendation: 'Remove disabled pools if not needed',
        });
        continue;
      }
      
      // List providers in the pool
      const providersResponse = await iam.projects.locations.workloadIdentityPools.providers.list({
        parent: pool.name,
      });
      
      const providers = providersResponse.data.workloadIdentityPoolProviders || [];
      
      for (const provider of providers) {
        // Check for overly permissive attribute conditions
        if (!provider.attributeCondition) {
          findings.push({
            id: 'gcp-workload-identity-no-condition',
            severity: 'warning',
            resource: provider.name,
            message: 'Workload Identity provider has no attribute condition',
            recommendation: 'Add attribute conditions to restrict which identities can authenticate',
          });
        }
        
        // Check AWS provider configuration
        if (provider.aws) {
          if (!provider.attributeCondition?.includes('aws.arn')) {
            findings.push({
              id: 'gcp-workload-identity-aws-no-arn-filter',
              severity: 'warning',
              resource: provider.name,
              message: 'AWS Workload Identity provider not filtering by ARN',
              recommendation: 'Add attribute condition on aws.arn to restrict access',
            });
          }
        }
        
        // Check OIDC provider configuration
        if (provider.oidc) {
          // Check allowed audiences
          if (!provider.oidc.allowedAudiences?.length) {
            findings.push({
              id: 'gcp-workload-identity-oidc-no-audience',
              severity: 'info',
              resource: provider.name,
              message: 'OIDC Workload Identity provider has no audience restriction',
              recommendation: 'Specify allowed audiences for OIDC tokens',
            });
          }
        }
      }
    }
    
  } catch (error) {
    if (error.code !== 403 && error.code !== 404) throw error;
  }
  
  return findings;
}

module.exports = { scanGCPAdvanced };
