/**
 * Compliance Framework Mapping
 * Maps findings to CIS, SOC2, PCI-DSS, NIST, and ISO27001 controls
 */

import type { Finding, Severity } from './types';

export interface ComplianceControl {
  id: string;
  description: string;
}

export interface ComplianceMapping {
  name: string;
  version: string;
  controls: ComplianceControl[];
}

export interface FindingWithCompliance extends Finding {
  compliance: Record<string, ComplianceMapping>;
}

export interface FrameworkSummary {
  name: string;
  version: string;
  totalControls: number;
  failedControls: string[];
  passedControls: string[];
  score: number;
  findings: {
    findingId: string;
    control: string;
    severity: Severity;
    resource: string;
  }[];
}

export interface ComplianceSummary {
  [frameworkId: string]: FrameworkSummary;
}

export interface SARIFOutput {
  $schema: string;
  version: string;
  runs: SARIFRun[];
}

interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

interface SARIFRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  help: { text: string; markdown: string };
  properties?: { tags: string[] };
}

interface SARIFResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }[];
  properties?: { compliance: Record<string, ComplianceMapping> };
}

interface ComplianceFramework {
  name: string;
  version: string;
  controls: Record<string, string>;
}

export const COMPLIANCE_FRAMEWORKS: Record<string, ComplianceFramework> = {
  // CIS Benchmark controls
  cis: {
    name: 'CIS Benchmark',
    version: 'v1.5.0',
    controls: {
      '1.1': 'Maintain current contact details',
      '1.2': 'Ensure security contact information is registered',
      '1.3': 'Ensure security questions are registered',
      '1.4': 'Ensure no root access keys exist',
      '1.5': 'Ensure MFA is enabled for root account',
      '1.6': 'Ensure hardware MFA is enabled for root',
      '1.7': 'Eliminate use of root user for admin tasks',
      '1.8': 'Ensure IAM password policy requires minimum length',
      '1.9': 'Ensure IAM password policy prevents reuse',
      '1.10': 'Ensure MFA is enabled for all IAM users with console',
      '1.11': 'Do not setup access keys during initial user setup',
      '1.12': 'Ensure credentials unused for 90+ days are disabled',
      '1.13': 'Ensure only one active access key per user',
      '1.14': 'Ensure access keys are rotated every 90 days',
      '1.15': 'Ensure IAM policies attached only to groups or roles',
      '1.16': 'Ensure no inline policies exist',
      '1.17': 'Ensure IAM policy allows access to AWSCloudShell',
      '1.18': 'Ensure IAM instance roles are used for EC2',
      '1.19': 'Ensure expired SSL/TLS certificates are removed',
      '1.20': 'Ensure IAM Access Analyzer is enabled',
      '1.21': 'Ensure IAM users are managed centrally via identity federation',
      '1.22': 'Ensure there are no more than 3 subscription owners',
      '1.23': 'Ensure there are at least 2 subscription owners',
      '1.24': 'Ensure no custom subscription administrator roles exist',
    },
  },

  // SOC 2 Trust Service Criteria
  soc2: {
    name: 'SOC 2',
    version: 'Trust Service Criteria',
    controls: {
      'CC6.1': 'Logical access security - boundary protection',
      'CC6.2': 'Prior to issuing system credentials',
      'CC6.3': 'Authentication mechanisms',
      'CC6.6': 'Encryption for data in transit',
      'CC6.7': 'Encryption for data at rest',
      'CC6.8': 'Protection against malicious code',
    },
  },

  // PCI-DSS v4.0
  'pci-dss': {
    name: 'PCI-DSS',
    version: 'v4.0',
    controls: {
      '7.1': 'Processes and mechanisms for restricting access are defined',
      '7.2': 'Access to system components is appropriately defined and assigned',
      '7.3': 'Access to system components is managed via an access control system',
      '8.1': 'Processes for identification and authentication are defined',
      '8.2': 'User identification and related accounts are managed',
      '8.3': 'Strong authentication for users and administrators',
      '8.4': 'MFA is implemented to secure access',
      '8.5': 'MFA systems are configured properly',
      '8.6': 'Use of application and system accounts is managed',
    },
  },

  // NIST 800-53
  nist: {
    name: 'NIST 800-53',
    version: 'Rev. 5',
    controls: {
      'AC-2': 'Account Management',
      'AC-3': 'Access Enforcement',
      'AC-4': 'Information Flow Enforcement',
      'AC-5': 'Separation of Duties',
      'AC-6': 'Least Privilege',
      'AC-17': 'Remote Access',
      'AC-24': 'Access Control Decisions',
      'IA-2': 'Identification and Authentication',
      'IA-4': 'Identifier Management',
      'IA-5': 'Authenticator Management',
      'IA-8': 'Identification and Authentication (Non-Organizational Users)',
      'SC-7': 'Boundary Protection',
      'SC-8': 'Transmission Confidentiality and Integrity',
    },
  },

  // ISO 27001:2022
  iso27001: {
    name: 'ISO 27001',
    version: '2022',
    controls: {
      'A.5.15': 'Access control policy',
      'A.5.16': 'Identity management',
      'A.5.17': 'Authentication information',
      'A.5.18': 'Access rights',
      'A.8.2': 'Privileged access rights',
      'A.8.3': 'Information access restriction',
      'A.8.5': 'Secure authentication',
    },
  },
};

type FrameworkControls = {
  cis?: string[];
  soc2?: string[];
  'pci-dss'?: string[];
  nist?: string[];
  iso27001?: string[];
};

/**
 * Mapping from finding IDs to compliance controls
 */
export const FINDING_TO_COMPLIANCE: Record<string, FrameworkControls> = {
  // Root account findings
  'aws-root-access-key': {
    cis: ['1.4'],
    soc2: ['CC6.1', 'CC6.2'],
    'pci-dss': ['8.2', '8.6'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'aws-root-mfa-disabled': {
    cis: ['1.5', '1.6'],
    soc2: ['CC6.3'],
    'pci-dss': ['8.4', '8.5'],
    nist: ['IA-2'],
    iso27001: ['A.8.5'],
  },
  'aws-root-used-recently': {
    cis: ['1.7'],
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },

  // User/MFA findings
  'aws-user-mfa-disabled': {
    cis: ['1.10'],
    soc2: ['CC6.3'],
    'pci-dss': ['8.4'],
    nist: ['IA-2'],
    iso27001: ['A.8.5'],
  },
  'aws-user-inactive': {
    cis: ['1.12'],
    soc2: ['CC6.2'],
    'pci-dss': ['8.2'],
    nist: ['AC-2'],
    iso27001: ['A.5.18'],
  },

  // Access key findings
  'aws-access-key-old': {
    cis: ['1.14'],
    soc2: ['CC6.2'],
    'pci-dss': ['8.2'],
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },
  'aws-access-key-unused': {
    cis: ['1.11', '1.12'],
    nist: ['AC-2'],
    iso27001: ['A.5.18'],
  },
  'aws-multiple-access-keys': {
    cis: ['1.13'],
    nist: ['AC-2'],
  },

  // Password policy
  'aws-password-length': {
    cis: ['1.8'],
    soc2: ['CC6.3'],
    'pci-dss': ['8.3'],
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },
  'aws-password-reuse': {
    cis: ['1.9'],
    'pci-dss': ['8.3'],
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },

  // Policy attachment
  'aws-policy-attached-to-user': {
    cis: ['1.15'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.5.18'],
  },
  'aws-inline-policy-user': {
    cis: ['1.16'],
    nist: ['AC-2', 'AC-6'],
  },
  'aws-inline-policy-role': {
    cis: ['1.16'],
    nist: ['AC-2'],
  },

  // Privilege escalation
  'aws-admin-access': {
    soc2: ['CC6.1'],
    'pci-dss': ['7.2'],
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'aws-open-trust-policy': {
    soc2: ['CC6.1'],
    nist: ['AC-3'],
    iso27001: ['A.8.3'],
  },

  // Access Analyzer
  'aws-no-access-analyzer': {
    cis: ['1.20'],
    nist: ['AC-2'],
  },

  // Azure findings
  'azure-sub-owner': {
    cis: ['1.21'],
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'azure-too-many-owners': {
    cis: ['1.22'],
    nist: ['AC-5', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'azure-single-owner': {
    cis: ['1.23'],
    nist: ['AC-2'],
  },
  'azure-classic-admins-exist': {
    cis: ['1.24'],
    nist: ['AC-2'],
  },
  'azure-guest-rbac': {
    cis: ['1.3'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.5.18'],
  },

  // Azure Entra ID findings
  'azure-too-many-global-admins': {
    cis: ['1.1.1'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'azure-single-global-admin': {
    cis: ['1.1.2'],
    nist: ['AC-2'],
  },
  'azure-guest-privileged-role': {
    cis: ['1.3'],
    soc2: ['CC6.1'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.5.18'],
  },
  'azure-sp-global-admin': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'azure-permanent-privileged-assignment': {
    cis: ['1.1.4'],
    nist: ['AC-2'],
    iso27001: ['A.5.18'],
  },
  'azure-pim-no-mfa': {
    cis: ['1.1.3'],
    soc2: ['CC6.3'],
    'pci-dss': ['8.4'],
    nist: ['IA-2'],
    iso27001: ['A.8.5'],
  },
  'azure-no-mfa-policy': {
    cis: ['1.1.3'],
    soc2: ['CC6.3'],
    'pci-dss': ['8.4'],
    nist: ['IA-2'],
    iso27001: ['A.8.5'],
  },
  'azure-legacy-auth-allowed': {
    cis: ['1.1.6'],
    soc2: ['CC6.1'],
    nist: ['AC-17'],
    iso27001: ['A.8.5'],
  },
  'azure-no-conditional-access': {
    soc2: ['CC6.1'],
    nist: ['AC-3'],
    iso27001: ['A.5.15'],
  },
  'azure-app-critical-permission': {
    nist: ['AC-6'],
    iso27001: ['A.5.18'],
  },

  // GCP findings
  'gcp-primitive-role': {
    cis: ['1.3'],
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'gcp-public-access': {
    soc2: ['CC6.1'],
    nist: ['AC-3'],
    iso27001: ['A.8.3'],
  },
  'gcp-user-managed-keys': {
    cis: ['1.4'],
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },
  'gcp-key-old': {
    cis: ['1.7'],
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },

  // GCP Advanced
  'gcp-orgpolicy-iam.disableServiceAccountKeyCreation': {
    cis: ['1.4'],
    nist: ['IA-5'],
  },
  'gcp-no-vpc-service-controls': {
    nist: ['AC-4', 'SC-7'],
    iso27001: ['A.8.3'],
  },
  'gcp-no-workload-identity': {
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },

  // Oracle Cloud (OCI) findings
  'oci-user-no-mfa': {
    soc2: ['CC6.3'],
    'pci-dss': ['8.4'],
    nist: ['IA-2'],
    iso27001: ['A.8.5'],
  },
  'oci-user-inactive': {
    nist: ['AC-2'],
    iso27001: ['A.5.18'],
  },
  'oci-too-many-admins': {
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'oci-single-admin': {
    nist: ['AC-2'],
  },
  'oci-policy-critical': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'oci-old-api-key': {
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },
  'oci-old-auth-token': {
    nist: ['IA-5'],
    iso27001: ['A.5.17'],
  },
  'oci-no-identity-federation': {
    nist: ['IA-8'],
    iso27001: ['A.5.16'],
  },

  // Kubernetes findings
  'k8s-clusterrole-critical': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'k8s-anonymous-cluster-admin': {
    soc2: ['CC6.1'],
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'k8s-all-users-privileged': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'k8s-default-sa-privileged': {
    nist: ['AC-6'],
    iso27001: ['A.5.18'],
  },
  'k8s-too-many-cluster-admins': {
    nist: ['AC-2', 'AC-6'],
    iso27001: ['A.8.2'],
  },
  'k8s-anonymous-in-critical-ns': {
    soc2: ['CC6.1'],
    nist: ['AC-3'],
    iso27001: ['A.8.3'],
  },

  // AWS Advanced findings
  'aws-ec2-imdsv1-allowed': {
    cis: ['5.6'],
    nist: ['SC-8'],
  },
  'aws-s3-account-public-access': {
    cis: ['2.1.4'],
    soc2: ['CC6.1'],
    nist: ['AC-3'],
    iso27001: ['A.8.3'],
  },
  'aws-cross-account-no-external-id': {
    nist: ['AC-3'],
    iso27001: ['A.8.3'],
  },
  'aws-no-scps': {
    nist: ['AC-3'],
  },
  'aws-users-without-boundary': {
    nist: ['AC-6'],
    iso27001: ['A.5.18'],
  },

  // Privilege escalation findings (all providers)
  'privesc-aws-CreateNewPolicyVersion': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'privesc-aws-PassRole_Lambda': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'privesc-azure-RoleAssignment_Write': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
  'privesc-gcp-SetIamPolicy': {
    nist: ['AC-6'],
    iso27001: ['A.8.2'],
  },
};

/**
 * Map finding to compliance controls
 */
export function mapToCompliance(finding: Finding): FindingWithCompliance {
  const mapping = FINDING_TO_COMPLIANCE[finding.id] || {};

  const compliance: Record<string, ComplianceMapping> = {};
  for (const [framework, controls] of Object.entries(mapping)) {
    const frameworkDef = COMPLIANCE_FRAMEWORKS[framework];
    if (frameworkDef && controls) {
      compliance[framework] = {
        name: frameworkDef.name,
        version: frameworkDef.version,
        controls: controls.map(c => ({
          id: c,
          description: frameworkDef.controls[c] || c,
        })),
      };
    }
  }

  return {
    ...finding,
    compliance,
  };
}

interface FrameworkAccumulator {
  name: string;
  version: string;
  totalControls: number;
  failedControls: Set<string>;
  passedControls: Set<string>;
  score: number;
  findings: {
    findingId: string;
    control: string;
    severity: Severity;
    resource: string;
  }[];
}

/**
 * Generate compliance summary report
 */
export function generateComplianceSummary(findings: Finding[]): ComplianceSummary {
  const summary: Record<string, FrameworkAccumulator> = {};

  for (const [frameworkId, framework] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    summary[frameworkId] = {
      name: framework.name,
      version: framework.version,
      totalControls: Object.keys(framework.controls).length,
      failedControls: new Set<string>(),
      passedControls: new Set<string>(),
      score: 0,
      findings: [],
    };
  }

  // Map findings to frameworks
  for (const finding of findings) {
    const mapping = FINDING_TO_COMPLIANCE[finding.id];
    if (!mapping) continue;

    for (const [frameworkId, controls] of Object.entries(mapping)) {
      if (!summary[frameworkId] || !controls) continue;

      for (const control of controls) {
        summary[frameworkId].failedControls.add(control);
        summary[frameworkId].findings.push({
          findingId: finding.id,
          control,
          severity: finding.severity,
          resource: finding.resource,
        });
      }
    }
  }

  // Calculate passed controls and convert to final format
  const result: ComplianceSummary = {};

  for (const [frameworkId, framework] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    const allControls = new Set(Object.keys(framework.controls));
    const passed = new Set<string>();

    for (const control of allControls) {
      if (!summary[frameworkId].failedControls.has(control)) {
        passed.add(control);
      }
    }

    const failedArr = Array.from(summary[frameworkId].failedControls);
    const passedArr = Array.from(passed);
    const score = Math.round((passedArr.length / summary[frameworkId].totalControls) * 100);

    result[frameworkId] = {
      name: summary[frameworkId].name,
      version: summary[frameworkId].version,
      totalControls: summary[frameworkId].totalControls,
      failedControls: failedArr,
      passedControls: passedArr,
      score,
      findings: summary[frameworkId].findings,
    };
  }

  return result;
}

/**
 * Map PermitVet severity to SARIF level
 */
function mapSeverityToSARIF(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'note';
    default:
      return 'none';
  }
}

export interface SARIFOptions {
  version: string;
}

/**
 * Generate SARIF output
 */
export function generateSARIF(findings: Finding[], options: SARIFOptions): SARIFOutput {
  const sarif: SARIFOutput = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PermitVet',
            version: options.version,
            informationUri: 'https://github.com/taku-tez/PermitVet',
            rules: [],
          },
        },
        results: [],
      },
    ],
  };

  const run = sarif.runs[0];
  const ruleMap = new Map<string, number>();

  for (const finding of findings) {
    // Add rule if not exists
    if (!ruleMap.has(finding.id)) {
      const rule: SARIFRule = {
        id: finding.id,
        name: finding.id,
        shortDescription: {
          text: finding.message,
        },
        fullDescription: {
          text: finding.recommendation || finding.message,
        },
        defaultConfiguration: {
          level: mapSeverityToSARIF(finding.severity),
        },
        help: {
          text: finding.recommendation || '',
          markdown: finding.recommendation || '',
        },
      };

      // Add compliance tags
      const mapping = FINDING_TO_COMPLIANCE[finding.id];
      if (mapping) {
        rule.properties = {
          tags: [],
        };
        for (const [framework, controls] of Object.entries(mapping)) {
          if (controls) {
            for (const control of controls) {
              rule.properties.tags.push(`${framework}/${control}`);
            }
          }
        }
      }

      run.tool.driver.rules.push(rule);
      ruleMap.set(finding.id, run.tool.driver.rules.length - 1);
    }

    // Add result
    const result: SARIFResult = {
      ruleId: finding.id,
      ruleIndex: ruleMap.get(finding.id)!,
      level: mapSeverityToSARIF(finding.severity),
      message: {
        text: `${finding.message} Resource: ${finding.resource}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.resource || 'unknown',
            },
          },
        },
      ],
    };

    // Add compliance info to properties
    const mappedFinding = mapToCompliance(finding);
    if (Object.keys(mappedFinding.compliance).length > 0) {
      result.properties = {
        compliance: mappedFinding.compliance,
      };
    }

    run.results.push(result);
  }

  return sarif;
}

export interface HTMLReportOptions {
  version?: string;
}

/**
 * Generate HTML report
 */
export function generateHTMLReport(findings: Finding[], _options: HTMLReportOptions = {}): string {
  const complianceSummary = generateComplianceSummary(findings);
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PermitVet Security Report</title>
  <style>
    :root {
      --critical: #dc3545;
      --warning: #ffc107;
      --info: #17a2b8;
      --success: #28a745;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
    .header h1 { margin: 0 0 10px 0; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
    .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .summary-card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
    .summary-card .value { font-size: 36px; font-weight: bold; }
    .summary-card.critical .value { color: var(--critical); }
    .summary-card.warning .value { color: var(--warning); }
    .summary-card.info .value { color: var(--info); }
    .section { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .section h2 { margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    .finding { padding: 15px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid; }
    .finding.critical { background: #fff5f5; border-color: var(--critical); }
    .finding.warning { background: #fffbf0; border-color: var(--warning); }
    .finding.info { background: #f0faff; border-color: var(--info); }
    .finding h4 { margin: 0 0 5px 0; }
    .finding .resource { color: #666; font-size: 14px; }
    .finding .recommendation { margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.05); border-radius: 5px; }
    .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    .compliance-card { border: 1px solid #eee; padding: 15px; border-radius: 5px; }
    .compliance-card h4 { margin: 0 0 10px 0; }
    .compliance-card .score { font-size: 24px; font-weight: bold; }
    .compliance-card .score.good { color: var(--success); }
    .compliance-card .score.warning { color: var(--warning); }
    .compliance-card .score.bad { color: var(--critical); }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; background: #eee; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🦅 PermitVet Security Report</h1>
      <p>Generated: ${new Date().toISOString()}</p>
    </div>
    
    <div class="summary">
      <div class="summary-card critical">
        <h3>Critical</h3>
        <div class="value">${criticalCount}</div>
      </div>
      <div class="summary-card warning">
        <h3>Warning</h3>
        <div class="value">${warningCount}</div>
      </div>
      <div class="summary-card info">
        <h3>Info</h3>
        <div class="value">${infoCount}</div>
      </div>
      <div class="summary-card">
        <h3>Total Findings</h3>
        <div class="value">${findings.length}</div>
      </div>
    </div>
    
    <div class="section">
      <h2>Compliance Summary</h2>
      <div class="compliance-grid">
        ${Object.entries(complianceSummary)
          .map(
            ([_id, fw]) => `
        <div class="compliance-card">
          <h4>${fw.name} ${fw.version}</h4>
          <div class="score ${fw.score >= 80 ? 'good' : fw.score >= 60 ? 'warning' : 'bad'}">${fw.score}%</div>
          <p>${fw.passedControls.length}/${fw.totalControls} controls passing</p>
          <p>Failed: ${fw.failedControls.join(', ') || 'None'}</p>
        </div>
        `
          )
          .join('')}
      </div>
    </div>
    
    <div class="section">
      <h2>Findings (${findings.length})</h2>
      ${findings
        .map(f => {
          const mappedFinding = mapToCompliance(f);
          const complianceTags = Object.entries(mappedFinding.compliance).flatMap(([fw, data]) =>
            data.controls.map(c => `${fw}:${c.id}`)
          );

          return `
        <div class="finding ${f.severity}">
          <h4>${f.id}</h4>
          <div class="resource">📍 ${f.resource}</div>
          <p>${f.message}</p>
          ${complianceTags.length ? `<div>${complianceTags.map(t => `<span class="tag">${t}</span>`).join('')}</div>` : ''}
          <div class="recommendation">💡 ${f.recommendation}</div>
        </div>
        `;
        })
        .join('')}
    </div>
  </div>
</body>
</html>`;
}
