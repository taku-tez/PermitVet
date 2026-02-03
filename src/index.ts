/**
 * PermitVet - Cloud IAM Permission Auditor
 * Wiz-level CIEM capabilities for multi-cloud environments
 */

import * as fs from 'fs';
import type { Finding, ScanOptions, ScanSummary, PrivescTechnique } from './types';

// Import scanners (still JS for now)
/* eslint-disable @typescript-eslint/no-require-imports */
const { scanAWS } = require('./scanners/aws.js');
const { scanAzure } = require('./scanners/azure.js');
const { scanEntraID } = require('./scanners/azure-entra.js');
const { scanGCP } = require('./scanners/gcp.js');
const { scanAccessAnalyzer } = require('./scanners/aws-access-analyzer.js');
const { scanAWSAdvanced } = require('./scanners/aws-advanced.js');
const { scanGCPRecommender } = require('./scanners/gcp-recommender.js');
const { scanGCPAdvanced } = require('./scanners/gcp-advanced.js');
const { scanGCPOrganization } = require('./scanners/gcp-organization.js');
const { scanAzureAdvanced } = require('./scanners/azure-advanced.js');
const { scanAzureTenant } = require('./scanners/azure-tenant.js');
const { scanOCI } = require('./scanners/oracle-cloud.js');
const { scanKubernetesRBAC } = require('./scanners/kubernetes.js');
const {
  detectPrivescPaths,
  buildAttackGraph,
  AWS_PRIVESC_TECHNIQUES,
  AZURE_PRIVESC_TECHNIQUES,
  GCP_PRIVESC_TECHNIQUES,
} = require('./scanners/privesc-detector.js');
const { analyzeRBAC, generateRBACReport } = require('./scanners/rbac-analyzer.js');
/* eslint-enable @typescript-eslint/no-require-imports */

import {
  mapToCompliance,
  generateComplianceSummary,
  generateSARIF,
  generateHTMLReport,
} from './compliance';
import { Reporter } from './reporter';
import { applyConfig, checkThresholds } from './config';

export const version = '0.14.0';

interface ExtendedScanOptions extends ScanOptions {
  aws?: boolean;
  azure?: boolean;
  gcp?: boolean;
  oci?: boolean;
  oracle?: boolean;
  kubernetes?: boolean;
  k8s?: boolean;
}

/**
 * Scan cloud provider for IAM permission issues
 */
export async function scan(
  provider: string,
  options: ExtendedScanOptions = {}
): Promise<ScanSummary> {
  const reporter = new Reporter(options);

  let findings: Finding[] = [];

  // Multi-cloud scanning
  if (provider.toLowerCase() === 'all') {
    console.log('\n🦅 PermitVet Multi-Cloud Scan\n');

    // AWS
    if (options.aws !== false) {
      console.log('━━━ AWS ━━━');
      try {
        const awsFindings = await scanAWS(options);
        findings.push(...awsFindings);

        // Enhanced: Access Analyzer + Advanced
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Access Analyzer)...');
          const accessAnalyzerFindings = await scanAccessAnalyzer(options);
          findings.push(...accessAnalyzerFindings);

          console.log('  Running advanced checks (SCPs, Boundaries, IMDSv2)...');
          const advancedFindings = await scanAWSAdvanced(options);
          findings.push(...advancedFindings);
        }
      } catch (e) {
        const err = e as Error;
        console.log(`  ⚠️ AWS scan skipped: ${err.message}`);
      }
    }

    // Azure
    if (options.azure !== false) {
      console.log('\n━━━ Azure ━━━');
      try {
        // Tenant/Management Group level scan
        if (options.tenant || options.managementGroup || options.allSubscriptions) {
          console.log('  Running tenant/management-group-level scan...');
          const tenantFindings = await scanAzureTenant(options);
          findings.push(...tenantFindings);
        }

        // Subscription-level scan
        if (
          options.subscription ||
          (!options.tenant && !options.managementGroup && !options.allSubscriptions)
        ) {
          const azureFindings = await scanAzure(options);
          findings.push(...azureFindings);

          // Enhanced: Entra ID + PIM + Advanced
          if (options.enhanced !== false) {
            console.log('  Running enhanced checks (Entra ID + PIM)...');
            const entraFindings = await scanEntraID(options);
            findings.push(...entraFindings);

            console.log('  Running advanced checks (Management Groups, Policy)...');
            const advancedFindings = await scanAzureAdvanced(options);
            findings.push(...advancedFindings);
          }
        }
      } catch (e) {
        const err = e as Error;
        console.log(`  ⚠️ Azure scan skipped: ${err.message}`);
      }
    }

    // GCP
    if (options.gcp !== false) {
      console.log('\n━━━ GCP ━━━');
      try {
        // Organization/Folder level scan
        if (options.organization || options.folder) {
          console.log('  Running organization/folder-level scan...');
          const orgFindings = await scanGCPOrganization(options);
          findings.push(...orgFindings);
        }

        // Project-level scan
        if (options.project || (!options.organization && !options.folder)) {
          const gcpFindings = await scanGCP(options);
          findings.push(...gcpFindings);

          // Enhanced: IAM Recommender + Advanced
          if (options.enhanced !== false) {
            console.log('  Running enhanced checks (IAM Recommender)...');
            const recommenderFindings = await scanGCPRecommender(options);
            findings.push(...recommenderFindings);

            console.log('  Running advanced checks (Org Policy, Hierarchy)...');
            const advancedFindings = await scanGCPAdvanced(options);
            findings.push(...advancedFindings);
          }
        }
      } catch (e) {
        const err = e as Error;
        console.log(`  ⚠️ GCP scan skipped: ${err.message}`);
      }
    }

    // OCI (Oracle Cloud)
    if (options.oci !== false && options.oracle !== false) {
      console.log('\n━━━ Oracle Cloud (OCI) ━━━');
      try {
        const ociFindings = await scanOCI(options);
        findings.push(...ociFindings);
      } catch (e) {
        const err = e as Error;
        console.log(`  ⚠️ OCI scan skipped: ${err.message}`);
      }
    }

    // Kubernetes
    if (options.kubernetes !== false && options.k8s !== false) {
      console.log('\n━━━ Kubernetes ━━━');
      try {
        const k8sFindings = await scanKubernetesRBAC(options);
        findings.push(...k8sFindings);
      } catch (e) {
        const err = e as Error;
        console.log(`  ⚠️ Kubernetes scan skipped: ${err.message}`);
      }
    }
  } else {
    // Single provider scan
    reporter.start(`Scanning ${provider.toUpperCase()} IAM permissions...`);

    switch (provider.toLowerCase()) {
      case 'aws':
        findings = await scanAWS(options);

        // Enhanced: Access Analyzer + Advanced
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Access Analyzer)...');
          const accessAnalyzerFindings = await scanAccessAnalyzer(options);
          findings.push(...accessAnalyzerFindings);

          console.log('  Running advanced checks (SCPs, Boundaries, IMDSv2)...');
          const advancedFindings = await scanAWSAdvanced(options);
          findings.push(...advancedFindings);
        }
        break;

      case 'azure':
        // Tenant/Management Group level scan
        if (options.tenant || options.managementGroup || options.allSubscriptions) {
          console.log('  Running tenant/management-group-level scan...');
          const tenantFindings = await scanAzureTenant(options);
          findings.push(...tenantFindings);
        }

        // Subscription-level scan
        if (
          options.subscription ||
          (!options.tenant && !options.managementGroup && !options.allSubscriptions)
        ) {
          const subFindings = await scanAzure(options);
          findings.push(...subFindings);

          // Enhanced: Entra ID + PIM + Advanced
          if (options.enhanced !== false) {
            console.log('  Running enhanced checks (Entra ID + PIM)...');
            const entraFindings = await scanEntraID(options);
            findings.push(...entraFindings);

            console.log('  Running advanced checks (Management Groups, Policy)...');
            const advancedFindings = await scanAzureAdvanced(options);
            findings.push(...advancedFindings);
          }
        }
        break;

      case 'gcp':
        // Organization/Folder level scan
        if (options.organization || options.folder) {
          console.log('  Running organization/folder-level scan...');
          const orgFindings = await scanGCPOrganization(options);
          findings.push(...orgFindings);
        }

        // Project-level scan (skip if only doing org scan with --all-projects)
        if (options.project || (!options.organization && !options.folder)) {
          const projectFindings = await scanGCP(options);
          findings.push(...projectFindings);

          // Enhanced: IAM Recommender + Advanced
          if (options.enhanced !== false) {
            console.log('  Running enhanced checks (IAM Recommender)...');
            const recommenderFindings = await scanGCPRecommender(options);
            findings.push(...recommenderFindings);

            console.log('  Running advanced checks (Org Policy, Hierarchy)...');
            const advancedFindings = await scanGCPAdvanced(options);
            findings.push(...advancedFindings);
          }
        }
        break;

      case 'kubernetes':
      case 'k8s':
        findings = await scanKubernetesRBAC(options);
        break;

      case 'oci':
      case 'oracle':
        findings = await scanOCI(options);
        break;

      default:
        throw new Error(`Unknown provider: ${provider}. Use: aws, azure, gcp, or all`);
    }
  }

  // Apply config file rules (exclude, rule overrides)
  findings = applyConfig(findings, options as unknown as import('./config').PermitVetConfig);

  // Map findings to compliance frameworks
  findings = findings.map(mapToCompliance);

  // Generate output based on format
  const summary = reporter.report(findings, options);

  // Check thresholds if configured
  if (options.thresholds) {
    const { exceeded, violations } = checkThresholds(summary, options.thresholds);
    if (exceeded) {
      console.log('\n⚠️ Threshold violations:');
      for (const v of violations) {
        console.log(`  - ${v}`);
      }
    }
  }

  // Additional output formats
  if (options.format === 'sarif') {
    const sarif = generateSARIF(findings, { version });
    if (options.output) {
      fs.writeFileSync(options.output, JSON.stringify(sarif, null, 2));
      console.log(`SARIF report written to: ${options.output}`);
    } else {
      console.log(JSON.stringify(sarif, null, 2));
    }
  } else if (options.format === 'html') {
    const html = generateHTMLReport(findings, { version });
    if (options.output) {
      fs.writeFileSync(options.output, html);
      console.log(`HTML report written to: ${options.output}`);
    } else {
      console.log(html);
    }
  } else if (options.format === 'compliance') {
    const compliance = generateComplianceSummary(findings);
    console.log('\n📋 Compliance Summary:\n');
    for (const [_id, fw] of Object.entries(compliance)) {
      const scoreEmoji = fw.score >= 80 ? '✅' : fw.score >= 60 ? '⚠️' : '❌';
      console.log(
        `  ${scoreEmoji} ${fw.name} ${fw.version}: ${fw.score}% (${fw.passedControls.length}/${fw.totalControls})`
      );
      if (fw.failedControls.length > 0) {
        console.log(`     Failed: ${fw.failedControls.join(', ')}`);
      }
    }
  }

  return summary;
}

/**
 * Analyze permissions for privilege escalation paths
 */
export function analyzePrivesc(
  provider: string,
  permissions: string[],
  options: ScanOptions = {}
): PrivescTechnique[] {
  return detectPrivescPaths(provider, permissions, options);
}

interface IAMData {
  users?: unknown[];
  roles?: unknown[];
  policies?: unknown[];
}

interface AttackGraph {
  nodes: unknown[];
  edges: unknown[];
}

/**
 * Build attack graph from IAM configuration
 */
export function buildGraph(iamData: IAMData): AttackGraph {
  return buildAttackGraph(iamData);
}

/**
 * Get compliance summary for findings
 */
export function getComplianceSummary(findings: Finding[]) {
  return generateComplianceSummary(findings);
}

interface RBACAnalysisResult {
  provider: string;
  unusedRoles: unknown[];
  overPrivileged: unknown[];
  recommendations: unknown[];
}

/**
 * Deep RBAC analysis including role utilization and JIT recommendations
 */
export async function analyzeRBACDeep(
  provider: string,
  options: ScanOptions = {}
): Promise<RBACAnalysisResult> {
  return analyzeRBAC(provider, options);
}

// Re-exports
export {
  generateSARIF,
  generateHTMLReport,
  generateRBACReport,
  AWS_PRIVESC_TECHNIQUES,
  AZURE_PRIVESC_TECHNIQUES,
  GCP_PRIVESC_TECHNIQUES,
};
