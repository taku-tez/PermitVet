/**
 * PermitVet - Cloud IAM Permission Auditor
 * Wiz-level CIEM capabilities for multi-cloud environments
 */

import * as fs from 'fs';
import type { Finding, ScanOptions, ScanSummary, PrivescTechnique } from './types';

// Import scanners (TypeScript)
import { scanAWS } from './scanners/aws';
import { scanAzure } from './scanners/azure';
import { scanEntraID } from './scanners/azure-entra';
import { scanGCP } from './scanners/gcp';
import { scanAccessAnalyzer } from './scanners/aws-access-analyzer';
import { scanAWSAdvanced } from './scanners/aws-advanced';
import { scanGCPRecommender } from './scanners/gcp-recommender';
import { scanGCPAdvanced } from './scanners/gcp-advanced';
import { scanGCPOrganization } from './scanners/gcp-organization';
import { scanAzureAdvanced } from './scanners/azure-advanced';
import { scanAzureTenant } from './scanners/azure-tenant';
import { scanOCI } from './scanners/oracle-cloud';
import { scanKubernetesRBAC } from './scanners/kubernetes';
import {
  detectPrivescPaths,
  buildAttackGraph,
  AWS_PRIVESC_TECHNIQUES,
  AZURE_PRIVESC_TECHNIQUES,
  GCP_PRIVESC_TECHNIQUES,
  type IAMData as PrivescIAMData,
  type AttackGraph as PrivescAttackGraph,
} from './scanners/privesc-detector';
import {
  analyzeRBAC,
  generateRBACReport,
  type RBACAnalysisResults,
} from './scanners/rbac-analyzer';

import {
  mapToCompliance,
  generateComplianceSummary,
  generateSARIF,
  generateHTMLReport,
} from './compliance';
import { Reporter } from './reporter';
import { applyConfig, checkThresholds } from './config';

export const version = '0.15.1';

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
  const reporter = new Reporter({ quiet: options.quiet, version });

  // Set context for detailed JSON reporting
  reporter.setContext(provider as import('./types').CloudProvider, options);

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
 * NOTE: Returns PrivescFinding[] which is compatible with PrivescTechnique[]
 */
export function analyzePrivesc(
  provider: string,
  permissions: string[],
  _options: ScanOptions = {}
): PrivescTechnique[] {
  // Type assertion needed due to slight interface differences
  // TODO: Align PrivescFinding and PrivescTechnique interfaces
  return detectPrivescPaths(provider, permissions, {}) as unknown as PrivescTechnique[];
}

/**
 * Build attack graph from IAM configuration
 */
export function buildGraph(iamData: PrivescIAMData): PrivescAttackGraph {
  return buildAttackGraph(iamData);
}

/**
 * Get compliance summary for findings
 */
export function getComplianceSummary(findings: Finding[]) {
  return generateComplianceSummary(findings);
}

/**
 * Deep RBAC analysis including role utilization and JIT recommendations
 */
export async function analyzeRBACDeep(
  provider: string,
  options: ScanOptions = {}
): Promise<RBACAnalysisResults> {
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

// Utility exports
export {
  createFinding,
  handleScanError,
  logProgress,
  logError,
  formatResource,
  matchesDangerousPattern,
  SeverityThresholds,
} from './utils';
export type { ScanErrorType, ScanErrorContext, ScanErrorResult } from './utils';
