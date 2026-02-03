/**
 * PermitVet - Cloud IAM Permission Auditor
 * Type declarations for the main module
 */

import {
  Finding,
  ScanOptions,
  ScanSummary,
  PrivescTechnique,
  ComplianceResult,
  SARIFReport,
  CloudProvider,
} from './types';

/**
 * Scan cloud provider for IAM permission issues
 * @param provider - Cloud provider (aws, azure, gcp, kubernetes, oci, all)
 * @param options - Scan options
 * @returns Scan results summary
 */
export function scan(provider: CloudProvider, options?: ScanOptions): Promise<ScanSummary>;

/**
 * Analyze permissions for privilege escalation paths
 * @param provider - Cloud provider
 * @param permissions - List of permissions to analyze
 * @param options - Analysis options
 * @returns Detected privilege escalation paths
 */
export function analyzePrivesc(
  provider: CloudProvider,
  permissions: string[],
  options?: ScanOptions
): PrivescTechnique[];

/**
 * Build attack graph from IAM configuration
 * @param iamData - IAM configuration data
 * @returns Attack graph
 */
export function buildGraph(iamData: unknown): unknown;

/**
 * Get compliance summary for findings
 * @param findings - Array of findings
 * @returns Compliance summary by framework
 */
export function getComplianceSummary(findings: Finding[]): Record<string, ComplianceResult>;

/**
 * Generate SARIF format report
 * @param findings - Array of findings
 * @param options - Report options
 * @returns SARIF report object
 */
export function generateSARIF(findings: Finding[], options: { version: string }): SARIFReport;

/**
 * Generate HTML format report
 * @param findings - Array of findings
 * @param options - Report options
 * @returns HTML report string
 */
export function generateHTMLReport(findings: Finding[], options: { version: string }): string;

/** Current PermitVet version */
export const version: string;

/** AWS privilege escalation techniques */
export const AWS_PRIVESC_TECHNIQUES: PrivescTechnique[];

/** Azure privilege escalation techniques */
export const AZURE_PRIVESC_TECHNIQUES: PrivescTechnique[];

/** GCP privilege escalation techniques */
export const GCP_PRIVESC_TECHNIQUES: PrivescTechnique[];

// Re-export types
export {
  Finding,
  ScanOptions,
  ScanSummary,
  PrivescTechnique,
  ComplianceResult,
  SARIFReport,
  CloudProvider,
  ThresholdConfig,
  RuleConfig,
} from './types';
