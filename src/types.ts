/**
 * PermitVet Type Definitions
 */

/** Finding severity levels */
export type Severity = 'critical' | 'warning' | 'info';

/** A security finding from a scan */
export interface Finding {
  /** Unique identifier for the finding type */
  id: string;
  /** Severity level */
  severity: Severity;
  /** Resource identifier (e.g., "IAMUser/admin") */
  resource: string;
  /** Human-readable description of the issue */
  message: string;
  /** Remediation guidance */
  recommendation: string;
  /** CIS benchmark reference (optional) */
  cis?: string;
  /** Additional context (optional) */
  details?: Record<string, unknown>;
}

/** Scan options */
export interface ScanOptions {
  // Common options
  format?: 'table' | 'json' | 'sarif' | 'html' | 'compliance';
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
  enhanced?: boolean;
  configPath?: string;

  // AWS options
  profile?: string;

  // Azure options
  subscription?: string;
  tenant?: string;
  managementGroup?: string;
  allSubscriptions?: boolean;

  // GCP options
  project?: string;
  organization?: string;
  folder?: string;
  allProjects?: boolean;

  // Kubernetes options
  kubeconfig?: string;
  context?: string;

  // Config file options
  exclude?: string[];
  thresholds?: ThresholdConfig;
  rules?: Record<string, RuleConfig>;
}

/** Threshold configuration for CI */
export interface ThresholdConfig {
  critical?: number;
  warning?: number;
  info?: number;
  total?: number;
}

/** Rule configuration */
export type RuleConfig = 'off' | 'warn' | 'error' | { severity: Severity | 'off' };

/** Scan results summary */
export interface ScanSummary {
  total: number;
  critical: number;
  warning: number;
  info: number;
}

/** Report options */
export interface ReportOptions {
  format?: 'table' | 'json' | 'sarif' | 'html' | 'compliance';
  output?: string;
}

/** Privilege escalation technique */
export interface PrivescTechnique {
  id: string;
  permissions: string[];
  severity: Severity;
  technique: string;
  message: string;
  recommendation: string;
  mitre?: string;
}

/** Compliance framework result */
export interface ComplianceResult {
  name: string;
  version: string;
  score: number;
  totalControls: number;
  passedControls: string[];
  failedControls: string[];
}

/** SARIF report format */
export interface SARIFReport {
  $schema: string;
  version: string;
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules?: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

export interface SARIFRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: string };
}

export interface SARIFResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }[];
}

/** Cloud provider types */
export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes' | 'all';

/** Scanner function signature */
export type ScannerFunction = (options: ScanOptions) => Promise<Finding[]>;

/** Privesc analyzer function signature */
export type PrivescAnalyzer = (
  provider: CloudProvider,
  permissions: string[],
  options?: ScanOptions
) => PrivescTechnique[];
