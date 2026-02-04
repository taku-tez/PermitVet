/**
 * Configuration file support for PermitVet
 * Supports .permitvet.yml, .permitvet.yaml, permitvet.config.js
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
import type { Finding, Severity, ThresholdConfig, RuleConfig, ScanSummary } from './types';

export const CONFIG_FILES = [
  '.permitvet.yml',
  '.permitvet.yaml',
  'permitvet.config.js',
  'permitvet.config.json',
] as const;

export interface PermitVetConfig {
  exclude?: string[];
  include?: string[];
  thresholds?: ThresholdConfig;
  rules?: Record<string, RuleConfig>;
  aws?: {
    profile?: string;
    regions?: string[];
  };
  azure?: {
    subscription?: string;
    tenant?: string;
  };
  gcp?: {
    project?: string;
    organization?: string;
  };
  output?: {
    format?: 'table' | 'json' | 'sarif' | 'html' | 'compliance';
    file?: string;
    quiet?: boolean;
  };
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export interface ThresholdCheckResult {
  exceeded: boolean;
  violations: string[];
}

/**
 * Load configuration from file or directory
 * @param configPathOrDir - Path to config file or directory to search
 */
export function loadConfig(configPathOrDir: string = process.cwd()): PermitVetConfig | null {
  // Check if the path is a file (direct config file specified)
  if (fs.existsSync(configPathOrDir) && fs.statSync(configPathOrDir).isFile()) {
    return loadConfigFile(configPathOrDir);
  }

  // Otherwise, search for config files in the directory
  const dir = configPathOrDir;
  for (const filename of CONFIG_FILES) {
    const filepath = path.join(dir, filename);

    if (fs.existsSync(filepath)) {
      return loadConfigFile(filepath);
    }
  }

  return null;
}

/**
 * Load configuration from a specific file path
 *
 * SECURITY NOTE: .js config files are executed via require(), which allows
 * arbitrary code execution. Only use .js configs from trusted sources.
 * Prefer .json or .yaml configs for better security.
 */
export function loadConfigFile(filepath: string): PermitVetConfig | null {
  try {
    if (filepath.endsWith('.js')) {
      // Security warning for JS config files
      if (process.env.PERMITVET_ALLOW_JS_CONFIG !== 'true') {
        console.warn(
          `⚠️  Security Warning: Loading JavaScript config file: ${filepath}\n` +
            `   JS config files can execute arbitrary code. Set PERMITVET_ALLOW_JS_CONFIG=true to suppress this warning.\n` +
            `   Consider using .json or .yaml config files instead.`
        );
      }
      return require(filepath) as PermitVetConfig;
    } else if (filepath.endsWith('.json')) {
      return JSON.parse(fs.readFileSync(filepath, 'utf-8')) as PermitVetConfig;
    } else {
      // YAML (default for .yml, .yaml, or unknown extensions)
      const content = fs.readFileSync(filepath, 'utf-8');
      return yaml.parse(content) as PermitVetConfig;
    }
  } catch (error) {
    const err = error as Error;
    console.error(`Error loading config from ${filepath}: ${err.message}`);
    return null;
  }
}

/**
 * Merge CLI options with config file
 * CLI options take precedence
 */
export function mergeOptions<T extends Record<string, unknown>>(
  cliOptions: T,
  fileConfig: PermitVetConfig | null
): T {
  if (!fileConfig) return cliOptions;

  const merged = { ...fileConfig, ...cliOptions } as T;

  // Handle arrays (exclude patterns, etc.)
  if (fileConfig.exclude && !('exclude' in cliOptions)) {
    (merged as Record<string, unknown>).exclude = fileConfig.exclude;
  }

  if (fileConfig.include && !('include' in cliOptions)) {
    (merged as Record<string, unknown>).include = fileConfig.include;
  }

  // Handle nested objects
  if (fileConfig.thresholds) {
    (merged as Record<string, unknown>).thresholds = {
      ...fileConfig.thresholds,
      ...((cliOptions as Record<string, unknown>).thresholds as ThresholdConfig | undefined),
    };
  }

  if (fileConfig.rules) {
    (merged as Record<string, unknown>).rules = {
      ...fileConfig.rules,
      ...((cliOptions as Record<string, unknown>).rules as Record<string, RuleConfig> | undefined),
    };
  }

  return merged;
}

/**
 * Validate configuration
 */
export function validateConfig(config: PermitVetConfig): ValidationResult {
  const errors: string[] = [];

  // Validate exclude patterns
  if (config.exclude && !Array.isArray(config.exclude)) {
    errors.push('exclude must be an array');
  }

  // Validate thresholds
  if (config.thresholds) {
    const validSeverities = ['critical', 'warning', 'info', 'total'];
    for (const severity of Object.keys(config.thresholds)) {
      if (!validSeverities.includes(severity)) {
        errors.push(`Invalid threshold severity: ${severity}`);
      }
      const value = config.thresholds[severity as keyof ThresholdConfig];
      if (typeof value !== 'number') {
        errors.push(`Threshold for ${severity} must be a number`);
      }
    }
  }

  // Validate rules
  if (config.rules) {
    for (const [ruleId, ruleConfig] of Object.entries(config.rules)) {
      if (typeof ruleConfig === 'string') {
        if (!['off', 'warn', 'error'].includes(ruleConfig)) {
          errors.push(`Invalid rule config for ${ruleId}: ${ruleConfig}`);
        }
      } else if (typeof ruleConfig === 'object' && ruleConfig !== null) {
        const validSeverities = ['off', 'warn', 'error', 'info', 'warning', 'critical'];
        if (ruleConfig.severity && !validSeverities.includes(ruleConfig.severity)) {
          errors.push(`Invalid severity for rule ${ruleId}`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Apply configuration to findings
 */
export function applyConfig(findings: Finding[], config: PermitVetConfig | null): Finding[] {
  if (!config) return findings;

  let result = [...findings];

  // Apply exclude patterns
  if (config.exclude && Array.isArray(config.exclude)) {
    result = result.filter(f => {
      const resource = f.resource || '';
      const id = f.id || '';

      for (const pattern of config.exclude!) {
        // Support glob-like patterns (simple wildcards)
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');

        if (regex.test(resource) || regex.test(id)) {
          return false; // Exclude this finding
        }
      }

      return true;
    });
  }

  // Apply rule overrides
  if (config.rules) {
    result = result
      .map(f => {
        const ruleConfig = config.rules![f.id];

        if (ruleConfig === 'off') {
          return null; // Remove finding
        }

        if (typeof ruleConfig === 'object' && ruleConfig !== null && ruleConfig.severity) {
          // Map 'error' -> 'critical', 'warn' -> 'warning'
          let severity: Severity = ruleConfig.severity as Severity;
          if (ruleConfig.severity === 'off') return null;
          if (severity === ('error' as unknown as Severity)) severity = 'critical';
          if (severity === ('warn' as unknown as Severity)) severity = 'warning';

          return { ...f, severity };
        }

        return f;
      })
      .filter((f): f is Finding => f !== null);
  }

  return result;
}

/**
 * Check if findings exceed thresholds
 */
export function checkThresholds(
  summary: ScanSummary,
  thresholds?: ThresholdConfig
): ThresholdCheckResult {
  if (!thresholds) return { exceeded: false, violations: [] };

  const violations: string[] = [];

  if (thresholds.critical !== undefined && summary.critical > thresholds.critical) {
    violations.push(
      `Critical findings (${summary.critical}) exceed threshold (${thresholds.critical})`
    );
  }

  if (thresholds.warning !== undefined && summary.warning > thresholds.warning) {
    violations.push(
      `Warning findings (${summary.warning}) exceed threshold (${thresholds.warning})`
    );
  }

  if (thresholds.info !== undefined && summary.info > thresholds.info) {
    violations.push(`Info findings (${summary.info}) exceed threshold (${thresholds.info})`);
  }

  if (thresholds.total !== undefined && summary.total > thresholds.total) {
    violations.push(`Total findings (${summary.total}) exceed threshold (${thresholds.total})`);
  }

  return {
    exceeded: violations.length > 0,
    violations,
  };
}

/**
 * Generate example configuration file
 */
export function generateExampleConfig(): string {
  return `# PermitVet Configuration
# Place this file as .permitvet.yml in your project root

# Exclude specific resources or finding IDs from scan results
exclude:
  - "IAMUser/service-*"           # Exclude service accounts
  - "ServiceAccount/*-agent@*"    # Exclude agent SAs
  - "aws-access-key-unused"       # Ignore unused key findings

# Override finding thresholds for CI/CD
# Scan will fail if findings exceed these counts
thresholds:
  critical: 0    # Zero tolerance for critical
  warning: 10    # Allow up to 10 warnings
  # info: 100    # Uncomment to set info threshold

# Rule-level configuration
rules:
  # Disable specific rules
  aws-iam-user-inline-policy: off
  gcp-no-workload-identity: off
  
  # Change severity
  aws-access-key-old:
    severity: info    # Downgrade from warning to info
  
  azure-no-deny-assignments:
    severity: off     # Disable this check

# Provider-specific options
aws:
  profile: default
  # regions:
  #   - us-east-1
  #   - us-west-2

azure:
  # subscription: "..."
  # tenant: "..."

gcp:
  # project: "..."
  # organization: "..."

# Output options
output:
  format: table       # table, json, sarif, html, compliance
  # file: report.json
  # quiet: false
`;
}
