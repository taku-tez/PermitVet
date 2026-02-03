/**
 * Configuration file support for PermitVet
 * Supports .permitvet.yml, .permitvet.yaml, permitvet.config.js
 */

const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

const CONFIG_FILES = [
  '.permitvet.yml',
  '.permitvet.yaml',
  'permitvet.config.js',
  'permitvet.config.json',
];

/**
 * Load configuration from file
 * @param {string} dir - Directory to search for config file
 * @returns {object|null} Configuration object or null if not found
 */
function loadConfig(dir = process.cwd()) {
  for (const filename of CONFIG_FILES) {
    const filepath = path.join(dir, filename);
    
    if (fs.existsSync(filepath)) {
      try {
        if (filename.endsWith('.js')) {
          return require(filepath);
        } else if (filename.endsWith('.json')) {
          return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
        } else {
          // YAML
          const content = fs.readFileSync(filepath, 'utf-8');
          return yaml.parse(content);
        }
      } catch (error) {
        console.error(`Error loading config from ${filepath}: ${error.message}`);
        return null;
      }
    }
  }
  
  return null;
}

/**
 * Merge CLI options with config file
 * CLI options take precedence
 * @param {object} cliOptions - Options from CLI
 * @param {object} fileConfig - Options from config file
 * @returns {object} Merged options
 */
function mergeOptions(cliOptions, fileConfig) {
  if (!fileConfig) return cliOptions;
  
  const merged = { ...fileConfig, ...cliOptions };
  
  // Handle arrays (exclude patterns, etc.)
  if (fileConfig.exclude && !cliOptions.exclude) {
    merged.exclude = fileConfig.exclude;
  }
  
  if (fileConfig.include && !cliOptions.include) {
    merged.include = fileConfig.include;
  }
  
  // Handle nested objects
  if (fileConfig.thresholds) {
    merged.thresholds = { ...fileConfig.thresholds, ...cliOptions.thresholds };
  }
  
  if (fileConfig.rules) {
    merged.rules = { ...fileConfig.rules, ...cliOptions.rules };
  }
  
  return merged;
}

/**
 * Validate configuration
 * @param {object} config - Configuration to validate
 * @returns {object} Validation result { valid: boolean, errors: string[] }
 */
function validateConfig(config) {
  const errors = [];
  
  // Validate exclude patterns
  if (config.exclude && !Array.isArray(config.exclude)) {
    errors.push('exclude must be an array');
  }
  
  // Validate thresholds
  if (config.thresholds) {
    const validSeverities = ['critical', 'warning', 'info'];
    for (const severity of Object.keys(config.thresholds)) {
      if (!validSeverities.includes(severity)) {
        errors.push(`Invalid threshold severity: ${severity}`);
      }
      if (typeof config.thresholds[severity] !== 'number') {
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
      } else if (typeof ruleConfig === 'object') {
        if (ruleConfig.severity && !['off', 'warn', 'error', 'info', 'warning', 'critical'].includes(ruleConfig.severity)) {
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
 * @param {array} findings - Array of findings
 * @param {object} config - Configuration object
 * @returns {array} Filtered/modified findings
 */
function applyConfig(findings, config) {
  if (!config) return findings;
  
  let result = [...findings];
  
  // Apply exclude patterns
  if (config.exclude && Array.isArray(config.exclude)) {
    result = result.filter(f => {
      const resource = f.resource || '';
      const id = f.id || '';
      
      for (const pattern of config.exclude) {
        // Support glob-like patterns (simple wildcards)
        const regex = new RegExp(
          '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
        );
        
        if (regex.test(resource) || regex.test(id)) {
          return false; // Exclude this finding
        }
      }
      
      return true;
    });
  }
  
  // Apply rule overrides
  if (config.rules) {
    result = result.map(f => {
      const ruleConfig = config.rules[f.id];
      
      if (ruleConfig === 'off') {
        return null; // Remove finding
      }
      
      if (typeof ruleConfig === 'object' && ruleConfig.severity) {
        // Map 'error' -> 'critical', 'warn' -> 'warning'
        let severity = ruleConfig.severity;
        if (severity === 'error') severity = 'critical';
        if (severity === 'warn') severity = 'warning';
        
        return { ...f, severity };
      }
      
      return f;
    }).filter(Boolean);
  }
  
  return result;
}

/**
 * Check if findings exceed thresholds
 * @param {object} summary - Summary with critical/warning/info counts
 * @param {object} thresholds - Threshold configuration
 * @returns {object} { exceeded: boolean, violations: string[] }
 */
function checkThresholds(summary, thresholds) {
  if (!thresholds) return { exceeded: false, violations: [] };
  
  const violations = [];
  
  if (thresholds.critical !== undefined && summary.critical > thresholds.critical) {
    violations.push(`Critical findings (${summary.critical}) exceed threshold (${thresholds.critical})`);
  }
  
  if (thresholds.warning !== undefined && summary.warning > thresholds.warning) {
    violations.push(`Warning findings (${summary.warning}) exceed threshold (${thresholds.warning})`);
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
 * @returns {string} YAML content
 */
function generateExampleConfig() {
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

module.exports = {
  loadConfig,
  mergeOptions,
  validateConfig,
  applyConfig,
  checkThresholds,
  generateExampleConfig,
  CONFIG_FILES,
};
