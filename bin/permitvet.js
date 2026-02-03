#!/usr/bin/env node

/**
 * PermitVet CLI
 * Cloud IAM Permission Auditor - Wiz-level CIEM
 */

// Use compiled TypeScript from dist/
const { scan, analyzePrivesc, analyzeRBACDeep, version } = require('../dist/index.js');
const {
  loadConfig,
  mergeOptions,
  generateExampleConfig,
  validateConfig,
} = require('../dist/config.js');
const fs = require('fs');

const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
  console.log(`
🦅 PermitVet v${version} - Cloud IAM Permission Auditor

Usage: permitvet <command> [options]

Commands:
  scan <provider>    Scan cloud IAM permissions
  privesc <provider> Analyze for privilege escalation paths
  rbac <provider>    Deep RBAC analysis (utilization, unused perms, JIT)
  version            Show version

Providers:
  aws                Amazon Web Services
  azure              Microsoft Azure
  gcp                Google Cloud Platform
  oci (oracle)       Oracle Cloud Infrastructure
  kubernetes (k8s)   Kubernetes clusters
  all                Scan all configured providers

Options:
  --profile <name>       AWS profile name
  --subscription <id>    Azure subscription ID
  --tenant <id>          Azure tenant ID (tenant-wide scan)
  --management-group <id> Azure management group ID
  --all-subscriptions    Scan all subscriptions (Azure)
  --project <id>         GCP project ID
  --organization <id>    GCP organization ID (org-level scan)
  --folder <id>          GCP folder ID (folder-level scan)
  --all-projects         Scan all projects under org/folder
  --kubeconfig <path>    Kubernetes config file path
  --context <name>       Kubernetes context name
  --format <type>        Output format (table, json, sarif, html, compliance)
  --output <file>        Output file path
  --quiet                Suppress non-essential output
  --verbose              Enable verbose output with progress details
  --config <path>        Path to config file (default: .permitvet.yml)
  --init-config          Generate example .permitvet.yml
  --no-enhanced          Skip enhanced checks (Access Analyzer, IAM Recommender)

Examples:
  # Scan single provider
  permitvet scan aws
  permitvet scan aws --profile production
  permitvet scan azure --subscription abc123
  permitvet scan gcp --project my-project

  # GCP Organization-level scan
  permitvet scan gcp --organization 123456789
  permitvet scan gcp --organization 123456789 --all-projects
  permitvet scan gcp --folder 987654321 --all-projects

  # Azure Tenant-level scan
  permitvet scan azure --tenant 00000000-0000-0000-0000-000000000000
  permitvet scan azure --management-group mg-root --all-subscriptions
  permitvet scan azure --all-subscriptions

  # Scan all providers
  permitvet scan all

  # Generate reports
  permitvet scan aws --format sarif --output report.sarif
  permitvet scan aws --format html --output report.html
  permitvet scan aws --format compliance

  # Analyze privilege escalation
  permitvet privesc aws --permissions iam:CreateUser,iam:AttachUserPolicy
`);
}

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    showHelp();
    process.exit(0);
  }

  if (command === 'version' || command === '--version' || command === '-v') {
    console.log(`PermitVet v${version}`);
    process.exit(0);
  }

  // Handle --init-config
  const initConfigIndex = args.indexOf('--init-config');
  if (initConfigIndex !== -1) {
    const configContent = generateExampleConfig();
    const configPath = '.permitvet.yml';

    if (fs.existsSync(configPath)) {
      console.error(`Error: ${configPath} already exists`);
      process.exit(1);
    }

    fs.writeFileSync(configPath, configContent);
    console.log(`✅ Created ${configPath}`);
    console.log('Edit this file to customize PermitVet behavior.');
    process.exit(0);
  }

  if (command === 'scan') {
    const provider = args[1];
    if (!provider) {
      console.error('Error: Provider required (aws, azure, gcp, all)');
      process.exit(1);
    }

    let options = parseOptions(args.slice(2));

    // Load config file (supports both file path and directory)
    const fileConfig = loadConfig(options.configPath || process.cwd());
    if (fileConfig) {
      if (options.verbose) {
        console.log('📄 Loaded configuration from file');
      }

      // Validate configuration
      const validation = validateConfig(fileConfig);
      if (!validation.valid) {
        console.error('❌ Configuration validation failed:');
        for (const error of validation.errors) {
          console.error(`   • ${error}`);
        }
        process.exit(1);
      }

      options = mergeOptions(options, fileConfig);
    }

    try {
      if (!options.quiet) {
        console.log(`\n🦅 PermitVet v${version}\n`);
      }
      const results = await scan(provider, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      if (options.debug) console.error(error.stack);
      process.exit(1);
    }
  }

  if (command === 'privesc') {
    const provider = args[1];
    if (!provider) {
      console.error('Error: Provider required (aws, azure, gcp)');
      process.exit(1);
    }

    const options = parseOptions(args.slice(2));
    const permissions = options.permissions?.split(',') || [];

    if (permissions.length === 0) {
      console.error('Error: --permissions required (comma-separated list)');
      process.exit(1);
    }

    try {
      console.log(`\n🦅 PermitVet Privilege Escalation Analysis\n`);
      console.log(`Provider: ${provider.toUpperCase()}`);
      console.log(`Permissions: ${permissions.join(', ')}\n`);

      const paths = analyzePrivesc(provider, permissions, options);

      if (paths.length === 0) {
        console.log('✅ No privilege escalation paths detected');
      } else {
        console.log(`⚠️ ${paths.length} privilege escalation path(s) detected:\n`);

        for (const path of paths) {
          const severityEmoji = path.severity === 'critical' ? '🔴' : '🟡';
          console.log(`${severityEmoji} ${path.technique}`);
          console.log(`   ${path.message}`);
          console.log(`   Required: ${path.requiredPermissions.join(', ')}`);
          console.log(`   Remediation: ${path.recommendation}`);
          if (path.mitre) console.log(`   MITRE: ${path.mitre}`);
          console.log('');
        }
      }

      process.exit(paths.some(p => p.severity === 'critical') ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'rbac') {
    const provider = args[1];
    if (!provider) {
      console.error('Error: Provider required (aws, azure, gcp)');
      process.exit(1);
    }

    const options = parseOptions(args.slice(2));

    try {
      console.log(`\n🦅 PermitVet RBAC Deep Analysis\n`);
      console.log(`Provider: ${provider.toUpperCase()}\n`);

      const results = await analyzeRBACDeep(provider, options);

      // Print summary
      console.log('📊 Summary');
      console.log(`  Total Roles: ${results.summary.totalRoles}`);
      console.log(`  Underutilized: ${results.summary.underutilizedRoles}`);
      console.log(`  Unused Permissions: ${results.summary.unusedPermissionCount}`);
      console.log(`  JIT Candidates: ${results.summary.jitCandidates}`);
      console.log('');

      // Print unused permissions
      if (results.unusedPermissions.length > 0) {
        console.log('🗑️ Unused/Overly Broad Permissions:');
        for (const item of results.unusedPermissions.slice(0, 10)) {
          console.log(`  • ${item.roleName || item.email || item.targetMember || 'Unknown'}`);
          console.log(`    → ${item.recommendation}: ${item.message || ''}`);
          if (item.command) console.log(`    $ ${item.command}`);
        }
        console.log('');
      }

      // Print JIT recommendations
      if (results.temporaryAccessRecommendations.length > 0) {
        console.log('⏱️ Just-In-Time Access Recommendations:');
        for (const rec of results.temporaryAccessRecommendations.slice(0, 5)) {
          console.log(`  • ${rec.roleName || rec.role || rec.member || 'Privileged Role'}`);
          console.log(`    ${rec.message}`);
        }
        console.log('');
      }

      // Exit code based on findings
      process.exit(results.summary.underutilizedRoles > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      if (options.debug) console.error(error.stack);
      process.exit(1);
    }
  }

  console.error(`Unknown command: ${command}`);
  showHelp();
  process.exit(1);
}

function parseOptions(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--profile' && args[i + 1]) {
      options.profile = args[++i];
    } else if (arg === '--format' && args[i + 1]) {
      options.format = args[++i];
    } else if (arg === '--output' && args[i + 1]) {
      options.output = args[++i];
    } else if (arg === '--quiet') {
      options.quiet = true;
    } else if (arg === '--subscription' && args[i + 1]) {
      options.subscription = args[++i];
    } else if (arg === '--tenant' && args[i + 1]) {
      options.tenant = args[++i];
    } else if (arg === '--management-group' && args[i + 1]) {
      options.managementGroup = args[++i];
    } else if (arg === '--all-subscriptions') {
      options.allSubscriptions = true;
    } else if (arg === '--project' && args[i + 1]) {
      options.project = args[++i];
    } else if (arg === '--organization' && args[i + 1]) {
      options.organization = args[++i];
    } else if (arg === '--folder' && args[i + 1]) {
      options.folder = args[++i];
    } else if (arg === '--all-projects') {
      options.allProjects = true;
    } else if (arg === '--kubeconfig' && args[i + 1]) {
      options.kubeconfig = args[++i];
    } else if (arg === '--context' && args[i + 1]) {
      options.context = args[++i];
    } else if (arg === '--permissions' && args[i + 1]) {
      options.permissions = args[++i];
    } else if (arg === '--no-enhanced') {
      options.enhanced = false;
    } else if (arg === '--debug') {
      options.debug = true;
    } else if (arg === '--verbose') {
      options.verbose = true;
    } else if (arg === '--config' && args[i + 1]) {
      options.configPath = args[++i];
    } else if (arg === '--init-config') {
      options.initConfig = true;
    }
  }
  return options;
}

main().catch(err => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
