#!/usr/bin/env node

/**
 * PermitVet CLI
 * Cloud IAM Permission Auditor - Wiz-level CIEM
 */

const { scan, analyzePrivesc, version } = require('../src/index.js');

const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
  console.log(`
🦅 PermitVet v${version} - Cloud IAM Permission Auditor

Usage: permitvet <command> [options]

Commands:
  scan <provider>    Scan cloud IAM permissions
  privesc <provider> Analyze for privilege escalation paths
  version            Show version

Providers:
  aws                Amazon Web Services
  azure              Microsoft Azure
  gcp                Google Cloud Platform
  all                Scan all configured providers

Options:
  --profile <name>       AWS profile name
  --subscription <id>    Azure subscription ID
  --project <id>         GCP project ID
  --format <type>        Output format (table, json, sarif, html, compliance)
  --output <file>        Output file path
  --quiet                Suppress non-essential output
  --no-enhanced          Skip enhanced checks (Access Analyzer, IAM Recommender)

Examples:
  # Scan single provider
  permitvet scan aws
  permitvet scan aws --profile production
  permitvet scan azure --subscription abc123
  permitvet scan gcp --project my-project

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

  if (command === 'scan') {
    const provider = args[1];
    if (!provider) {
      console.error('Error: Provider required (aws, azure, gcp, all)');
      process.exit(1);
    }

    const options = parseOptions(args.slice(2));
    
    try {
      console.log(`\n🦅 PermitVet v${version}\n`);
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
    } else if (arg === '--project' && args[i + 1]) {
      options.project = args[++i];
    } else if (arg === '--permissions' && args[i + 1]) {
      options.permissions = args[++i];
    } else if (arg === '--no-enhanced') {
      options.enhanced = false;
    } else if (arg === '--debug') {
      options.debug = true;
    }
  }
  return options;
}

main().catch(err => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
