#!/usr/bin/env node

/**
 * PermitVet CLI
 * Cloud IAM Permission Auditor
 */

const { scan, version } = require('../src/index.js');

const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
  console.log(`
🦅 PermitVet - Cloud IAM Permission Auditor

Usage: permitvet <command> [options]

Commands:
  scan <provider>    Scan cloud IAM permissions
  version            Show version

Providers:
  aws                Amazon Web Services
  azure              Microsoft Azure
  gcp                Google Cloud Platform

Options:
  --profile <name>   AWS profile name
  --format <type>    Output format (table, json, sarif)
  --output <file>    Output file path
  --quiet            Suppress non-essential output

Examples:
  permitvet scan aws
  permitvet scan aws --profile production --format json
  permitvet scan azure --subscription abc123
  permitvet scan gcp --project my-project
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
      console.error('Error: Provider required (aws, azure, gcp)');
      process.exit(1);
    }

    const options = parseOptions(args.slice(2));
    
    try {
      const results = await scan(provider, options);
      process.exit(results.critical > 0 ? 1 : 0);
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
    if (args[i] === '--profile' && args[i + 1]) {
      options.profile = args[++i];
    } else if (args[i] === '--format' && args[i + 1]) {
      options.format = args[++i];
    } else if (args[i] === '--output' && args[i + 1]) {
      options.output = args[++i];
    } else if (args[i] === '--quiet') {
      options.quiet = true;
    } else if (args[i] === '--subscription' && args[i + 1]) {
      options.subscription = args[++i];
    } else if (args[i] === '--project' && args[i + 1]) {
      options.project = args[++i];
    }
  }
  return options;
}

main().catch(console.error);
