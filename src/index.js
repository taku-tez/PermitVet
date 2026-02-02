/**
 * PermitVet - Cloud IAM Permission Auditor
 */

const { scanAWS } = require('./scanners/aws.js');
const { scanGCP } = require('./scanners/gcp.js');
const { Reporter } = require('./reporter.js');

const version = '0.2.0';

/**
 * Scan cloud provider for IAM permission issues
 * @param {string} provider - Cloud provider (aws, azure, gcp)
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
async function scan(provider, options = {}) {
  const reporter = new Reporter(options);
  
  reporter.start(`Scanning ${provider.toUpperCase()} IAM permissions...`);

  let findings = [];

  switch (provider.toLowerCase()) {
    case 'aws':
      findings = await scanAWS(options);
      break;
    case 'azure':
      reporter.warn('Azure scanning not yet implemented');
      break;
    case 'gcp':
      findings = await scanGCP(options);
      break;
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }

  const summary = reporter.report(findings, options);
  
  return summary;
}

module.exports = {
  scan,
  version,
};
