/**
 * PermitVet - Cloud IAM Permission Auditor
 * Wiz-level CIEM capabilities for multi-cloud environments
 */

const { scanAWS } = require('./scanners/aws.js');
const { scanAzure } = require('./scanners/azure.js');
const { scanEntraID } = require('./scanners/azure-entra.js');
const { scanGCP } = require('./scanners/gcp.js');
const { scanAccessAnalyzer } = require('./scanners/aws-access-analyzer.js');
const { scanGCPRecommender } = require('./scanners/gcp-recommender.js');
const { detectPrivescPaths, buildAttackGraph, AWS_PRIVESC_TECHNIQUES, AZURE_PRIVESC_TECHNIQUES, GCP_PRIVESC_TECHNIQUES } = require('./scanners/privesc-detector.js');
const { mapToCompliance, generateComplianceSummary, generateSARIF, generateHTMLReport } = require('./compliance.js');
const { Reporter } = require('./reporter.js');

const version = '0.5.0';

/**
 * Scan cloud provider for IAM permission issues
 * @param {string} provider - Cloud provider (aws, azure, gcp, all)
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
async function scan(provider, options = {}) {
  const reporter = new Reporter(options);
  
  let findings = [];

  // Multi-cloud scanning
  if (provider.toLowerCase() === 'all') {
    console.log('\n🦅 PermitVet Multi-Cloud Scan\n');
    
    // AWS
    if (options.aws !== false) {
      console.log('━━━ AWS ━━━');
      try {
        const awsFindings = await scanAWS(options);
        findings.push(...awsFindings);
        
        // Enhanced: Access Analyzer
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Access Analyzer)...');
          const accessAnalyzerFindings = await scanAccessAnalyzer(options);
          findings.push(...accessAnalyzerFindings);
        }
      } catch (e) {
        console.log(`  ⚠️ AWS scan skipped: ${e.message}`);
      }
    }
    
    // Azure
    if (options.azure !== false) {
      console.log('\n━━━ Azure ━━━');
      try {
        const azureFindings = await scanAzure(options);
        findings.push(...azureFindings);
        
        // Enhanced: Entra ID + PIM
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Entra ID + PIM)...');
          const entraFindings = await scanEntraID(options);
          findings.push(...entraFindings);
        }
      } catch (e) {
        console.log(`  ⚠️ Azure scan skipped: ${e.message}`);
      }
    }
    
    // GCP
    if (options.gcp !== false) {
      console.log('\n━━━ GCP ━━━');
      try {
        const gcpFindings = await scanGCP(options);
        findings.push(...gcpFindings);
        
        // Enhanced: IAM Recommender
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (IAM Recommender)...');
          const recommenderFindings = await scanGCPRecommender(options);
          findings.push(...recommenderFindings);
        }
      } catch (e) {
        console.log(`  ⚠️ GCP scan skipped: ${e.message}`);
      }
    }
  } else {
    // Single provider scan
    reporter.start(`Scanning ${provider.toUpperCase()} IAM permissions...`);

    switch (provider.toLowerCase()) {
      case 'aws':
        findings = await scanAWS(options);
        
        // Enhanced: Access Analyzer
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Access Analyzer)...');
          const accessAnalyzerFindings = await scanAccessAnalyzer(options);
          findings.push(...accessAnalyzerFindings);
        }
        break;
        
      case 'azure':
        findings = await scanAzure(options);
        
        // Enhanced: Entra ID + PIM
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (Entra ID + PIM)...');
          const entraFindings = await scanEntraID(options);
          findings.push(...entraFindings);
        }
        break;
        
      case 'gcp':
        findings = await scanGCP(options);
        
        // Enhanced: IAM Recommender
        if (options.enhanced !== false) {
          console.log('  Running enhanced checks (IAM Recommender)...');
          const recommenderFindings = await scanGCPRecommender(options);
          findings.push(...recommenderFindings);
        }
        break;
        
      default:
        throw new Error(`Unknown provider: ${provider}. Use: aws, azure, gcp, or all`);
    }
  }

  // Map findings to compliance frameworks
  findings = findings.map(mapToCompliance);

  // Generate output based on format
  const summary = reporter.report(findings, options);
  
  // Additional output formats
  if (options.format === 'sarif') {
    const sarif = generateSARIF(findings, { version });
    if (options.output) {
      require('fs').writeFileSync(options.output, JSON.stringify(sarif, null, 2));
      console.log(`SARIF report written to: ${options.output}`);
    } else {
      console.log(JSON.stringify(sarif, null, 2));
    }
  } else if (options.format === 'html') {
    const html = generateHTMLReport(findings, { version });
    if (options.output) {
      require('fs').writeFileSync(options.output, html);
      console.log(`HTML report written to: ${options.output}`);
    } else {
      console.log(html);
    }
  } else if (options.format === 'compliance') {
    const compliance = generateComplianceSummary(findings);
    console.log('\n📋 Compliance Summary:\n');
    for (const [id, fw] of Object.entries(compliance)) {
      const scoreEmoji = fw.score >= 80 ? '✅' : fw.score >= 60 ? '⚠️' : '❌';
      console.log(`  ${scoreEmoji} ${fw.name} ${fw.version}: ${fw.score}% (${fw.passedControls.length}/${fw.totalControls})`);
      if (fw.failedControls.length > 0) {
        console.log(`     Failed: ${fw.failedControls.join(', ')}`);
      }
    }
  }
  
  return summary;
}

/**
 * Analyze permissions for privilege escalation paths
 * @param {string} provider - Cloud provider
 * @param {array} permissions - Permissions to analyze
 * @param {object} options - Analysis options
 * @returns {array} Detected privilege escalation paths
 */
function analyzePrivesc(provider, permissions, options = {}) {
  return detectPrivescPaths(provider, permissions, options);
}

/**
 * Build attack graph from IAM configuration
 * @param {object} iamData - IAM configuration data
 * @returns {object} Attack graph
 */
function buildGraph(iamData) {
  return buildAttackGraph(iamData);
}

/**
 * Get compliance summary for findings
 * @param {array} findings - PermitVet findings
 * @returns {object} Compliance summary
 */
function getComplianceSummary(findings) {
  return generateComplianceSummary(findings);
}

module.exports = {
  scan,
  analyzePrivesc,
  buildGraph,
  getComplianceSummary,
  generateSARIF,
  generateHTMLReport,
  version,
  // Export technique lists for external use
  AWS_PRIVESC_TECHNIQUES,
  AZURE_PRIVESC_TECHNIQUES,
  GCP_PRIVESC_TECHNIQUES,
};
