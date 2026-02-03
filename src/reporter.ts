/**
 * PermitVet Reporter
 */

import * as fs from 'fs';
import type { Finding, ScanSummary, ReportOptions, SARIFReport } from './types';

export interface ReporterOptions {
  quiet?: boolean;
}

export class Reporter {
  private quiet: boolean;

  constructor(options: ReporterOptions = {}) {
    this.quiet = options.quiet || false;
  }

  start(message: string): void {
    if (!this.quiet) {
      console.log(`\n🦅 ${message}\n`);
    }
  }

  warn(message: string): void {
    if (!this.quiet) {
      console.log(`⚠️  ${message}`);
    }
  }

  report(findings: Finding[], options: ReportOptions = {}): ScanSummary {
    const summary: ScanSummary = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      warning: findings.filter(f => f.severity === 'warning').length,
      info: findings.filter(f => f.severity === 'info').length,
    };

    if (options.format === 'json') {
      const output = JSON.stringify({ summary, findings }, null, 2);
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`Results written to ${options.output}`);
      } else {
        console.log(output);
      }
    } else if (options.format === 'sarif') {
      const sarif = this.toSARIF(findings);
      const output = JSON.stringify(sarif, null, 2);
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`SARIF results written to ${options.output}`);
      } else {
        console.log(output);
      }
    } else {
      // Table format (default)
      this.printTable(findings, summary);
    }

    return summary;
  }

  private printTable(findings: Finding[], summary: ScanSummary): void {
    console.log('\n📊 Scan Results\n');
    console.log('─'.repeat(80));

    if (findings.length === 0) {
      console.log('✅ No issues found!');
    } else {
      for (const finding of findings) {
        const icon =
          finding.severity === 'critical' ? '🔴' : finding.severity === 'warning' ? '🟡' : '🔵';
        console.log(`${icon} [${finding.severity.toUpperCase()}] ${finding.id}`);
        console.log(`   Resource: ${finding.resource}`);
        console.log(`   ${finding.message}`);
        console.log(`   💡 ${finding.recommendation}`);
        console.log('');
      }
    }

    console.log('─'.repeat(80));
    console.log(`\n📈 Summary: ${summary.total} issues found`);
    console.log(`   🔴 Critical: ${summary.critical}`);
    console.log(`   🟡 Warning: ${summary.warning}`);
    console.log(`   🔵 Info: ${summary.info}`);
    console.log('');
  }

  private toSARIF(findings: Finding[]): SARIFReport {
    return {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'PermitVet',
              version: '0.13.0',
              informationUri: 'https://github.com/taku-tez/PermitVet',
            },
          },
          results: findings.map(f => ({
            ruleId: f.id,
            level:
              f.severity === 'critical'
                ? ('error' as const)
                : f.severity === 'warning'
                  ? ('warning' as const)
                  : ('note' as const),
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.resource },
                },
              },
            ],
          })),
        },
      ],
    };
  }
}
