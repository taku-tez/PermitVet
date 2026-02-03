/**
 * PermitVet Reporter
 */

import * as fs from 'fs';
import type { Finding, ScanSummary, ReportOptions } from './types';
import { generateSARIF } from './compliance';

export interface ReporterOptions {
  quiet?: boolean;
  version?: string;
}

export class Reporter {
  private quiet: boolean;
  private version?: string;

  constructor(options: ReporterOptions = {}) {
    this.quiet = options.quiet || false;
    this.version = options.version;
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
      if (!this.version) {
        throw new Error('Reporter requires a version to generate SARIF output.');
      }
      const sarif = generateSARIF(findings, { version: this.version });
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
}
