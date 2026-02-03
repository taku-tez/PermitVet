/**
 * PermitVet Reporter
 */

import * as fs from 'fs';
import type { Finding, ScanSummary, ReportOptions, ScanOptions, CloudProvider } from './types';
import { generateSARIF } from './compliance';

export interface ReporterOptions {
  quiet?: boolean;
  version?: string;
}

/** Detailed JSON output format */
export interface DetailedJSONReport {
  /** Report metadata */
  metadata: {
    tool: string;
    version: string;
    timestamp: string;
    provider: CloudProvider | string;
    options: Partial<ScanOptions>;
  };
  /** Scan summary */
  summary: ScanSummary & {
    /** Findings grouped by severity */
    bySeverity: {
      critical: Finding[];
      warning: Finding[];
      info: Finding[];
    };
    /** Findings grouped by check ID */
    byCheckId: Record<string, Finding[]>;
    /** Unique resources affected */
    uniqueResources: string[];
  };
  /** All findings with full details */
  findings: Finding[];
  /** Statistics */
  statistics: {
    scanDurationMs?: number;
    resourcesScanned?: number;
    checksPerformed?: number;
  };
}

export class Reporter {
  private quiet: boolean;
  private version?: string;
  private startTime?: number;
  private provider?: CloudProvider | string;
  private scanOptions?: Partial<ScanOptions>;

  constructor(options: ReporterOptions = {}) {
    this.quiet = options.quiet || false;
    this.version = options.version;
  }

  /** Set scan context for detailed reporting */
  setContext(provider: CloudProvider | string, scanOptions?: Partial<ScanOptions>): void {
    this.provider = provider;
    this.scanOptions = scanOptions;
    this.startTime = Date.now();
  }

  start(message: string): void {
    if (!this.quiet) {
      console.log(`\n🦅 ${message}\n`);
    }
    if (!this.startTime) {
      this.startTime = Date.now();
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
      const output = JSON.stringify(this.buildDetailedReport(findings, summary), null, 2);
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

  /** Build detailed JSON report */
  private buildDetailedReport(findings: Finding[], summary: ScanSummary): DetailedJSONReport {
    const scanDuration = this.startTime ? Date.now() - this.startTime : undefined;

    // Group findings by severity
    const bySeverity = {
      critical: findings.filter(f => f.severity === 'critical'),
      warning: findings.filter(f => f.severity === 'warning'),
      info: findings.filter(f => f.severity === 'info'),
    };

    // Group findings by check ID
    const byCheckId: Record<string, Finding[]> = {};
    for (const finding of findings) {
      if (!byCheckId[finding.id]) {
        byCheckId[finding.id] = [];
      }
      byCheckId[finding.id].push(finding);
    }

    // Get unique resources
    const uniqueResources = [...new Set(findings.map(f => f.resource))];

    // Filter out sensitive options
    const safeOptions: Partial<ScanOptions> = this.scanOptions
      ? {
          format: this.scanOptions.format,
          enhanced: this.scanOptions.enhanced,
          verbose: this.scanOptions.verbose,
          // Include provider-specific non-sensitive options
          ...(this.scanOptions.project && { project: this.scanOptions.project }),
          ...(this.scanOptions.organization && { organization: this.scanOptions.organization }),
          ...(this.scanOptions.subscription && { subscription: '[redacted]' }),
          ...(this.scanOptions.tenant && { tenant: '[redacted]' }),
          ...(this.scanOptions.allProjects && { allProjects: this.scanOptions.allProjects }),
          ...(this.scanOptions.allSubscriptions && {
            allSubscriptions: this.scanOptions.allSubscriptions,
          }),
        }
      : {};

    return {
      metadata: {
        tool: 'PermitVet',
        version: this.version || 'unknown',
        timestamp: new Date().toISOString(),
        provider: this.provider || 'unknown',
        options: safeOptions,
      },
      summary: {
        ...summary,
        bySeverity,
        byCheckId,
        uniqueResources,
      },
      findings,
      statistics: {
        scanDurationMs: scanDuration,
        resourcesScanned: uniqueResources.length,
        checksPerformed: Object.keys(byCheckId).length,
      },
    };
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
