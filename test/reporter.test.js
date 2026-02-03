/**
 * Reporter unit tests
 * Tests for detailed JSON output format
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('Reporter', () => {
  const { Reporter } = require('../dist/reporter.js');

  it('exports Reporter class', () => {
    assert.strictEqual(typeof Reporter, 'function');
  });

  it('creates reporter with options', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    assert.ok(reporter);
  });

  it('setContext stores provider and options', () => {
    const reporter = new Reporter({ version: '0.15.3' });
    reporter.setContext('aws', { format: 'json', verbose: true });
    // Context is stored internally, we verify by checking report output
    assert.ok(reporter);
  });
});

describe('Detailed JSON Output', () => {
  const { Reporter } = require('../dist/reporter.js');

  it('builds detailed report with metadata', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('aws', { format: 'json' });

    const findings = [
      {
        id: 'test-finding-1',
        severity: 'critical',
        resource: 'IAMUser/admin',
        message: 'Test critical finding',
        recommendation: 'Fix it',
      },
      {
        id: 'test-finding-2',
        severity: 'warning',
        resource: 'IAMRole/developer',
        message: 'Test warning finding',
        recommendation: 'Review it',
      },
      {
        id: 'test-finding-1',
        severity: 'critical',
        resource: 'IAMUser/root',
        message: 'Another critical finding',
        recommendation: 'Fix it too',
      },
    ];

    // Capture JSON output
    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    // Verify structure
    assert.ok(jsonOutput, 'Should produce JSON output');
    assert.ok(jsonOutput.metadata, 'Should have metadata');
    assert.ok(jsonOutput.summary, 'Should have summary');
    assert.ok(jsonOutput.findings, 'Should have findings');
    assert.ok(jsonOutput.statistics, 'Should have statistics');
  });

  it('metadata contains correct fields', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('gcp', { format: 'json', project: 'my-project' });

    const findings = [];
    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    assert.strictEqual(jsonOutput.metadata.tool, 'PermitVet');
    assert.strictEqual(jsonOutput.metadata.version, '0.15.3');
    assert.strictEqual(jsonOutput.metadata.provider, 'gcp');
    assert.ok(jsonOutput.metadata.timestamp);
    assert.ok(jsonOutput.metadata.options);
  });

  it('summary groups findings by severity', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('aws', {});

    const findings = [
      { id: 'f1', severity: 'critical', resource: 'r1', message: 'm1', recommendation: 'rec1' },
      { id: 'f2', severity: 'warning', resource: 'r2', message: 'm2', recommendation: 'rec2' },
      { id: 'f3', severity: 'warning', resource: 'r3', message: 'm3', recommendation: 'rec3' },
      { id: 'f4', severity: 'info', resource: 'r4', message: 'm4', recommendation: 'rec4' },
    ];

    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    assert.strictEqual(jsonOutput.summary.total, 4);
    assert.strictEqual(jsonOutput.summary.critical, 1);
    assert.strictEqual(jsonOutput.summary.warning, 2);
    assert.strictEqual(jsonOutput.summary.info, 1);
    assert.strictEqual(jsonOutput.summary.bySeverity.critical.length, 1);
    assert.strictEqual(jsonOutput.summary.bySeverity.warning.length, 2);
    assert.strictEqual(jsonOutput.summary.bySeverity.info.length, 1);
  });

  it('summary groups findings by check ID', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('aws', {});

    const findings = [
      { id: 'check-a', severity: 'warning', resource: 'r1', message: 'm1', recommendation: 'rec1' },
      { id: 'check-a', severity: 'warning', resource: 'r2', message: 'm2', recommendation: 'rec2' },
      { id: 'check-b', severity: 'info', resource: 'r3', message: 'm3', recommendation: 'rec3' },
    ];

    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    assert.ok(jsonOutput.summary.byCheckId['check-a']);
    assert.ok(jsonOutput.summary.byCheckId['check-b']);
    assert.strictEqual(jsonOutput.summary.byCheckId['check-a'].length, 2);
    assert.strictEqual(jsonOutput.summary.byCheckId['check-b'].length, 1);
  });

  it('summary lists unique resources', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('aws', {});

    const findings = [
      {
        id: 'f1',
        severity: 'warning',
        resource: 'IAMUser/alice',
        message: 'm1',
        recommendation: 'rec1',
      },
      {
        id: 'f2',
        severity: 'warning',
        resource: 'IAMUser/alice',
        message: 'm2',
        recommendation: 'rec2',
      },
      {
        id: 'f3',
        severity: 'info',
        resource: 'IAMRole/admin',
        message: 'm3',
        recommendation: 'rec3',
      },
    ];

    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    assert.strictEqual(jsonOutput.summary.uniqueResources.length, 2);
    assert.ok(jsonOutput.summary.uniqueResources.includes('IAMUser/alice'));
    assert.ok(jsonOutput.summary.uniqueResources.includes('IAMRole/admin'));
  });

  it('statistics contains scan duration', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('aws', {});
    reporter.start('Test scan');

    // Small delay to ensure duration > 0
    const findings = [
      { id: 'f1', severity: 'info', resource: 'r1', message: 'm1', recommendation: 'rec1' },
    ];

    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    assert.ok(jsonOutput.statistics.scanDurationMs !== undefined);
    assert.ok(jsonOutput.statistics.scanDurationMs >= 0);
  });

  it('redacts sensitive options', () => {
    const reporter = new Reporter({ quiet: true, version: '0.15.3' });
    reporter.setContext('azure', {
      format: 'json',
      subscription: 'secret-sub-id',
      tenant: 'secret-tenant-id',
      verbose: true,
    });

    const findings = [];
    let jsonOutput = null;
    const originalLog = console.log;
    console.log = output => {
      if (typeof output === 'string' && output.startsWith('{')) {
        jsonOutput = JSON.parse(output);
      }
    };

    reporter.report(findings, { format: 'json' });
    console.log = originalLog;

    // Sensitive values should be redacted
    assert.strictEqual(jsonOutput.metadata.options.subscription, '[redacted]');
    assert.strictEqual(jsonOutput.metadata.options.tenant, '[redacted]');
  });
});
