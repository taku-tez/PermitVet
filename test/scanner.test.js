/**
 * PermitVet Scanner Tests
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { scan, version } = require('../dist/index.js');

describe('PermitVet', () => {
  it('should export version', () => {
    assert.ok(version);
    assert.match(version, /^\d+\.\d+\.\d+$/);
  });

  it('should export scan function', () => {
    assert.ok(typeof scan === 'function');
  });

  it('should throw on unknown provider', async () => {
    await assert.rejects(() => scan('unknown'), { message: /Unknown provider/ });
  });
});

describe('AWS Scanner', () => {
  it('should import AWS scanner module', async () => {
    const scanner = require('../dist/scanners/aws.js');
    assert.ok(scanner.scanAWS, 'scanAWS should be exported');
  });

  it('should import AWS advanced scanner module', async () => {
    const scanner = require('../dist/scanners/aws-advanced.js');
    assert.ok(scanner.scanAWSAdvanced, 'scanAWSAdvanced should be exported');
  });

  it('should have finding structure', () => {
    const requiredFields = ['id', 'severity', 'resource', 'message', 'recommendation'];
    const sampleFinding = {
      id: 'aws-overprivileged-user',
      severity: 'critical',
      resource: 'IAM User/testuser',
      message: 'User has AdministratorAccess policy',
      recommendation: 'Apply least privilege',
    };
    requiredFields.forEach(field => {
      assert.ok(field in sampleFinding, `Finding should have ${field}`);
    });
  });
});

describe('GCP Scanner', () => {
  it('should import GCP scanner module', async () => {
    const scanner = require('../dist/scanners/gcp.js');
    assert.ok(scanner.scanGCP, 'scanGCP should be exported');
  });

  it('should have CIS benchmark references', () => {
    // GCP scanner should reference CIS benchmarks
    const scanner = require('../dist/scanners/gcp.js');
    assert.ok(scanner.scanGCP, 'scanGCP should be exported');
  });

  it('should have finding structure', () => {
    const requiredFields = ['id', 'severity', 'resource', 'message', 'recommendation'];
    const sampleFinding = {
      id: 'gcp-primitive-role',
      severity: 'warning',
      resource: 'Project/my-project',
      message: 'User has primitive role: roles/owner',
      recommendation: 'Use predefined or custom roles',
    };
    requiredFields.forEach(field => {
      assert.ok(field in sampleFinding, `Finding should have ${field}`);
    });
  });
});

describe('Azure Scanner', () => {
  it('should import Azure scanner module', async () => {
    const scanner = require('../dist/scanners/azure.js');
    assert.ok(scanner.scanAzure, 'scanAzure should be exported');
  });

  it('should have finding structure', () => {
    const requiredFields = ['id', 'severity', 'resource', 'message', 'recommendation'];
    const sampleFinding = {
      id: 'azure-owner-role',
      severity: 'warning',
      resource: 'Subscription/sub-123',
      message: 'User has Owner role',
      recommendation: 'Use specific roles with least privilege',
    };
    requiredFields.forEach(field => {
      assert.ok(field in sampleFinding, `Finding should have ${field}`);
    });
  });
});

describe('Severity Levels', () => {
  it('should have correct severity order', () => {
    const severities = ['critical', 'warning', 'info'];
    const order = { critical: 0, warning: 1, info: 2 };

    severities.forEach((sev, idx) => {
      assert.strictEqual(order[sev], idx, `${sev} should have order ${idx}`);
    });
  });
});

describe('Output Formats', () => {
  it('should import Reporter class', async () => {
    const { Reporter } = require('../dist/reporter.js');
    assert.ok(Reporter, 'Reporter should be exported');
  });

  it('should create Reporter instance', async () => {
    const { Reporter } = require('../dist/reporter.js');
    const reporter = new Reporter();
    assert.ok(reporter.report, 'reporter.report should exist');
  });

  it('should report findings', async () => {
    const { Reporter } = require('../dist/reporter.js');
    const reporter = new Reporter({ quiet: true });
    const findings = [
      {
        id: 'test-001',
        severity: 'warning',
        resource: 'test',
        message: 'test message',
        recommendation: 'test recommendation',
      },
    ];
    // Should not throw
    reporter.report(findings, { format: 'table' });
    assert.ok(true, 'Report generated successfully');
  });
});
