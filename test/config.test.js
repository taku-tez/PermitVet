/**
 * Configuration file support tests
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');

const {
  mergeOptions,
  validateConfig,
  applyConfig,
  checkThresholds,
  generateExampleConfig,
} = require('../dist/config.js');

describe('Configuration Merging', () => {
  it('merges CLI options with file config', () => {
    const cliOptions = { profile: 'production', format: 'json' };
    const fileConfig = { profile: 'default', quiet: true };

    const merged = mergeOptions(cliOptions, fileConfig);

    // CLI takes precedence
    assert.strictEqual(merged.profile, 'production');
    // File config is preserved
    assert.strictEqual(merged.quiet, true);
    // CLI format preserved
    assert.strictEqual(merged.format, 'json');
  });

  it('handles null file config', () => {
    const cliOptions = { profile: 'test' };

    const merged = mergeOptions(cliOptions, null);

    assert.strictEqual(merged.profile, 'test');
  });

  it('preserves exclude arrays from file config', () => {
    const cliOptions = {};
    const fileConfig = { exclude: ['IAMUser/*', 'ServiceAccount/*'] };

    const merged = mergeOptions(cliOptions, fileConfig);

    assert.deepStrictEqual(merged.exclude, ['IAMUser/*', 'ServiceAccount/*']);
  });
});

describe('Configuration Validation', () => {
  it('validates valid config', () => {
    const config = {
      exclude: ['IAMUser/*'],
      thresholds: { critical: 0, warning: 10 },
      rules: {
        'aws-iam-user-mfa': 'off',
        'gcp-primitive-role': { severity: 'warning' },
      },
    };

    const result = validateConfig(config);

    assert.ok(result.valid);
    assert.strictEqual(result.errors.length, 0);
  });

  it('rejects invalid exclude type', () => {
    const config = { exclude: 'not-an-array' };

    const result = validateConfig(config);

    assert.ok(!result.valid);
    assert.ok(result.errors.some(e => e.includes('exclude must be an array')));
  });

  it('rejects invalid threshold severity', () => {
    const config = { thresholds: { high: 5 } };

    const result = validateConfig(config);

    assert.ok(!result.valid);
    assert.ok(result.errors.some(e => e.includes('Invalid threshold severity')));
  });

  it('rejects non-number threshold value', () => {
    const config = { thresholds: { critical: 'zero' } };

    const result = validateConfig(config);

    assert.ok(!result.valid);
    assert.ok(result.errors.some(e => e.includes('must be a number')));
  });
});

describe('Apply Config to Findings', () => {
  it('excludes findings by resource pattern', () => {
    const findings = [
      { id: 'test-1', resource: 'IAMUser/admin' },
      { id: 'test-2', resource: 'IAMUser/service-account' },
      { id: 'test-3', resource: 'IAMRole/admin' },
    ];
    const config = { exclude: ['IAMUser/service-*'] };

    const result = applyConfig(findings, config);

    assert.strictEqual(result.length, 2);
    assert.ok(!result.some(f => f.resource === 'IAMUser/service-account'));
  });

  it('excludes findings by rule ID', () => {
    const findings = [
      { id: 'aws-iam-user-mfa', resource: 'User/test' },
      { id: 'aws-access-key-old', resource: 'Key/test' },
    ];
    const config = { exclude: ['aws-iam-user-mfa'] };

    const result = applyConfig(findings, config);

    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].id, 'aws-access-key-old');
  });

  it('disables rules with off', () => {
    const findings = [
      { id: 'rule-1', resource: 'test' },
      { id: 'rule-2', resource: 'test' },
    ];
    const config = { rules: { 'rule-1': 'off' } };

    const result = applyConfig(findings, config);

    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].id, 'rule-2');
  });

  it('overrides severity', () => {
    const findings = [{ id: 'rule-1', severity: 'warning', resource: 'test' }];
    const config = { rules: { 'rule-1': { severity: 'info' } } };

    const result = applyConfig(findings, config);

    assert.strictEqual(result[0].severity, 'info');
  });

  it('handles null config', () => {
    const findings = [{ id: 'test', resource: 'test' }];

    const result = applyConfig(findings, null);

    assert.strictEqual(result.length, 1);
  });
});

describe('Threshold Checking', () => {
  it('passes when under thresholds', () => {
    const summary = { critical: 0, warning: 5, info: 10, total: 15 };
    const thresholds = { critical: 0, warning: 10 };

    const result = checkThresholds(summary, thresholds);

    assert.ok(!result.exceeded);
    assert.strictEqual(result.violations.length, 0);
  });

  it('fails when critical exceeds threshold', () => {
    const summary = { critical: 2, warning: 5, info: 10, total: 17 };
    const thresholds = { critical: 0 };

    const result = checkThresholds(summary, thresholds);

    assert.ok(result.exceeded);
    assert.ok(result.violations.some(v => v.includes('Critical')));
  });

  it('fails when warning exceeds threshold', () => {
    const summary = { critical: 0, warning: 15, info: 10, total: 25 };
    const thresholds = { warning: 10 };

    const result = checkThresholds(summary, thresholds);

    assert.ok(result.exceeded);
    assert.ok(result.violations.some(v => v.includes('Warning')));
  });

  it('checks total threshold', () => {
    const summary = { critical: 0, warning: 5, info: 100, total: 105 };
    const thresholds = { total: 50 };

    const result = checkThresholds(summary, thresholds);

    assert.ok(result.exceeded);
    assert.ok(result.violations.some(v => v.includes('Total')));
  });

  it('handles null thresholds', () => {
    const summary = { critical: 10, warning: 50, info: 100, total: 160 };

    const result = checkThresholds(summary, null);

    assert.ok(!result.exceeded);
  });
});

describe('Example Config Generation', () => {
  it('generates valid YAML content', () => {
    const content = generateExampleConfig();

    assert.ok(content.includes('# PermitVet Configuration'));
    assert.ok(content.includes('exclude:'));
    assert.ok(content.includes('thresholds:'));
    assert.ok(content.includes('rules:'));
  });

  it('includes provider sections', () => {
    const content = generateExampleConfig();

    assert.ok(content.includes('aws:'));
    assert.ok(content.includes('azure:'));
    assert.ok(content.includes('gcp:'));
  });
});
