/**
 * PermitVet Scanner Tests
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { scan, version } = require('../src/index.js');

describe('PermitVet', () => {
  it('should export version', () => {
    assert.ok(version);
    assert.match(version, /^\d+\.\d+\.\d+$/);
  });

  it('should export scan function', () => {
    assert.ok(typeof scan === 'function');
  });

  it('should throw on unknown provider', async () => {
    await assert.rejects(
      () => scan('unknown'),
      { message: /Unknown provider/ }
    );
  });
});
