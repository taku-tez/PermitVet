/**
 * Scanner unit tests with mocks
 */
const { describe, it, mock } = require('node:test');
const assert = require('node:assert');

describe('Scanner Modules', () => {
  
  it('aws.js exports scanAWS function', () => {
    const { scanAWS } = require('../src/scanners/aws.js');
    assert.strictEqual(typeof scanAWS, 'function');
  });
  
  it('azure.js exports scanAzure function', () => {
    const { scanAzure } = require('../src/scanners/azure.js');
    assert.strictEqual(typeof scanAzure, 'function');
  });
  
  it('gcp.js exports scanGCP function', () => {
    const { scanGCP } = require('../src/scanners/gcp.js');
    assert.strictEqual(typeof scanGCP, 'function');
  });
  
  it('aws-advanced.js exports scanAWSAdvanced function', () => {
    const { scanAWSAdvanced } = require('../src/scanners/aws-advanced.js');
    assert.strictEqual(typeof scanAWSAdvanced, 'function');
  });
  
  it('azure-advanced.js exports scanAzureAdvanced function', () => {
    const { scanAzureAdvanced } = require('../src/scanners/azure-advanced.js');
    assert.strictEqual(typeof scanAzureAdvanced, 'function');
  });
  
  it('gcp-advanced.js exports scanGCPAdvanced function', () => {
    const { scanGCPAdvanced } = require('../src/scanners/gcp-advanced.js');
    assert.strictEqual(typeof scanGCPAdvanced, 'function');
  });
  
  it('kubernetes.js exports scanKubernetesRBAC function', () => {
    const { scanKubernetesRBAC } = require('../src/scanners/kubernetes.js');
    assert.strictEqual(typeof scanKubernetesRBAC, 'function');
  });
  
  it('oracle-cloud.js exports scanOCI function', () => {
    const { scanOCI } = require('../src/scanners/oracle-cloud.js');
    assert.strictEqual(typeof scanOCI, 'function');
  });
  
  it('privesc-detector.js exports detectPrivescPaths function', () => {
    const { detectPrivescPaths } = require('../src/scanners/privesc-detector.js');
    assert.strictEqual(typeof detectPrivescPaths, 'function');
  });

});

describe('Privesc Techniques', () => {
  const { AWS_PRIVESC_TECHNIQUES, AZURE_PRIVESC_TECHNIQUES, GCP_PRIVESC_TECHNIQUES } = require('../src/scanners/privesc-detector.js');
  
  it('AWS has 25+ privesc techniques', () => {
    assert.ok(AWS_PRIVESC_TECHNIQUES.length >= 25, `Expected 25+, got ${AWS_PRIVESC_TECHNIQUES.length}`);
  });
  
  it('Azure has 8+ privesc techniques', () => {
    assert.ok(AZURE_PRIVESC_TECHNIQUES.length >= 8, `Expected 8+, got ${AZURE_PRIVESC_TECHNIQUES.length}`);
  });
  
  it('GCP has 10+ privesc techniques', () => {
    assert.ok(GCP_PRIVESC_TECHNIQUES.length >= 10, `Expected 10+, got ${GCP_PRIVESC_TECHNIQUES.length}`);
  });
  
  it('AWS includes CreatePolicyVersion technique', () => {
    const hasTechnique = AWS_PRIVESC_TECHNIQUES.some(t => 
      t.id.includes('CreatePolicyVersion') || t.permissions?.includes('iam:CreatePolicyVersion')
    );
    assert.ok(hasTechnique, 'Should have CreatePolicyVersion');
  });
  
  it('AWS includes PassRole + Lambda combo', () => {
    const hasTechnique = AWS_PRIVESC_TECHNIQUES.some(t => 
      (t.permissions?.includes('iam:PassRole') && t.permissions?.includes('lambda:CreateFunction')) ||
      t.id.toLowerCase().includes('lambda')
    );
    assert.ok(hasTechnique, 'Should have PassRole+Lambda');
  });
  
  it('Azure includes roleAssignments/write', () => {
    const hasTechnique = AZURE_PRIVESC_TECHNIQUES.some(t => 
      t.permissions?.some(p => p.includes('roleAssignments'))
    );
    assert.ok(hasTechnique, 'Should have roleAssignments');
  });
  
  it('GCP includes serviceAccountKeys.create', () => {
    const hasTechnique = GCP_PRIVESC_TECHNIQUES.some(t => 
      t.permissions?.some(p => p.includes('serviceAccountKeys'))
    );
    assert.ok(hasTechnique, 'Should have SA keys');
  });

});

describe('CIEM Focus Verification', () => {
  const fs = require('fs');
  const path = require('path');
  
  it('aws-advanced.js does not contain IMDSv2', () => {
    const content = fs.readFileSync(
      path.join(__dirname, '../src/scanners/aws-advanced.js'), 
      'utf-8'
    );
    assert.ok(!content.includes('checkIMDSv2'), 'Should not have IMDSv2 check');
    assert.ok(!content.includes('IMDSv1'), 'Should not reference IMDSv1');
  });
  
  it('aws-advanced.js does not contain S3 public access', () => {
    const content = fs.readFileSync(
      path.join(__dirname, '../src/scanners/aws-advanced.js'), 
      'utf-8'
    );
    assert.ok(!content.includes('checkS3PublicAccess'), 'Should not have S3 public access check');
    assert.ok(!content.includes('BlockPublicAcls'), 'Should not reference BlockPublicAcls');
  });
  
  it('azure-advanced.js does not contain Resource Locks', () => {
    const content = fs.readFileSync(
      path.join(__dirname, '../src/scanners/azure-advanced.js'), 
      'utf-8'
    );
    assert.ok(!content.includes('checkResourceLocks'), 'Should not have Resource Locks check');
    assert.ok(!content.includes('ManagementLockClient'), 'Should not use lock client');
  });
  
  it('gcp-advanced.js does not contain VPC Service Controls', () => {
    const content = fs.readFileSync(
      path.join(__dirname, '../src/scanners/gcp-advanced.js'), 
      'utf-8'
    );
    assert.ok(!content.includes('scanVPCServiceControls'), 'Should not have VPC SC check');
    assert.ok(!content.includes('servicePerimeters'), 'Should not reference perimeters');
  });

});
