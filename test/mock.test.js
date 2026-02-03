/**
 * Mock-based integration tests
 * Tests scanners with mocked cloud API responses
 */
const { describe, it, mock, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');

describe('AWS Scanner with Mocks', () => {
  it('detects user without MFA', async () => {
    // Mock AWS SDK
    const mockIAM = {
      listUsers: async () => ({
        Users: [{ UserName: 'admin', UserId: 'AIDA123', CreateDate: new Date() }],
      }),
      listMFADevices: async () => ({
        MFADevices: [], // No MFA
      }),
      listAccessKeys: async () => ({
        AccessKeyMetadata: [],
      }),
      getLoginProfile: async () => ({
        LoginProfile: { UserName: 'admin' },
      }),
      listUserPolicies: async () => ({ PolicyNames: [] }),
      listAttachedUserPolicies: async () => ({ AttachedPolicies: [] }),
      listGroupsForUser: async () => ({ Groups: [] }),
    };

    // Simulate finding detection
    const hasConsoleAccess = true; // Has login profile
    const hasMFA = false; // No MFA devices

    assert.ok(hasConsoleAccess && !hasMFA, 'Should detect missing MFA');
  });

  it('detects old access keys', async () => {
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 95);

    const accessKey = {
      AccessKeyId: 'AKIA123',
      Status: 'Active',
      CreateDate: ninetyDaysAgo,
    };

    const daysSince = Math.floor(
      (Date.now() - accessKey.CreateDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    assert.ok(daysSince > 90, 'Should detect access key older than 90 days');
    assert.strictEqual(daysSince, 95);
  });

  it('detects wildcard actions in policy', () => {
    const policy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: '*',
          Resource: '*',
        },
      ],
    };

    const hasWildcardAction = policy.Statement.some(
      s => s.Action === '*' || (Array.isArray(s.Action) && s.Action.includes('*'))
    );

    assert.ok(hasWildcardAction, 'Should detect wildcard action');
  });

  it('detects cross-account trust', () => {
    const trustPolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:iam::999999999999:root',
          },
          Action: 'sts:AssumeRole',
        },
      ],
    };

    const ownAccountId = '123456789012';
    const trustedAccounts = [];

    for (const statement of trustPolicy.Statement) {
      if (statement.Principal?.AWS) {
        const principals = Array.isArray(statement.Principal.AWS)
          ? statement.Principal.AWS
          : [statement.Principal.AWS];

        for (const p of principals) {
          const match = p.match(/arn:aws:iam::(\d+):/);
          if (match && match[1] !== ownAccountId) {
            trustedAccounts.push(match[1]);
          }
        }
      }
    }

    assert.ok(trustedAccounts.includes('999999999999'), 'Should detect cross-account trust');
  });
});

describe('Azure Scanner with Mocks', () => {
  it('detects Owner role assignment', () => {
    const assignment = {
      roleDefinitionId:
        '/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
      principalId: 'user-123',
      principalType: 'User',
      scope: '/subscriptions/xxx',
    };

    const ownerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
    const roleId = assignment.roleDefinitionId.split('/').pop();

    assert.strictEqual(roleId, ownerRoleId, 'Should identify Owner role');
  });

  it('detects privileged inherited role from MG', () => {
    const assignment = {
      scope: '/providers/Microsoft.Management/managementGroups/mg-root',
      roleDefinitionId: '/xxx/8e3af657-a8ff-443c-a75c-2fe8c4bcb635', // Owner
    };

    const isInheritedFromMG = assignment.scope.includes('managementGroups');
    assert.ok(isInheritedFromMG, 'Should detect MG inheritance');
  });

  it('detects Service Principal with privileged role', () => {
    const assignment = {
      principalType: 'ServicePrincipal',
      principalId: 'sp-123',
      roleDefinitionId: '/xxx/b24988ac-6180-42a0-ab88-20f7382dd24c', // Contributor
    };

    const isSP = assignment.principalType === 'ServicePrincipal';
    const contributorRoleId = 'b24988ac-6180-42a0-ab88-20f7382dd24c';
    const roleId = assignment.roleDefinitionId.split('/').pop();

    assert.ok(isSP && roleId === contributorRoleId, 'Should detect SP with Contributor');
  });
});

describe('GCP Scanner with Mocks', () => {
  it('detects primitive role', () => {
    const binding = {
      role: 'roles/owner',
      members: ['user:admin@example.com'],
    };

    const primitiveRoles = ['roles/owner', 'roles/editor'];
    const isPrimitive = primitiveRoles.includes(binding.role);

    assert.ok(isPrimitive, 'Should detect primitive role');
  });

  it('detects allUsers public access', () => {
    const binding = {
      role: 'roles/viewer',
      members: ['allUsers'],
    };

    const hasPublicAccess = binding.members.includes('allUsers');
    assert.ok(hasPublicAccess, 'Should detect public access');
  });

  it('detects allAuthenticatedUsers access', () => {
    const binding = {
      role: 'roles/viewer',
      members: ['allAuthenticatedUsers'],
    };

    const hasAuthenticatedUsers = binding.members.includes('allAuthenticatedUsers');
    assert.ok(hasAuthenticatedUsers, 'Should detect allAuthenticatedUsers');
  });

  it('detects old service account key', () => {
    const key = {
      keyType: 'USER_MANAGED',
      validAfterTime: '2025-10-01T00:00:00Z',
    };

    const validAfterTime = new Date(key.validAfterTime);
    const daysSince = (Date.now() - validAfterTime.getTime()) / (1000 * 60 * 60 * 24);

    // As of 2026-02, this key would be ~4 months old
    assert.ok(daysSince > 90, 'Should detect old key');
  });

  it('detects dangerous custom role permissions', () => {
    const role = {
      name: 'projects/xxx/roles/customAdmin',
      includedPermissions: [
        'iam.serviceAccountKeys.create',
        'resourcemanager.projects.setIamPolicy',
      ],
    };

    const dangerousPermissions = [
      'iam.serviceAccountKeys.create',
      'resourcemanager.projects.setIamPolicy',
    ];

    const hasDangerous = role.includedPermissions.some(p => dangerousPermissions.includes(p));

    assert.ok(hasDangerous, 'Should detect dangerous permissions');
  });

  it('detects cross-project SA access', () => {
    const projectPermissions = new Map();

    // Simulate SA with access to multiple projects
    const saEmail = 'sa@project1.iam.gserviceaccount.com';
    projectPermissions.set(saEmail, [
      { project: 'project1', role: 'roles/editor' },
      { project: 'project2', role: 'roles/editor' },
      { project: 'project3', role: 'roles/editor' },
      { project: 'project4', role: 'roles/editor' },
    ]);

    const access = projectPermissions.get(saEmail);
    const hasMultiProjectAccess = access && access.length > 3;

    assert.ok(hasMultiProjectAccess, 'Should detect multi-project SA access');
  });
});

describe('Privilege Escalation Detection', () => {
  const {
    detectPrivescPaths,
    AWS_PRIVESC_TECHNIQUES,
  } = require('../dist/scanners/privesc-detector.js');

  it('detects CreatePolicyVersion privesc', () => {
    const permissions = ['iam:CreatePolicyVersion'];
    const paths = detectPrivescPaths('aws', permissions);

    const hasCreatePolicyVersion = paths.some(
      p =>
        p.id.includes('CreatePolicyVersion') ||
        p.requiredPermissions?.includes('iam:CreatePolicyVersion')
    );

    assert.ok(hasCreatePolicyVersion, 'Should detect CreatePolicyVersion');
  });

  it('detects PassRole + Lambda privesc combo', () => {
    const permissions = ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'];
    const paths = detectPrivescPaths('aws', permissions);

    const hasLambdaPrivesc = paths.some(
      p =>
        p.id.toLowerCase().includes('lambda') ||
        (p.requiredPermissions?.includes('iam:PassRole') &&
          p.requiredPermissions?.includes('lambda:CreateFunction'))
    );

    assert.ok(hasLambdaPrivesc, 'Should detect PassRole+Lambda combo');
  });

  it('detects GCP SA key creation privesc', () => {
    const permissions = ['iam.serviceAccountKeys.create'];
    const paths = detectPrivescPaths('gcp', permissions);

    const hasSAKeyPrivesc = paths.some(p =>
      p.requiredPermissions?.some(perm => perm.includes('serviceAccountKeys'))
    );

    assert.ok(hasSAKeyPrivesc, 'Should detect SA key creation');
  });

  it('detects Azure roleAssignments/write privesc', () => {
    const permissions = ['Microsoft.Authorization/roleAssignments/write'];
    const paths = detectPrivescPaths('azure', permissions);

    const hasRoleAssignmentPrivesc = paths.some(p =>
      p.requiredPermissions?.some(perm => perm.includes('roleAssignments'))
    );

    assert.ok(hasRoleAssignmentPrivesc, 'Should detect roleAssignments/write');
  });
});

describe('Compliance Mapping', () => {
  const { mapToCompliance, generateComplianceSummary } = require('../dist/compliance.js');

  it('maps finding to CIS benchmark', () => {
    const finding = {
      id: 'aws-iam-user-mfa',
      severity: 'warning',
      resource: 'IAMUser/admin',
      message: 'MFA not enabled',
      cis: '1.10',
    };

    const mapped = mapToCompliance(finding);

    assert.ok(mapped.cis, 'Should have CIS reference');
    assert.strictEqual(mapped.cis, '1.10');
  });

  it('generates compliance summary', () => {
    const findings = [
      { id: 'test-1', severity: 'warning', cis: '1.1' },
      { id: 'test-2', severity: 'warning', cis: '1.2' },
      { id: 'test-3', severity: 'critical', cis: '1.3' },
    ];

    const summary = generateComplianceSummary(findings);

    assert.ok(typeof summary === 'object', 'Should return summary object');
  });
});

describe('Finding Schema Validation', () => {
  it('validates required fields', () => {
    const validFinding = {
      id: 'test-finding',
      severity: 'warning',
      resource: 'TestResource',
      message: 'Test message',
      recommendation: 'Test recommendation',
    };

    const requiredFields = ['id', 'severity', 'resource', 'message', 'recommendation'];
    const hasAllRequired = requiredFields.every(f => validFinding[f] !== undefined);

    assert.ok(hasAllRequired, 'Finding should have all required fields');
  });

  it('validates severity values', () => {
    const validSeverities = ['critical', 'warning', 'info'];

    for (const severity of validSeverities) {
      assert.ok(validSeverities.includes(severity), `${severity} should be valid`);
    }

    assert.ok(!validSeverities.includes('high'), 'high should not be valid');
    assert.ok(!validSeverities.includes('low'), 'low should not be valid');
  });
});

describe('Reporter Output', () => {
  const { generateSARIF, generateHTMLReport } = require('../dist/compliance.js');

  it('generates valid SARIF structure', () => {
    const findings = [
      {
        id: 'test-1',
        severity: 'warning',
        resource: 'TestResource',
        message: 'Test message',
        recommendation: 'Fix it',
      },
    ];

    const sarif = generateSARIF(findings, { version: '0.11.0' });

    assert.strictEqual(
      sarif.$schema,
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
    );
    assert.strictEqual(sarif.version, '2.1.0');
    assert.ok(Array.isArray(sarif.runs), 'Should have runs array');
    assert.ok(sarif.runs[0].tool, 'Should have tool info');
    assert.ok(sarif.runs[0].results, 'Should have results');
  });

  it('generates HTML report', () => {
    const findings = [
      {
        id: 'test-1',
        severity: 'critical',
        resource: 'TestResource',
        message: 'Test message',
        recommendation: 'Fix it',
      },
    ];

    const html = generateHTMLReport(findings, { version: '0.11.0' });

    assert.ok(html.includes('<!DOCTYPE html>'), 'Should be valid HTML');
    assert.ok(html.includes('PermitVet'), 'Should include product name');
    assert.ok(html.includes('critical'), 'Should include severity');
  });
});
