/**
 * AWS IAM Access Analyzer Integration
 * Detects unused access, external access, and generates least-privilege recommendations
 */

import type { Finding, ScanOptions, Severity } from '../types';
// Utils imported as needed

interface AccessAnalyzerClient {
  send: (command: unknown) => Promise<unknown>;
}

interface Analyzer {
  name: string;
  arn: string;
  type: string;
}

interface AccessAnalyzerFinding {
  resourceType?: string;
  resource: string;
  principal?: {
    AWS?: string;
    Federated?: string;
  };
  action?: string[];
  condition?: Record<string, unknown>;
  isPublic?: boolean;
  findingType?: string;
  unusedAccess?: {
    lastAccessed?: string;
    unusedServices?: string[];
    unusedActions?: string[];
  };
}

interface PolicyGenerationOptions {
  principalArn: string;
  trailArn: string;
  regions?: string[];
  accessRole: string;
  startTime?: Date;
  endTime?: Date;
}

/**
 * Scan using AWS IAM Access Analyzer
 */
export async function scanAccessAnalyzer(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { AccessAnalyzerClient } = await import('@aws-sdk/client-accessanalyzer');

    const config = options.profile ? { profile: options.profile } : {};

    const client = new AccessAnalyzerClient(config) as any;

    // 1. Check for existing analyzers
    console.log('  Checking IAM Access Analyzer...');
    const analyzers = await listAnalyzers(client);

    if (analyzers.length === 0) {
      findings.push({
        id: 'aws-no-access-analyzer',
        severity: 'warning',
        resource: 'Account',
        message: 'No IAM Access Analyzer configured',
        recommendation:
          'Create an Access Analyzer to detect external access and unused permissions',
        cis: '1.20',
      });
      return findings;
    }

    // 2. Scan findings from each analyzer
    for (const analyzer of analyzers) {
      console.log(`  Scanning analyzer: ${analyzer.name} (${analyzer.type})...`);

      if (analyzer.type === 'ACCOUNT' || analyzer.type === 'ORGANIZATION') {
        // External access findings
        const externalFindings = await scanExternalAccess(client, analyzer.arn);
        findings.push(...externalFindings);
      }

      if (
        analyzer.type === 'ACCOUNT_UNUSED_ACCESS' ||
        analyzer.type === 'ORGANIZATION_UNUSED_ACCESS'
      ) {
        // Unused access findings
        const unusedFindings = await scanUnusedAccess(client, analyzer.arn);
        findings.push(...unusedFindings);
      }
    }
  } catch (error) {
    const err = error as Error & { code?: string; name?: string };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed. Run: npm install @aws-sdk/client-accessanalyzer');
    } else if (err.name === 'AccessDeniedException') {
      findings.push({
        id: 'aws-access-analyzer-denied',
        severity: 'info',
        resource: 'Account',
        message: 'Unable to access IAM Access Analyzer',
        recommendation: 'Ensure scanner has access-analyzer:* permissions',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * List all Access Analyzers in the account
 */
async function listAnalyzers(client: AccessAnalyzerClient): Promise<Analyzer[]> {
  const { ListAnalyzersCommand } = await import('@aws-sdk/client-accessanalyzer');

  const analyzers: Analyzer[] = [];
  let nextToken: string | undefined;

  do {
    const response = (await client.send(
      new ListAnalyzersCommand({
        nextToken,
      })
    )) as { analyzers?: Analyzer[]; nextToken?: string };
    analyzers.push(...(response.analyzers || []));
    nextToken = response.nextToken;
  } while (nextToken);

  return analyzers;
}

/**
 * Scan for external access findings
 * CIEM scope: Only IAM-related resources (roles, users, policies)
 * S3, Lambda, etc. are CSPM scope - excluded
 */
async function scanExternalAccess(
  client: AccessAnalyzerClient,
  analyzerArn: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { ListFindingsCommand } = await import('@aws-sdk/client-accessanalyzer');

  // CIEM scope: Only identity/entitlement resources
  const CIEM_RESOURCE_TYPES = [
    'AWS::IAM::Role',
    'AWS::IAM::User',
    'AWS::IAM::Group',
    'AWS::IAM::Policy',
    'AWS::KMS::Key', // KMS key policies affect access control
  ];

  try {
    let nextToken: string | undefined;

    do {
      const response = (await client.send(
        new ListFindingsCommand({
          analyzerArn,
          filter: {
            status: { eq: ['ACTIVE'] },
          },
          nextToken,
        })
      )) as { findings?: AccessAnalyzerFinding[]; nextToken?: string };

      for (const finding of response.findings || []) {
        // Skip non-CIEM resources (S3, Lambda, SQS, etc. = CSPM scope)
        if (!CIEM_RESOURCE_TYPES.includes(finding.resourceType || '')) {
          continue;
        }

        const severity = mapAccessAnalyzerSeverity(finding);

        findings.push({
          id: `aws-external-access-${finding.resourceType?.toLowerCase().replace(/::/g, '-')}`,
          severity,
          resource: finding.resource,
          message: `${finding.resourceType} allows external access: ${finding.principal?.AWS || finding.principal?.Federated || 'Unknown'}`,
          recommendation: `Review ${finding.resourceType} policy. Condition: ${JSON.stringify(finding.condition || {})}`,
          details: {
            resourceType: finding.resourceType,
            principal: finding.principal,
            action: finding.action,
            condition: finding.condition,
            isPublic: finding.isPublic,
          },
        });
      }

      nextToken = response.nextToken;
    } while (nextToken);
  } catch (error) {
    const err = error as Error & { name?: string };
    // Skip if permission denied
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan for unused access findings
 */
async function scanUnusedAccess(
  client: AccessAnalyzerClient,
  analyzerArn: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { ListFindingsCommand } = await import('@aws-sdk/client-accessanalyzer');

  try {
    let nextToken: string | undefined;

    do {
      const response = (await client.send(
        new ListFindingsCommand({
          analyzerArn,
          filter: {
            status: { eq: ['ACTIVE'] },
          },
          nextToken,
        })
      )) as { findings?: AccessAnalyzerFinding[]; nextToken?: string };

      for (const finding of response.findings || []) {
        const findingType = finding.findingType;

        switch (findingType) {
          case 'UnusedIAMRole':
            findings.push({
              id: 'aws-unused-role',
              severity: 'warning',
              resource: finding.resource,
              message: `IAM Role has not been used in ${finding.unusedAccess?.lastAccessed ? 'over ' + finding.unusedAccess.lastAccessed : 'a long time'}`,
              recommendation:
                'Review if this role is still needed. Consider deleting unused roles.',
              details: finding.unusedAccess,
            });
            break;

          case 'UnusedIAMUserAccessKey':
            findings.push({
              id: 'aws-unused-access-key',
              severity: 'warning',
              resource: finding.resource,
              message: 'Access key has not been used',
              recommendation: 'Delete unused access keys to reduce attack surface.',
              details: finding.unusedAccess,
            });
            break;

          case 'UnusedIAMUserPassword':
            findings.push({
              id: 'aws-unused-password',
              severity: 'info',
              resource: finding.resource,
              message: 'Console password has not been used',
              recommendation: 'Consider disabling console access if not needed.',
              details: finding.unusedAccess,
            });
            break;

          case 'UnusedPermission':
            findings.push({
              id: 'aws-unused-permission',
              severity: 'info',
              resource: finding.resource,
              message: `Unused permissions detected: ${finding.unusedAccess?.unusedServices?.length || 0} unused services`,
              recommendation: 'Review and remove unused permissions to enforce least privilege.',
              details: {
                unusedServices: finding.unusedAccess?.unusedServices,
                unusedActions: finding.unusedAccess?.unusedActions,
              },
            });
            break;

          default:
            findings.push({
              id: `aws-unused-${findingType?.toLowerCase() || 'unknown'}`,
              severity: 'info',
              resource: finding.resource,
              message: `Unused access detected: ${findingType}`,
              recommendation: 'Review and remediate unused access.',
              details: finding.unusedAccess,
            });
        }
      }

      nextToken = response.nextToken;
    } while (nextToken);
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Map Access Analyzer severity to PermitVet severity
 */
function mapAccessAnalyzerSeverity(finding: AccessAnalyzerFinding): Severity {
  // Public access is always critical
  if (finding.isPublic) return 'critical';

  // Cross-account with '*' principal
  if (finding.principal?.AWS === '*') return 'critical';

  // External account access
  if (finding.principal?.AWS && !finding.principal.AWS.includes(':root')) {
    return 'warning';
  }

  return 'info';
}

/**
 * Generate least privilege policy recommendations
 * (Requires CloudTrail access and may take time)
 */
export async function generatePolicyRecommendation(
  client: AccessAnalyzerClient,
  options: PolicyGenerationOptions
): Promise<unknown[] | null> {
  const { StartPolicyGenerationCommand, GetGeneratedPolicyCommand } =
    await import('@aws-sdk/client-accessanalyzer');

  // Start policy generation based on CloudTrail activity

  const response = (await client.send(
    new StartPolicyGenerationCommand({
      policyGenerationDetails: {
        principalArn: options.principalArn,
      },
      cloudTrailDetails: {
        trailArn: options.trailArn,
        regions: options.regions || [],
        accessRole: options.accessRole,
        startTime: options.startTime || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000), // 90 days ago
        endTime: options.endTime || new Date(),
      },
    } as any)
  )) as { jobId: string };

  const jobId = response.jobId;

  // Poll for completion (in production, use async/event-driven approach)
  let status = 'IN_PROGRESS';
  let policy: unknown[] | null = null;

  while (status === 'IN_PROGRESS') {
    await new Promise(r => setTimeout(r, 5000));

    const statusResponse = (await client.send(
      new GetGeneratedPolicyCommand({
        jobId,
      })
    )) as {
      jobDetails?: { status: string };
      generatedPolicyResult?: { generatedPolicies: unknown[] };
    };

    status = statusResponse.jobDetails?.status || 'FAILED';
    if (status === 'SUCCEEDED') {
      policy = statusResponse.generatedPolicyResult?.generatedPolicies || null;
    }
  }

  return policy;
}
