/**
 * AWS Secrets & Encryption Scanner
 * Secrets Manager, KMS, Lambda environment variables, Parameter Store
 */

import type { Finding, ScanOptions } from '../types';
import { logProgress, logError, logDebug, handleScanError } from '../utils';

interface Secret {
  Name: string;
  ARN: string;
  RotationEnabled?: boolean;
  RotationRules?: { AutomaticallyAfterDays?: number };
  KmsKeyId?: string;
  LastAccessedDate?: string;
}

interface SecretDetail {
  ResourcePolicy?: string;
}

interface KMSKey {
  KeyId: string;
}

interface KMSKeyMetadata {
  KeyId: string;
  KeyManager: string;
  KeyState: string;
  KeySpec?: string;
}

interface LambdaFunction {
  FunctionName: string;
  Environment?: { Variables?: Record<string, string> };
  KMSKeyArn?: string;
}

interface SSMParameter {
  Name: string;
  Type: string;
  KeyId?: string;
  LastModifiedDate?: string;
}

interface SNSTopic {
  TopicArn: string;
}

interface PolicyStatement {
  Effect: string;
  Principal?: string | { AWS?: string };
  Condition?: Record<string, unknown>;
}

interface Policy {
  Statement?: PolicyStatement[];
}

interface SecretPattern {
  pattern: RegExp;
  type: string;
}

/**
 * Scan AWS secrets and encryption configuration
 */
export async function scanAWSSecrets(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const config = options.profile ? { profile: options.profile } : {};
    const verbose = options.verbose !== false;

    // 1. Secrets Manager
    logProgress('Scanning Secrets Manager...', verbose);
    const secretsFindings = await scanSecretsManager(config);
    findings.push(...secretsFindings);

    // 2. KMS Keys
    logProgress('Scanning KMS keys...', verbose);
    const kmsFindings = await scanKMSKeys(config);
    findings.push(...kmsFindings);

    // 3. Lambda Environment Variables
    logProgress('Scanning Lambda environment variables...', verbose);
    const lambdaFindings = await scanLambdaSecrets(config);
    findings.push(...lambdaFindings);

    // 4. SSM Parameter Store
    logProgress('Scanning SSM Parameter Store...', verbose);
    const ssmFindings = await scanSSMParameters(config);
    findings.push(...ssmFindings);

    // 5. SNS Topic Policies
    logProgress('Scanning SNS topic policies...', verbose);
    const snsFindings = await scanSNSPolicies(config);
    findings.push(...snsFindings);

    // 6. SQS Queue Policies
    logProgress('Scanning SQS queue policies...', verbose);
    const sqsFindings = await scanSQSPolicies(config);
    findings.push(...sqsFindings);
  } catch (error) {
    const result = handleScanError(error, { provider: 'aws', operation: 'secrets scan' });
    if (result.type === 'sdk_not_installed') {
      logError(result.message);
    } else if (result.shouldThrow) {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Secrets Manager for security issues
 */
async function scanSecretsManager(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { SecretsManagerClient, ListSecretsCommand, DescribeSecretCommand } =
      await import('@aws-sdk/client-secrets-manager');
    const client = new SecretsManagerClient(config);

    let nextToken: string | undefined;
    const secrets: Secret[] = [];

    do {
      const response = (await client.send(
        new ListSecretsCommand({
          NextToken: nextToken,
        })
      )) as { SecretList?: Secret[]; NextToken?: string };
      secrets.push(...(response.SecretList || []));
      nextToken = response.NextToken;
    } while (nextToken);

    for (const secret of secrets) {
      // Check rotation configuration
      if (!secret.RotationEnabled) {
        findings.push({
          id: 'aws-secret-no-rotation',
          severity: 'warning',
          resource: `Secret/${secret.Name}`,
          message: 'Secret does not have automatic rotation enabled',
          recommendation: 'Enable automatic rotation for secrets',
          cis: '2.4',
        });
      } else if (
        // Check rotation frequency
        secret.RotationRules?.AutomaticallyAfterDays &&
        secret.RotationRules.AutomaticallyAfterDays > 90
      ) {
        findings.push({
          id: 'aws-secret-long-rotation',
          severity: 'info',
          resource: `Secret/${secret.Name}`,
          message: `Secret rotates every ${secret.RotationRules.AutomaticallyAfterDays} days`,
          recommendation: 'Consider rotating secrets more frequently (30-90 days)',
        });
      }

      // Check for KMS encryption
      if (!secret.KmsKeyId) {
        findings.push({
          id: 'aws-secret-default-kms',
          severity: 'info',
          resource: `Secret/${secret.Name}`,
          message: 'Secret uses default AWS managed KMS key',
          recommendation: 'Consider using a customer managed KMS key for better control',
        });
      }

      // Check last accessed/rotated
      if (secret.LastAccessedDate) {
        const daysSinceAccess =
          (Date.now() - new Date(secret.LastAccessedDate).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceAccess > 90) {
          findings.push({
            id: 'aws-secret-unused',
            severity: 'info',
            resource: `Secret/${secret.Name}`,
            message: `Secret has not been accessed in ${Math.floor(daysSinceAccess)} days`,
            recommendation: 'Review if this secret is still needed',
          });
        }
      }

      // Get detailed info for resource policy check
      try {
        const detail = (await client.send(
          new DescribeSecretCommand({
            SecretId: secret.ARN,
          })
        )) as SecretDetail;

        // Check resource policy
        if (detail.ResourcePolicy) {
          const policy: Policy = JSON.parse(detail.ResourcePolicy);
          for (const statement of policy.Statement || []) {
            if (
              statement.Principal === '*' ||
              (typeof statement.Principal === 'object' && statement.Principal?.AWS === '*')
            ) {
              if (!statement.Condition) {
                findings.push({
                  id: 'aws-secret-public-policy',
                  severity: 'critical',
                  resource: `Secret/${secret.Name}`,
                  message: 'Secret has a resource policy allowing public access',
                  recommendation: 'Restrict the resource policy to specific principals',
                });
              }
            }
          }
        }
      } catch (e) {
        logDebug(`Failed to get details for secret ${secret.Name}`, e);
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan KMS Keys for security issues
 */
async function scanKMSKeys(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const {
      KMSClient,
      ListKeysCommand,
      DescribeKeyCommand,
      GetKeyPolicyCommand,
      GetKeyRotationStatusCommand,
    } = await import('@aws-sdk/client-kms');
    const client = new KMSClient(config);

    let marker: string | undefined;
    const keys: KMSKey[] = [];

    do {
      const response = (await client.send(
        new ListKeysCommand({
          Marker: marker,
        })
      )) as { Keys?: KMSKey[]; NextMarker?: string };
      keys.push(...(response.Keys || []));
      marker = response.NextMarker;
    } while (marker);

    for (const key of keys) {
      try {
        // Get key details
        const detail = (await client.send(
          new DescribeKeyCommand({
            KeyId: key.KeyId,
          })
        )) as { KeyMetadata?: KMSKeyMetadata };

        const keyMetadata = detail.KeyMetadata;
        if (!keyMetadata) continue;

        // Skip AWS managed keys
        if (keyMetadata.KeyManager === 'AWS') continue;

        // Check key state
        if (keyMetadata.KeyState !== 'Enabled') {
          findings.push({
            id: 'aws-kms-key-not-enabled',
            severity: 'info',
            resource: `KMS/${keyMetadata.KeyId}`,
            message: `KMS key is in ${keyMetadata.KeyState} state`,
            recommendation: 'Review disabled/pending deletion keys',
          });
          continue;
        }

        // Check key rotation (for symmetric keys)
        if (keyMetadata.KeySpec === 'SYMMETRIC_DEFAULT') {
          try {
            const rotation = (await client.send(
              new GetKeyRotationStatusCommand({
                KeyId: key.KeyId,
              })
            )) as { KeyRotationEnabled?: boolean };

            if (!rotation.KeyRotationEnabled) {
              findings.push({
                id: 'aws-kms-no-rotation',
                severity: 'warning',
                resource: `KMS/${keyMetadata.KeyId}`,
                message: 'KMS key does not have automatic rotation enabled',
                recommendation: 'Enable automatic key rotation for symmetric keys',
                cis: '3.8',
              });
            }
          } catch (e) {
            logDebug("Skip if can't check rotation", e);
          }
        }

        // Check key policy
        try {
          const policy = (await client.send(
            new GetKeyPolicyCommand({
              KeyId: key.KeyId,
              PolicyName: 'default',
            })
          )) as { Policy?: string };

          const policyDoc: Policy = JSON.parse(policy.Policy || '{}');

          for (const statement of policyDoc.Statement || []) {
            // Check for * principal
            if (
              statement.Principal === '*' ||
              (typeof statement.Principal === 'object' && statement.Principal?.AWS === '*')
            ) {
              if (!statement.Condition) {
                findings.push({
                  id: 'aws-kms-public-policy',
                  severity: 'critical',
                  resource: `KMS/${keyMetadata.KeyId}`,
                  message: 'KMS key policy allows public access without conditions',
                  recommendation: 'Restrict key policy to specific principals or add conditions',
                });
              }
            }
          }
        } catch (e) {
          logDebug('Operation skipped due to error', e);
        }
      } catch (e) {
        logDebug('Operation skipped due to error', e);
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan Lambda functions for secrets in environment variables
 */
async function scanLambdaSecrets(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Patterns that indicate secrets
  const secretPatterns: SecretPattern[] = [
    { pattern: /password/i, type: 'password' },
    { pattern: /secret/i, type: 'secret' },
    { pattern: /api[_-]?key/i, type: 'api_key' },
    { pattern: /access[_-]?key/i, type: 'access_key' },
    { pattern: /private[_-]?key/i, type: 'private_key' },
    { pattern: /token/i, type: 'token' },
    { pattern: /credential/i, type: 'credential' },
    { pattern: /auth/i, type: 'auth' },
  ];

  // Patterns for actual secret values
  const valuePatterns: SecretPattern[] = [
    { pattern: /^[A-Za-z0-9+/]{40,}={0,2}$/, type: 'base64_secret' },
    { pattern: /^AKIA[0-9A-Z]{16}$/, type: 'aws_access_key' },
    { pattern: /^[a-z0-9]{32,}$/i, type: 'api_key' },
    { pattern: /-----BEGIN.*PRIVATE KEY-----/i, type: 'private_key' },
  ];

  try {
    const { LambdaClient, ListFunctionsCommand } = await import('@aws-sdk/client-lambda');
    const client = new LambdaClient(config);

    let marker: string | undefined;
    const functions: LambdaFunction[] = [];

    do {
      const response = (await client.send(
        new ListFunctionsCommand({
          Marker: marker,
        })
      )) as { Functions?: LambdaFunction[]; NextMarker?: string };
      functions.push(...(response.Functions || []));
      marker = response.NextMarker;
    } while (marker);

    for (const fn of functions) {
      const envVars = fn.Environment?.Variables || {};

      for (const [key, value] of Object.entries(envVars)) {
        // Check if key name suggests a secret
        for (const sp of secretPatterns) {
          if (sp.pattern.test(key)) {
            // Check if value looks like a hardcoded secret
            let isHardcoded = false;
            for (const vp of valuePatterns) {
              if (vp.pattern.test(value)) {
                isHardcoded = true;
                break;
              }
            }

            // Skip if it's a reference to Secrets Manager or SSM
            const isReference =
              value.startsWith('{{resolve:') ||
              value.startsWith('arn:aws:secretsmanager:') ||
              value.startsWith('arn:aws:ssm:');

            if (!isReference) {
              findings.push({
                id: isHardcoded ? 'aws-lambda-hardcoded-secret' : 'aws-lambda-potential-secret',
                severity: isHardcoded ? 'critical' : 'warning',
                resource: `Lambda/${fn.FunctionName}`,
                message: `Environment variable '${key}' may contain ${isHardcoded ? 'a hardcoded secret' : 'sensitive data'}`,
                recommendation: 'Use Secrets Manager or SSM Parameter Store for sensitive values',
                details: {
                  variableName: key,
                  type: sp.type,
                },
              });
            }
            break;
          }
        }
      }

      // Check if Lambda uses KMS for env var encryption
      if (Object.keys(envVars).length > 0 && !fn.KMSKeyArn) {
        findings.push({
          id: 'aws-lambda-default-encryption',
          severity: 'info',
          resource: `Lambda/${fn.FunctionName}`,
          message: 'Lambda uses default AWS managed key for environment variable encryption',
          recommendation: 'Consider using a customer managed KMS key',
        });
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan SSM Parameter Store for security issues
 */
async function scanSSMParameters(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { SSMClient, DescribeParametersCommand } = await import('@aws-sdk/client-ssm');
    const client = new SSMClient(config);

    let nextToken: string | undefined;
    const parameters: SSMParameter[] = [];

    do {
      const response = (await client.send(
        new DescribeParametersCommand({
          NextToken: nextToken,
        })
      )) as { Parameters?: SSMParameter[]; NextToken?: string };
      parameters.push(...(response.Parameters || []));
      nextToken = response.NextToken;
    } while (nextToken);

    for (const param of parameters) {
      // Check for non-SecureString secrets
      if (param.Type === 'String') {
        const name = param.Name.toLowerCase();
        if (
          name.includes('password') ||
          name.includes('secret') ||
          name.includes('key') ||
          name.includes('token')
        ) {
          findings.push({
            id: 'aws-ssm-insecure-parameter',
            severity: 'warning',
            resource: `SSM/${param.Name}`,
            message: 'Parameter with sensitive name is stored as String (not SecureString)',
            recommendation: 'Use SecureString type for sensitive parameters',
          });
        }
      }

      // Check SecureString encryption
      if (param.Type === 'SecureString') {
        if (!param.KeyId || param.KeyId === 'alias/aws/ssm') {
          findings.push({
            id: 'aws-ssm-default-kms',
            severity: 'info',
            resource: `SSM/${param.Name}`,
            message: 'SecureString parameter uses default AWS managed KMS key',
            recommendation: 'Consider using a customer managed KMS key',
          });
        }
      }

      // Check last modified (stale parameters)
      if (param.LastModifiedDate) {
        const daysSinceModified =
          (Date.now() - new Date(param.LastModifiedDate).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceModified > 365) {
          findings.push({
            id: 'aws-ssm-stale-parameter',
            severity: 'info',
            resource: `SSM/${param.Name}`,
            message: `Parameter has not been modified in ${Math.floor(daysSinceModified)} days`,
            recommendation:
              'Review if this parameter is still in use and if the value needs rotation',
          });
        }
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan SNS Topic Policies
 */
async function scanSNSPolicies(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } =
      await import('@aws-sdk/client-sns');
    const client = new SNSClient(config);

    let nextToken: string | undefined;
    const topics: SNSTopic[] = [];

    do {
      const response = (await client.send(
        new ListTopicsCommand({
          NextToken: nextToken,
        })
      )) as { Topics?: SNSTopic[]; NextToken?: string };
      topics.push(...(response.Topics || []));
      nextToken = response.NextToken;
    } while (nextToken);

    for (const topic of topics) {
      try {
        const attrs = (await client.send(
          new GetTopicAttributesCommand({
            TopicArn: topic.TopicArn,
          })
        )) as { Attributes?: { Policy?: string; KmsMasterKeyId?: string } };

        const topicName = topic.TopicArn.split(':').pop() || topic.TopicArn;

        // Check policy
        if (attrs.Attributes?.Policy) {
          const policy: Policy = JSON.parse(attrs.Attributes.Policy);

          for (const statement of policy.Statement || []) {
            if (
              statement.Principal === '*' ||
              (typeof statement.Principal === 'object' && statement.Principal?.AWS === '*')
            ) {
              if (!statement.Condition) {
                findings.push({
                  id: 'aws-sns-public-topic',
                  severity: 'warning',
                  resource: `SNS/${topicName}`,
                  message: 'SNS topic allows public access without conditions',
                  recommendation: 'Restrict topic policy to specific principals or add conditions',
                });
              }
            }
          }
        }

        // Check encryption
        if (!attrs.Attributes?.KmsMasterKeyId) {
          findings.push({
            id: 'aws-sns-no-encryption',
            severity: 'info',
            resource: `SNS/${topicName}`,
            message: 'SNS topic does not have server-side encryption enabled',
            recommendation: 'Enable SSE for sensitive topics',
          });
        }
      } catch (e) {
        logDebug('Operation skipped due to error', e);
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}

/**
 * Scan SQS Queue Policies
 */
async function scanSQSPolicies(config: { profile?: string }): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } =
      await import('@aws-sdk/client-sqs');
    const client = new SQSClient(config);

    let nextToken: string | undefined;
    const queues: string[] = [];

    do {
      const response = (await client.send(
        new ListQueuesCommand({
          NextToken: nextToken,
        })
      )) as { QueueUrls?: string[]; NextToken?: string };
      queues.push(...(response.QueueUrls || []));
      nextToken = response.NextToken;
    } while (nextToken);

    for (const queueUrl of queues) {
      try {
        const attrs = (await client.send(
          new GetQueueAttributesCommand({
            QueueUrl: queueUrl,
            AttributeNames: ['All'],
          })
        )) as {
          Attributes?: { Policy?: string; KmsMasterKeyId?: string; SqsManagedSseEnabled?: string };
        };

        const queueName = queueUrl.split('/').pop() || queueUrl;

        // Check policy
        if (attrs.Attributes?.Policy) {
          const policy: Policy = JSON.parse(attrs.Attributes.Policy);

          for (const statement of policy.Statement || []) {
            if (
              statement.Principal === '*' ||
              (typeof statement.Principal === 'object' && statement.Principal?.AWS === '*')
            ) {
              if (!statement.Condition) {
                findings.push({
                  id: 'aws-sqs-public-queue',
                  severity: 'warning',
                  resource: `SQS/${queueName}`,
                  message: 'SQS queue allows public access without conditions',
                  recommendation: 'Restrict queue policy to specific principals or add conditions',
                });
              }
            }
          }
        }

        // Check encryption
        if (!attrs.Attributes?.KmsMasterKeyId && !attrs.Attributes?.SqsManagedSseEnabled) {
          findings.push({
            id: 'aws-sqs-no-encryption',
            severity: 'info',
            resource: `SQS/${queueName}`,
            message: 'SQS queue does not have server-side encryption enabled',
            recommendation: 'Enable SSE for sensitive queues',
          });
        }
      } catch (e) {
        logDebug('Operation skipped due to error', e);
      }
    }
  } catch (error) {
    const err = error as Error & { name?: string };
    if (err.name !== 'AccessDeniedException') throw error;
  }

  return findings;
}
