/**
 * AWS Secrets & Encryption Scanner
 * Secrets Manager, KMS, Lambda environment variables, Parameter Store
 */

/**
 * Scan AWS secrets and encryption configuration
 * @param {object} options - Scan options
 * @returns {array} Findings
 */
async function scanAWSSecrets(options = {}) {
  const findings = [];

  try {
    const config = options.profile ? { profile: options.profile } : {};

    // 1. Secrets Manager
    console.log('  Scanning Secrets Manager...');
    const secretsFindings = await scanSecretsManager(config);
    findings.push(...secretsFindings);

    // 2. KMS Keys
    console.log('  Scanning KMS keys...');
    const kmsFindings = await scanKMSKeys(config);
    findings.push(...kmsFindings);

    // 3. Lambda Environment Variables
    console.log('  Scanning Lambda environment variables...');
    const lambdaFindings = await scanLambdaSecrets(config);
    findings.push(...lambdaFindings);

    // 4. SSM Parameter Store
    console.log('  Scanning SSM Parameter Store...');
    const ssmFindings = await scanSSMParameters(config);
    findings.push(...ssmFindings);

    // 5. SNS Topic Policies
    console.log('  Scanning SNS topic policies...');
    const snsFindings = await scanSNSPolicies(config);
    findings.push(...snsFindings);

    // 6. SQS Queue Policies
    console.log('  Scanning SQS queue policies...');
    const sqsFindings = await scanSQSPolicies(config);
    findings.push(...sqsFindings);

  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('AWS SDK not installed.');
    } else if (error.name === 'CredentialsProviderError') {
      // Skip if no credentials
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan Secrets Manager for security issues
 */
async function scanSecretsManager(config) {
  const findings = [];
  
  try {
    const { SecretsManagerClient, ListSecretsCommand, DescribeSecretCommand } = require('@aws-sdk/client-secrets-manager');
    const client = new SecretsManagerClient(config);
    
    let nextToken;
    const secrets = [];
    
    do {
      const response = await client.send(new ListSecretsCommand({
        NextToken: nextToken,
      }));
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
      } else {
        // Check rotation frequency
        if (secret.RotationRules?.AutomaticallyAfterDays > 90) {
          findings.push({
            id: 'aws-secret-long-rotation',
            severity: 'info',
            resource: `Secret/${secret.Name}`,
            message: `Secret rotates every ${secret.RotationRules.AutomaticallyAfterDays} days`,
            recommendation: 'Consider rotating secrets more frequently (30-90 days)',
          });
        }
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
        const daysSinceAccess = (Date.now() - new Date(secret.LastAccessedDate).getTime()) / (1000 * 60 * 60 * 24);
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
        const detail = await client.send(new DescribeSecretCommand({
          SecretId: secret.ARN,
        }));
        
        // Check resource policy
        if (detail.ResourcePolicy) {
          const policy = JSON.parse(detail.ResourcePolicy);
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
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
        // Skip if can't get details
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan KMS Keys for security issues
 */
async function scanKMSKeys(config) {
  const findings = [];
  
  try {
    const { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyPolicyCommand, GetKeyRotationStatusCommand } = require('@aws-sdk/client-kms');
    const client = new KMSClient(config);
    
    let marker;
    const keys = [];
    
    do {
      const response = await client.send(new ListKeysCommand({
        Marker: marker,
      }));
      keys.push(...(response.Keys || []));
      marker = response.NextMarker;
    } while (marker);
    
    for (const key of keys) {
      try {
        // Get key details
        const detail = await client.send(new DescribeKeyCommand({
          KeyId: key.KeyId,
        }));
        
        const keyMetadata = detail.KeyMetadata;
        
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
            const rotation = await client.send(new GetKeyRotationStatusCommand({
              KeyId: key.KeyId,
            }));
            
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
            // Skip if can't check rotation
          }
        }
        
        // Check key policy
        try {
          const policy = await client.send(new GetKeyPolicyCommand({
            KeyId: key.KeyId,
            PolicyName: 'default',
          }));
          
          const policyDoc = JSON.parse(policy.Policy);
          
          for (const statement of policyDoc.Statement || []) {
            // Check for * principal
            if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
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
            
            // Check for dangerous actions
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            if (actions.includes('kms:*')) {
              findings.push({
                id: 'aws-kms-wildcard-action',
                severity: 'warning',
                resource: `KMS/${keyMetadata.KeyId}`,
                message: 'KMS key policy grants all KMS actions',
                recommendation: 'Restrict to specific required actions',
              });
            }
          }
        } catch (e) {
          // Skip if can't get policy
        }
        
      } catch (e) {
        // Skip keys we can't describe
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan Lambda functions for secrets in environment variables
 */
async function scanLambdaSecrets(config) {
  const findings = [];
  
  // Patterns that indicate secrets
  const secretPatterns = [
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
  const valuePatterns = [
    { pattern: /^[A-Za-z0-9+/]{40,}={0,2}$/, type: 'base64_secret' },
    { pattern: /^AKIA[0-9A-Z]{16}$/, type: 'aws_access_key' },
    { pattern: /^[a-z0-9]{32,}$/i, type: 'api_key' },
    { pattern: /-----BEGIN.*PRIVATE KEY-----/i, type: 'private_key' },
  ];
  
  try {
    const { LambdaClient, ListFunctionsCommand, GetFunctionCommand } = require('@aws-sdk/client-lambda');
    const client = new LambdaClient(config);
    
    let marker;
    const functions = [];
    
    do {
      const response = await client.send(new ListFunctionsCommand({
        Marker: marker,
      }));
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
            const isReference = value.startsWith('{{resolve:') || 
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
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan SSM Parameter Store for security issues
 */
async function scanSSMParameters(config) {
  const findings = [];
  
  try {
    const { SSMClient, DescribeParametersCommand, GetParameterCommand } = require('@aws-sdk/client-ssm');
    const client = new SSMClient(config);
    
    let nextToken;
    const parameters = [];
    
    do {
      const response = await client.send(new DescribeParametersCommand({
        NextToken: nextToken,
      }));
      parameters.push(...(response.Parameters || []));
      nextToken = response.NextToken;
    } while (nextToken);
    
    for (const param of parameters) {
      // Check for non-SecureString secrets
      if (param.Type === 'String') {
        const name = param.Name.toLowerCase();
        if (name.includes('password') || name.includes('secret') || 
            name.includes('key') || name.includes('token')) {
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
        const daysSinceModified = (Date.now() - new Date(param.LastModifiedDate).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceModified > 365) {
          findings.push({
            id: 'aws-ssm-stale-parameter',
            severity: 'info',
            resource: `SSM/${param.Name}`,
            message: `Parameter has not been modified in ${Math.floor(daysSinceModified)} days`,
            recommendation: 'Review if this parameter is still in use and if the value needs rotation',
          });
        }
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan SNS Topic Policies
 */
async function scanSNSPolicies(config) {
  const findings = [];
  
  try {
    const { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } = require('@aws-sdk/client-sns');
    const client = new SNSClient(config);
    
    let nextToken;
    const topics = [];
    
    do {
      const response = await client.send(new ListTopicsCommand({
        NextToken: nextToken,
      }));
      topics.push(...(response.Topics || []));
      nextToken = response.NextToken;
    } while (nextToken);
    
    for (const topic of topics) {
      try {
        const attrs = await client.send(new GetTopicAttributesCommand({
          TopicArn: topic.TopicArn,
        }));
        
        const topicName = topic.TopicArn.split(':').pop();
        
        // Check policy
        if (attrs.Attributes?.Policy) {
          const policy = JSON.parse(attrs.Attributes.Policy);
          
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
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
        // Skip topics we can't access
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

/**
 * Scan SQS Queue Policies
 */
async function scanSQSPolicies(config) {
  const findings = [];
  
  try {
    const { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } = require('@aws-sdk/client-sqs');
    const client = new SQSClient(config);
    
    let nextToken;
    const queues = [];
    
    do {
      const response = await client.send(new ListQueuesCommand({
        NextToken: nextToken,
      }));
      queues.push(...(response.QueueUrls || []));
      nextToken = response.NextToken;
    } while (nextToken);
    
    for (const queueUrl of queues) {
      try {
        const attrs = await client.send(new GetQueueAttributesCommand({
          QueueUrl: queueUrl,
          AttributeNames: ['All'],
        }));
        
        const queueName = queueUrl.split('/').pop();
        
        // Check policy
        if (attrs.Attributes?.Policy) {
          const policy = JSON.parse(attrs.Attributes.Policy);
          
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
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
        // Skip queues we can't access
      }
    }
    
  } catch (error) {
    if (error.name !== 'AccessDeniedException') throw error;
  }
  
  return findings;
}

module.exports = { scanAWSSecrets };
