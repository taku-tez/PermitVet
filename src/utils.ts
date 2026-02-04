/**
 * PermitVet Common Utilities
 * Shared helpers for scanners to reduce code duplication
 */

import type { Finding, Severity } from './types';

/**
 * Create a Finding object with consistent structure
 */
export function createFinding(
  id: string,
  resource: string,
  message: string,
  severity: Severity,
  recommendation: string,
  options?: { cis?: string; details?: Record<string, unknown> }
): Finding {
  const finding: Finding = {
    id,
    severity,
    resource,
    message,
    recommendation,
  };

  if (options?.cis) {
    finding.cis = options.cis;
  }

  if (options?.details) {
    finding.details = options.details;
  }

  return finding;
}

/**
 * Error type classification for cloud SDKs
 */
export type ScanErrorType =
  | 'sdk_not_installed'
  | 'auth_failed'
  | 'permission_denied'
  | 'not_found'
  | 'unknown';

/**
 * Context for error handling
 */
export interface ScanErrorContext {
  provider: 'aws' | 'azure' | 'gcp' | 'kubernetes' | 'oci';
  operation?: string;
}

/**
 * Result of error handling
 */
export interface ScanErrorResult {
  type: ScanErrorType;
  message: string;
  shouldThrow: boolean;
}

/**
 * Handle scan errors consistently across providers
 * Returns error type and whether the error should be re-thrown
 */
export function handleScanError(error: unknown, context: ScanErrorContext): ScanErrorResult {
  const err = error as Error & { code?: string | number; name?: string };
  const { provider, operation } = context;

  // SDK not installed
  if (err.code === 'MODULE_NOT_FOUND' || err.message?.includes('Cannot find module')) {
    const sdkMessages: Record<string, string> = {
      aws: 'AWS SDK not installed. Run: npm install @aws-sdk/client-iam',
      azure:
        'Azure SDK not installed. Run: npm install @azure/identity @azure/arm-authorization @azure/arm-subscriptions',
      gcp: 'GCP SDK not installed. Run: npm install googleapis',
      kubernetes: 'Kubernetes client not installed. Run: npm install @kubernetes/client-node',
      oci: 'OCI SDK not installed. Run: npm install oci-sdk',
    };

    return {
      type: 'sdk_not_installed',
      message: sdkMessages[provider] || 'SDK not installed',
      shouldThrow: false,
    };
  }

  // Authentication failures
  const authErrors = [
    'CredentialsProviderError',
    'CredentialUnavailableError',
    'AuthenticationError',
    'AADSTS',
    'UnauthorizedError',
  ];

  const authCodes = [401, 'EAUTH', 'NO_CREDENTIALS'];

  if (
    authErrors.some(e => err.name?.includes(e) || err.message?.includes(e)) ||
    authCodes.includes(err.code as string | number)
  ) {
    const authMessages: Record<string, string> = {
      aws: 'AWS credentials not configured. Run: aws configure',
      azure: 'Azure authentication failed. Run: az login',
      gcp: 'GCP authentication failed. Run: gcloud auth application-default login',
      kubernetes: 'Kubernetes authentication failed. Check your kubeconfig',
      oci: 'OCI authentication failed. Check your config file at ~/.oci/config',
    };

    return {
      type: 'auth_failed',
      message: authMessages[provider] || 'Authentication failed',
      shouldThrow: false,
    };
  }

  // Permission denied
  if (err.code === 403 || err.code === 'AccessDenied' || err.name === 'AccessDeniedError') {
    const opText = operation ? ` for ${operation}` : '';
    return {
      type: 'permission_denied',
      message: `Permission denied${opText}. Check IAM permissions.`,
      shouldThrow: false,
    };
  }

  // Resource not found - usually ignorable
  if (err.code === 404 || err.code === 'ResourceNotFound' || err.name === 'NotFoundException') {
    return {
      type: 'not_found',
      message: `Resource not found${operation ? `: ${operation}` : ''}`,
      shouldThrow: false,
    };
  }

  // Unknown error - should be re-thrown
  return {
    type: 'unknown',
    message: err.message || 'Unknown error occurred',
    shouldThrow: true,
  };
}

/**
 * Log progress message (respects verbose flag)
 * Uses consistent indentation for scanner output
 */
export function logProgress(message: string, verbose: boolean = true): void {
  if (verbose) {
    console.log(`  ${message}`);
  }
}

/**
 * Log error message to stderr
 */
export function logError(message: string): void {
  console.error(message);
}

/**
 * Log debug message (only when DEBUG=permitvet or verbose mode)
 * Use this for gracefully handled errors that shouldn't stop execution
 */
export function logDebug(message: string, error?: unknown): void {
  if (process.env.DEBUG?.includes('permitvet') || process.env.PERMITVET_VERBOSE) {
    const errMsg = error instanceof Error ? `: ${error.message}` : '';
    console.error(`[DEBUG] ${message}${errMsg}`);
  }
}

/**
 * Common severity thresholds for different issue types
 */
export const SeverityThresholds = {
  /** Issues that allow privilege escalation or data exfiltration */
  CRITICAL: 'critical' as Severity,
  /** Issues that weaken security posture but don't directly enable attacks */
  WARNING: 'warning' as Severity,
  /** Best practice recommendations */
  INFO: 'info' as Severity,
};

/**
 * Check if a permission matches any of the dangerous patterns
 */
export function matchesDangerousPattern(
  permission: string,
  patterns: Array<{ pattern: RegExp; id: string; severity: Severity; msg: string }>
): { id: string; severity: Severity; msg: string } | null {
  for (const { pattern, id, severity, msg } of patterns) {
    if (pattern.test(permission)) {
      return { id, severity, msg };
    }
  }
  return null;
}

/**
 * Format resource identifier consistently
 */
export function formatResource(type: string, name: string, namespace?: string): string {
  if (namespace) {
    return `${type}/${namespace}/${name}`;
  }
  return `${type}/${name}`;
}
