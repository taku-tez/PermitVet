/**
 * SDK Type Definitions
 * Proper types for external SDK clients
 *
 * Note: These types are intentionally loose to accommodate SDK version differences.
 * We use 'unknown' for response data and cast to our internal types at point of use.
 */

// =============================================================================
// Google Cloud SDK Types
// =============================================================================

export interface GCPAuthClient {
  getClient(): Promise<unknown>;
}

export interface GCPIAMClient {
  projects: {
    serviceAccounts: {
      list(params: { name: string }): Promise<{ data: { accounts?: unknown[] } }>;
      keys: {
        list(params: { name: string }): Promise<{ data: { keys?: unknown[] } }>;
      };
      getIamPolicy(params: { resource: string }): Promise<{ data: { bindings?: unknown[] } }>;
    };
    roles: {
      list(params: { parent: string }): Promise<{ data: { roles?: unknown[] } }>;
      get(params: { name: string }): Promise<{ data: unknown }>;
    };
    locations: {
      workloadIdentityPools: {
        list(params: { parent: string }): Promise<{ data: { workloadIdentityPools?: unknown[] } }>;
      };
    };
  };
  organizations: {
    roles: {
      list(params: { parent: string }): Promise<{ data: { roles?: unknown[] } }>;
      get(params: { name: string }): Promise<{ data: unknown }>;
    };
  };
}

export interface GCPCloudResourceManagerClient {
  projects: {
    get(params: { name: string }): Promise<{ data: unknown }>;
    getIamPolicy(params: {
      resource: string;
      requestBody?: unknown;
    }): Promise<{ data: { bindings?: unknown[] } }>;
  };
  folders: {
    list(params: { parent: string }): Promise<{ data: { folders?: unknown[] } }>;
    getIamPolicy(params: {
      resource: string;
      requestBody?: unknown;
    }): Promise<{ data: { bindings?: unknown[] } }>;
  };
  organizations: {
    getIamPolicy(params: {
      resource: string;
      requestBody?: unknown;
    }): Promise<{ data: { bindings?: unknown[] } }>;
  };
}

export interface GCPOrgPolicyClient {
  projects: {
    policies: {
      list(params: { parent: string }): Promise<{ data: { policies?: unknown[] } }>;
    };
  };
}

// =============================================================================
// Azure SDK Types
// =============================================================================

export interface AzureSubscription {
  subscriptionId?: string;
  displayName?: string;
  state?: string;
  tenantId?: string;
}

export interface AzureRoleAssignment {
  id?: string;
  name?: string;
  properties?: {
    roleDefinitionId?: string;
    principalId?: string;
    principalType?: string;
    scope?: string;
  };
}

export interface AzureRoleDefinition {
  id?: string;
  name?: string;
  properties?: {
    roleName?: string;
    type?: string;
    permissions?: Array<{
      actions?: string[];
      notActions?: string[];
      dataActions?: string[];
      notDataActions?: string[];
    }>;
  };
}

export interface AzureDenyAssignment {
  id?: string;
  name?: string;
  properties?: {
    denyAssignmentName?: string;
    principals?: Array<{ id?: string; type?: string }>;
    excludePrincipals?: Array<{ id?: string; type?: string }>;
    permissions?: unknown[];
    scope?: string;
  };
}

// =============================================================================
// AWS SDK Types
// =============================================================================

export interface AWSClientSendable<TInput, TOutput> {
  send(command: TInput): Promise<TOutput>;
}

// =============================================================================
// OCI SDK Types
// =============================================================================

export interface OCIUser {
  id: string;
  name: string;
  email?: string;
  lifecycleState: string;
  isMfaActivated?: boolean;
  timeCreated?: Date;
  inactiveStatus?: number;
}

export interface OCIGroup {
  id: string;
  name: string;
  description?: string;
  lifecycleState: string;
}

export interface OCIPolicy {
  id: string;
  name: string;
  statements: string[];
  compartmentId: string;
}

export interface OCIApiKey {
  keyId: string;
  keyValue?: string;
  fingerprint: string;
  userId: string;
  timeCreated?: Date;
  lifecycleState: string;
}

// =============================================================================
// Kubernetes SDK Types
// =============================================================================

export interface K8sClusterRole {
  metadata?: {
    name?: string;
    namespace?: string;
    annotations?: Record<string, string>;
  };
  rules?: Array<{
    apiGroups?: string[];
    resources?: string[];
    verbs?: string[];
    resourceNames?: string[];
  }>;
}

export interface K8sClusterRoleBinding {
  metadata?: {
    name?: string;
  };
  roleRef?: {
    apiGroup?: string;
    kind?: string;
    name?: string;
  };
  subjects?: Array<{
    apiGroup?: string;
    kind?: string;
    name?: string;
    namespace?: string;
  }>;
}

export interface K8sRoleBinding {
  metadata?: {
    name?: string;
    namespace?: string;
  };
  roleRef?: {
    apiGroup?: string;
    kind?: string;
    name?: string;
  };
  subjects?: Array<{
    apiGroup?: string;
    kind?: string;
    name?: string;
    namespace?: string;
  }>;
}

export interface K8sServiceAccount {
  metadata?: {
    name?: string;
    namespace?: string;
    annotations?: Record<string, string>;
  };
  secrets?: Array<{ name?: string }>;
  automountServiceAccountToken?: boolean;
}
