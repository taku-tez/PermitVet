/**
 * Kubernetes RBAC Scanner
 * Scans Kubernetes clusters for RBAC security issues
 * Works with EKS, AKS, GKE, and on-prem clusters
 */

import type { Finding, ScanOptions, Severity } from '../types';

interface RBACRule {
  verbs?: string[];
  resources?: string[];
  apiGroups?: string[];
}

interface ClusterRole {
  metadata?: { name?: string };
  rules?: RBACRule[];
}

interface Subject {
  kind: string;
  name: string;
  namespace?: string;
}

interface ClusterRoleBinding {
  metadata?: { name?: string };
  roleRef?: { name?: string };
  subjects?: Subject[];
}

interface RoleBinding {
  metadata?: { name?: string; namespace?: string };
  roleRef?: { name?: string };
  subjects?: Subject[];
}

interface Role {
  metadata?: { name?: string };
  rules?: RBACRule[];
}

interface Namespace {
  metadata?: { name?: string };
}

interface ServiceAccount {
  metadata?: { name?: string; namespace?: string };
  automountServiceAccountToken?: boolean;
  secrets?: unknown[];
}

interface DangerousRule {
  verbs: string[];
  resources: string[];
  severity: Severity;
  msg: string;
}

interface RBACApi {
  listClusterRole: () => Promise<{ body: { items?: ClusterRole[] } }>;
  listClusterRoleBinding: () => Promise<{ body: { items?: ClusterRoleBinding[] } }>;
  listNamespacedRoleBinding: (namespace: string) => Promise<{ body: { items?: RoleBinding[] } }>;
  listNamespacedRole: (namespace: string) => Promise<{ body: { items?: Role[] } }>;
}

interface CoreApi {
  listNamespace: () => Promise<{ body: { items?: Namespace[] } }>;
  listServiceAccountForAllNamespaces: () => Promise<{ body: { items?: ServiceAccount[] } }>;
}

interface KubeConfig {
  loadFromFile: (path: string) => void;
  loadFromDefault: () => void;
  setCurrentContext: (context: string) => void;
  getCurrentContext: () => string;
  makeApiClient: <T>(api: unknown) => T;
}

/**
 * Scan Kubernetes RBAC for security issues
 */
export async function scanKubernetesRBAC(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const k8s = await import('@kubernetes/client-node');

    // Load kubeconfig
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const kc = new k8s.KubeConfig() as any;

    if (options.kubeconfig) {
      kc.loadFromFile(options.kubeconfig);
    } else if (options.context) {
      kc.loadFromDefault();
      kc.setCurrentContext(options.context);
    } else {
      kc.loadFromDefault();
    }

    const rbacApi = kc.makeApiClient(k8s.RbacAuthorizationV1Api) as unknown as RBACApi;
    const coreApi = kc.makeApiClient(k8s.CoreV1Api) as unknown as CoreApi;

    const context = kc.getCurrentContext();
    console.log(`  Scanning Kubernetes cluster: ${context}...`);

    // 1. Scan ClusterRoles
    console.log('  Scanning ClusterRoles...');
    const clusterRoleFindings = await scanClusterRoles(rbacApi);
    findings.push(...clusterRoleFindings);

    // 2. Scan ClusterRoleBindings
    console.log('  Scanning ClusterRoleBindings...');
    const crbFindings = await scanClusterRoleBindings(rbacApi);
    findings.push(...crbFindings);

    // 3. Scan Roles and RoleBindings per namespace
    console.log('  Scanning namespaced Roles and RoleBindings...');
    const namespacedFindings = await scanNamespacedRBAC(rbacApi, coreApi);
    findings.push(...namespacedFindings);

    // 4. Scan ServiceAccounts
    console.log('  Scanning ServiceAccounts...');
    const saFindings = await scanServiceAccounts(coreApi, rbacApi);
    findings.push(...saFindings);

    // 5. Check for dangerous default configurations
    console.log('  Checking default configurations...');
    const defaultFindings = await checkDefaultConfigs(rbacApi);
    findings.push(...defaultFindings);
  } catch (error) {
    const err = error as Error & { code?: string; statusCode?: number };
    if (err.code === 'MODULE_NOT_FOUND') {
      console.error('Kubernetes client not installed. Run: npm install @kubernetes/client-node');
    } else if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
      findings.push({
        id: 'k8s-connection-failed',
        severity: 'info',
        resource: 'Kubernetes',
        message: 'Unable to connect to Kubernetes cluster',
        recommendation: 'Ensure kubectl is configured and cluster is accessible',
      });
    } else {
      throw error;
    }
  }

  return findings;
}

/**
 * Scan ClusterRoles for dangerous permissions
 */
async function scanClusterRoles(rbacApi: RBACApi): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Dangerous verbs and resources
  const dangerousRules: DangerousRule[] = [
    {
      verbs: ['*'],
      resources: ['*'],
      severity: 'critical',
      msg: 'Cluster admin - all permissions',
    },
    { verbs: ['*'], resources: ['secrets'], severity: 'critical', msg: 'Full access to secrets' },
    {
      verbs: ['create', 'update', 'patch'],
      resources: ['clusterroles', 'clusterrolebindings'],
      severity: 'critical',
      msg: 'Can escalate privileges',
    },
    {
      verbs: ['create', 'update', 'patch'],
      resources: ['roles', 'rolebindings'],
      severity: 'warning',
      msg: 'Can create/modify roles',
    },
    {
      verbs: ['get', 'list'],
      resources: ['secrets'],
      severity: 'warning',
      msg: 'Can read all secrets',
    },
    { verbs: ['create'], resources: ['pods'], severity: 'warning', msg: 'Can create pods' },
    {
      verbs: ['create', 'update', 'patch'],
      resources: ['pods/exec'],
      severity: 'critical',
      msg: 'Can exec into pods',
    },
    {
      verbs: ['create'],
      resources: ['serviceaccounts/token'],
      severity: 'critical',
      msg: 'Can create SA tokens',
    },
    {
      verbs: ['impersonate'],
      resources: ['users', 'groups', 'serviceaccounts'],
      severity: 'critical',
      msg: 'Can impersonate identities',
    },
    {
      verbs: ['escalate'],
      resources: ['clusterroles', 'roles'],
      severity: 'critical',
      msg: 'Can escalate role permissions',
    },
    {
      verbs: ['bind'],
      resources: ['clusterroles', 'roles'],
      severity: 'critical',
      msg: 'Can bind roles to users',
    },
  ];

  try {
    const response = await rbacApi.listClusterRole();

    for (const role of response.body.items || []) {
      // Skip system roles
      if (role.metadata?.name?.startsWith('system:')) continue;

      const rules = role.rules || [];

      for (const rule of rules) {
        const verbs = rule.verbs || [];
        const resources = rule.resources || [];
        const apiGroups = rule.apiGroups || [''];

        for (const dangerous of dangerousRules) {
          const hasVerb = dangerous.verbs.some(v => verbs.includes(v) || verbs.includes('*'));
          const hasResource = dangerous.resources.some(
            r => resources.includes(r) || resources.includes('*')
          );

          if (hasVerb && hasResource) {
            findings.push({
              id: `k8s-clusterrole-${dangerous.severity}`,
              severity: dangerous.severity,
              resource: `ClusterRole/${role.metadata?.name}`,
              message: dangerous.msg,
              recommendation: 'Review if these permissions are necessary. Follow least privilege.',
              details: {
                verbs,
                resources,
                apiGroups,
              },
            });
            break; // One finding per rule
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan ClusterRoleBindings for risky bindings
 */
async function scanClusterRoleBindings(rbacApi: RBACApi): Promise<Finding[]> {
  const findings: Finding[] = [];

  // High-privilege roles to watch
  const criticalRoles = ['cluster-admin', 'admin', 'edit'];

  try {
    const response = await rbacApi.listClusterRoleBinding();

    for (const binding of response.body.items || []) {
      // Skip system bindings
      if (binding.metadata?.name?.startsWith('system:')) continue;

      const roleRef = binding.roleRef;
      const subjects = binding.subjects || [];

      // Check for critical role bindings
      if (roleRef?.name && criticalRoles.includes(roleRef.name)) {
        for (const subject of subjects) {
          // Binding to 'system:anonymous' or 'system:unauthenticated'
          if (subject.name === 'system:anonymous' || subject.name === 'system:unauthenticated') {
            findings.push({
              id: 'k8s-anonymous-cluster-admin',
              severity: 'critical',
              resource: `ClusterRoleBinding/${binding.metadata?.name}`,
              message: `${roleRef.name} bound to anonymous/unauthenticated users`,
              recommendation: 'Remove anonymous access to privileged roles immediately',
            });
          }

          // Binding to all authenticated users
          if (subject.name === 'system:authenticated') {
            findings.push({
              id: 'k8s-all-users-privileged',
              severity: 'warning',
              resource: `ClusterRoleBinding/${binding.metadata?.name}`,
              message: `${roleRef.name} bound to all authenticated users`,
              recommendation: 'Restrict privileged roles to specific users/groups',
            });
          }

          // Default ServiceAccount in any namespace
          if (subject.kind === 'ServiceAccount' && subject.name === 'default') {
            findings.push({
              id: 'k8s-default-sa-privileged',
              severity: 'warning',
              resource: `ClusterRoleBinding/${binding.metadata?.name}`,
              message: `${roleRef.name} bound to default ServiceAccount in ${subject.namespace || 'all namespaces'}`,
              recommendation: 'Create specific ServiceAccounts instead of using default',
            });
          }
        }
      }
    }

    // Count cluster-admin bindings
    const adminBindings =
      response.body.items?.filter(
        b => b.roleRef?.name === 'cluster-admin' && !b.metadata?.name?.startsWith('system:')
      ) || [];

    if (adminBindings.length > 5) {
      findings.push({
        id: 'k8s-too-many-cluster-admins',
        severity: 'warning',
        resource: 'ClusterRoleBindings',
        message: `${adminBindings.length} non-system cluster-admin bindings`,
        recommendation: 'Review and reduce cluster-admin assignments',
      });
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan namespaced Roles and RoleBindings
 */
async function scanNamespacedRBAC(rbacApi: RBACApi, coreApi: CoreApi): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Get all namespaces
    const nsResponse = await coreApi.listNamespace();
    const namespaces =
      nsResponse.body.items?.map(ns => ns.metadata?.name).filter((n): n is string => !!n) || [];

    // Critical namespaces to check more carefully
    const criticalNamespaces = ['kube-system', 'kube-public', 'default'];

    for (const ns of namespaces) {
      // Skip very large number of namespaces
      if (!criticalNamespaces.includes(ns) && namespaces.length > 20) continue;

      // Scan RoleBindings in namespace
      const rbResponse = await rbacApi.listNamespacedRoleBinding(ns);

      for (const binding of rbResponse.body.items || []) {
        const subjects = binding.subjects || [];

        for (const subject of subjects) {
          // Check for anonymous access in critical namespaces
          if (
            criticalNamespaces.includes(ns) &&
            (subject.name === 'system:anonymous' || subject.name === 'system:unauthenticated')
          ) {
            findings.push({
              id: 'k8s-anonymous-in-critical-ns',
              severity: 'critical',
              resource: `RoleBinding/${ns}/${binding.metadata?.name}`,
              message: `Anonymous access granted in ${ns} namespace`,
              recommendation: 'Remove anonymous access from critical namespaces',
            });
          }
        }
      }

      // Check for Roles with secrets access in kube-system
      if (ns === 'kube-system') {
        const roleResponse = await rbacApi.listNamespacedRole(ns);

        for (const role of roleResponse.body.items || []) {
          for (const rule of role.rules || []) {
            if (
              rule.resources?.includes('secrets') &&
              (rule.verbs?.includes('*') || rule.verbs?.includes('get'))
            ) {
              findings.push({
                id: 'k8s-kube-system-secrets-access',
                severity: 'info',
                resource: `Role/${ns}/${role.metadata?.name}`,
                message: 'Role grants secrets access in kube-system',
                recommendation: 'Review if this secrets access is necessary',
              });
            }
          }
        }
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Scan ServiceAccounts
 */
async function scanServiceAccounts(coreApi: CoreApi, rbacApi: RBACApi): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const saResponse = await coreApi.listServiceAccountForAllNamespaces();

    // Check for ServiceAccounts with automounted tokens (pre-1.24 behavior)
    for (const sa of saResponse.body.items || []) {
      // Skip system ServiceAccounts
      if (sa.metadata?.namespace === 'kube-system') continue;

      // Check for secrets associated with SA (long-lived tokens)
      if (sa.secrets && sa.secrets.length > 0) {
        findings.push({
          id: 'k8s-sa-long-lived-token',
          severity: 'info',
          resource: `ServiceAccount/${sa.metadata?.namespace}/${sa.metadata?.name}`,
          message: 'ServiceAccount has long-lived token secrets',
          recommendation: 'Use TokenRequest API for short-lived tokens (K8s 1.24+)',
        });
      }
    }

    // Check default ServiceAccount in each namespace
    const namespaces = new Set(
      saResponse.body.items?.map(sa => sa.metadata?.namespace).filter((n): n is string => !!n) || []
    );

    for (const ns of namespaces) {
      if (ns === 'kube-system' || ns === 'kube-public') continue;

      const defaultSA = saResponse.body.items?.find(
        sa => sa.metadata?.namespace === ns && sa.metadata?.name === 'default'
      );

      if (defaultSA && defaultSA.automountServiceAccountToken !== false) {
        // Check if default SA has any RoleBindings
        const rbResponse = await rbacApi.listNamespacedRoleBinding(ns);
        const defaultBindings = rbResponse.body.items?.filter(rb =>
          rb.subjects?.some(s => s.kind === 'ServiceAccount' && s.name === 'default')
        );

        if (defaultBindings && defaultBindings.length > 0) {
          findings.push({
            id: 'k8s-default-sa-has-bindings',
            severity: 'warning',
            resource: `ServiceAccount/${ns}/default`,
            message: `Default ServiceAccount has ${defaultBindings.length} RoleBindings`,
            recommendation: 'Create specific ServiceAccounts for pods instead of using default',
          });
        }
      }
    }
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}

/**
 * Check default configurations
 */
async function checkDefaultConfigs(rbacApi: RBACApi): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Check for common misconfigurations

    // 1. system:masters group (too powerful)
    const crbResponse = await rbacApi.listClusterRoleBinding();
    const mastersBindings =
      crbResponse.body.items?.filter(crb => crb.subjects?.some(s => s.name === 'system:masters')) ||
      [];

    // system:masters is fine if it's only the default binding
    if (mastersBindings.length > 1) {
      findings.push({
        id: 'k8s-multiple-masters-bindings',
        severity: 'info',
        resource: 'ClusterRoleBindings',
        message: `${mastersBindings.length} bindings reference system:masters group`,
        recommendation: 'Avoid adding more bindings to system:masters',
      });
    }

    // 2. Check for publicly accessible API server (would need network check)
    // This is typically done at infrastructure level

    // 3. Check for deprecated API versions
    // Would need to scan all resources
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode !== 403) throw error;
  }

  return findings;
}
