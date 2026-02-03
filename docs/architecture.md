# Architecture

PermitVet is a Pure CIEM (Cloud Infrastructure Entitlement Management) CLI tool designed for multi-cloud IAM security scanning.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  bin/permitvet.js - Command parsing, options handling       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core Layer                             │
│  src/index.ts - Orchestration, multi-cloud coordination     │
│  src/reporter.ts - Output formatting (table/json/sarif)     │
│  src/compliance.ts - CIS/SOC2/PCI-DSS/NIST mapping          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Layer                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │    AWS      │ │   Azure     │ │    GCP      │           │
│  │ ─────────── │ │ ─────────── │ │ ─────────── │           │
│  │ aws.ts      │ │ azure.ts    │ │ gcp.ts      │           │
│  │ aws-advanced│ │ azure-advanc│ │ gcp-advanced│           │
│  │ .ts         │ │ ed.ts       │ │ .ts         │           │
│  │ aws-access- │ │ azure-      │ │ gcp-organi- │           │
│  │ analyzer.ts │ │ tenant.ts   │ │ zation.ts   │           │
│  │             │ │ azure-entra │ │ gcp-recomm- │           │
│  │             │ │ .ts         │ │ ender.ts    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Kubernetes  │ │    OCI      │ │  Privesc    │           │
│  │ ─────────── │ │ ─────────── │ │ ─────────── │           │
│  │ kubernetes  │ │ oracle-     │ │ privesc-    │           │
│  │ .ts         │ │ cloud.ts    │ │ detector.ts │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Cloud Provider SDKs                        │
│  @aws-sdk/* | @azure/* | googleapis | oci-sdk | k8s client │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
permitvet/
├── bin/
│   └── permitvet.js      # CLI entrypoint
├── src/
│   ├── index.ts          # Main orchestrator
│   ├── reporter.ts       # Output formatting
│   ├── compliance.ts     # Compliance framework mapping
│   └── scanners/
│       ├── aws.ts                 # AWS IAM scanner
│       ├── aws-access-analyzer.ts # AWS Access Analyzer
│       ├── aws-advanced.ts        # AWS SCPs, boundaries
│       ├── azure.ts               # Azure RBAC scanner
│       ├── azure-entra.ts         # Entra ID (Azure AD)
│       ├── azure-advanced.ts      # Management Groups
│       ├── azure-tenant.ts        # Tenant-wide scanning
│       ├── gcp.ts                 # GCP IAM scanner
│       ├── gcp-advanced.ts        # Org policies, hierarchy
│       ├── gcp-organization.ts    # Organization-level
│       ├── gcp-recommender.ts     # IAM Recommender
│       ├── kubernetes.ts          # K8s RBAC scanner
│       ├── oracle-cloud.ts        # OCI IAM scanner
│       └── privesc-detector.ts    # Privilege escalation
├── docs/                  # Documentation
├── test/                  # Test suites
└── package.json
```

## Scanner Design

Each scanner follows a consistent pattern:

```javascript
async function scanProvider(options = {}) {
  const findings = [];

  // 1. Initialize SDK client
  const client = initializeClient(options);

  // 2. Fetch IAM resources
  const resources = await fetchResources(client);

  // 3. Analyze for issues
  for (const resource of resources) {
    const issues = analyzeResource(resource);
    findings.push(...issues);
  }

  return findings;
}
```

### Finding Schema

```javascript
{
  id: 'aws-iam-user-mfa',           // Unique identifier
  severity: 'warning',              // critical | warning | info
  resource: 'IAMUser/admin',        // Resource identifier
  message: 'MFA not enabled',       // Human-readable message
  recommendation: 'Enable MFA',     // Remediation guidance
  cis: '1.10',                      // CIS benchmark reference
  details: { ... }                  // Additional context
}
```

## Multi-Cloud Scanning

When `permitvet scan all` is invoked:

1. **Parallel Discovery**: Detect configured providers
2. **Sequential Scanning**: Each provider scanned in sequence
3. **Result Aggregation**: Findings merged with provider tagging
4. **Unified Reporting**: Single output with compliance mapping

## Privilege Escalation Detection

The `privesc-detector.ts` module implements 70+ attack techniques:

- **AWS**: 30+ techniques (CreatePolicyVersion, PassRole+Lambda, etc.)
- **Azure**: 8+ techniques (roleAssignments/write, etc.)
- **GCP**: 10+ techniques (serviceAccountKeys.create, etc.)

Techniques are modeled as:

```javascript
{
  id: 'aws-CreatePolicyVersion',
  permissions: ['iam:CreatePolicyVersion'],
  severity: 'critical',
  mitre: 'T1098',
  message: 'Can create new policy version...',
  recommendation: 'Restrict CreatePolicyVersion...'
}
```

## Compliance Mapping

Findings are automatically mapped to:

- CIS Benchmarks (AWS/Azure/GCP/K8s)
- SOC 2 Type II
- PCI-DSS v4.0
- NIST 800-53
- ISO 27001

## Extension Points

### Adding a New Scanner

1. Create `src/scanners/<provider>.ts`
2. Export `scan<Provider>(options)` function
3. Register in `src/index.ts`
4. Add CLI options in `bin/permitvet.js`

### Adding New Checks

1. Add check function to appropriate scanner
2. Return findings with consistent schema
3. Add CIS/compliance mapping if applicable
4. Add test coverage

## Performance Considerations

- **API Rate Limiting**: Built-in retry with exponential backoff
- **Pagination**: All list operations handle pagination
- **Parallel Execution**: Used within provider (e.g., multi-project GCP)
- **Caching**: Not implemented (planned for v1.0)
