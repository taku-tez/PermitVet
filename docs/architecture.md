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
│  src/index.js - Orchestration, multi-cloud coordination     │
│  src/reporter.js - Output formatting (table/json/sarif)     │
│  src/compliance.js - CIS/SOC2/PCI-DSS/NIST mapping          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Layer                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │    AWS      │ │   Azure     │ │    GCP      │           │
│  │ ─────────── │ │ ─────────── │ │ ─────────── │           │
│  │ aws.js      │ │ azure.js    │ │ gcp.js      │           │
│  │ aws-adv.js  │ │ azure-adv.js│ │ gcp-adv.js  │           │
│  │ access-     │ │ azure-      │ │ gcp-org.js  │           │
│  │ analyzer.js │ │ tenant.js   │ │ recommender │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Kubernetes  │ │    OCI      │ │  Privesc    │           │
│  │ ─────────── │ │ ─────────── │ │ ─────────── │           │
│  │ kubernetes  │ │ oracle-     │ │ privesc-    │           │
│  │ .js         │ │ cloud.js    │ │ detector.js │           │
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
│   ├── index.js          # Main orchestrator
│   ├── reporter.js       # Output formatting
│   ├── compliance.js     # Compliance framework mapping
│   └── scanners/
│       ├── aws.js                 # AWS IAM scanner
│       ├── aws-access-analyzer.js # AWS Access Analyzer
│       ├── aws-advanced.js        # AWS SCPs, boundaries
│       ├── azure.js               # Azure RBAC scanner
│       ├── azure-entra.js         # Entra ID (Azure AD)
│       ├── azure-advanced.js      # Management Groups
│       ├── azure-tenant.js        # Tenant-wide scanning
│       ├── gcp.js                 # GCP IAM scanner
│       ├── gcp-advanced.js        # Org policies, hierarchy
│       ├── gcp-organization.js    # Organization-level
│       ├── gcp-recommender.js     # IAM Recommender
│       ├── kubernetes.js          # K8s RBAC scanner
│       ├── oracle-cloud.js        # OCI IAM scanner
│       └── privesc-detector.js    # Privilege escalation
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

The `privesc-detector.js` module implements 70+ attack techniques:

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

1. Create `src/scanners/<provider>.js`
2. Export `scan<Provider>(options)` function
3. Register in `src/index.js`
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
