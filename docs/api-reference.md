# API Reference

PermitVet can be used as a library in your Node.js applications.

## Installation

```bash
npm install @permitvet/cli
```

## Basic Usage

```javascript
const { scan, analyzePrivesc, version } = require('@permitvet/cli');

// Scan AWS
const results = await scan('aws', { profile: 'production' });

// Scan all providers
const results = await scan('all');

// Analyze specific permissions
const paths = analyzePrivesc('aws', ['iam:CreateUser', 'iam:AttachUserPolicy']);
```

## Functions

### scan(provider, options)

Scan cloud provider for IAM permission issues.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| provider | string | Provider name: `aws`, `azure`, `gcp`, `kubernetes`, `oci`, `all` |
| options | object | Scan options (see below) |

**Options:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| profile | string | default | AWS profile name |
| subscription | string | env | Azure subscription ID |
| tenant | string | - | Azure tenant ID (tenant-wide scan) |
| managementGroup | string | - | Azure management group ID |
| allSubscriptions | boolean | false | Scan all Azure subscriptions |
| project | string | env | GCP project ID |
| organization | string | - | GCP organization ID |
| folder | string | - | GCP folder ID |
| allProjects | boolean | false | Scan all GCP projects |
| kubeconfig | string | default | Kubernetes config path |
| context | string | current | Kubernetes context |
| enhanced | boolean | true | Run enhanced checks |
| format | string | table | Output format |
| output | string | - | Output file path |
| quiet | boolean | false | Suppress output |

**Returns:** `Promise<object>` - Scan results summary

```javascript
{
  total: 64,
  critical: 0,
  warning: 3,
  info: 61,
  findings: [...] // Array of finding objects
}
```

### analyzePrivesc(provider, permissions, options)

Analyze permissions for privilege escalation paths.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| provider | string | Provider name: `aws`, `azure`, `gcp` |
| permissions | string[] | List of permissions to analyze |
| options | object | Analysis options |

**Returns:** `Array<object>` - Detected privilege escalation paths

```javascript
[
  {
    id: 'aws-CreatePolicyVersion',
    severity: 'critical',
    technique: 'Create Policy Version',
    message: 'Can create new policy version with elevated permissions',
    requiredPermissions: ['iam:CreatePolicyVersion'],
    recommendation: 'Restrict this permission or use IAM boundaries',
    mitre: 'T1098'
  }
]
```

### generateSARIF(findings, options)

Generate SARIF format report.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| findings | object[] | Array of findings |
| options | object | `{ version: string }` |

**Returns:** `object` - SARIF report object

### generateHTMLReport(findings, options)

Generate HTML format report.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| findings | object[] | Array of findings |
| options | object | `{ version: string }` |

**Returns:** `string` - HTML report string

### getComplianceSummary(findings)

Generate compliance framework summary.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| findings | object[] | Array of findings |

**Returns:** `object` - Compliance summary by framework

```javascript
{
  'cis-aws': {
    name: 'CIS AWS Foundations',
    version: '1.5.0',
    score: 85,
    totalControls: 50,
    passedControls: ['1.1', '1.2', ...],
    failedControls: ['1.10', '1.14', ...]
  },
  // ... other frameworks
}
```

## Constants

### AWS_PRIVESC_TECHNIQUES

Array of AWS privilege escalation techniques (30+).

### AZURE_PRIVESC_TECHNIQUES

Array of Azure privilege escalation techniques (8+).

### GCP_PRIVESC_TECHNIQUES

Array of GCP privilege escalation techniques (10+).

### version

Current PermitVet version string.

## Finding Schema

All findings follow this schema:

```typescript
interface Finding {
  id: string;           // Unique identifier (e.g., 'aws-iam-user-mfa')
  severity: 'critical' | 'warning' | 'info';
  resource: string;     // Resource identifier
  message: string;      // Human-readable description
  recommendation: string; // Remediation guidance
  cis?: string;         // CIS benchmark reference
  details?: object;     // Additional context
}
```

## Examples

### Scan with Custom Options

```javascript
const { scan } = require('@permitvet/cli');

async function auditAWS() {
  const results = await scan('aws', {
    profile: 'production',
    enhanced: true,
    format: 'json'
  });
  
  // Filter critical findings
  const critical = results.findings.filter(f => f.severity === 'critical');
  
  if (critical.length > 0) {
    console.error(`Found ${critical.length} critical issues!`);
    process.exit(1);
  }
}
```

### GCP Organization Scan

```javascript
const { scan } = require('@permitvet/cli');

async function auditGCPOrg() {
  const results = await scan('gcp', {
    organization: '123456789',
    allProjects: true
  });
  
  console.log(`Scanned ${results.total} findings`);
}
```

### CI/CD Integration

```javascript
const { scan, generateSARIF } = require('@permitvet/cli');
const fs = require('fs');

async function ciScan() {
  const results = await scan('all', { quiet: true });
  
  // Generate SARIF for GitHub Security
  const sarif = generateSARIF(results.findings, { version: '0.11.0' });
  fs.writeFileSync('permitvet.sarif', JSON.stringify(sarif, null, 2));
  
  // Exit with error if critical findings
  process.exit(results.critical > 0 ? 1 : 0);
}
```
