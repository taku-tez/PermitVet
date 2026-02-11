# 🦅 PermitVet

> **CIEM** (Cloud Infrastructure Entitlement Management) - Pure IAM Security Scanner

[![npm version](https://img.shields.io/npm/v/@permitvet/cli.svg)](https://www.npmjs.com/package/@permitvet/cli)
[![CI](https://github.com/taku-tez/PermitVet/actions/workflows/ci.yml/badge.svg)](https://github.com/taku-tez/PermitVet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

---

## Why PermitVet?

Open-source, self-hosted **CIEM capabilities for free**:

- 🔐 **IAM-focused** — Pure entitlement management, no CSPM noise
- ⚠️ **Privilege escalation detection** — 70+ attack techniques (PMapper/Pacu-level)
- 🔍 **Multi-cloud** — AWS, Azure, GCP, OCI, Kubernetes RBAC
- 🔄 **Native integrations** — Access Analyzer, IAM Recommender
- 📊 **Compliance reporting** — CIS, SOC2, PCI-DSS, NIST, ISO27001

---

## Features

| Feature                     | Description                                               |
| --------------------------- | --------------------------------------------------------- |
| **Pure CIEM**               | 100% focused on IAM/RBAC - no network or storage noise    |
| **Privilege Escalation**    | 70+ attack techniques (30 AWS, 8 Azure, 10 GCP, K8s RBAC) |
| **Unused Access Detection** | AWS Access Analyzer + GCP IAM Recommender integration     |
| **Compliance Mapping**      | Findings mapped to 5 IAM-relevant frameworks              |
| **Multi-Cloud + K8s**       | AWS, Azure, GCP, OCI, Kubernetes in one tool              |
| **Permission Boundaries**   | SCPs, Azure Management Groups, GCP Org Policies           |

---

## Quick Start

```bash
# Install
npm install -g @permitvet/cli

# Generate example config
permitvet --init-config

# Scan AWS
permitvet scan aws

# Scan all configured providers
permitvet scan all

# Generate compliance report
permitvet scan aws --format compliance

# Export SARIF for CI/CD
permitvet scan aws --format sarif --output report.sarif

# Analyze specific permissions for privesc
permitvet privesc aws --permissions iam:CreateUser,iam:AttachUserPolicy
```

---

## Scan Examples

### AWS

```bash
# Basic scan (CIS + best practices)
permitvet scan aws

# With specific profile
permitvet scan aws --profile production

# Full scan with Access Analyzer integration
permitvet scan aws  # Enhanced checks run by default

# Skip enhanced checks (faster)
permitvet scan aws --no-enhanced
```

### Azure

```bash
# Scan subscription
permitvet scan azure --subscription abc123-def456

# Auto-detect subscription
permitvet scan azure

# Tenant-level scan (v0.11.0+)
permitvet scan azure --tenant 00000000-0000-0000-0000-000000000000

# Management group scan with all subscriptions
permitvet scan azure --management-group mg-root --all-subscriptions

# Scan all accessible subscriptions
permitvet scan azure --all-subscriptions
```

### GCP

```bash
# Scan project
permitvet scan gcp --project my-project

# With IAM Recommender insights
permitvet scan gcp --project my-project  # Enhanced by default

# Organization-level scan (v0.10.0+)
permitvet scan gcp --organization 123456789

# Scan all projects in organization
permitvet scan gcp --organization 123456789 --all-projects

# Folder-level scan
permitvet scan gcp --folder 987654321 --all-projects
```

### Multi-Cloud

```bash
# Scan everything
permitvet scan all

# Skip specific provider
permitvet scan all --no-azure
```

---

## Output Formats

| Format            | Use Case                          |
| ----------------- | --------------------------------- |
| `table` (default) | Human-readable terminal output    |
| `json`            | Programmatic processing           |
| `sarif`           | GitHub Advanced Security, VS Code |
| `html`            | Executive reports                 |
| `compliance`      | Compliance summary dashboard      |

```bash
# Generate HTML report
permitvet scan aws --format html --output report.html

# SARIF for GitHub Security tab
permitvet scan aws --format sarif --output permitvet.sarif
```

---

## What It Detects

### CIS Benchmark Compliance

| Provider | Checks                                                                      |
| -------- | --------------------------------------------------------------------------- |
| AWS      | Root access keys, MFA, password policy, unused credentials, Access Analyzer |
| Azure    | Subscription owners, custom roles, classic admins, guest users              |
| GCP      | Primitive roles, service account keys, custom role permissions              |

### Privilege Escalation Paths

**AWS (25+ techniques):**

- `iam:CreatePolicyVersion` - Create malicious policy version
- `iam:PassRole` + `lambda:CreateFunction` - Exec code as any role
- `iam:AttachUserPolicy` - Self-grant admin
- `sts:AssumeRole` with wildcard - Assume any role
- `ssm:SendCommand` - Execute on any EC2

**Azure (8+ techniques):**

- `roleAssignments/write` - Self-grant Owner
- `extensions/write` - VM code execution
- `runCommand/action` - Execute on VMs
- Automation Run As abuse

**GCP (10+ techniques):**

- `setIamPolicy` - Grant self Owner
- `serviceAccountKeys.create` - Create keys for any SA
- `actAs` + `cloudfunctions.create` - Deploy as privileged SA
- `setMetadata` - Inject SSH keys

### Lateral Movement

- Trust relationship analysis
- Service account impersonation chains
- Cross-account access mapping

---

## Compliance Frameworks

Findings are automatically mapped to:

- **CIS Benchmark** — AWS/Azure/GCP Foundations
- **SOC 2** — Trust Service Criteria
- **PCI-DSS v4.0** — Payment Card Industry
- **NIST 800-53** — Federal security controls
- **ISO 27001:2022** — Information security

```bash
# View compliance summary
permitvet scan aws --format compliance

# Output:
# 📋 Compliance Summary:
#   ✅ CIS Benchmark v1.5.0: 85% (17/20)
#   ⚠️ SOC 2 Trust Service Criteria: 67% (4/6)
#   ⚠️ PCI-DSS v4.0: 71% (5/7)
#   ✅ NIST 800-53 Rev. 5: 89% (8/9)
#   ✅ ISO 27001 2022: 86% (6/7)
```

---

## Configuration File

PermitVet supports `.permitvet.yml` for project-level configuration:

```yaml
# .permitvet.yml
exclude:
  - 'IAMUser/service-*' # Exclude service accounts
  - 'ServiceAccount/*-agent@*' # Exclude agent SAs

thresholds:
  critical: 0 # Fail if any critical findings
  warning: 10 # Allow up to 10 warnings

rules:
  aws-iam-user-inline-policy: off # Disable specific rule
  aws-access-key-old:
    severity: info # Downgrade to info

aws:
  profile: default

gcp:
  # project: "..."
  # organization: "..."

output:
  format: table
```

```bash
# Use config from specific path
permitvet scan aws --config ./custom-config.yml

# Generate example config
permitvet --init-config
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run PermitVet
  run: |
    npm install -g @permitvet/cli
    permitvet scan aws --format sarif --output permitvet.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: permitvet.sarif
```

### GitLab CI

```yaml
permitvet:
  script:
    - npm install -g @permitvet/cli
    - permitvet scan aws --format json > permitvet.json
  artifacts:
    reports:
      sast: permitvet.json
```

---

## Programmatic Usage

```javascript
const { scan, analyzePrivesc, getComplianceSummary } = require('@permitvet/cli');

// Scan and get findings
const results = await scan('aws', { profile: 'production' });
console.log(`Found ${results.critical} critical issues`);

// Analyze permissions for privesc
const paths = analyzePrivesc('aws', ['iam:CreateUser', 'iam:AttachUserPolicy']);
console.log(`Detected ${paths.length} escalation paths`);

// Get compliance summary
const compliance = getComplianceSummary(results.findings);
console.log(`CIS Score: ${compliance.cis.score}%`);
```

---

## Roadmap

- [x] AWS IAM scanning (CIS 1.x)
- [x] Azure RBAC scanning
- [x] GCP IAM scanning
- [x] Privilege escalation detection
- [x] AWS Access Analyzer integration
- [x] GCP IAM Recommender integration
- [x] Compliance framework mapping
- [x] SARIF/HTML reporting
- [x] **TypeScript migration** (v0.15.0)
- [x] Configuration file support (v0.12.0)
- [x] **Codebase refactoring** (v0.15.3) - ESLint TypeScript, common utilities
- [ ] Azure Entra ID / PIM integration
- [ ] Policy recommendations engine
- [ ] Attack graph visualization (D3.js)
- [ ] Slack/Teams notifications
- [ ] Terraform/Pulumi remediation

---

## Related Projects

- [AgentVet](https://github.com/taku-tez/agentvet) — Security scanner for AI agent configurations

---

## Development

```bash
# Clone
git clone https://github.com/taku-tez/PermitVet.git
cd PermitVet

# Install
npm install

# Build (TypeScript → JavaScript)
npm run build

# Test (79 tests)
npm test

# Lint
npm run lint
```

> **Note:** Build requires ~4GB heap for TypeScript compilation. This is handled automatically via `NODE_OPTIONS` in the build script.

---

## Contributing

PRs welcome! See [docs/contributing.md](docs/contributing.md).

---

## Part of xxVet Series

xxVet is a collection of 15 focused security CLI tools. See [full catalog](https://www.notion.so/xxVet-CLI-304b1e6bcbc2817abe62d4aecee9914a).

## License

MIT © [tez](https://github.com/taku-tez)
