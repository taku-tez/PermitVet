# 🦅 PermitVet

> Wiz-level Cloud IAM Security Scanner - Because $250K/year for CIEM is insane.

[![CI](https://github.com/taku-tez/PermitVet/actions/workflows/ci.yml/badge.svg)](https://github.com/taku-tez/PermitVet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

---

## Why PermitVet?

Enterprise CIEM tools like Wiz cost $250K+ annually. PermitVet gives you **80% of the value for free**:

- 🔍 **Multi-cloud scanning** — AWS, Azure, GCP in one tool
- ⚠️ **Privilege escalation detection** — PMapper/Pacu-level analysis
- 📊 **Compliance reporting** — CIS, SOC2, PCI-DSS, NIST, ISO27001
- 🔄 **Native integrations** — Access Analyzer, IAM Recommender
- 📄 **Standard outputs** — SARIF, HTML, JSON

---

## Features

| Feature | Description |
|---------|-------------|
| **CIS Benchmark Checks** | 50+ checks across AWS, Azure, GCP |
| **Privilege Escalation** | 30+ known attack techniques detected |
| **Unused Access Detection** | AWS Access Analyzer + GCP IAM Recommender |
| **Compliance Mapping** | Findings mapped to 5 frameworks |
| **Attack Graph** | Visualize who can reach what |
| **Multi-Cloud** | Scan all providers in one command |

---

## Quick Start

```bash
# Install
npm install -g @permitvet/cli

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
```

### GCP

```bash
# Scan project
permitvet scan gcp --project my-project

# With IAM Recommender insights
permitvet scan gcp --project my-project  # Enhanced by default
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

| Format | Use Case |
|--------|----------|
| `table` (default) | Human-readable terminal output |
| `json` | Programmatic processing |
| `sarif` | GitHub Advanced Security, VS Code |
| `html` | Executive reports |
| `compliance` | Compliance summary dashboard |

```bash
# Generate HTML report
permitvet scan aws --format html --output report.html

# SARIF for GitHub Security tab
permitvet scan aws --format sarif --output permitvet.sarif
```

---

## What It Detects

### CIS Benchmark Compliance

| Provider | Checks |
|----------|--------|
| AWS | Root access keys, MFA, password policy, unused credentials, Access Analyzer |
| Azure | Subscription owners, custom roles, classic admins, guest users |
| GCP | Primitive roles, service account keys, custom role permissions |

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
const paths = analyzePrivesc('aws', [
  'iam:CreateUser',
  'iam:AttachUserPolicy',
]);
console.log(`Detected ${paths.length} escalation paths`);

// Get compliance summary
const compliance = getComplianceSummary(results.findings);
console.log(`CIS Score: ${compliance.cis.score}%`);
```

---

## vs. Wiz / Orca / Lacework

| Feature | PermitVet | Wiz | Orca |
|---------|-----------|-----|------|
| Price | **Free** | $250K+/yr | $100K+/yr |
| Multi-cloud | ✅ | ✅ | ✅ |
| CIS Checks | ✅ | ✅ | ✅ |
| Privesc Detection | ✅ | ✅ | ✅ |
| Access Analyzer | ✅ | ✅ | ❌ |
| IAM Recommender | ✅ | ✅ | ❌ |
| SARIF Output | ✅ | ❌ | ❌ |
| Self-hosted | ✅ | ❌ | ❌ |
| Open Source | ✅ | ❌ | ❌ |

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
- [ ] Azure Entra ID / PIM integration
- [ ] Policy recommendations engine
- [ ] Attack graph visualization (D3.js)
- [ ] Slack/Teams notifications
- [ ] Terraform/Pulumi remediation

---

## Related Projects

- [AgentVet](https://github.com/taku-tez/agentvet) — Security scanner for AI agent configurations

---

## Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT © [tez](https://github.com/taku-tez)
