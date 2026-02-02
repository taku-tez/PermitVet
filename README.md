# 🦅 PermitVet

> Cloud IAM Permission Auditor - Vet your entitlements before they become liabilities.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Why PermitVet?

Cloud environments accumulate excessive permissions over time. Unused roles, overly permissive policies, and forgotten service accounts create attack surfaces that adversaries exploit.

**PermitVet scans your cloud IAM configurations to find and fix permission risks.**

---

## Features

- 🔍 **Permission Discovery** — Inventory all IAM users, roles, and policies
- ⚠️ **Over-Privilege Detection** — Find unused or excessive permissions
- 📊 **Risk Scoring** — Prioritize fixes by blast radius
- 🔄 **Least Privilege Recommendations** — Suggest right-sized policies
- 🌐 **Multi-Cloud Support** — AWS, Azure, GCP

---

## Installation

```bash
npm install -g @permitvet/cli
```

Or run directly with npx:

```bash
npx @permitvet/cli scan
```

---

## Usage

### Scan AWS IAM

```bash
# Scan current AWS account
permitvet scan aws

# Scan with specific profile
permitvet scan aws --profile production

# Output to JSON
permitvet scan aws --format json --output report.json
```

### Scan Azure

```bash
permitvet scan azure --subscription <subscription-id>
```

### Scan GCP

```bash
permitvet scan gcp --project <project-id>
```

---

## What It Detects

| Category | Examples |
|----------|----------|
| **Unused Permissions** | Roles not used in 90+ days |
| **Over-Privileged** | Admin access where read-only suffices |
| **Dangerous Policies** | `*:*` wildcards, privilege escalation paths |
| **Service Account Risks** | Long-lived keys, external access |
| **Cross-Account Risks** | Overly permissive trust policies |

---

## Roadmap

- [ ] AWS IAM scanning
- [ ] Azure RBAC scanning
- [ ] GCP IAM scanning
- [ ] Privilege escalation path detection
- [ ] Policy recommendations
- [ ] CI/CD integration
- [ ] Securify dashboard integration

---

## Related Projects

- [AgentVet](https://github.com/taku-tez/agentvet) — Security scanner for AI agent skills

---

## License

MIT
