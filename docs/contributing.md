# Contributing to PermitVet

Thank you for your interest in contributing to PermitVet! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and constructive in all interactions.

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- Cloud provider credentials (for testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/taku-tez/PermitVet.git
cd PermitVet

# Install dependencies
npm install

# Run tests
npm test

# Run linter
npm run lint
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
npm test

# Run specific test file
npm test -- --test-name-pattern="AWS"

# Test against real AWS (requires credentials)
npm run test:aws
```

### 4. Commit Your Changes

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat(aws): add SCP inheritance analysis"
git commit -m "fix(gcp): handle pagination in service account list"
git commit -m "docs: update architecture documentation"
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding/updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `ci`: CI/CD changes

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Adding New Scanners

### 1. Create Scanner File

```javascript
// src/scanners/newprovider.js

async function scanNewProvider(options = {}) {
  const findings = [];
  
  // Initialize client
  // Fetch resources
  // Analyze for issues
  
  return findings;
}

module.exports = { scanNewProvider };
```

### 2. Register in Index

```javascript
// src/index.js
const { scanNewProvider } = require('./scanners/newprovider.js');

// Add to scan function switch statement
case 'newprovider':
  findings = await scanNewProvider(options);
  break;
```

### 3. Add CLI Support

```javascript
// bin/permitvet.js
// Add to providers list and help text
```

### 4. Add Documentation

Create `docs/scanners/newprovider.md` with:
- Required permissions
- Supported checks
- Usage examples

### 5. Add Tests

```javascript
// test/scanners.test.js
it('newprovider.js exports scanNewProvider function', () => {
  const { scanNewProvider } = require('../src/scanners/newprovider.js');
  assert.strictEqual(typeof scanNewProvider, 'function');
});
```

## Adding New Checks

### Finding Schema

All findings must follow this schema:

```javascript
{
  id: 'provider-check-name',      // Required: unique identifier
  severity: 'critical',           // Required: critical | warning | info
  resource: 'ResourceType/Name',  // Required: resource identifier
  message: 'Description',         // Required: human-readable message
  recommendation: 'Fix guidance', // Required: remediation steps
  cis: '1.10',                    // Optional: CIS benchmark reference
  details: { }                    // Optional: additional context
}
```

### Severity Guidelines

- **critical**: Immediate security risk, public exposure, privilege escalation
- **warning**: Security best practice violation, potential risk
- **info**: Informational, optimization opportunity

## Testing Guidelines

### Unit Tests

- Test each scanner exports correctly
- Test finding schema compliance
- Mock cloud API responses

### Integration Tests

- Use real credentials in isolated test environment
- Clean up resources after tests
- Don't commit credentials

### Coverage Goals

- Aim for 80%+ code coverage
- All public functions must have tests
- Edge cases (API errors, empty responses) must be covered

## Documentation Guidelines

### Code Comments

- Use JSDoc for all exported functions
- Explain "why" not just "what"
- Keep comments up to date

### Documentation Files

- Use Markdown
- Include code examples
- Keep documentation in sync with code

## Review Process

1. All PRs require at least one review
2. CI must pass (tests, linting)
3. Documentation must be updated
4. Breaking changes require discussion

## Release Process

Maintainers handle releases:

1. Update version in `package.json` and `src/index.js`
2. Update CHANGELOG.md
3. Create git tag
4. Publish to npm

## Questions?

- Open a GitHub Issue
- Check existing documentation
- Review closed PRs for similar changes
