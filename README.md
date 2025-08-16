# cicd-guard

A CLI tool to scan CI/CD pipeline configuration files for security issues, hardcoded secrets, and best practice violations.

## Features

- **Supported File Types**:
  - GitHub Actions (`.github/workflows/*.yml`)
  - GitLab CI (`gitlab-ci.yml`)
  - Jenkins (`Jenkinsfile`)
  - Azure Pipelines (`azure-pipelines.yml`)

- **Security Checks**:
  - Hardcoded secrets (AWS keys, tokens, passwords)
  - Unpinned versions (GitHub Actions using `@main` or `@master`)
  - Echo statements that might expose secrets
  - Incorrect secret references

## Installation

```bash
# Navigate to the cicd-guard directory
cd cicd-guard

# Install dependencies
go mod tidy

# Build the binary
go build -o cicd-guard
```

## Usage

```bash
# Scan current directory
./cicd-guard scan

# Scan specific path
./cicd-guard scan --path .github/workflows

# Output in JSON format
./cicd-guard scan --json

# Filter by severity
./cicd-guard scan --severity HIGH

# Combine options
./cicd-guard scan --path . --severity HIGH --json
```

## Example Output

```
🚨 Found 3 security issues:

[HIGH] Hardcoded secret detected found in .github/workflows/sample.yml (line 15)
   Context: sk_test_123...

[MEDIUM] Unpinned action detected - consider using a specific version or SHA found in .github/workflows/sample.yml (line 8)
   Context: Action: actions/checkout@main

[MEDIUM] Secret reference exposed via echo - this could leak sensitive data found in .github/workflows/sample.yml (line 18)
   Context: echo "Deploying with token: ${{ secrets.DEPLOY_TOKEN }}"
```

## Project Structure

```
cicd-guard/
├── cmd/           # CLI commands using Cobra
├── scanner/       # File scanning logic
├── rules/         # Security rules and checks
├── types/         # Shared types and constants
├── .github/       # Sample workflow for testing
├── main.go        # Entry point
├── go.mod         # Dependencies
└── README.md      # This file
```

## Security Rules

### High Severity
- **Hardcoded AWS Secret Key**: Detects AWS secret access keys in configuration
- **Hardcoded AWS Access Key**: Detects AWS access key IDs in configuration
- **Hardcoded API Token**: Detects API keys, tokens, and passwords

### Medium Severity
- **Unpinned GitHub Action**: Warns about actions using `@main` or `@master`
- **Echo Secret**: Detects echo statements that might expose secrets
- **Exposed Secret Reference**: Warns about echo statements with secret references

## Development

### Adding New Rules

To add a new security rule:

1. Add the rule definition in `rules/engine.go`
2. Implement the check function in `rules/checks.go`
3. Add tests in `rules/engine_test.go`

### Running Tests

```bash
go test ./...
```

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing
- `github.com/fatih/color` - Colored console output

## License

MIT
