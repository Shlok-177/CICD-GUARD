# cicd-guard

A CLI tool to scan CI/CD pipeline configuration files for security issues, hardcoded secrets, and best practice violations.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.0-green.svg)](https://github.com/Shlok-177/cicd-guard/releases)

> **🔒 Secure your CI/CD pipelines with automated security scanning**

## ✨ Features

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

- **🚀 NEW in v1.0.0 - Custom Rules Engine**:
  - Define your own regex-based security rules in YAML
  - Custom rules take priority over built-in rules
  - Easy to extend and customize for your organization
  - Support for custom severity levels and messages

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cicd-guard.git
cd cicd-guard

# Install dependencies
go mod tidy

# Build the binary
go build -o cicd-guard

# Or install directly with Go
go install github.com/Shlok-177/cicd-guard@latest
```

### Basic Usage

```bash
# Scan current directory
./cicd-guard scan

# Scan specific path
./cicd-guard scan --path .github/workflows

# Output in JSON format
./cicd-guard scan --json

# Filter by severity
./cicd-guard scan --severity HIGH

# Use custom rules
./cicd-guard scan --rules custom-rules.yml

# Combine options
./cicd-guard scan --path . --severity HIGH --json --rules rules.yml
```

## 📋 Example Output

```bash
🚨 Found 4 security issues:

[HIGH] Hardcoded API key detected found in .github/workflows/sample.yml (line 27)
   Context: echo "SECRET_KEY=sk_test_1234567890abcdef"

[HIGH] Hardcoded API key detected found in .github/workflows/sample.yml (line 28)
   Context: echo "API_TOKEN=ghp_abcdef1234567890"

[HIGH] Hardcoded secret detected found in .github/workflows/sample.yml (line 29)
   Context: Deploying with token: ${{ secrets.DEPLOY_TOKEN }}

[MEDIUM] Unpinned action detected - consider using a specific version or SHA found in .github/workflows/sample.yml (line 13)
   Context: Action: actions/checkout@main
```

## 🔧 Custom Rules Engine

### Creating Custom Rules

Create a `rules.yml` file with your custom security rules:

```yaml
rules:
  - id: CUSTOM_API_KEY
    pattern: "(SECRET_KEY|API_TOKEN)=[A-Za-z0-9_]{20,}"
    severity: HIGH
    message: "Hardcoded API key detected"
    description: "Detects hardcoded API keys in various formats"
    
  - id: AZURE_KEYVAULT
    pattern: "AZURE_KEYVAULT_URI"
    severity: MEDIUM
    message: "Consider using Azure Key Vault for secrets"
    description: "Encourages use of Azure Key Vault for secret management"
```

### Using Custom Rules

```bash
# Load custom rules
./cicd-guard scan --rules rules.yml

# Custom rules take priority over built-in rules
./cicd-guard scan --rules rules.yml --severity HIGH
```


## � Project Structure

```

cicd-guard/
├── cmd/           # CLI commands using Cobra
├── scanner/       # File scanning logic
├── rules/         # Security rules and checks
├── types/         # Shared types and constants
├── .github/       # Sample workflow for testing
├── rules.yml      # Example custom rules
├── main.go        # Entry point
├── go.mod         # Dependencies
└── README.md      # This file

```


## 🛡️ Security Rules

### Built-in Rules

#### High Severity
- **Hardcoded AWS Secret Key**: Detects AWS secret access keys in configuration
- **Hardcoded AWS Access Key**: Detects AWS access key IDs in configuration
- **Hardcoded API Token**: Detects API keys, tokens, and passwords

#### Medium Severity
- **Unpinned GitHub Action**: Warns about actions using `@main` or `@master`
- **Echo Secret**: Detects echo statements that might expose secrets
- **Exposed Secret Reference**: Warns about echo statements with secret references

### Custom Rules Examples

The included `rules.yml` provides examples for:
- API key detection
- Azure Key Vault best practices
- Docker registry credentials
- Kubernetes secrets
- Slack webhooks
- JWT tokens
- Database connection strings
- Git credentials
- Environment variable dumps

## 🧪 Development

### Adding New Built-in Rules

To add a new security rule:

1. Add the rule definition in `rules/engine.go`
2. Implement the check function in `rules/checks.go`
3. Add tests in `rules/engine_test.go`

### Running Tests

```bash
go test ./...
```

### Building for Release

```bash
# Build for current platform
go build -o cicd-guard
```

## 📦 Dependencies

- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing for custom rules
- `github.com/fatih/color` - Colored console output

## 🚀 Release v1.0.0

### What's New
- ✨ **Custom Rules Engine**: Define your own security rules in YAML
- 🔒 **Enhanced Security**: More comprehensive secret detection
- 🎯 **Priority System**: Custom rules override built-in rules
- � **Better Output**: Cleaner, more informative results
- � **Improved Testing**: Better test coverage and examples

### Breaking Changes
- None - fully backward compatible

### Migration Guide
- Existing usage continues to work unchanged
- New `--rules` flag available for custom rules
- Custom rules take priority when specified

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## � Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for the CLI framework
- Inspired by the need for better CI/CD security practices
- Community feedback and contributions

---

**Made with ❤️ for better CI/CD security**
