# cicd-guard

A CLI tool to scan CI/CD pipeline configuration files for security issues, hardcoded secrets, and best practice violations.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.1-green.svg)](https://github.com/Shlok-177/cicd-guard/releases)

> **🔒 Secure your CI/CD pipelines with automated security scanning**

## ✨ Features

- **AI-Powered Pipeline Analysis**:
  - Utilizes Gemini Pro API for intelligent logical and security analysis.
  - Detects security vulnerabilities, logical errors, best practice violations, and provides optimization suggestions.
  - Supports interactive file selection, file exclusion, and severity filtering.
  - Outputs results in a user-friendly format or raw JSON.

- **API Key Management**:
  - Securely stores and manages Gemini API keys locally (`~/.cicd-guard/config.json`).
  - Provides commands to set, remove, and check the status of the stored API key.

- **Flexible File Scanning**:
  - Recursively scan directories for pipeline files.
  - Scan single files.
  - Automatically discovers `*.yml`, `*.yaml`, `Jenkinsfile`, and files with `pipeline` in their name.

- **Security Checks**:
  - Hardcoded secrets (AWS keys, tokens, passwords)
  - Unpinned versions (GitHub Actions using `@main` or `@master`)
  - Echo statements that might expose secrets
  - Incorrect secret references

- **Custom Rules Engine**:
  - Define your own regex-based security rules in YAML
  - Custom rules take priority over built-in rules
  - Easy to extend and customize for your organization
  - Support for custom severity levels and messages

- **🚀 NEW in v1.0.1 - Context-Aware Secret Detection**:
  - Detects real secrets like AWS keys, tokens, and credentials
  - Reduces false positives by ignoring test values, comments, and non-sensitive strings    
  - Supports `.cicd-guard-ignore` for excluding files
  - New flag: `--secrets-only` to run secret scanning exclusively

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
# Scan the current directory recursively (interactive mode)
# This will list detected pipeline files and prompt for selection.
./cicd-guard scan

# Scan all detected pipeline files automatically
./cicd-guard scan --all

# Scan a specific directory
./cicd-guard scan --path ci/

# Scan a single file
./cicd-guard scan --path ci/build.yml

# Exclude specific files by index (e.g., exclude the 2nd and 4th detected files)
./cicd-guard scan --exclude 2,4

# Exclude specific files by filename (e.g., exclude 'azure-ci/deploy.yaml' and 'gitlab/.gitlab-ci.yml')
./cicd-guard scan --exclude azure-ci/deploy.yaml,gitlab/.gitlab-ci.yml

# Output in JSON format
./cicd-guard scan --json

# Filter by severity
./cicd-guard scan --severity HIGH

# Use custom rules
./cicd-guard scan --rules custom-rules.yml

# Run only secret detection
./cicd-guard scan --secrets-only

# Combine options (e.g., scan all files in a directory, exclude one, and output JSON)
./cicd-guard scan --path . --all --exclude custom/ci-pipeline.yaml --json
```

### AI Scan Usage

```bash
# Perform an AI-based scan (interactive mode)
# This will list detected pipeline files and prompt for selection.
./cicd-guard ai-scan

# AI scan all detected pipeline files automatically
./cicd-guard ai-scan --all

# AI scan a specific directory
./cicd-guard ai-scan --path ci/

# AI scan a single file
./cicd-guard ai-scan --path ci/build.yml

# Exclude specific files from AI scan
./cicd-guard ai-scan --exclude rules.yml,test.yml

# Filter AI scan results by severity
./cicd-guard ai-scan --severity HIGH

# Output raw Gemini JSON response
./cicd-guard ai-scan --json

# Show verbose AI scan output (includes suggestions)
./cicd-guard ai-scan --verbose

# Combine options (e.g., AI scan all files, exclude one, filter by severity, and show verbose output)
./cicd-guard ai-scan --all --exclude custom/ci-pipeline.yaml --severity MEDIUM --verbose
```

### Configuration Management

```bash
# Set or update your Gemini API key
./cicd-guard config set-api-key

# Check if a Gemini API key is currently stored
./cicd-guard config show-api-key

# Remove the stored Gemini API key
./cicd-guard config remove-api-key
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
- **Hardcoded AWS Secret Key**: Detects AWS secret access keys in configuration.
- **Hardcoded AWS Access Key**: Detects AWS access key IDs in configuration.
- **Hardcoded API Token**: Detects API keys, tokens, and passwords.
- **SSH Private Key**: Detects SSH private keys.
- **Azure Connection String**: Detects Azure connection strings.
- **GitHub Token**: Detects GitHub tokens.
- **Generic High-Entropy Secret**: Detects generic high-entropy secrets.
- **Azure Pipelines Inline Secret**: Detects inline secrets in Azure Pipelines YAML.
- **Jenkins Plaintext withCredentials**: Warns on 'withCredentials' using plaintext in Jenkins.
- **Jenkins Hardcoded Password in Groovy**: Detects hardcoded passwords in Jenkins Groovy DSL.
- **GitLab CI Insecure Curl to Bash Pipe**: Detects insecure patterns like 'curl ... | bash' in GitLab CI scripts.
- **Azure Pipelines Allow Scripts To Access OAuth Token**: Detects 'allowScriptsToAccessOAuthToken: true', which can lead to token exposure.
- **Azure Pipelines System.AccessToken Usage**: Detects direct usage of System.AccessToken in Azure Pipelines scripts.
- **Jenkins Unsafe Shell Step**: Detects potentially unsafe shell steps (sh, bat) in Jenkins pipelines.
- **GitHub Actions Write-All Permissions**: Warns if 'permissions: write-all' is used in GitHub Actions.
- **GitHub Actions Pull Request Target without Permissions**: Warns if 'pull_request_target' trigger is used without explicitly limiting permissions.

#### Medium Severity
- **Unpinned GitHub Action**: Warns about actions using `@main` or `@master`.
- **Echo Secret**: Detects echo statements that might expose secrets.
- **Exposed Secret Reference**: Warns about echo statements with secret references.
- **GitLab CI Hardcoded Master Branch**: Warns if default branch is hardcoded as 'master' instead of 'main'.
- **GitLab CI Job Without Only/Except**: Detects GitLab CI jobs without 'only/except' for insecure triggering.
- **Azure Pipelines Unpinned VM Image**: Detects unpinned VM images in Azure Pipelines (e.g., 'windows-latest').
- **GitLab CI Allow Failure True**: Warns if 'allow_failure: true' is set, which can hide critical security scan failures.
- **Jenkins Input Step Without Timeout**: Warns on 'input' steps in Jenkins pipelines without a defined timeout.
- **GitHub Actions Sudo Run**: Detects 'sudo' usage in GitHub Actions 'run' steps.

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
