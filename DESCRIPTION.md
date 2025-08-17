# cicd-guard - CI/CD Security Scanner

## What is cicd-guard?

`cicd-guard` is a powerful command-line tool that helps developers and DevOps engineers find security problems in their CI/CD pipeline files before they become real security risks. **Now with a custom rules engine for ultimate flexibility!**

## What does it do?

Think of it as a security guard for your CI/CD pipelines. It automatically scans your pipeline configuration files and looks for common security mistakes like:

- **Hardcoded secrets** - When someone accidentally puts passwords, API keys, or tokens directly in the code
- **Unpinned versions** - When GitHub Actions use `@main` instead of a specific version (which can be dangerous)
- **Exposed secrets** - When pipeline scripts might accidentally show sensitive information
- **🚀 NEW: Custom security rules** - Define your own security checks that matter to your organization

## Why do you need it?

CI/CD pipelines often handle sensitive information like:
- Database passwords
- API keys
- Access tokens
- Deployment credentials
- Custom business secrets

If these get exposed, hackers could access your systems, databases, or cloud resources. `cicd-guard` catches these problems early, before they reach production.

## 🚀 NEW: Custom Rules Engine

### What's New in v1.0.0

The biggest new feature is the **Custom Rules Engine** that lets you:

- **Create your own security rules** using simple regex patterns
- **Customize severity levels** (HIGH, MEDIUM, LOW) for your organization
- **Add organization-specific checks** that built-in rules don't cover
- **Override built-in rules** when your custom rules are more relevant
- **Share rule sets** across teams and projects

### Example Custom Rules

```yaml
rules:
  - id: CUSTOM_API_KEY
    pattern: "(SECRET_KEY|API_TOKEN)=[A-Za-z0-9_]{20,}"
    severity: HIGH
    message: "Hardcoded API key detected"
    description: "Detects hardcoded API keys in various formats"
```

## How does it work?

1. **Point it at your project** - Tell it where to look
2. **Load custom rules** - Use `--rules your-rules.yml` for custom checks
3. **It scans automatically** - Checks all your CI/CD files with both built-in and custom rules
4. **Get a clear report** - See exactly what's wrong and where
5. **Fix the issues** - Address security problems before they become threats

## What files does it check?

- GitHub Actions workflows (`.github/workflows/*.yml`)
- GitLab CI configuration (`gitlab-ci.yml`)
- Jenkins pipelines (`Jenkinsfile`)
- Azure DevOps pipelines (`azure-pipelines.yml`)
- **Any file you specify** with custom rules

## Example output
🚨 Found 4 security issues:
[HIGH] Hardcoded API key detected found in .github/workflows/deploy.yml (line 27)
Context: echo "SECRET_KEY=sk_test_1234567890abcdef"
[HIGH] Hardcoded API key detected found in .github/workflows/deploy.yml (line 28)
Context: echo "API_TOKEN=ghp_abcdef1234567890"
[HIGH] Hardcoded secret detected found in .github/workflows/deploy.yml (line 29)
Context: Deploying with token: ${{ secrets.DEPLOY_TOKEN }}
[MEDIUM] Unpinned action detected - consider using a specific version or SHA
Context: Action: actions/checkout@main


## Who should use it?

- **Developers** - Check your own projects before pushing
- **DevOps Engineers** - Audit team pipelines for security
- **Security Teams** - Automated security scanning with custom rules
- **CI/CD Pipeline Reviewers** - Quick security assessment
- **Organizations** - Create standardized security rule sets

## Key benefits

✅ **Easy to use** - Simple commands, clear output  
✅ **Fast scanning** - Checks entire projects in seconds  
✅ **Comprehensive** - Covers multiple CI/CD platforms  
✅ **Actionable** - Shows exactly what to fix and where  
✅ **Flexible** - JSON output for automation, severity filtering  
✅ **🚀 NEW: Customizable** - Define your own security rules  
✅ **🚀 NEW: Extensible** - Easy to add organization-specific checks  

## Simple usage

```bash
# Check current directory with built-in rules
./cicd-guard scan

# Check specific folder
./cicd-guard scan --path .github/workflows

# Use custom rules
./cicd-guard scan --rules my-security-rules.yml

# Get JSON output for automation
./cicd-guard scan --json

# Only show high-severity issues
./cicd-guard scan --severity HIGH

# Combine custom rules with other options
./cicd-guard scan --rules rules.yml --severity HIGH --json
```

## Think of it as...

A security scanner that automatically reviews your CI/CD setup and says "Hey, I found some security problems you should fix!" - like having a security expert review your pipelines, but automated, always available, and **now customizable to your specific needs**.

## �� What's New in v1.0.0

- **Custom Rules Engine**: Define your own security rules in YAML
- **Priority System**: Custom rules override built-in rules
- **Enhanced Examples**: More comprehensive rule examples
- **Better Documentation**: Clear guides for custom rule creation
- **Improved Testing**: Better test coverage and examples

---

**Bottom line**: `cicd-guard` helps you catch security mistakes in your CI/CD pipelines before they become security breaches. It's simple, fast, **highly customizable**, and could save you from a lot of trouble.