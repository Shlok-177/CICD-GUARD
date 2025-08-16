# cicd-guard - CI/CD Security Scanner

## What is cicd-guard?

`cicd-guard` is a simple command-line tool that helps developers and DevOps engineers find security problems in their CI/CD pipeline files before they become real security risks.

## What does it do?

Think of it as a security guard for your CI/CD pipelines. It automatically scans your pipeline configuration files and looks for common security mistakes like:

- **Hardcoded secrets** - When someone accidentally puts passwords, API keys, or tokens directly in the code
- **Unpinned versions** - When GitHub Actions use `@main` instead of a specific version (which can be dangerous)
- **Exposed secrets** - When pipeline scripts might accidentally show sensitive information

## Why do you need it?

CI/CD pipelines often handle sensitive information like:
- Database passwords
- API keys
- Access tokens
- Deployment credentials

If these get exposed, hackers could access your systems, databases, or cloud resources. `cicd-guard` catches these problems early, before they reach production.

## How does it work?

1. **Point it at your project** - Tell it where to look
2. **It scans automatically** - Checks all your CI/CD files
3. **Get a clear report** - See exactly what's wrong and where
4. **Fix the issues** - Address security problems before they become threats

## What files does it check?

- GitHub Actions workflows (`.github/workflows/*.yml`)
- GitLab CI configuration (`gitlab-ci.yml`)
- Jenkins pipelines (`Jenkinsfile`)
- Azure DevOps pipelines (`azure-pipelines.yml`)

## Example output

```
🚨 Found 3 security issues:

[HIGH] Hardcoded secret detected found in .github/workflows/deploy.yml (line 15)
   Context: sk_test_123...

[MEDIUM] Unpinned action detected - consider using a specific version or SHA
   Context: Action: actions/checkout@main
```

## Who should use it?

- **Developers** - Check your own projects before pushing
- **DevOps Engineers** - Audit team pipelines for security
- **Security Teams** - Automated security scanning
- **CI/CD Pipeline Reviewers** - Quick security assessment

## Key benefits

✅ **Easy to use** - Simple commands, clear output  
✅ **Fast scanning** - Checks entire projects in seconds  
✅ **Comprehensive** - Covers multiple CI/CD platforms  
✅ **Actionable** - Shows exactly what to fix and where  
✅ **Flexible** - JSON output for automation, severity filtering  

## Simple usage

```bash
# Check current directory
./cicd-guard scan

# Check specific folder
./cicd-guard scan --path .github/workflows

# Get JSON output for automation
./cicd-guard scan --json

# Only show high-severity issues
./cicd-guard scan --severity HIGH
```

## Think of it as...

A security scanner that automatically reviews your CI/CD setup and says "Hey, I found some security problems you should fix!" - like having a security expert review your pipelines, but automated and always available.

---

**Bottom line**: `cicd-guard` helps you catch security mistakes in your CI/CD pipelines before they become security breaches. It's simple, fast, and could save you from a lot of trouble.
