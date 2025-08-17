# Release v1.0.0 - Custom Rules Engine

## �� What's New

**cicd-guard v1.0.0** introduces the **Custom Rules Engine**, a powerful new feature that lets you define your own security rules tailored to your organization's needs.

## ✨ Key Features

### Custom Rules Engine
- **Define Custom Rules**: Create regex-based security rules in YAML format
- **Priority System**: Custom rules override built-in rules for the same issues
- **Flexible Severity**: Set custom severity levels (HIGH, MEDIUM, LOW)
- **Organization-Specific**: Add checks that matter to your business

### Enhanced Security
- **Better Detection**: Improved pattern matching for existing rules
- **Cleaner Output**: More organized and informative security reports
- **No Duplicates**: Eliminated duplicate findings between custom and built-in rules

## 🚀 Getting Started

### 1. Install
```bash
# Clone and build
git clone https://github.com/Shlok-177/CICD-GUARD.git
cd cicd-guard
go build -o cicd-guard

# Or install directly
go install github.com/Shlok-177/cicd-guard@latest
```

### 2. Use Built-in Rules
```bash
# Basic scan
./cicd-guard scan

# With options
./cicd-guard scan --path .github/workflows --severity HIGH --json
```

### 3. Use Custom Rules
```bash
# Create custom rules file
cp rules.yml my-rules.yml

# Edit my-rules.yml with your rules

# Scan with custom rules
./cicd-guard scan --rules my-rules.yml
```

## �� Migration Guide

- **Existing Usage**: All existing commands continue to work unchanged
- **New Flag**: `--rules` flag available for custom rules
- **Backward Compatible**: No breaking changes

## 🔧 Custom Rules Examples

See `rules.yml` for 10+ example custom rules including:
- API key detection
- Azure Key Vault best practices
- Docker registry credentials
- Kubernetes secrets
- Slack webhooks
- JWT tokens
- Database connection strings

## 📊 Performance

- **Scan Speed**: Scans entire projects pipelines in seconds
- **Memory Usage**: Efficient memory usage for large codebases
- **Rule Processing**: Fast custom rule compilation and matching

## �� Testing

```bash
# Run all tests
go test ./...

# Test specific packages
go test ./rules
go test ./scanner
```

## 📚 Documentation

- **README.md**: Complete usage guide and examples
- **DESCRIPTION.md**: User-friendly project overview
- **rules.yml**: Example custom rules
- **CHANGELOG.md**: Detailed change history

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**Ready to secure your CI/CD pipelines with custom rules? Get started with cicd-guard v1.0.0! 🚀**