# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-08-17

### Added
- ✨ **Custom Rules Engine**: Define your own regex-based security rules in YAML
- 🎯 **Priority System**: Custom rules take priority over built-in rules
- 📊 **Enhanced Output**: Cleaner, more informative security findings
- 🔧 **Flexible Configuration**: Support for custom severity levels and messages
- 📚 **Comprehensive Examples**: 10+ example custom rules in `rules.yml`

### Changed
- �� **Rules Processing**: Improved rule matching and priority handling
- �� **Documentation**: Enhanced README and DESCRIPTION with custom rules guide
- 🧪 **Testing**: Better test coverage and examples

### Fixed
- 🐛 **Duplicate Findings**: Eliminated duplicate security findings
- �� **Rule Matching**: Improved regex pattern matching accuracy

### Breaking Changes
- None - fully backward compatible

## [0.1.0] - 2025-08-16

### Added
- 🚀 **Initial Release**: Basic CI/CD security scanning
- 🔒 **Built-in Security Rules**: AWS keys, API tokens, unpinned actions
- 📁 **Multi-Platform Support**: GitHub Actions, GitLab CI, Jenkins, Azure Pipelines
- 🎨 **Color-coded Output**: Easy-to-read security reports
- 📊 **JSON Output**: Machine-readable results for automation
- 🎯 **Severity Filtering**: Filter results by HIGH, MEDIUM, LOW