# Contributing to Auto-ZAP

Thank you for your interest in contributing to Auto-ZAP! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/auto-zap.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Push and open a pull request

## Development Setup

### Windows (PowerShell)
```powershell
# Install prerequisites
winget install ZAP.ZAP
winget install EclipseAdoptium.Temurin.17.JRE

# Run the script
.\auto-zap.ps1 --help
```

### Linux (Bash)
```bash
# Requires Docker, curl, jq
chmod +x auto-zap.sh
./auto-zap.sh --help
```

## Code Style

### PowerShell (`auto-zap.ps1`)
- Follow [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) rules
- Excluded rules: `PSAvoidUsingWriteHost`, `PSUseShouldProcessForStateChangingFunctions`, `PSAvoidUsingInvokeExpression`

### Bash (`auto-zap.sh`)
- Must pass [ShellCheck](https://www.shellcheck.net/) at warning severity
- Use `bash -n` to verify syntax before committing

### YAML
- `action.yml` and workflow files must be valid YAML

## CI Pipeline

All pull requests are validated by the CI pipeline which checks:

- **Lint & Syntax**: ShellCheck, PSScriptAnalyzer, YAML validation
- **Test Linux**: Help flag and error handling behavior
- **Test Windows**: PowerShell syntax and parameter validation
- **Test Action**: Full integration test with Docker ZAP
- **Documentation**: README completeness and link validation
- **Feature Parity**: Ensures `.ps1` and `.sh` have matching capabilities
- **Security**: Scans for hardcoded secrets and dangerous patterns

All jobs must pass before a PR can be merged.

## Adding Framework Support

To add a new framework:

1. **PowerShell** (`auto-zap.ps1`): Add detection logic in the `Detect-AppFramework` function
2. **Bash** (`auto-zap.sh`): Add matching detection in the framework detection section
3. **README**: Add the framework to the Supported Frameworks table
4. **Feature Parity**: The CI will verify both scripts detect the same frameworks

## Reporting Bugs

Use the [bug report template](https://github.com/anubissbe/auto-zap/issues/new?template=bug_report.yml) and include:
- OS and version
- Framework being scanned
- Full console output
- Steps to reproduce

## Suggesting Features

Use the [feature request template](https://github.com/anubissbe/auto-zap/issues/new?template=feature_request.yml).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
