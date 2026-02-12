# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Auto-ZAP itself (not vulnerabilities found by Auto-ZAP in scanned applications), please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. Email the maintainer or use [GitHub's private vulnerability reporting](https://github.com/anubissbe/auto-zap/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Depending on severity, within 1-4 weeks

### Scope

The following are in scope:
- Command injection via crafted project files (`.auto-zap.json`, `package.json`, etc.)
- Credential exposure in logs or reports
- Insecure defaults in ZAP configuration
- Path traversal in report generation

The following are out of scope:
- Vulnerabilities in OWASP ZAP itself (report to [ZAP](https://www.zaproxy.org/docs/team/))
- Vulnerabilities found by Auto-ZAP in scanned applications (those are the intended output)
- Issues requiring physical access to the machine

## Responsible Use

Auto-ZAP is a security testing tool. Only use it on applications you own or have explicit permission to test. Unauthorized security testing may violate laws and regulations.
