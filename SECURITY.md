# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please report it responsibly. **Do not open a public issue.**

Email **security@blu3raven.com** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

## Security Practices

- All sensitive data (tokens, TOTP secrets) is encrypted at rest using Fernet
- JWT-based authentication with role-based access control
- Rate limiting on scan initiation, runner registration, and AI review endpoints
- Git clone restricted to HTTPS only
- File path validation against directory traversal
- SSRF validation on container registry hosts
- Runner service accounts scoped to minimal S3 permissions
- No telemetry or external data transmission

## Disclosure Policy

We follow coordinated disclosure. We ask that you give us reasonable time to address the issue before making it public. We're happy to credit researchers who report valid vulnerabilities.
