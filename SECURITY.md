# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within Valkyrie-V, please send an e-mail to the security team. All security vulnerabilities should be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Requirements

1. **Memory Safety**: All code must be memory-safe. We use Rust for this reason.
2. **No Unsafe Code**: Minimize use of `unsafe` blocks. Each must be documented.
3. **Input Validation**: All guest input must be validated.
4. **Privilege Separation**: Hypervisor must run with minimal privileges.
5. **Audit Trail**: All security-relevant events must be logged.

## Security Features

- **SMEP**: Supervisor Mode Execution Protection
- **SMAP**: Supervisor Mode Access Prevention
- **NX**: No-Execute bit
- **EPT**: Extended Page Tables for memory isolation
- **VT-x**: Hardware virtualization

## Disclosure Policy

- We follow a **coordinated disclosure** process
- We aim to respond to reports within 48 hours
- We aim to release fixes within 30 days
- We credit researchers (with permission)
