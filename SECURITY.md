# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| < latest | No       |

Only the latest release receives security updates. We recommend always running the most recent version.

## Reporting a Vulnerability

If you discover a security vulnerability in BouncerFox CLI, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@bouncerfox.dev** with:

- A description of the vulnerability
- Steps to reproduce
- The affected version(s)
- Any potential impact assessment

You should receive an acknowledgement within 48 hours. We aim to provide a fix or mitigation within 7 days of confirmed vulnerabilities.

## Scope

This policy covers the BouncerFox CLI scanner (`bouncerfox` binary) and its GitHub Action (`bouncerfox/cli`).

## Security Design

- **Offline by default.** No network calls unless `BOUNCERFOX_API_KEY` is set or `--github-comment` is used.
- **No code execution.** The scanner reads and analyzes files. It never executes scanned content.
- **No secret exfiltration.** `SEC_001` findings never store matched secret values in output.
- **RE2 regex only.** All pattern matching uses RE2, eliminating ReDoS risk.
- **Symlink containment.** Symlinks resolving outside the scan root are rejected.
- **File limits.** Max 1 MB per file, max 500 files, 5-minute scan timeout.
- **Signed releases.** Binaries include SLSA provenance attestation. Verify with `gh attestation verify`.
