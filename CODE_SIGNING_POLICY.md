# Code Signing Policy

Free code signing is provided by [SignPath.io](https://signpath.io/), with certificates issued by the [SignPath Foundation](https://signpath.org/).

## Team Roles

- **Committers and Reviewers**: Repository maintainers (`ion-lgb`).
- **Approvers**: Repository owner (`ion-lgb`).

## Build and Signing Process

- All signed binaries are built exclusively from source code in this public repository via GitHub Actions (`.github/workflows/build.yml`).
- Local/developer builds are never submitted for signing.
- Releases are triggered only from tagged commits reviewed and pushed by the repository owner.

## Privacy Policy

This program will **not** transfer any information to other networked systems unless specifically requested by the user (read-only LAN BMC discovery probes initiated by the user on the local network). No telemetry, analytics, or credentials are collected or transmitted.

## Security & Vulnerability Reporting

If you discover a security issue or suspect a compromised release, please open an issue or contact the maintainer at `maxssr6@163.com`.
