# Security policy

## Supported versions

Security fixes are applied to the latest release.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for the repository. Do not open a public issue for a suspected vulnerability that could expose users or repository data.

Include the affected version, platform, reproduction steps, impact, and any suggested mitigation.

## Threat model

Port Map Check treats scanned repositories as untrusted input.

- It reads candidate configuration files but does not execute commands, start containers, load plugins, evaluate templates, or make network requests.
- Candidate files are size-limited and common generated/dependency directories are skipped.
- Reports retain normalized host and port references, not URL credentials, query strings, or complete environment values.
- HTML output is generated with contextual escaping.

Repository owners should still review generated reports before publishing them because service names, internal hostnames, and source paths may be operationally sensitive.
