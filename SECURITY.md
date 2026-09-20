# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting

Open a GitHub Security Advisory or a private issue. Do not post exploits
publicly. We aim to respond within 72h and disclose within 90 days.

## Scope & guarantees

- The gate **fail-opens to ask-human**: a broken gate never silently allows.
- API keys are never logged; secrets are redacted before Jev calls.
- Catastrophic shell patterns are rejected locally without calling Jev.
- Log files are written with `0600` permissions.
