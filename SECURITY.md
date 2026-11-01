# Security policy

## Reporting a vulnerability
Please open a private security advisory (GitHub: Security > Report a vulnerability) rather than a
public issue. Include steps to reproduce and the affected version.

## Handling secrets
API keys belong in a local `.env` file, which is git-ignored. Never commit keys, cache files
(`~/.ioc-enricher/`) or generated reports that contain sensitive indicators.

## Responsible use
This tool is for defensive security work. Do not submit sensitive or internal indicators to
third-party services without authorisation. Private IP addresses are never sent to external
sources.
