# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository (Security tab → "Report a vulnerability", or GitHub Security Advisories directly):

https://github.com/fastrevmd-lab/firewallintentconverter/security/advisories/new

Include what you'd include in a bug report — affected version or commit, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, discussion, or comment.

## Scope

firewallintentconverter parses vendor firewall and cloud security-group configurations (PAN-OS, Junos SRX, FortiGate, Cisco ASA/FTD, Check Point, SonicWall, Huawei USG, AWS Security Groups, Azure NSG, GCP Firewall Rules), can optionally call an LLM to draft translated policies or run a greenfield interview, and can optionally push results to a live SRX device through a PyEZ bridge. Vulnerability classes we especially want to hear about:

- Parser issues that let a malformed or malicious source configuration escape the intended parse (e.g. injection into generated SRX `set`/XML output, path traversal, prototype pollution)
- Anything that lets an LLM response bypass the human "Accept" review gate and reach generated output, or a live device, without explicit human review
- Anything that lets the PyEZ bridge / device-push path fire a device-changing operation without the operator's explicit action
- Sanitization bypass — cases where the built-in sanitizer fails to redact sensitive data (passwords, keys, hostnames, IPs, etc.) it claims to redact
- Cross-site scripting or similar issues in the browser UI, since source configs may originate from untrusted paste/upload input

## Response

This is a community-maintained project. There's no guaranteed SLA, but reports are read and triaged by a human maintainer, not by any automated or model-based process.
