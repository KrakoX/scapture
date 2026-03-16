# Security Policy

## Reporting a vulnerability

Open a GitHub issue tagged `security`. For sensitive findings, use GitHub's private vulnerability reporting feature (Security → Report a vulnerability).

## Security considerations for users

**This tool requires privileged access.** Running `scapture.sh` will:

- Deploy a privileged container with `hostPID=true`, `hostNetwork=true`, and access to `/dev`, `/proc`, and `/sys`
- Use eBPF/kernel modules to capture all syscalls on the host
- Produce `.scap` capture files that may contain:
  - Process names and command-line arguments of all host processes
  - File paths accessed during the capture window
  - Network connection metadata (IPs, ports, process names)
  - Fragments of environment variables or in-memory data passed through syscalls

**Do not run this tool on production systems** unless you understand the data that will be captured and have appropriate authorization.

**Do not commit `.scap` files** to version control. The `scaps/` directory is gitignored by default.

## Threat model

This tool is designed for:
- Falco rule development in isolated test environments
- Malware behavior analysis in controlled lab settings
- MITRE ATT&CK technique validation against non-production clusters

It is not designed for production monitoring. Use Falco directly for that purpose.
