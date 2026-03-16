# Contributing

## Prerequisites

- Linux host (eBPF/sysdig requires a Linux kernel; Docker Desktop on macOS is not supported)
- `kubectl` with cluster access, or `docker`
- `shellcheck` for local linting
- `yamllint` for YAML linting (`brew install yamllint` or `pip install yamllint`)

## Development workflow

1. Fork and clone the repo
2. Make changes to `scapture.sh`
3. Run `shellcheck scapture.sh` and fix any warnings
4. Run `yamllint -c .yamllint.yml scapture-deployment.yaml` and fix any warnings
5. Test with `--command` on both Kubernetes and Docker platforms if possible
6. Open a pull request against `main`

## Commit style

Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`

## Testing

There are no automated integration tests. Manual verification steps:

```bash
# Kubernetes
./scapture.sh --command "curl https://example.com" --packages "curl"

# Docker
./scapture.sh --platform docker --command "curl https://example.com" --packages "curl"
```

Verify that:
- The `.scap` file appears in `scaps/` and is non-empty
- Analysis output is produced
- The pod/container is cleaned up after the run

## Captured data

`.scap` files may contain sensitive host data (process names, file paths, network endpoints).
Do not commit capture files. The `scaps/` directory is gitignored for this reason.
