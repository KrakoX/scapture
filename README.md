# scapture

[![CI](https://github.com/KrakoX/scapture/actions/workflows/ci.yml/badge.svg)](https://github.com/KrakoX/scapture/actions/workflows/ci.yml)

Automated syscall capture using sysdig/eBPF for Falco rule development and security research.

Executes commands or scripts inside isolated containers, captures their full syscall trace, and produces `.scap` files with an analysis report covering file access, process behavior, and network activity.

> **Security warning**: This tool deploys a privileged container with `hostPID=true` and `hostNetwork=true`. It captures selected syscalls from both host and container processes. Run only in isolated, non-production environments. See [SECURITY.md](SECURITY.md).

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  scapture.sh                                                    │
│                                                                 │
│  1. Deploy         Deploy privileged sysdig container           │
│     (K8s or Docker)  - installs sysdig + eBPF probe            │
│                                                                 │
│  2. Capture        Start sysdig --modern-bpf in background      │
│                      - restricted syscall set (execve, open,    │
│                        connect, etc.) tuned for Falco rules     │
│                      - writes to /tmp/*.scap inside container   │
│                                                                 │
│  3. Execute        Run the target command/script                │
│                      - optional package install first           │
│                                                                 │
│  4. Collect        Stop sysdig, copy .scap to scaps/ locally,  │
│                      delete from container                      │
│                                                                 │
│  5. Analyze        Read .scap and produce:                      │
│                      - file access report                       │
│                      - process behavior / parent-child tree     │
│                      - network protocol classification          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Integration with Falco rules

This is the primary use case. The syscall set captured is deliberately restricted to the events Falco monitors.

**Workflow:**

1. Capture the behavior of an attack technique, exploit, or malware sample
2. Inspect the analysis report to identify distinguishing syscall patterns
3. Write Falco rules targeting those patterns
4. Validate the rules by replaying the `.scap` file through Falco

**Validating rules against a capture:**

The `.scap` is saved locally in `scaps/`. Copy it (and your rule file) into the running container to replay:

```bash
# Kubernetes
kubectl cp scaps/scapture-YYYYMMDD-HHMMSS.scap \
    -n scapture deployment/scapture-deployment:/tmp/
kubectl cp your_rule.yaml \
    -n scapture deployment/scapture-deployment:/tmp/

kubectl exec deployment/scapture-deployment -n scapture -- \
    falco -r /tmp/your_rule.yaml \
    -o engine.kind=replay \
    -o engine.replay.capture_file=/tmp/scapture-YYYYMMDD-HHMMSS.scap

# Docker
docker cp scaps/scapture-YYYYMMDD-HHMMSS.scap scapture-container:/tmp/
docker cp your_rule.yaml scapture-container:/tmp/

docker exec scapture-container \
    falco -r /tmp/your_rule.yaml \
    -o engine.kind=replay \
    -o engine.replay.capture_file=/tmp/scapture-YYYYMMDD-HHMMSS.scap
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Kubernetes **or** Docker | K8s path: `kubectl` with cluster access and permission to create privileged pods. Docker path: `docker` CLI with permission to run `--privileged` containers. |
| Privileged pod/container policy | K8s: PSA must allow `privileged` in the target namespace, or use a cluster where this is not restricted. |
| Internet access from the container | The container downloads sysdig at startup from GitHub releases. |

---

## Installation

```bash
git clone https://github.com/KrakoX/scapture
cd scapture
chmod +x scapture.sh
```

No build step. The script is self-contained.

For Kubernetes, the deployment manifest (`scapture-deployment.yaml`) is included in the repo. The script applies it automatically on first run — no manual `kubectl apply` needed.

---

## Usage

### Capture a single command

```bash
./scapture.sh --platform kubernetes --command "curl https://example.com"
```

### Capture with packages pre-installed

```bash
./scapture.sh --platform docker --command "hping3 -1 -c 4 127.0.0.1" --packages "hping3"
```

### Capture a script

```bash
./scapture.sh --platform kubernetes --script ./exploit.sh --packages "wget curl netcat"
```

### Capture only (skip analysis)

```bash
./scapture.sh --platform docker --command "suspicious_cmd" --no-analysis
```

---

## Options

| Flag | Description |
|------|-------------|
| `--command "CMD"` | Command to execute and capture |
| `--script FILE` | Script file to execute and capture |
| `--packages "pkg1 pkg2"` | Packages to install before running the command |
| `--no-analysis` | Skip analysis, produce only the `.scap` file |
| `--platform kubernetes\|docker` | **Required**: target platform |

---

## Output

### Capture files

`.scap` files are saved locally to `scaps/` with a timestamp in the filename:

```
scaps/scapture-20260315-143022.scap
```

Typical size: 100 KB – 20 MB depending on command duration and syscall volume. The file is deleted from the container after being copied.

### Analysis report

After capture, the script prints a structured report:

**File System Analysis**
- Files created during the run
- Most frequently accessed files (top 30)

**Process Behavior Analysis**
- Parent–child process tree
- Suspicious spawn patterns (e.g. curl → bash)
- Process execution timeline

**Enhanced Network Analysis**
- Protocol classification with risk scoring (LOW/MEDIUM/HIGH)
- External vs. internal connections
- Port scanning detection
- Listening services

### Re-analyzing a capture

The `.scap` is local in `scaps/`. To re-analyze offline, copy it into the running container:

```bash
# Kubernetes
kubectl cp scaps/scapture-YYYYMMDD-HHMMSS.scap \
    -n scapture deployment/scapture-deployment:/tmp/

kubectl exec deployment/scapture-deployment -n scapture -- \
    sysdig -r /tmp/scapture-YYYYMMDD-HHMMSS.scap "evt.type=execve" \
    -p "%proc.name %proc.cmdline"

# Docker
docker cp scaps/scapture-YYYYMMDD-HHMMSS.scap scapture-container:/tmp/

docker exec scapture-container \
    sysdig -r /tmp/scapture-YYYYMMDD-HHMMSS.scap "evt.type=execve" \
    -p "%proc.name %proc.cmdline"
```

---

## Local validation

Run the same checks CI runs before pushing:

```bash
shellcheck --severity=warning scapture.sh
yamllint -c .yamllint.yml scapture-deployment.yaml
```

---

## License

[MIT](LICENSE)
