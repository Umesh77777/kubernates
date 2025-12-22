
#!/usr/bin/env bash
# Audit Kubernetes pods/containers for UID, username, and writable sensitive files.
# Produces a CSV report similar to the referenced Python script.

# --- Safety flags (do NOT use `set -e` to avoid aborting on exec failures) ---
set -u
IFS=$'\n\t'

# --- ANSI Colors ---
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

# --- Check kubectl availability ---
if ! command -v kubectl >/dev/null 2>&1; then
  echo -e "${RED}[ERROR]${NC} kubectl not found in PATH. Please install/configure kubectl."
  exit 1
fi

# --- Prompt for CSV filename ---
read -r -p "Enter CSV filename (e.g., k8s_pod_audit_report.csv): " report_file
report_file="${report_file:-k8s_pod_audit_report.csv}"

# --- Write CSV headers ---
csv_headers="Namespace,Pod,Container,UID,Username,File,Status,ExecStatus,Risk"
printf "%s\n" "$csv_headers" > "$report_file"

# --- Prompt for namespaces ---
read -r -p "Enter namespaces (space-separated) or 'all' to scan all: " ns_input
ns_input="${ns_input:-}"
if [[ -z "$ns_input" ]]; then
  echo "No namespaces provided. Exiting."
  exit 0
fi

# --- Resolve namespaces ---
declare -a namespaces
if [[ "${ns_input,,}" == "all" ]]; then
  mapfile -t namespaces < <(kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
else
  # split by spaces
  read -r -a namespaces <<< "$ns_input"
fi

# --- Helper: trim output to a single line, no CRs ---
trim() {
  # Usage: trim "string"
  echo -n "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | head -n1
}

# --- Helper: exec inside a container ---
exec_cmd() {
  local ns="$1" pod="$2" container="$3"; shift 3
  # Remaining args are the command to run
  local output
  output=$(kubectl exec -n "$ns" "$pod" -c "$container" -- "$@" 2>&1)
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "ERROR: $output"
  else
    trim "$output"
  fi
}

# --- Helper: get UID and username inside container ---
get_uid_username() {
  local ns="$1" pod="$2" container="$3"
  local uid="" username="" exec_status="OK"

  # Try UID detection
  local uid_try
  uid_try=$(exec_cmd "$ns" "$pod" "$container" id -u)
  if [[ -n "$uid_try" && "$uid_try" != ERROR:* ]]; then
    uid="$uid_try"
  else
    uid_try=$(exec_cmd "$ns" "$pod" "$container" sh -c "awk '/^Uid:/ {print \$2}' /proc/self/status")
    if [[ -n "$uid_try" && "$uid_try" != ERROR:* ]]; then
      uid="$uid_try"
    fi
  fi
  if [[ -z "$uid" ]]; then
    uid="unknown"
    exec_status="UID detection failed"
  fi

  # Username detection
  local uname_try
  uname_try=$(exec_cmd "$ns" "$pod" "$container" whoami)
  if [[ -n "$uname_try" && "$uname_try" != ERROR:* ]]; then
    username="$uname_try"
  else
    uname_try=$(exec_cmd "$ns" "$pod" "$container" sh -c "id -un")
    if [[ -n "$uname_try" && "$uname_try" != ERROR:* ]]; then
      username="$uname_try"
    else
      # Fallback via /etc/passwd lookup using UID
      if [[ "$uid" != "unknown" ]]; then
        uname_try=$(exec_cmd "$ns" "$pod" "$container" sh -c "awk -F: '\$3==${uid} {print \$1}' /etc/passwd")
        if [[ -n "$uname_try" && "$uname_try" != ERROR:* ]]; then
          username="$uname_try"
        fi
      fi
    fi
  fi

  if [[ -z "$username" ]]; then
    if [[ "$uid" != "unknown" ]]; then
      username="UID ${uid}"
    else
      username="unknown"
    fi
    exec_status="Username detection failed"
  fi

  printf "%s|%s|%s\n" "$uid" "$username" "$exec_status"
}

# --- Helper: check if file is writable inside container (for current user) ---
check_file_writable() {
  local ns="$1" pod="$2" container="$3" file_path="$4"
  local res
  res=$(exec_cmd "$ns" "$pod" "$container" sh -c "[ -w \"$file_path\" ] && echo writable || echo not_writable")
  if [[ "$res" == "writable" ]]; then
    echo "writable"
  else
    echo "not_writable"
  fi
}

# --- Main scan loop ---
total=0
alerts=0

for ns in "${namespaces[@]}"; do
  # Fetch pods in namespace
  mapfile -t pods < <(kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
  if [[ ${#pods[@]} -eq 0 ]]; then
    continue
  fi

  for pod in "${pods[@]}"; do
    # List containers in the pod
    mapfile -t containers < <(kubectl get pod "$pod" -n "$ns" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)
    if [[ ${#containers[@]} -eq 0 ]]; then
      continue
    fi

    for container in "${containers[@]}"; do
      echo -e "\n--- Pod: ${pod} | Container: ${container} ---"

      IFS='|' read -r uid username exec_status < <(get_uid_username "$ns" "$pod" "$container")
      echo "User: ${username} | UID: ${uid} | ExecStatus: ${exec_status}"

      risk="OK"
      if [[ "$uid" == "0" ]]; then
        echo -e "${YELLOW}[INFO]${NC} Running as ROOT"
        risk="RISKY"
      else
        echo -e "${GREEN}[OK]${NC} Running as non-root"
      fi

      for file in "/etc/passwd" "/etc/shadow"; do
        writable_state=$(check_file_writable "$ns" "$pod" "$container" "$file")
        if [[ "$uid" != "0" && "$writable_state" == "writable" ]]; then
          echo -e "${RED}[ALERT]${NC} Non-root user has WRITE access to ${file}"
          status="NON-ROOT WRITABLE"
          risk="RISKY"
          alerts=$((alerts + 1))
        else
          echo -e "${GREEN}[OK]${NC} No write access to ${file}"
          status="OK"
        fi

        # Append row to CSV
        printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
          "$ns" "$pod" "$container" "$uid" "$username" "$file" "$status" "$exec_status" "$risk" >> "$report_file"
      done

      total=$((total + 1))
    done
  done
done

# --- Summary ---
echo -e "\n✅ Scan complete. Total containers scanned: ${total}"
echo -e "🚨 Alerts (non-root writable files): ${alerts}"
echo -e "📁 Report saved to: ${report_file}"
