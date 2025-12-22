
cat > checkroot.sh <<'EOF'
#!/bin/sh
# POSIX-compatible Kubernetes pod audit script
# Scans containers for UID/username and checks write access to /etc/passwd and /etc/shadow.
# Outputs a CSV report.

RED="$(printf '\033[0;31m')"
GREEN="$(printf '\033[0;32m')"
YELLOW="$(printf '\033[1;33m')"
NC="$(printf '\033[0m')"

# Check kubectl
if ! command -v kubectl >/dev/null 2>&1; then
  printf "%s[ERROR]%s kubectl not found in PATH. Please install/configure kubectl.\n" "$RED" "$NC"
  exit 1
fi

# Read CSV filename
printf "Enter CSV filename (e.g., k8s_pod_audit_report.csv): "
IFS= read -r report_file
[ -z "$report_file" ] && report_file="k8s_pod_audit_report.csv"

# Write CSV header
printf "Namespace,Pod,Container,UID,Username,File,Status,ExecStatus,Risk\n" > "$report_file"

# Read namespaces
printf "Enter namespaces (space-separated) or 'all' to scan all: "
IFS= read -r ns_input
[ -z "$ns_input" ] && { echo "No namespaces provided. Exiting."; exit 0; }

# Build the namespace list
namespaces_tmp="$(mktemp)"
if [ "$(printf %s "$ns_input" | tr '[:upper:]' '[:lower:]')" = "all" ]; then
  kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' > "$namespaces_tmp" 2>/dev/null
else
  for ns in $ns_input; do
    printf "%s\n" "$ns" >> "$namespaces_tmp"
  done
fi

trim() {
  # strip CR and leading/trailing spaces, first line only
  printf "%s" "$*" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | head -n1
}

exec_cmd() {
  ns="$1"; pod="$2"; container="$3"; shift 3
  out="$(kubectl exec -n "$ns" "$pod" -c "$container" -- "$@" 2>&1)"
  rc=$?
  if [ $rc -ne 0 ]; then
    printf "ERROR: %s" "$out"
  else
    trim "$out"
  fi
}

get_uid_username() {
  ns="$1"; pod="$2"; container="$3"
  uid=""; username=""; exec_status="OK"

  uid_try="$(exec_cmd "$ns" "$pod" "$container" id -u)"
  case "$uid_try" in
    ERROR:*) uid_try="" ;;
  esac
  if [ -n "$uid_try" ]; then
    uid="$uid_try"
  else
    uid_try="$(exec_cmd "$ns" "$pod" "$container" sh -c "awk '/^Uid:/ {print $2}' /proc/self/status")"
    case "$uid_try" in
      ERROR:*) uid_try="" ;;
    esac
    [ -n "$uid_try" ] && uid="$uid_try"
  fi
  if [ -z "$uid" ]; then
    uid="unknown"
    exec_status="UID detection failed"
  fi

  uname_try="$(exec_cmd "$ns" "$pod" "$container" whoami)"
  case "$uname_try" in
    ERROR:*) uname_try="" ;;
  esac
  if [ -n "$uname_try" ]; then
    username="$uname_try"
  else
    uname_try="$(exec_cmd "$ns" "$pod" "$container" sh -c "id -un")"
    case "$uname_try" in
      ERROR:*) uname_try="" ;;
    esac
    if [ -n "$uname_try" ]; then
      username="$uname_try"
    else
      if [ "$uid" != "unknown" ]; then
        uname_try="$(exec_cmd "$ns" "$pod" "$container" sh -c "awk -F: '\$3==${uid} {print \$1}' /etc/passwd")"
        case "$uname_try" in
          ERROR:*) uname_try="" ;;
        esac
        [ -n "$uname_try" ] && username="$uname_try"
      fi
    fi
  fi

  if [ -z "$username" ]; then
    if [ "$uid" != "unknown" ]; then
      username="UID $uid"
    else
      username="unknown"
    fi
    [ "$exec_status" = "OK" ] && exec_status="Username detection failed"
  fi

  printf "%s|%s|%s" "$uid" "$username" "$exec_status"
}

check_file_writable() {
  ns="$1"; pod="$2"; container="$3"; file="$4"
  res="$(exec_cmd "$ns" "$pod" "$container" sh -c "[ -w '$file' ] && echo writable || echo not_writable")"
  [ "$res" = "writable" ] && echo "writable" || echo "not_writable"
}

total=0
alerts=0

while IFS= read -r ns; do
  [ -z "$ns" ] && continue

  pods_tmp="$(mktemp)"
  kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' > "$pods_tmp" 2>/dev/null

  while IFS= read -r pod; do
    [ -z "$pod" ] && continue

    containers_tmp="$(mktemp)"
    kubectl get pod "$pod" -n "$ns" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' > "$containers_tmp" 2>/dev/null

    while IFS= read -r container; do
      [ -z "$container" ] && continue

      printf "\n--- Pod: %s | Container: %s ---\n" "$pod" "$container"

      IFS='|' read -r uid username exec_status <<EOF2
$(get_uid_username "$ns" "$pod" "$container")
EOF2
      printf "User: %s | UID: %s | ExecStatus: %s\n" "$username" "$uid" "$exec_status"

      risk="OK"
      if [ "$uid" = "0" ]; then
        printf "%s[INFO]%s Running as ROOT\n" "$YELLOW" "$NC"
        risk="RISKY"
      else
        printf "%s[OK]%s Running as non-root\n" "$GREEN" "$NC"
      fi

      for file in /etc/passwd /etc/shadow; do
        writable_state="$(check_file_writable "$ns" "$pod" "$container" "$file")"
        if [ "$uid" != "0" ] && [ "$writable_state" = "writable" ]; then
          printf "%s[ALERT]%s Non-root user has WRITE access to %s\n" "$RED" "$NC" "$file"
          status="NON-ROOT WRITABLE"
          risk="RISKY"
          alerts=$((alerts + 1))
        else
          printf "%s[OK]%s No write access to %s\n" "$GREEN" "$NC" "$file"
          status="OK"
        fi

        printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
          "$ns" "$pod" "$container" "$uid" "$username" "$file" "$status" "$exec_status" "$risk" >> "$report_file"
      done

      total=$((total + 1))
    done < "$containers_tmp"
    rm -f "$containers_tmp"
  done < "$pods_tmp"
  rm -f "$pods_tmp"

done < "$namespaces_tmp"
rm -f "$namespaces_tmp"

printf "\n✅ Scan complete. Total containers scanned: %s\n" "$total"
printf "🚨 Alerts (non-root writable files): %s\n" "$alerts"
printf "📁 Report saved to: %s\n" "$report_file"
EOF
