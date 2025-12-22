#!/usr/bin/env python3
import csv
from kubernetes import client, config, stream

# ---- Load kubeconfig ----
try:
    config.load_kube_config()
except:
    config.load_incluster_config()

core_v1 = client.CoreV1Api()

# ---- CSV Report ----
report_file = input("Enter CSV filename (e.g., k8s_pod_audit_report.csv): ").strip() or "k8s_pod_audit_report.csv"
csv_headers = ["Namespace", "Pod", "Container", "UID", "Username", "File", "Status", "ExecStatus", "Risk"]

with open(report_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)

# ---- ANSI Colors ----
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

# ---- Namespace selection ----
ns_input = input("Enter namespaces (space-separated) or 'all' to scan all: ").strip()
if not ns_input:
    exit(0)
namespaces = [ns.metadata.name for ns in core_v1.list_namespace().items] if ns_input.lower() == "all" else ns_input.split()

# ---- Helper functions ----
def exec_cmd(pod_name, namespace, container, cmd):
    try:
        return stream.stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod_name, namespace,
            container=container,
            command=cmd,
            stderr=True, stdin=False, stdout=True, tty=False
        ).strip()
    except Exception as e:
        return f"ERROR: {e}"

def get_uid_username(pod_name, namespace, container):
    uid = None
    username = None
    exec_status = "OK"

    # UID detection
    for cmd in [["id", "-u"], ["sh", "-c", "awk '/^Uid:/ {print $2}' /proc/self/status"]]:
        uid_result = exec_cmd(pod_name, namespace, container, cmd)
        if uid_result and not uid_result.startswith("ERROR"):
            uid = uid_result
            break
    if not uid:
        uid = "unknown"
        exec_status = "UID detection failed"

    # Username detection
    for cmd in [["whoami"], ["sh", "-c", "id -un"], ["sh", "-c", f"awk -F: '$3=={uid}{{print $1}}' /etc/passwd"]]:
        uname_result = exec_cmd(pod_name, namespace, container, cmd)
        if uname_result and not uname_result.startswith("ERROR"):
            username = uname_result
            break
    if not username:
        username = f"UID {uid}" if uid != "unknown" else "unknown"
        exec_status = "Username detection failed"

    return uid, username, exec_status

def check_file_writable(pod_name, namespace, container, file_path, uid):
    result = exec_cmd(pod_name, namespace, container, ["sh", "-c", f"[ -w {file_path} ] && echo writable || echo not_writable"])
    if uid != "0" and result == "writable":
        return True
    return False

# ---- Scan all pods ----
total = 0
alerts = 0

for ns in namespaces:
    try:
        pods = core_v1.list_namespaced_pod(ns)
    except Exception as e:
        print(f"Error fetching pods in {ns}: {e}")
        continue
    if not pods.items:
        continue

    for pod in pods.items:
        pod_name = pod.metadata.name
        for container in pod.spec.containers:
            container_name = container.name
            print(f"\n--- Pod: {pod_name} | Container: {container_name} ---")

            uid, username, exec_status = get_uid_username(pod_name, ns, container_name)
            print(f"User: {username} | UID: {uid} | ExecStatus: {exec_status}")

            risk = "OK"
            if uid == "0":
                print(f"{YELLOW}[INFO]{NC} Running as ROOT")
                risk = "RISKY"
            else:
                print(f"{GREEN}[OK]{NC} Running as non-root")

            for file in ["/etc/passwd", "/etc/shadow"]:
                writable = check_file_writable(pod_name, ns, container_name, file, uid)
                if writable:
                    print(f"{RED}[ALERT]{NC} Non-root user has WRITE access to {file}")
                    status = "NON-ROOT WRITABLE"
                    risk = "RISKY"
                    alerts += 1
                else:
                    print(f"{GREEN}[OK]{NC} No write access to {file}")
                    status = "OK"

                # Write to CSV
                with open(report_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([ns, pod_name, container_name, uid, username, file, status, exec_status, risk])

            total += 1

# ---- Summary ----
print(f"\n✅ Scan complete. Total containers scanned: {total}")
print(f"🚨 Alerts (non-root writable files): {alerts}")
print(f"📁 Report saved to: {report_file}")
