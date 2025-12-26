
#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="kube-system"
# List of pod names to process (edit as needed)
PODS=(
  "aks-secrets-store-csi-driver-6jntp"
  "aks-secrets-store-csi-driver-qb689"
  "aks-secrets-store-provider-azure-jk8gb"
  "aks-secrets-store-provider-azure-qtph4"
  "ama-logs-kq9c4"
  "ama-logs-r62r8"
  "ama-logs-rs-6b57f5db99-lftg4"
  "azure-cns-7mt5w"
  "azure-cns-l4xjb"
  "azure-ip-masq-agent-rxl64"
  "azure-ip-masq-agent-x8bsq"
  "azure-npm-8slcv"
  "azure-npm-cbg2g"
  "azure-policy-5dc48f977b-g4psr"
  "azure-policy-webhook-695bfd4cb7-c7w4f"
  "cloud-node-manager-kdmdn"
  "cloud-node-manager-wlxp4"
  "coredns-6865d647c6-8dd4v"
  "coredns-6865d647c6-lld5n"
  "coredns-autoscaler-fbbdff56-q4tfk"
  "csi-azuredisk-node-mn9dg"
  "csi-azuredisk-node-xnrg5"
  "csi-azurefile-node-54284"
  "csi-azurefile-node-sd8l6"
  "ingress-appgw-deployment-7bc84f7475-qgp2x"
  "konnectivity-agent-74dbd764b-6ztbp"
  "konnectivity-agent-74dbd764b-9b7k7"
  "konnectivity-agent-autoscaler-6ff7779788-kr4h7"
  "kube-proxy-cjm5g"
  "kube-proxy-dg5lb"
  "metrics-server-5554f5bfbd-jlrq8"
  "metrics-server-5554f5bfbd-zhgjr"
  "microsoft-defender-collector-ds-27ff6"
  "microsoft-defender-collector-ds-qfgs8"
  "microsoft-defender-collector-misc-5d4f59568-hpnkx"
  "microsoft-defender-publisher-ds-rmqt7"
  "microsoft-defender-publisher-ds-slbvb"
)

# Try a shell path inside the container
try_shell() {
  local pod="$1" ns="$2" container="$3"
  local shells=("/bin/sh" "/bin/bash" "/busybox/sh")

  for shpath in "${shells[@]}"; do
    if kubectl exec -n "$ns" "$pod" -c "$container" -- "$shpath" -c 'id; exit' 2>/dev/null; then
      echo "✅ [$pod/$container] Shell: $shpath"
      # Drop into interactive shell if desired:
      kubectl exec -it -n "$ns" "$pod" -c "$container" -- "$shpath"
      return 0
    fi
  done
  return 1
}

# Optional: attach ephemeral debug container if no shell was found
attach_debug() {
  local pod="$1" ns="$2" target_container="$3"
  echo "ℹ️ Attaching ephemeral debug to $pod targeting container $target_container..."
  # share-processes helps inspecting, but may be denied by policy; remove if blocked
  if kubectl debug -n "$ns" -it "$pod" --image=busybox --target="$target_container" --share-processes -- sh; then
    return 0
  else
    echo "❌ Failed to attach debug container to $pod (RBAC/policy may block it)."
    return 1
  fi
}

for pod in "${PODS[@]}"; do
  echo -e "\n=== Pod: $pod (ns: $NAMESPACE) ==="
  # Get container names
  containers=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[*].name}')
  if [[ -z "$containers" ]]; then
    echo "❌ No containers found or pod not present."
    continue
  fi

  for c in $containers; do
    echo "→ Trying container: $c"
    if try_shell "$pod" "$NAMESPACE" "$c"; then
      # Inside shell, you can run 'id' to check root and exit
      # The script already printed ID via -c above
      break
    else
      echo "⚠️ [$pod/$c] No shell found."
    fi
  done

  # If none had a shell, offer debug attachment
  read -r -p "Attach ephemeral debug to $pod? (y/N) " ans
  if [[ "${ans,,}" == "y" ]]; then
    # Default target: first container
    first_container=$(echo "$containers" | awk '{print $1}')
    attach_debug "$pod" "$NAMESPACE" "$first_container" || true
  fi
done
