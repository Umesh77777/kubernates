
#!/bin/bash
set -euo pipefail

NAMESPACE="kube-system"
PODS=(
  aks-secrets-store-csi-driver-6jntp
  aks-secrets-store-csi-driver-qb689
  aks-secrets-store-provider-azure-jk8gb
  aks-secrets-store-provider-azure-qtph4
)

for pod in "${PODS[@]}"; do
  echo "Checking pod: $pod"
  containers=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[*].name}')
  for c in $containers; do
    echo "→ Container: $c"
    kubectl exec -n "$NAMESPACE" "$pod" -c "$c" -- id || echo "No shell in $c"
  done
done
``
