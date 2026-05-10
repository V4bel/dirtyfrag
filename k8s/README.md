# Kubernetes mitigation

A self-contained Kubernetes manifest that applies the [Dirty Frag mitigation](../README.md#mitigation) to every Linux node in a cluster.

## What it does

Deploys a DaemonSet (`dirtyfrag-mitigation` in `kube-system`) whose init container — running on every Linux node, including system pools — performs the steps from the disclosure README inside the host's namespaces via `nsenter`:

1. Writes `/etc/modprobe.d/disable-dirtyfrag.conf` blacklisting `esp4`, `esp6` and `rxrpc` so they cannot be loaded on demand.
2. For each of these modules currently loaded with `refcnt=0`, runs `modprobe -r` to unload it from the live kernel.
3. Runs `sync; echo 3 > /proc/sys/vm/drop_caches` to clear any contaminated cached pages.
4. If any of these modules is loaded with `refcnt > 0` (in active use), emits a single aggregated Warning [Kubernetes Event](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/) (`reason=DirtyFragModulesInUse`) on the affected `Node` listing the in-use modules, so operators can drain and reboot/replace the node. **No auto-cordon.**

A long-running [`pause`](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/#understanding-init-containers) container keeps the pod in `Running` state so the init container is only re-executed on pod recreation — i.e. on each new node that joins the cluster (autoscaling, node-image upgrade, scale-set rolling update).

## Apply

```bash
kubectl apply -f https://raw.githubusercontent.com/V4bel/dirtyfrag/master/k8s/dirtyfrag-mitigation.yaml
kubectl -n kube-system rollout status ds/dirtyfrag-mitigation
```

Check for nodes that need a drain+reboot to complete the mitigation (modules that were already in use):

```bash
kubectl -n default get events --field-selector reason=DirtyFragModulesInUse
```

## Compatibility

`esp4` and `esp6` provide IPsec ESP transforms; `rxrpc` provides the RxRPC socket family used by AFS. **None of these are required by a typical workload-only Kubernetes cluster.**

If your cluster does require one of these modules (e.g. a node-level IPsec tunnel, an AFS client running on the host or in a privileged pod), edit the `MODULES` env var in the manifest and remove the affected module(s) before applying — or label-exclude the affected node pool.

## Revert (once upstream kernel patches roll out)

The modprobe drop-in persists for the lifetime of each node. To clean it up from live nodes before deleting the DaemonSet:

```bash
# 1. Flip the init container into cleanup mode and roll the fleet
kubectl -n kube-system set env ds/dirtyfrag-mitigation CLEANUP_MODE=true
kubectl -n kube-system rollout restart ds/dirtyfrag-mitigation
kubectl -n kube-system rollout status  ds/dirtyfrag-mitigation

# 2. Delete the DaemonSet, ServiceAccount and ClusterRole/Binding
kubectl delete -f https://raw.githubusercontent.com/V4bel/dirtyfrag/master/k8s/dirtyfrag-mitigation.yaml
```

If you skip step 1, the `/etc/modprobe.d/disable-dirtyfrag.conf` drop-in remains on existing nodes until each is recycled (node-image upgrade, scale-down, or manual `kubectl drain && kubectl delete node`).

## Tested with

- Kubernetes 1.30 on AKS (Azure), in a production environment across staging and production clusters
- Linux nodes only (the DaemonSet has `nodeSelector: kubernetes.io/os: linux` so Windows nodes are skipped automatically)
