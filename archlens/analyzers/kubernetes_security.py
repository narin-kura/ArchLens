"""Kubernetes-specific security analyzer — checks K8s manifest best practices."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, ComponentType
from ..models.findings import Finding, FindingType, Severity

_WORKLOAD_SERVICES = {"deployment", "statefulset", "daemonset", "replicaset", "job", "cronjob", "pod"}

_DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "SETUID", "SETGID",
    "NET_RAW", "SYS_RAWIO", "AUDIT_WRITE", "SYS_CHROOT",
    "KILL", "MKNOD", "NET_BIND_SERVICE",
}

_SENSITIVE_KEY_FRAGMENTS = {
    "password", "secret", "token", "api_key", "apikey",
    "private_key", "credentials", "passwd", "auth",
}


class KubernetesSecurityAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        if model.source != "kubernetes":
            return []
        findings: list[Finding] = []
        for check in [
            # Pod / workload
            self._check_host_namespaces,
            self._check_privileged_container,
            self._check_allow_privilege_escalation,
            self._check_readonly_root_filesystem,
            self._check_run_as_root,
            self._check_no_security_context,
            self._check_dangerous_capabilities,
            self._check_no_cap_drop_all,
            self._check_no_resource_limits,
            self._check_no_resource_requests,
            self._check_no_liveness_probe,
            self._check_no_readiness_probe,
            self._check_no_seccomp_profile,
            self._check_unsafe_sysctls,
            # Image hygiene
            self._check_image_latest_tag,
            self._check_image_no_tag,
            self._check_image_from_public_registry,
            # Volumes
            self._check_host_path_volume,
            self._check_pv_host_path,
            self._check_pv_delete_reclaim_policy,
            # Service account
            self._check_default_service_account,
            self._check_automount_sa_token,
            # RBAC
            self._check_cluster_admin_binding,
            self._check_wildcard_rbac_verbs,
            self._check_wildcard_rbac_resources,
            self._check_rbac_access_to_secrets,
            self._check_rbac_binds_all_service_accounts,
            # Network
            self._check_no_network_policy,
            self._check_service_type_loadbalancer,
            self._check_service_type_nodeport,
            self._check_ingress_no_tls,
            self._check_ingress_no_class,
            # Secrets / config
            self._check_configmap_sensitive_keys,
            self._check_default_namespace,
        ]:
            findings.extend(check(model))
        return findings

    # ----------------------------------------------------------------- helpers

    def _workloads(self, model: ArchitectureModel) -> list:
        return [
            c for c in model.components_by_type(ComponentType.CONTAINER)
            if c.provider == "kubernetes"
            and c.service in _WORKLOAD_SERVICES
        ]

    # --------------------------------------------------------- Host namespaces

    def _check_host_namespaces(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            for key, label in [
                ("k8s_host_network", "hostNetwork"),
                ("k8s_host_pid", "hostPID"),
                ("k8s_host_ipc", "hostIPC"),
            ]:
                if c.properties.get(key, False):
                    findings.append(Finding(
                        type=FindingType.SECURITY,
                        severity=Severity.CRITICAL,
                        title=f"Workload '{c.name}' sets {label}: true",
                        description=f"{label} shares the host's namespace with the container, enabling surveillance of host processes and trivial container escape.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation=f"Remove {label}: true. Only CNI/node-level daemonsets ever legitimately need this.",
                        references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                    ))
        return findings

    # --------------------------------------------------------- Privileged mode

    def _check_privileged_container(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if c.properties.get("k8s_privileged", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Workload '{c.name}' runs a privileged container",
                    description="privileged: true grants root-equivalent host access — a container escape becomes a full node compromise.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Remove privileged: true. Use securityContext.capabilities.add for the specific capabilities actually needed.",
                    references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged"],
                ))
        return findings

    # ----------------------------------------------- Privilege escalation

    def _check_allow_privilege_escalation(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if c.properties.get("k8s_allow_privilege_escalation", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Workload '{c.name}' allows privilege escalation",
                    description="allowPrivilegeEscalation defaults to true, permitting setuid binaries to gain more privileges than their parent process.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set securityContext.allowPrivilegeEscalation: false on every container.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                ))
        return findings

    # --------------------------------------------------- Read-only rootfs

    def _check_readonly_root_filesystem(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_readonly_root_filesystem", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' does not use a read-only root filesystem",
                    description="A writable root filesystem lets an attacker persist malware or modify binaries after compromising a container.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set securityContext.readOnlyRootFilesystem: true. Mount writable emptyDir volumes for paths that genuinely need writes.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                ))
        return findings

    # ------------------------------------------------------------- Run as root

    def _check_run_as_root(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            run_as_non_root = c.properties.get("k8s_run_as_non_root", False)
            run_as_user = c.properties.get("k8s_run_as_user")
            if not run_as_non_root and (run_as_user is None or str(run_as_user) == "0"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Workload '{c.name}' may run as root (UID 0)",
                    description="Most images default to root. Running as root maximises the impact of any vulnerability or escape.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID (e.g. 1000).",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                ))
        return findings

    # ----------------------------------------------------- No security context

    def _check_no_security_context(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_has_security_context", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' has no securityContext on at least one container",
                    description="Containers without a securityContext inherit permissive defaults: root UID, privilege escalation allowed, writable rootfs.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Add a securityContext to every container with runAsNonRoot, readOnlyRootFilesystem, and allowPrivilegeEscalation: false at minimum.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                ))
        return findings

    # ------------------------------------------------------ Capabilities

    def _check_dangerous_capabilities(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            caps = set(c.properties.get("k8s_capabilities_add") or [])
            dangerous = {cap.upper() for cap in caps} & _DANGEROUS_CAPS
            if dangerous:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Workload '{c.name}' adds dangerous capabilities: {', '.join(sorted(dangerous))}",
                    description="Capabilities like SYS_ADMIN and NET_ADMIN give near-root kernel access, enabling container escape and host manipulation.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Drop ALL capabilities first (capabilities.drop: [ALL]) then add back only those the process strictly requires.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container"],
                ))
        return findings

    def _check_no_cap_drop_all(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_drops_all_caps", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' does not drop all Linux capabilities",
                    description="Without capabilities.drop: [ALL], the container retains its default capability set, which includes several that can be abused.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Add capabilities.drop: [ALL] to every container's securityContext, then explicitly add back required capabilities.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container"],
                ))
        return findings

    # -------------------------------------------------- Resource limits/requests

    def _check_no_resource_limits(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_has_resource_limits", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' has no resource limits (CPU/memory)",
                    description="Without limits, a compromised or buggy container can exhaust node resources and cause a denial-of-service for other pods.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set resources.limits.cpu and resources.limits.memory on every container.",
                    references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"],
                ))
        return findings

    def _check_no_resource_requests(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_has_resource_requests", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Workload '{c.name}' has no resource requests",
                    description="Without requests, the scheduler cannot make informed placement decisions, leading to resource contention and noisy-neighbour effects.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set resources.requests.cpu and resources.requests.memory so the scheduler can plan appropriately.",
                    references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"],
                ))
        return findings

    # -------------------------------------------- Liveness / readiness probes

    def _check_no_liveness_probe(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_has_liveness_probe", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Workload '{c.name}' has no livenessProbe",
                    description="Without a liveness probe, a deadlocked container is never restarted — degrading availability without alerting operators.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Define a livenessProbe (HTTP GET, TCP, or exec) matching the application's health check semantics.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"],
                ))
        return findings

    def _check_no_readiness_probe(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_has_readiness_probe", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Workload '{c.name}' has no readinessProbe",
                    description="Without a readiness probe, traffic is routed to containers before they are ready to serve, causing errors during startup or rolling updates.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Define a readinessProbe so Kubernetes gates traffic until the container signals readiness.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"],
                ))
        return findings

    # ---------------------------------------------------------- Seccomp / sysctls

    def _check_no_seccomp_profile(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if not c.properties.get("k8s_seccomp_profile", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' has no seccomp profile",
                    description="Without seccomp, the container can make any Linux syscall — a broad kernel attack surface exploitable via CVEs.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set securityContext.seccompProfile.type: RuntimeDefault (or Localhost with a custom profile for stricter enforcement).",
                    references=["https://kubernetes.io/docs/tutorials/security/seccomp/"],
                ))
        return findings

    def _check_unsafe_sysctls(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        unsafe_prefixes = {"net.", "kernel.", "vm.", "fs."}
        for c in self._workloads(model):
            sysctls = c.properties.get("k8s_sysctls") or []
            unsafe = [s.get("name", "") for s in sysctls if any(s.get("name", "").startswith(p) for p in unsafe_prefixes)]
            if unsafe:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Workload '{c.name}' modifies unsafe kernel parameters via sysctls: {', '.join(unsafe)}",
                    description="Unsafe sysctls modify kernel networking or memory settings that can destabilise the node or bypass network isolation.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Remove unsafe sysctls. If absolutely required, confine them with PodSecurityAdmission allowedUnsafeSysctls.",
                    references=["https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/"],
                ))
        return findings

    # ---------------------------------------------------- Image hygiene

    def _check_image_latest_tag(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            images = c.properties.get("k8s_images") or []
            bad = [img for img in images if img.endswith(":latest")]
            if bad:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' uses ':latest' image tag: {', '.join(bad)}",
                    description=":latest is a mutable pointer — an upstream push can silently change what runs in production without a re-deploy.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Pin images to an immutable digest (image@sha256:...) or a specific semver tag (image:1.2.3).",
                    references=["https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy"],
                ))
        return findings

    def _check_image_no_tag(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            images = c.properties.get("k8s_images") or []
            untagged = [img for img in images if img and ":" not in img and "@" not in img]
            if untagged:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' references untagged images: {', '.join(untagged)}",
                    description="Images without a tag or digest default to :latest and are indeterminate — you cannot reason about what version is running.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Always specify an explicit tag or digest.",
                    references=["https://kubernetes.io/docs/concepts/containers/images/"],
                ))
        return findings

    def _check_image_from_public_registry(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            images = c.properties.get("k8s_images") or []
            public = [
                img for img in images
                if img and "." not in img.split("/")[0] and "/" in img
                or (img and "/" not in img.split(":")[0])
            ]
            if public:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Workload '{c.name}' pulls images from Docker Hub (public registry)",
                    description="Public registries have rate limits, no SLA, and allow anyone to push to public repos — compromised images are a supply-chain risk.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Mirror approved images to a private registry (ECR, Artifact Registry, Harbor) with vulnerability scanning enabled.",
                    references=["https://kubernetes.io/docs/concepts/containers/images/"],
                ))
        return findings

    # ----------------------------------------------------- Volumes

    def _check_host_path_volume(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if c.properties.get("k8s_host_path_volumes", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Workload '{c.name}' mounts a hostPath volume",
                    description="hostPath mounts expose arbitrary host filesystem paths — a container escape can read or modify the entire host.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Replace hostPath mounts with PersistentVolumeClaims backed by a CSI driver. Restrict remaining cases with PodSecurityAdmission.",
                    references=["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"],
                ))
        return findings

    def _check_pv_host_path(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            if c.provider == "kubernetes" and c.properties.get("k8s_pv_host_path", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"PersistentVolume '{c.name}' uses hostPath storage",
                    description="hostPath PVs bind to a specific node's filesystem, enabling container escape and creating opaque data persistence outside normal backup paths.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Replace with a network-attached CSI driver (EBS, EFS, NFS, Longhorn) that is node-independent and backup-friendly.",
                    references=["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"],
                ))
        return findings

    def _check_pv_delete_reclaim_policy(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.STORAGE):
            if c.provider == "kubernetes" and c.properties.get("k8s_pv_reclaim_policy", "Delete") == "Delete":
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"PersistentVolume '{c.name}' uses reclaimPolicy: Delete",
                    description="Delete reclaim policy permanently destroys the underlying volume when the PVC is released — data is unrecoverable.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set persistentVolumeReclaimPolicy: Retain for stateful workloads. Implement a separate backup and manual cleanup process.",
                    references=["https://kubernetes.io/docs/concepts/storage/persistent-volumes/#reclaiming"],
                ))
        return findings

    # ------------------------------------------------ Service account

    def _check_default_service_account(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if c.properties.get("k8s_service_account", "default") == "default":
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' uses the default service account",
                    description="The default service account is shared across all workloads in a namespace, making least-privilege RBAC and token scope impossible.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Create a dedicated ServiceAccount per workload and bind only the RBAC permissions that workload requires.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"],
                ))
        return findings

    def _check_automount_sa_token(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._workloads(model):
            if c.properties.get("k8s_automount_sa_token", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Workload '{c.name}' auto-mounts the service account token",
                    description="Auto-mounted tokens are available to any process in the container. A compromised workload can use the token to call the Kubernetes API.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set automountServiceAccountToken: false on pod specs (and ServiceAccount objects) for workloads that don't need API access.",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting"],
                ))
        return findings

    # ---------------------------------------------------------------- RBAC

    def _check_cluster_admin_binding(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            if c.provider == "kubernetes" and c.properties.get("k8s_is_cluster_admin", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"RBAC '{c.name}' binds to the cluster-admin role",
                    description="cluster-admin grants unrestricted access to every API and resource in the cluster — a stolen token is a total compromise.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Replace cluster-admin bindings with least-privilege Roles scoped to specific namespaces and resource types.",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles"],
                ))
        return findings

    def _check_wildcard_rbac_verbs(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            if c.provider == "kubernetes" and c.properties.get("k8s_wildcard_verbs", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"RBAC '{c.name}' grants wildcard verbs (*)",
                    description="verbs: ['*'] allows get, list, create, delete, escalate, and more on all matched resources.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Replace ['*'] with the exact verb list needed (e.g. [get, list, watch]).",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                ))
        return findings

    def _check_wildcard_rbac_resources(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            if c.provider == "kubernetes" and c.properties.get("k8s_wildcard_resources", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"RBAC '{c.name}' grants access to all resources (*)",
                    description="resources: ['*'] covers every API resource type including secrets, configmaps, and pods/exec — all sensitive.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="List only the specific resource types needed. Treat secrets access as a separate, explicitly justified grant.",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                ))
        return findings

    def _check_rbac_access_to_secrets(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            if (
                c.provider == "kubernetes"
                and c.service in ("role", "clusterrole")
                and c.properties.get("k8s_accesses_secrets", False)
                and not c.properties.get("k8s_wildcard_resources", False)
            ):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"RBAC '{c.name}' explicitly grants access to Secrets",
                    description="Permissions on secrets allow reading API tokens, TLS private keys, and application credentials stored in the cluster.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Minimise who can read Secrets. Prefer injecting secrets via an external secrets operator (Vault, ASM) with per-workload scoping.",
                    references=["https://kubernetes.io/docs/concepts/configuration/secret/#information-security-for-secrets"],
                ))
        return findings

    def _check_rbac_binds_all_service_accounts(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.IAM):
            if c.provider == "kubernetes" and c.properties.get("k8s_binds_all_sa", False):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"RBAC '{c.name}' grants permissions to ALL service accounts in the cluster",
                    description="Binding to system:serviceaccounts gives every pod in every namespace these permissions — any workload compromise becomes privileged.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Bind roles to specific ServiceAccount subjects, not the system:serviceaccounts group.",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-subjects"],
                ))
        return findings

    # -------------------------------------------------------------- Network

    def _check_no_network_policy(self, model: ArchitectureModel) -> list[Finding]:
        has_netpol = any(c.properties.get("k8s_kind") == "NetworkPolicy" for c in model.components)
        if self._workloads(model) and not has_netpol:
            return [Finding(
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                title="No NetworkPolicy found — all pod-to-pod traffic is unrestricted",
                description="Without NetworkPolicies, any compromised pod can freely reach every other pod, database, and internal API in the cluster.",
                recommendation="Define a default-deny NetworkPolicy per namespace, then whitelist only the pod-to-pod connections that are required.",
                references=["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
            )]
        return []

    def _check_service_type_loadbalancer(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            if c.provider == "kubernetes" and c.properties.get("k8s_service_type") == "LoadBalancer":
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Service '{c.name}' is type LoadBalancer (public cloud LB per service)",
                    description="LoadBalancer services provision a separate public LB for each service, potentially exposing internal services directly to the internet.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Use a shared Ingress controller with TLS termination and WAF instead of per-service LoadBalancers.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"],
                ))
        return findings

    def _check_service_type_nodeport(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.NETWORK):
            if c.provider == "kubernetes" and c.properties.get("k8s_service_type") == "NodePort":
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Service '{c.name}' is type NodePort",
                    description="NodePort opens a high-numbered port on every cluster node, bypassing ingress controls and exposing the service on every node IP.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Replace NodePort with ClusterIP + Ingress for external traffic, or LoadBalancer with strict security groups.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport"],
                ))
        return findings

    def _check_ingress_no_tls(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.GATEWAY):
            if c.provider == "kubernetes" and not c.properties.get("k8s_has_tls", True):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Ingress '{c.name}' has no TLS configured",
                    description="An Ingress without TLS serves traffic over plain HTTP, exposing credentials, session tokens, and data to network interception.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Add a tls: block with a valid certificate. Use cert-manager with Let's Encrypt for automated certificate lifecycle.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"],
                ))
        return findings

    def _check_ingress_no_class(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.GATEWAY):
            if c.provider == "kubernetes" and not c.properties.get("k8s_ingress_class", ""):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Ingress '{c.name}' has no ingress class specified",
                    description="Without an explicit ingressClassName, any controller in the cluster may claim the Ingress, leading to unintended routing.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Set spec.ingressClassName (or the kubernetes.io/ingress.class annotation) to the intended controller.",
                    references=["https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class"],
                ))
        return findings

    # ------------------------------------------------- Secrets / ConfigMap

    def _check_configmap_sensitive_keys(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components:
            if c.provider != "kubernetes" or c.properties.get("k8s_kind") != "ConfigMap":
                continue
            keys = [k.lower() for k in c.properties.get("k8s_configmap_keys") or []]
            matched = [k for k in keys if any(s in k for s in _SENSITIVE_KEY_FRAGMENTS)]
            if matched:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.HIGH,
                    title=f"ConfigMap '{c.name}' may store sensitive data (keys: {', '.join(matched)})",
                    description="ConfigMaps are stored in plaintext in etcd and are readable by anyone with namespace read access.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Move sensitive values to Kubernetes Secrets (with KMS encryption at rest), or use an external secrets operator.",
                    references=["https://kubernetes.io/docs/concepts/configuration/secret/"],
                ))
        return findings

    # ----------------------------------------------------------- Namespace

    def _check_default_namespace(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        for c in model.components:
            if c.provider != "kubernetes":
                continue
            ns = c.properties.get("k8s_namespace", "")
            if ns == "default" and ns not in seen:
                seen.add(c.name)
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Resource '{c.name}' is deployed in the 'default' namespace",
                    description="Deploying workloads in 'default' mixes concerns and makes namespace-scoped RBAC and NetworkPolicies harder to apply and audit.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Create dedicated namespaces per team or application and enforce RBAC and NetworkPolicy per namespace.",
                    references=["https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/"],
                ))
        return findings
