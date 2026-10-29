"""Every Kubernetes object kind ArchLens recognizes — built-in API kinds plus
the Gateway API and widely used ecosystem CRDs.

Single source of truth for both the manifest parser (component type per
kind) and the diagram builder's palette, which is generated from this file by
scripts/gen_k8s_catalog.py. Edit here, then regenerate.

A built-in kind's service id is kind.lower() ("deployment"). A CRD kind's
service id is prefixed with its project ("istio_gateway", "knative_service")
because several CRDs reuse a built-in name — an Istio Gateway or a Knative
Service must not be read as the core object of the same name.
"""

from __future__ import annotations

from ..models.architecture import ComponentType as C

# (kind, api_group, component_type, palette_group, display_name, icon, legacy)
# api_group "" is the core group (apiVersion: v1).
BUILTIN_KINDS: list[tuple] = [
    # Workloads
    ("Pod",                     "",                        C.CONTAINER,  "Workloads",           "Pod",                       "POD",  False),
    ("Deployment",              "apps",                    C.CONTAINER,  "Workloads",           "Deployment",                "DEP",  False),
    ("StatefulSet",             "apps",                    C.CONTAINER,  "Workloads",           "StatefulSet",               "STS",  False),
    ("DaemonSet",               "apps",                    C.CONTAINER,  "Workloads",           "DaemonSet",                 "DS",   False),
    ("ReplicaSet",              "apps",                    C.CONTAINER,  "Workloads",           "ReplicaSet",                "RS",   False),
    ("ReplicationController",   "",                        C.CONTAINER,  "Workloads",           "ReplicationController",     "RC",   True),
    ("Job",                     "batch",                   C.CONTAINER,  "Workloads",           "Job",                       "JOB",  False),
    ("CronJob",                 "batch",                   C.CONTAINER,  "Workloads",           "CronJob",                   "CRON", False),
    ("PodTemplate",             "",                        C.OTHER,      "Workloads",           "PodTemplate",               "PT",   False),
    ("ControllerRevision",      "apps",                    C.OTHER,      "Workloads",           "ControllerRevision",        "CR",   False),
    # Service discovery & networking
    ("Service",                 "",                        C.NETWORK,    "Networking",          "Service",                   "SVC",  False),
    ("Endpoints",               "",                        C.NETWORK,    "Networking",          "Endpoints",                 "EP",   True),
    ("EndpointSlice",           "discovery.k8s.io",        C.NETWORK,    "Networking",          "EndpointSlice",             "EPS",  False),
    ("Ingress",                 "networking.k8s.io",       C.GATEWAY,    "Networking",          "Ingress",                   "ING",  False),
    ("IngressClass",            "networking.k8s.io",       C.OTHER,      "Networking",          "IngressClass",              "INGC", False),
    ("NetworkPolicy",           "networking.k8s.io",       C.NETWORK,    "Networking",          "NetworkPolicy",             "NP",   False),
    ("IPAddress",               "networking.k8s.io",       C.NETWORK,    "Networking",          "IPAddress",                 "IP",   False),
    ("ServiceCIDR",             "networking.k8s.io",       C.NETWORK,    "Networking",          "ServiceCIDR",               "CIDR", False),
    # Gateway API (gateway.networking.k8s.io) — the Ingress successor.
    ("GatewayClass",            "gateway.networking.k8s.io", C.OTHER,    "Gateway API",         "GatewayClass",              "GWC",  False),
    ("Gateway",                 "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "Gateway",                   "GW",   False),
    ("HTTPRoute",               "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "HTTPRoute",                 "HTTP", False),
    ("GRPCRoute",               "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "GRPCRoute",                 "GRPC", False),
    ("TLSRoute",                "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "TLSRoute",                  "TLS",  False),
    ("TCPRoute",                "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "TCPRoute",                  "TCP",  False),
    ("UDPRoute",                "gateway.networking.k8s.io", C.GATEWAY,  "Gateway API",         "UDPRoute",                  "UDP",  False),
    ("ReferenceGrant",          "gateway.networking.k8s.io", C.IAM,      "Gateway API",         "ReferenceGrant",            "RG",   False),
    ("BackendTLSPolicy",        "gateway.networking.k8s.io", C.IAM,      "Gateway API",         "BackendTLSPolicy",          "BTLS", False),
    # Config & storage
    ("ConfigMap",               "",                        C.OTHER,      "Config & Storage",    "ConfigMap",                 "CM",   False),
    ("Secret",                  "",                        C.OTHER,      "Config & Storage",    "Secret",                    "SEC",  False),
    ("PersistentVolume",        "",                        C.STORAGE,    "Config & Storage",    "PersistentVolume",          "PV",   False),
    ("PersistentVolumeClaim",   "",                        C.STORAGE,    "Config & Storage",    "PersistentVolumeClaim",     "PVC",  False),
    ("StorageClass",            "storage.k8s.io",          C.OTHER,      "Config & Storage",    "StorageClass",              "SC",   False),
    ("VolumeAttributesClass",   "storage.k8s.io",          C.OTHER,      "Config & Storage",    "VolumeAttributesClass",     "VAC",  False),
    ("VolumeAttachment",        "storage.k8s.io",          C.OTHER,      "Config & Storage",    "VolumeAttachment",          "VA",   False),
    ("CSIDriver",               "storage.k8s.io",          C.OTHER,      "Config & Storage",    "CSIDriver",                 "CSI",  False),
    ("CSINode",                 "storage.k8s.io",          C.OTHER,      "Config & Storage",    "CSINode",                   "CSIN", False),
    ("CSIStorageCapacity",      "storage.k8s.io",          C.OTHER,      "Config & Storage",    "CSIStorageCapacity",        "CSIC", False),
    # Access control
    ("ServiceAccount",          "",                        C.IAM,        "Access Control",      "ServiceAccount",            "SA",   False),
    ("Role",                    "rbac.authorization.k8s.io", C.IAM,      "Access Control",      "Role",                      "ROLE", False),
    ("ClusterRole",             "rbac.authorization.k8s.io", C.IAM,      "Access Control",      "ClusterRole",               "CRL",  False),
    ("RoleBinding",             "rbac.authorization.k8s.io", C.IAM,      "Access Control",      "RoleBinding",               "RB",   False),
    ("ClusterRoleBinding",      "rbac.authorization.k8s.io", C.IAM,      "Access Control",      "ClusterRoleBinding",        "CRB",  False),
    ("CertificateSigningRequest", "certificates.k8s.io",   C.IAM,        "Access Control",      "CertificateSigningRequest", "CSR",  False),
    ("ClusterTrustBundle",      "certificates.k8s.io",     C.IAM,        "Access Control",      "ClusterTrustBundle",        "CTB",  False),
    ("PodSecurityPolicy",       "policy",                  C.IAM,        "Access Control",      "PodSecurityPolicy (removed in 1.25)", "PSP", True),
    # Policy, quota & scheduling
    ("PodDisruptionBudget",     "policy",                  C.OTHER,      "Policy & Scheduling", "PodDisruptionBudget",       "PDB",  False),
    ("ResourceQuota",           "",                        C.OTHER,      "Policy & Scheduling", "ResourceQuota",             "RQ",   False),
    ("LimitRange",              "",                        C.OTHER,      "Policy & Scheduling", "LimitRange",                "LR",   False),
    ("PriorityClass",           "scheduling.k8s.io",       C.OTHER,      "Policy & Scheduling", "PriorityClass",             "PC",   False),
    ("RuntimeClass",            "node.k8s.io",             C.OTHER,      "Policy & Scheduling", "RuntimeClass",              "RTC",  False),
    ("HorizontalPodAutoscaler", "autoscaling",             C.COMPUTE,    "Policy & Scheduling", "HorizontalPodAutoscaler",   "HPA",  False),
    ("ValidatingAdmissionPolicy", "admissionregistration.k8s.io", C.IAM, "Policy & Scheduling", "ValidatingAdmissionPolicy", "VAP",  False),
    ("ValidatingAdmissionPolicyBinding", "admissionregistration.k8s.io", C.IAM, "Policy & Scheduling", "ValidatingAdmissionPolicyBinding", "VAPB", False),
    ("ValidatingWebhookConfiguration", "admissionregistration.k8s.io", C.IAM, "Policy & Scheduling", "ValidatingWebhookConfiguration", "VWC", False),
    ("MutatingWebhookConfiguration", "admissionregistration.k8s.io", C.IAM, "Policy & Scheduling", "MutatingWebhookConfiguration", "MWC", False),
    # Dynamic Resource Allocation (GPUs and other devices)
    ("DeviceClass",             "resource.k8s.io",         C.OTHER,      "Policy & Scheduling", "DeviceClass (DRA)",         "DVC",  False),
    ("ResourceClaim",           "resource.k8s.io",         C.OTHER,      "Policy & Scheduling", "ResourceClaim (DRA)",       "RCL",  False),
    ("ResourceClaimTemplate",   "resource.k8s.io",         C.OTHER,      "Policy & Scheduling", "ResourceClaimTemplate (DRA)", "RCT", False),
    ("ResourceSlice",           "resource.k8s.io",         C.OTHER,      "Policy & Scheduling", "ResourceSlice (DRA)",       "RSL",  False),
    # Cluster
    ("Namespace",               "",                        C.OTHER,      "Cluster",             "Namespace",                 "NS",   False),
    ("Node",                    "",                        C.COMPUTE,    "Cluster",             "Node",                      "NODE", False),
    ("Lease",                   "coordination.k8s.io",     C.OTHER,      "Cluster",             "Lease",                     "LSE",  False),
    ("Event",                   "events.k8s.io",           C.MONITORING, "Cluster",             "Event",                     "EVT",  False),
    ("CustomResourceDefinition", "apiextensions.k8s.io",   C.OTHER,      "Cluster",             "CustomResourceDefinition",  "CRD",  False),
    ("APIService",              "apiregistration.k8s.io",  C.OTHER,      "Cluster",             "APIService",                "APIS", False),
    ("FlowSchema",              "flowcontrol.apiserver.k8s.io", C.OTHER, "Cluster",             "FlowSchema",                "FS",   False),
    ("PriorityLevelConfiguration", "flowcontrol.apiserver.k8s.io", C.OTHER, "Cluster",          "PriorityLevelConfiguration", "PLC", False),
    ("ComponentStatus",         "",                        C.MONITORING, "Cluster",             "ComponentStatus",           "CS",   True),
]

# (kind, api_group, service_prefix, component_type, palette_group, display_name, icon)
ECOSYSTEM_KINDS: list[tuple] = [
    ("VerticalPodAutoscaler", "autoscaling.k8s.io",     "vpa_",       C.COMPUTE,    "Autoscaling",     "VerticalPodAutoscaler",     "VPA"),
    ("ScaledObject",          "keda.sh",                "keda_",      C.COMPUTE,    "Autoscaling",     "KEDA ScaledObject",         "KEDA"),
    ("ScaledJob",             "keda.sh",                "keda_",      C.CONTAINER,  "Autoscaling",     "KEDA ScaledJob",            "KEDJ"),
    ("TriggerAuthentication", "keda.sh",                "keda_",      C.IAM,        "Autoscaling",     "KEDA TriggerAuthentication","KEDT"),
    ("NodePool",              "karpenter.sh",           "karpenter_", C.COMPUTE,    "Autoscaling",     "Karpenter NodePool",        "KARP"),
    ("NodeClaim",             "karpenter.sh",           "karpenter_", C.COMPUTE,    "Autoscaling",     "Karpenter NodeClaim",       "KRNC"),
    ("Certificate",           "cert-manager.io",        "certmanager_", C.IAM,      "Certificates & Secrets", "cert-manager Certificate", "CERT"),
    ("Issuer",                "cert-manager.io",        "certmanager_", C.IAM,      "Certificates & Secrets", "cert-manager Issuer",    "ISS"),
    ("ClusterIssuer",         "cert-manager.io",        "certmanager_", C.IAM,      "Certificates & Secrets", "cert-manager ClusterIssuer", "CISS"),
    ("ExternalSecret",        "external-secrets.io",    "eso_",       C.IAM,        "Certificates & Secrets", "External Secrets ExternalSecret", "ESO"),
    ("SecretStore",           "external-secrets.io",    "eso_",       C.IAM,        "Certificates & Secrets", "External Secrets SecretStore", "ESS"),
    ("ClusterSecretStore",    "external-secrets.io",    "eso_",       C.IAM,        "Certificates & Secrets", "External Secrets ClusterSecretStore", "ECSS"),
    ("SealedSecret",          "bitnami.com",            "sealed_",    C.IAM,        "Certificates & Secrets", "Sealed Secret",          "SLD"),
    ("VirtualService",        "networking.istio.io",    "istio_",     C.GATEWAY,    "Service Mesh",    "Istio VirtualService",      "IVS"),
    ("DestinationRule",       "networking.istio.io",    "istio_",     C.NETWORK,    "Service Mesh",    "Istio DestinationRule",     "IDR"),
    ("Gateway",               "networking.istio.io",    "istio_",     C.GATEWAY,    "Service Mesh",    "Istio Gateway",             "IGW"),
    ("ServiceEntry",          "networking.istio.io",    "istio_",     C.NETWORK,    "Service Mesh",    "Istio ServiceEntry",        "ISE"),
    ("Sidecar",               "networking.istio.io",    "istio_",     C.NETWORK,    "Service Mesh",    "Istio Sidecar",             "ISC"),
    ("PeerAuthentication",    "security.istio.io",      "istio_",     C.IAM,        "Service Mesh",    "Istio PeerAuthentication (mTLS)", "IPA"),
    ("AuthorizationPolicy",   "security.istio.io",      "istio_",     C.IAM,        "Service Mesh",    "Istio AuthorizationPolicy", "IAP"),
    ("RequestAuthentication", "security.istio.io",      "istio_",     C.IAM,        "Service Mesh",    "Istio RequestAuthentication", "IRA"),
    ("Server",                "policy.linkerd.io",      "linkerd_",   C.NETWORK,    "Service Mesh",    "Linkerd Server",            "LKS"),
    ("AuthorizationPolicy",   "policy.linkerd.io",      "linkerd_",   C.IAM,        "Service Mesh",    "Linkerd AuthorizationPolicy", "LKA"),
    ("CiliumNetworkPolicy",   "cilium.io",              "cilium_",    C.NETWORK,    "Network Policy",  "CiliumNetworkPolicy",       "CNP"),
    ("CiliumClusterwideNetworkPolicy", "cilium.io",     "cilium_",    C.NETWORK,    "Network Policy",  "CiliumClusterwideNetworkPolicy", "CCNP"),
    ("NetworkPolicy",         "crd.projectcalico.org",  "calico_",    C.NETWORK,    "Network Policy",  "Calico NetworkPolicy",      "CAL"),
    ("GlobalNetworkPolicy",   "crd.projectcalico.org",  "calico_",    C.NETWORK,    "Network Policy",  "Calico GlobalNetworkPolicy","CALG"),
    ("IngressRoute",          "traefik.io",             "traefik_",   C.GATEWAY,    "Ingress Controllers", "Traefik IngressRoute",  "TRF"),
    ("ServiceMonitor",        "monitoring.coreos.com",  "prom_",      C.MONITORING, "Observability",   "Prometheus ServiceMonitor", "SMON"),
    ("PodMonitor",            "monitoring.coreos.com",  "prom_",      C.MONITORING, "Observability",   "Prometheus PodMonitor",     "PMON"),
    ("PrometheusRule",        "monitoring.coreos.com",  "prom_",      C.MONITORING, "Observability",   "PrometheusRule",            "PRUL"),
    ("Prometheus",            "monitoring.coreos.com",  "prom_",      C.MONITORING, "Observability",   "Prometheus (Operator)",     "PROM"),
    ("Alertmanager",          "monitoring.coreos.com",  "prom_",      C.MONITORING, "Observability",   "Alertmanager (Operator)",   "ALRT"),
    ("OpenTelemetryCollector","opentelemetry.io",       "otel_",      C.MONITORING, "Observability",   "OpenTelemetry Collector",   "OTEL"),
    ("Application",           "argoproj.io",            "argocd_",    C.OTHER,      "GitOps & Delivery", "Argo CD Application",     "ARGA"),
    ("ApplicationSet",        "argoproj.io",            "argocd_",    C.OTHER,      "GitOps & Delivery", "Argo CD ApplicationSet",  "ARGS"),
    ("AppProject",            "argoproj.io",            "argocd_",    C.IAM,        "GitOps & Delivery", "Argo CD AppProject",      "ARGP"),
    ("Rollout",               "argoproj.io",            "argo_",      C.CONTAINER,  "GitOps & Delivery", "Argo Rollout",            "ROLL"),
    ("Workflow",              "argoproj.io",            "argo_",      C.CONTAINER,  "GitOps & Delivery", "Argo Workflow",           "AWF"),
    ("Kustomization",         "kustomize.toolkit.fluxcd.io", "flux_", C.OTHER,      "GitOps & Delivery", "Flux Kustomization",      "FLXK"),
    ("HelmRelease",           "helm.toolkit.fluxcd.io", "flux_",      C.OTHER,      "GitOps & Delivery", "Flux HelmRelease",        "FLXH"),
    ("GitRepository",         "source.toolkit.fluxcd.io", "flux_",    C.OTHER,      "GitOps & Delivery", "Flux GitRepository",      "FLXG"),
    ("Service",               "serving.knative.dev",    "knative_",   C.SERVERLESS, "Serverless",      "Knative Service",           "KN"),
    ("Trigger",               "eventing.knative.dev",   "knative_",   C.QUEUE,      "Serverless",      "Knative Trigger",           "KNT"),
    ("Broker",                "eventing.knative.dev",   "knative_",   C.QUEUE,      "Serverless",      "Knative Broker",            "KNB"),
    ("ClusterPolicy",         "kyverno.io",             "kyverno_",   C.IAM,        "Policy Engines",  "Kyverno ClusterPolicy",     "KYV"),
    ("Policy",                "kyverno.io",             "kyverno_",   C.IAM,        "Policy Engines",  "Kyverno Policy",            "KYVP"),
    ("ConstraintTemplate",    "templates.gatekeeper.sh","gatekeeper_",C.IAM,        "Policy Engines",  "Gatekeeper ConstraintTemplate", "GK"),
    ("Backup",                "velero.io",              "velero_",    C.OTHER,      "Backup & DR",     "Velero Backup",             "VEL"),
    ("Schedule",              "velero.io",              "velero_",    C.OTHER,      "Backup & DR",     "Velero Schedule",           "VELS"),
    ("Cluster",               "postgresql.cnpg.io",     "cnpg_",      C.DATABASE,   "Data Operators",  "CloudNativePG Cluster",     "CNPG"),
    ("Kafka",                 "kafka.strimzi.io",       "strimzi_",   C.QUEUE,      "Data Operators",  "Strimzi Kafka",             "STRZ"),
]

_BUILTIN_GROUPS = {group for _, group, *_ in BUILTIN_KINDS}

# (api_group, kind) -> (service id, component type)
_ECOSYSTEM_INDEX = {(group, kind): (prefix + kind.lower(), ctype)
                    for kind, group, prefix, ctype, *_ in ECOSYSTEM_KINDS}
_BUILTIN_INDEX = {kind: ctype for kind, _, ctype, *_ in BUILTIN_KINDS}


def api_group(api_version: str) -> str:
    """'apps/v1' -> 'apps'; 'v1' -> '' (the core group)."""
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def classify(kind: str, api_version: str) -> tuple[str, C, bool]:
    """(service id, component type, is_builtin) for a manifest's kind.

    A kind from a known CRD group is never treated as the built-in kind of
    the same name. An unknown CRD keeps kind.lower() but is typed OTHER so no
    built-in check is pointed at it.
    """
    group = api_group(api_version)
    eco = _ECOSYSTEM_INDEX.get((group, kind))
    if eco:
        return eco[0], eco[1], False
    if kind in _BUILTIN_INDEX and (group in _BUILTIN_GROUPS or group.endswith(".k8s.io")):
        return kind.lower(), _BUILTIN_INDEX[kind], True
    if kind in _BUILTIN_INDEX and not api_version:
        return kind.lower(), _BUILTIN_INDEX[kind], True
    return kind.lower(), C.OTHER, False
