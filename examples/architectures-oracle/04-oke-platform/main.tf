# ArchLens reference architecture 04 (OCI) — OKE Kubernetes platform
#
# A private Oracle Kubernetes Engine cluster: the API endpoint has no public
# IP, Kubernetes secrets are encrypted with a Vault key, and image signature
# verification means only images signed by the release key can run. Nodes
# sit in a private subnet with in-transit volume encryption; the Cluster
# Autoscaler add-on sizes the node pool. OCIR repositories are private and
# immutable and continuously scanned for vulnerabilities.
#
# Services: VCN, Subnets, NAT/Service Gateways, NSGs, OKE (cluster, node
# pool, Cluster Autoscaler add-on), Container Registry, Vulnerability
# Scanning, Autonomous Database, Vault (KMS), Logging, Monitoring.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "availability_domain" {}
variable "node_image_id" {}
variable "service_id" {}

# ------------------------------------------------------------------- Network

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.30.0.0/16"]
  display_name   = "vcn-oke"
}

resource "oci_core_nat_gateway" "main" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nat-oke"
}

resource "oci_core_service_gateway" "main" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "sgw-oke"

  services {
    service_id = var.service_id
  }
}

resource "oci_core_route_table" "private" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "rt-private"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_nat_gateway.main.id
  }
}

resource "oci_core_subnet" "api" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.30.0.0/28"
  display_name               = "snet-k8s-api"
  route_table_id             = oci_core_route_table.private.id
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_subnet" "nodes" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.30.16.0/20"
  display_name               = "snet-nodes"
  route_table_id             = oci_core_route_table.private.id
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "api" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-k8s-api"
}

resource "oci_core_network_security_group_security_rule" "api_from_nodes" {
  network_security_group_id = oci_core_network_security_group.api.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.30.16.0/20"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 6443
      max = 6443
    }
  }
}

resource "oci_core_network_security_group" "nodes" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-nodes"
}

resource "oci_core_network_security_group_security_rule" "nodes_from_vcn" {
  network_security_group_id = oci_core_network_security_group.nodes.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = "10.30.0.0/16"
  source_type               = "CIDR_BLOCK"
}

# --------------------------------------------------------------------- Keys

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-oke"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "secrets" {
  compartment_id      = var.compartment_id
  display_name        = "key-k8s-secrets"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_kms_key" "image_signing" {
  compartment_id      = var.compartment_id
  display_name        = "key-image-signing"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "RSA"
    length    = 512
  }
}

# ----------------------------------------------------------------- Cluster

resource "oci_containerengine_cluster" "main" {
  compartment_id     = var.compartment_id
  name               = "oke-platform"
  kubernetes_version = "v1.31.1"
  vcn_id             = oci_core_vcn.main.id
  kms_key_id         = oci_kms_key.secrets.id
  type               = "ENHANCED_CLUSTER"

  endpoint_config {
    is_public_ip_enabled = false
    subnet_id            = oci_core_subnet.api.id
    nsg_ids              = [oci_core_network_security_group.api.id]
  }

  cluster_pod_network_options {
    cni_type = "OCI_VCN_IP_NATIVE"
  }

  image_policy_config {
    is_policy_enabled = true

    key_details {
      kms_key_id = oci_kms_key.image_signing.id
    }
  }
}

resource "oci_containerengine_node_pool" "general" {
  cluster_id         = oci_containerengine_cluster.main.id
  compartment_id     = var.compartment_id
  name               = "general"
  kubernetes_version = "v1.31.1"
  node_shape         = "VM.Standard.E5.Flex"

  node_shape_config {
    ocpus         = 4
    memory_in_gbs = 32
  }

  node_source_details {
    source_type = "IMAGE"
    image_id    = var.node_image_id
  }

  node_config_details {
    size                                = 3
    is_pv_encryption_in_transit_enabled = true
    kms_key_id                          = oci_kms_key.secrets.id
    nsg_ids                             = [oci_core_network_security_group.nodes.id]

    placement_configs {
      availability_domain = var.availability_domain
      subnet_id           = oci_core_subnet.nodes.id
    }
  }
}

resource "oci_containerengine_addon" "autoscaler" {
  cluster_id                       = oci_containerengine_cluster.main.id
  addon_name                       = "ClusterAutoscaler"
  remove_addon_resources_on_delete = true

  configurations {
    key   = "nodes"
    value = "3:12:${oci_containerengine_node_pool.general.id}"
  }
}

# ---------------------------------------------------------------- Registry

resource "oci_artifacts_container_repository" "app" {
  compartment_id = var.compartment_id
  display_name   = "platform/app"
  is_public      = false
  is_immutable   = true
}

resource "oci_vulnerability_scanning_container_scan_recipe" "main" {
  compartment_id = var.compartment_id
  display_name   = "oke-image-scan"

  scan_settings {
    scan_level = "STANDARD"
  }

  image_count = 5
}

resource "oci_vulnerability_scanning_container_scan_target" "main" {
  compartment_id           = var.compartment_id
  display_name             = "oke-repos"
  container_scan_recipe_id = oci_vulnerability_scanning_container_scan_recipe.main.id

  target_registry {
    compartment_id = var.compartment_id
    type           = "OCIR"
    repositories   = ["platform/app"]
  }
}

# -------------------------------------------------------------------- Data

resource "oci_database_autonomous_database" "platform" {
  compartment_id              = var.compartment_id
  db_name                     = "platformdb"
  display_name                = "adb-platform"
  db_workload                 = "OLTP"
  compute_model               = "ECPU"
  compute_count               = 4
  data_storage_size_in_tbs    = 1
  subnet_id                   = oci_core_subnet.nodes.id
  nsg_ids                     = [oci_core_network_security_group.nodes.id]
  is_mtls_connection_required = true
  is_local_data_guard_enabled = true
  kms_key_id                  = oci_kms_key.secrets.id
  vault_id                    = oci_kms_vault.main.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-oke"
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "oke-alerts"
}

resource "oci_monitoring_alarm" "node_cpu" {
  compartment_id        = var.compartment_id
  display_name          = "oke-node-cpu"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_computeagent"
  query                 = "CpuUtilization[5m].mean() > 85"
  severity              = "WARNING"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
