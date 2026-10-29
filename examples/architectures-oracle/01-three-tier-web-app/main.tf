# ArchLens reference architecture 01 (OCI) — Three-tier web application
#
# The classic production web stack on Oracle Cloud: a public flexible load
# balancer behind a Web Application Firewall, an autoscaling instance pool of
# app servers in a private subnet, and an Autonomous Database reachable only
# through a private endpoint. Secure-by-default: customer-managed Vault keys,
# no public IPs below the load balancer, legacy IMDS endpoints disabled, and
# every tier shipping logs.
#
# Services: VCN, Subnets, Internet/NAT/Service Gateways, Route Tables, NSGs,
# Load Balancer, WAF, Instance Configuration, Instance Pool, Autoscaling,
# Autonomous Database, Object Storage, Vault (KMS), Logging, Monitoring,
# Notifications.
#
# Expected ArchLens findings: the load balancer NSG intentionally accepts
# 0.0.0.0/0 on 443 — that is what a public web tier is for. Everything else
# should come back clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "tenancy_namespace" {}
variable "availability_domain" {}
variable "app_image_id" {}
variable "service_cidr" {}
variable "service_id" {}

# ------------------------------------------------------------------- Network

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "vcn-three-tier"
  dns_label      = "threetier"
}

resource "oci_core_internet_gateway" "main" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "igw-three-tier"
}

resource "oci_core_nat_gateway" "main" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nat-three-tier"
}

resource "oci_core_service_gateway" "main" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "sgw-three-tier"

  services {
    service_id = var.service_id
  }
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "rt-public"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.main.id
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

  route_rules {
    destination       = var.service_cidr
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = oci_core_service_gateway.main.id
  }
}

resource "oci_core_subnet" "lb" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  cidr_block     = "10.0.0.0/24"
  display_name   = "snet-lb"
  route_table_id = oci_core_route_table.public.id
}

resource "oci_core_subnet" "app" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.0.1.0/24"
  display_name               = "snet-app"
  route_table_id             = oci_core_route_table.private.id
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_subnet" "data" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.0.2.0/24"
  display_name               = "snet-data"
  route_table_id             = oci_core_route_table.private.id
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "lb" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-lb"
}

resource "oci_core_network_security_group_security_rule" "lb_https_in" {
  network_security_group_id = oci_core_network_security_group.lb.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

resource "oci_core_network_security_group" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-app"
}

resource "oci_core_network_security_group_security_rule" "app_from_lb" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.lb.id
  source_type               = "NETWORK_SECURITY_GROUP"

  tcp_options {
    destination_port_range {
      min = 8443
      max = 8443
    }
  }
}

resource "oci_core_network_security_group" "db" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-db"
}

resource "oci_core_network_security_group_security_rule" "db_from_app" {
  network_security_group_id = oci_core_network_security_group.db.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.app.id
  source_type               = "NETWORK_SECURITY_GROUP"

  tcp_options {
    destination_port_range {
      min = 1522
      max = 1522
    }
  }
}

# --------------------------------------------------------------------- Keys

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-three-tier"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "data" {
  compartment_id      = var.compartment_id
  display_name        = "key-data"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# --------------------------------------------------------------- Application

resource "oci_core_instance_configuration" "app" {
  compartment_id = var.compartment_id
  display_name   = "app-config"

  instance_details {
    instance_type = "compute"

    launch_details {
      compartment_id = var.compartment_id
      shape          = "VM.Standard.E5.Flex"

      shape_config {
        ocpus         = 2
        memory_in_gbs = 16
      }

      create_vnic_details {
        subnet_id        = oci_core_subnet.app.id
        assign_public_ip = false
        nsg_ids          = [oci_core_network_security_group.app.id]
      }

      instance_options {
        are_legacy_imds_endpoints_disabled = true
      }

      is_pv_encryption_in_transit_enabled = true

      source_details {
        source_type = "image"
        image_id    = var.app_image_id
        kms_key_id  = oci_kms_key.data.id
      }
    }
  }
}

resource "oci_core_instance_pool" "app" {
  compartment_id            = var.compartment_id
  instance_configuration_id = oci_core_instance_configuration.app.id
  size                      = 3
  display_name              = "app-pool"

  placement_configurations {
    availability_domain = var.availability_domain
    primary_subnet_id   = oci_core_subnet.app.id
  }

  load_balancers {
    backend_set_name = oci_load_balancer_backend_set.app.name
    load_balancer_id = oci_load_balancer_load_balancer.public.id
    port             = 8443
    vnic_selection   = "PrimaryVnic"
  }
}

resource "oci_autoscaling_auto_scaling_configuration" "app" {
  compartment_id       = var.compartment_id
  display_name         = "app-autoscaling"
  cool_down_in_seconds = 300

  auto_scaling_resources {
    id   = oci_core_instance_pool.app.id
    type = "instancePool"
  }

  policies {
    policy_type  = "threshold"
    display_name = "cpu"

    capacity {
      initial = 3
      min     = 3
      max     = 10
    }

    rules {
      display_name = "scale-out"

      action {
        type  = "CHANGE_COUNT_BY"
        value = 1
      }

      metric {
        metric_type = "CPU_UTILIZATION"

        threshold {
          operator = "GT"
          value    = 70
        }
      }
    }

    rules {
      display_name = "scale-in"

      action {
        type  = "CHANGE_COUNT_BY"
        value = -1
      }

      metric {
        metric_type = "CPU_UTILIZATION"

        threshold {
          operator = "LT"
          value    = 25
        }
      }
    }
  }
}

# ---------------------------------------------------------------- Edge / LB

resource "oci_load_balancer_load_balancer" "public" {
  compartment_id             = var.compartment_id
  display_name               = "lb-public"
  shape                      = "flexible"
  subnet_ids                 = [oci_core_subnet.lb.id]
  network_security_group_ids = [oci_core_network_security_group.lb.id]
  is_private                 = false

  shape_details {
    minimum_bandwidth_in_mbps = 10
    maximum_bandwidth_in_mbps = 400
  }
}

resource "oci_load_balancer_backend_set" "app" {
  load_balancer_id = oci_load_balancer_load_balancer.public.id
  name             = "app-backends"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol = "HTTP"
    port     = 8443
    url_path = "/health"
  }

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.app.certificate_name
    verify_peer_certificate = false
  }
}

resource "oci_load_balancer_certificate" "app" {
  load_balancer_id   = oci_load_balancer_load_balancer.public.id
  certificate_name   = "app-cert"
  public_certificate = file("app.crt")
  private_key        = file("app.key")
}

resource "oci_load_balancer_listener" "https" {
  load_balancer_id         = oci_load_balancer_load_balancer.public.id
  name                     = "https"
  default_backend_set_name = oci_load_balancer_backend_set.app.name
  port                     = 443
  protocol                 = "HTTP"

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.app.certificate_name
    protocols               = ["TLSv1.2", "TLSv1.3"]
    verify_peer_certificate = false
  }
}

resource "oci_waf_web_app_firewall_policy" "main" {
  compartment_id = var.compartment_id
  display_name   = "waf-policy"

  actions {
    name = "block"
    type = "RETURN_HTTP_RESPONSE"
    code = 403
  }

  request_protection {
    rules {
      name        = "owasp-top10"
      type        = "PROTECTION"
      action_name = "block"

      protection_capabilities {
        key     = "9300000"
        version = 1
      }
    }
  }
}

resource "oci_waf_web_app_firewall" "main" {
  compartment_id             = var.compartment_id
  display_name               = "waf-lb"
  backend_type               = "LOAD_BALANCER"
  load_balancer_id           = oci_load_balancer_load_balancer.public.id
  web_app_firewall_policy_id = oci_waf_web_app_firewall_policy.main.id
}

# -------------------------------------------------------------------- Data

resource "oci_database_autonomous_database" "app" {
  compartment_id              = var.compartment_id
  db_name                     = "appdb"
  display_name                = "adb-app"
  db_workload                 = "OLTP"
  compute_model               = "ECPU"
  compute_count               = 4
  data_storage_size_in_tbs    = 1
  is_auto_scaling_enabled     = true
  subnet_id                   = oci_core_subnet.data.id
  nsg_ids                     = [oci_core_network_security_group.db.id]
  is_mtls_connection_required = true
  is_local_data_guard_enabled = true
  kms_key_id                  = oci_kms_key.data.id
  vault_id                    = oci_kms_vault.main.id
}

resource "oci_objectstorage_bucket" "assets" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "three-tier-assets"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.data.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-three-tier"
}

resource "oci_logging_log" "assets_access" {
  display_name = "assets-access"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.assets.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_logging_log" "lb_access" {
  display_name = "lb-access"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "access"
      resource    = oci_load_balancer_load_balancer.public.id
      service     = "loadbalancer"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "three-tier-alerts"
}

resource "oci_monitoring_alarm" "app_cpu" {
  compartment_id        = var.compartment_id
  display_name          = "app-cpu-high"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_computeagent"
  query                 = "CpuUtilization[5m].mean() > 85"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
