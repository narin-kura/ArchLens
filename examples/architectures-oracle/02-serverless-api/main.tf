# ArchLens reference architecture 02 (OCI) — Serverless API
#
# API Gateway in front of OCI Functions, NoSQL for request-scoped data, and
# an OCI Queue (with a dead-letter limit) for deferred work. Functions can't
# run outside a VCN, so even the "serverless" tier sits in a private subnet.
#
# OCI WAF attaches only to load balancers, so the API gateway is private and
# a public load balancer carrying the WAF forwards to it.
#
# Services: Load Balancer, WAF, API Gateway (private gateway + deployment),
# Functions (application + functions), NoSQL Database, Queue, Vault (KMS +
# secret), Logging, Monitoring, Notifications.
#
# Expected ArchLens findings: the edge load balancer NSG intentionally
# accepts 0.0.0.0/0 on 443 — that is the API's public entry point.
# Everything else should come back clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "api_image" {}
variable "worker_image" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.10.0.0/16"]
  display_name   = "vcn-serverless"
}

resource "oci_core_subnet" "gateway" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  cidr_block     = "10.10.0.0/24"
  display_name   = "snet-apigw"
}

resource "oci_core_subnet" "functions" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.10.1.0/24"
  display_name               = "snet-functions"
  prohibit_public_ip_on_vnic = true
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-serverless"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "data" {
  compartment_id      = var.compartment_id
  display_name        = "key-serverless"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_vault_secret" "third_party_api_key" {
  compartment_id = var.compartment_id
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.data.id
  secret_name    = "third-party-api-key"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("populated-out-of-band")
  }
}

# --------------------------------------------------------------------- Data

resource "oci_nosql_table" "orders" {
  compartment_id = var.compartment_id
  name           = "orders"
  ddl_statement  = "CREATE TABLE IF NOT EXISTS orders (id STRING, payload JSON, PRIMARY KEY(id))"

  table_limits {
    capacity_mode = "ON_DEMAND"
    max_storage_in_gbs = 25
  }
}

resource "oci_queue_queue" "deferred" {
  compartment_id                   = var.compartment_id
  display_name                     = "deferred-work"
  retention_in_seconds             = 86400
  visibility_in_seconds            = 60
  dead_letter_queue_delivery_count = 5
  custom_encryption_key_id         = oci_kms_key.data.id
}

# ------------------------------------------------------------------ Compute

resource "oci_functions_application" "api" {
  compartment_id = var.compartment_id
  display_name   = "serverless-api"
  subnet_ids     = [oci_core_subnet.functions.id]
}

resource "oci_functions_function" "api" {
  application_id     = oci_functions_application.api.id
  display_name       = "api"
  image              = var.api_image
  memory_in_mbs      = 512
  timeout_in_seconds = 30
}

resource "oci_functions_function" "worker" {
  application_id     = oci_functions_application.api.id
  display_name       = "worker"
  image              = var.worker_image
  memory_in_mbs      = 512
  timeout_in_seconds = 120
}

# ---------------------------------------------------------------------- Edge

# OCI WAF attaches only to load balancers, so the gateway is private and a
# public load balancer carrying the WAF forwards to its private IP — Oracle's
# documented pattern for putting a WAF in front of API Gateway.
resource "oci_apigateway_gateway" "main" {
  compartment_id = var.compartment_id
  display_name   = "api-gateway"
  endpoint_type  = "PRIVATE"
  subnet_id      = oci_core_subnet.gateway.id
}

resource "oci_core_subnet" "edge" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  cidr_block     = "10.10.2.0/24"
  display_name   = "snet-edge"
}

resource "oci_core_network_security_group" "edge" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-edge"
}

resource "oci_core_network_security_group_security_rule" "edge_https_in" {
  network_security_group_id = oci_core_network_security_group.edge.id
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

resource "oci_load_balancer_load_balancer" "edge" {
  compartment_id             = var.compartment_id
  display_name               = "lb-api-edge"
  shape                      = "flexible"
  subnet_ids                 = [oci_core_subnet.edge.id]
  network_security_group_ids = [oci_core_network_security_group.edge.id]

  shape_details {
    minimum_bandwidth_in_mbps = 10
    maximum_bandwidth_in_mbps = 100
  }
}

resource "oci_load_balancer_certificate" "edge" {
  load_balancer_id   = oci_load_balancer_load_balancer.edge.id
  certificate_name   = "api-cert"
  public_certificate = file("api.crt")
  private_key        = file("api.key")
}

resource "oci_load_balancer_backend_set" "gateway" {
  load_balancer_id = oci_load_balancer_load_balancer.edge.id
  name             = "api-gateway"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol = "TCP"
    port     = 443
  }

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.edge.certificate_name
    verify_peer_certificate = false
  }
}

resource "oci_load_balancer_backend" "gateway" {
  load_balancer_id = oci_load_balancer_load_balancer.edge.id
  backendset_name  = oci_load_balancer_backend_set.gateway.name
  ip_address       = oci_apigateway_gateway.main.ip_addresses[0].ip_address
  port             = 443
}

resource "oci_load_balancer_listener" "https" {
  load_balancer_id         = oci_load_balancer_load_balancer.edge.id
  name                     = "https"
  default_backend_set_name = oci_load_balancer_backend_set.gateway.name
  port                     = 443
  protocol                 = "HTTP"

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.edge.certificate_name
    protocols               = ["TLSv1.2", "TLSv1.3"]
    verify_peer_certificate = false
  }
}

resource "oci_waf_web_app_firewall_policy" "edge" {
  compartment_id = var.compartment_id
  display_name   = "waf-policy-api"
}

resource "oci_waf_web_app_firewall" "edge" {
  compartment_id             = var.compartment_id
  display_name               = "waf-api"
  backend_type               = "LOAD_BALANCER"
  load_balancer_id           = oci_load_balancer_load_balancer.edge.id
  web_app_firewall_policy_id = oci_waf_web_app_firewall_policy.edge.id
}

resource "oci_apigateway_deployment" "v1" {
  compartment_id = var.compartment_id
  gateway_id     = oci_apigateway_gateway.main.id
  path_prefix    = "/v1"
  display_name   = "api-v1"

  specification {
    logging_policies {
      access_log {
        is_enabled = true
      }

      execution_log {
        is_enabled = true
        log_level  = "INFO"
      }
    }

    request_policies {
      authentication {
        type                        = "JWT_AUTHENTICATION"
        token_header                = "Authorization"
        token_auth_scheme           = "Bearer"
        is_anonymous_access_allowed = false
        issuers                     = ["https://idcs.example.com"]
        audiences                   = ["serverless-api"]

        public_keys {
          type = "REMOTE_JWKS"
          uri  = "https://idcs.example.com/admin/v1/SigningCert/jwk"
        }
      }

      rate_limiting {
        rate_in_requests_per_second = 100
        rate_key                    = "CLIENT_IP"
      }
    }

    routes {
      path    = "/orders"
      methods = ["GET", "POST"]

      backend {
        type        = "ORACLE_FUNCTIONS_BACKEND"
        function_id = oci_functions_function.api.id
      }
    }
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-serverless"
}

resource "oci_logging_log" "functions" {
  display_name = "functions-invoke"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "invoke"
      resource    = oci_functions_application.api.id
      service     = "functions"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "serverless-alerts"
}

resource "oci_monitoring_alarm" "function_errors" {
  compartment_id        = var.compartment_id
  display_name          = "function-errors"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_faas"
  query                 = "FunctionInvocationCount[5m]{status = \"error\"}.sum() > 10"
  severity              = "CRITICAL"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
