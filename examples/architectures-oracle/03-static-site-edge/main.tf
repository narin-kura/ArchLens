# ArchLens reference architecture 03 (OCI) — Static site at the edge
#
# OCI has no CloudFront-style CDN for arbitrary origins, and a load balancer
# can't use a bucket as a backend (backends are IP:port). Oracle's pattern:
# the bucket stays private and is read through a list-denied pre-authenticated
# request; a private API Gateway proxies that PAR; and a public load balancer
# carrying Web App Acceleration (caching + gzip) and WAF forwards to the
# gateway's private IP. DNS steering health-checks the whole path.
#
# Services: Object Storage (+ pre-authenticated request), API Gateway
# (private), Load Balancer, Web App Acceleration, WAF, DNS Zone + Steering
# Policy, Health Check, Vault (KMS), Logging.
#
# Expected ArchLens findings: the load balancer NSG intentionally accepts
# 0.0.0.0/0 on 443, and the gateway intentionally allows anonymous access —
# a public website has neither a restricted audience nor a login. Everything
# else should come back clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "tenancy_namespace" {}
variable "region" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.20.0.0/16"]
  display_name   = "vcn-static-site"
}

resource "oci_core_subnet" "edge" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  cidr_block     = "10.20.0.0/24"
  display_name   = "snet-edge"
}

resource "oci_core_subnet" "gateway" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.20.1.0/24"
  display_name               = "snet-gateway"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "edge" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-edge"
}

resource "oci_core_network_security_group_security_rule" "https_in" {
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

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-static-site"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "site" {
  compartment_id      = var.compartment_id
  display_name        = "key-static-site"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# ------------------------------------------------------------------ Content

resource "oci_objectstorage_bucket" "site" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "static-site"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.site.id
}

resource "oci_objectstorage_preauthrequest" "site_read" {
  namespace             = var.tenancy_namespace
  bucket                = oci_objectstorage_bucket.site.name
  name                  = "site-read"
  access_type           = "AnyObjectRead"
  bucket_listing_action = "Deny"
  time_expires          = "2027-12-31T00:00:00Z"
}

# ------------------------------------------------------------------ Gateway

resource "oci_apigateway_gateway" "site" {
  compartment_id = var.compartment_id
  display_name   = "gw-static-site"
  endpoint_type  = "PRIVATE"
  subnet_id      = oci_core_subnet.gateway.id
}

resource "oci_apigateway_deployment" "site" {
  compartment_id = var.compartment_id
  gateway_id     = oci_apigateway_gateway.site.id
  path_prefix    = "/"
  display_name   = "static-site"

  specification {
    logging_policies {
      access_log {
        is_enabled = true
      }
    }

    request_policies {
      rate_limiting {
        rate_in_requests_per_second = 200
        rate_key                    = "CLIENT_IP"
      }
    }

    routes {
      path    = "/{object*}"
      methods = ["GET", "HEAD"]

      backend {
        type = "HTTP_BACKEND"
        url  = "https://objectstorage.${var.region}.oraclecloud.com${oci_objectstorage_preauthrequest.site_read.access_uri}$${request.path[object]}"
      }
    }
  }
}

# --------------------------------------------------------------------- Edge

resource "oci_load_balancer_load_balancer" "site" {
  compartment_id             = var.compartment_id
  display_name               = "lb-static-site"
  shape                      = "flexible"
  subnet_ids                 = [oci_core_subnet.edge.id]
  network_security_group_ids = [oci_core_network_security_group.edge.id]

  shape_details {
    minimum_bandwidth_in_mbps = 10
    maximum_bandwidth_in_mbps = 100
  }
}

resource "oci_load_balancer_certificate" "site" {
  load_balancer_id   = oci_load_balancer_load_balancer.site.id
  certificate_name   = "site-cert"
  public_certificate = file("site.crt")
  private_key        = file("site.key")
}

resource "oci_load_balancer_backend_set" "gateway" {
  load_balancer_id = oci_load_balancer_load_balancer.site.id
  name             = "gateway"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol = "TCP"
    port     = 443
  }

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.site.certificate_name
    verify_peer_certificate = false
  }
}

resource "oci_load_balancer_backend" "gateway" {
  load_balancer_id = oci_load_balancer_load_balancer.site.id
  backendset_name  = oci_load_balancer_backend_set.gateway.name
  ip_address       = oci_apigateway_gateway.site.ip_addresses[0].ip_address
  port             = 443
}

resource "oci_load_balancer_listener" "https" {
  load_balancer_id         = oci_load_balancer_load_balancer.site.id
  name                     = "https"
  default_backend_set_name = oci_load_balancer_backend_set.gateway.name
  port                     = 443
  protocol                 = "HTTP"

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.site.certificate_name
    protocols               = ["TLSv1.2", "TLSv1.3"]
    verify_peer_certificate = false
  }
}

resource "oci_waa_web_app_acceleration_policy" "site" {
  compartment_id = var.compartment_id
  display_name   = "waa-policy-static-site"

  response_caching_policy {
    is_response_header_based_caching_enabled = true
  }

  response_compression_policy {
    gzip_compression {
      is_enabled = true
    }
  }
}

resource "oci_waa_web_app_acceleration" "site" {
  compartment_id                 = var.compartment_id
  display_name                   = "waa-static-site"
  backend_type                   = "LOAD_BALANCER"
  load_balancer_id               = oci_load_balancer_load_balancer.site.id
  web_app_acceleration_policy_id = oci_waa_web_app_acceleration_policy.site.id
}

resource "oci_waf_web_app_firewall_policy" "site" {
  compartment_id = var.compartment_id
  display_name   = "waf-policy-static-site"
}

resource "oci_waf_web_app_firewall" "site" {
  compartment_id             = var.compartment_id
  display_name               = "waf-static-site"
  backend_type               = "LOAD_BALANCER"
  load_balancer_id           = oci_load_balancer_load_balancer.site.id
  web_app_firewall_policy_id = oci_waf_web_app_firewall_policy.site.id
}

# ---------------------------------------------------------------------- DNS

resource "oci_dns_zone" "main" {
  compartment_id = var.compartment_id
  name           = "example.com"
  zone_type      = "PRIMARY"
}

resource "oci_health_checks_http_monitor" "site" {
  compartment_id      = var.compartment_id
  display_name        = "site-health"
  interval_in_seconds = 30
  protocol            = "HTTPS"
  targets             = ["www.example.com"]
  path                = "/index.html"
}

resource "oci_dns_steering_policy" "site" {
  compartment_id          = var.compartment_id
  display_name            = "site-failover"
  template                = "FAILOVER"
  health_check_monitor_id = oci_health_checks_http_monitor.site.id
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-static-site"
}

resource "oci_logging_log" "site_reads" {
  display_name = "site-object-reads"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.site.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}
