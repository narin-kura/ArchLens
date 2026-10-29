# ArchLens reference architecture 14 (OCI) — Workforce applications
#
# Employees get managed virtual desktops from OCI Secure Desktops, signed in
# through a dedicated Identity Domain (MFA and SSO live there). Desktops are
# private-access only, clipboard / drive mapping / printing are locked down,
# idle sessions disconnect and disconnected ones stop, and the desktop pool
# shuts off outside working hours. Admins reach the private subnet only
# through the Bastion service, never through a public IP.
#
# Services: Secure Desktops (pool), Identity Domain, Bastion, VCN + private
# subnet + NSG, Vault (KMS), Logging, Monitoring, Notifications.
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
variable "desktop_image_id" {}
variable "desktop_backup_policy_id" {}
variable "domain_license_type" {}
variable "corporate_egress_cidr" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.110.0.0/16"]
  display_name   = "vcn-workforce"
}

resource "oci_core_subnet" "desktops" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.110.0.0/22"
  display_name               = "snet-desktops"
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "desktops" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "nsg-desktops"
}

resource "oci_core_network_security_group_security_rule" "desktops_internal" {
  network_security_group_id = oci_core_network_security_group.desktops.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.110.0.0/16"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

# ---------------------------------------------------------------- Identity

resource "oci_identity_domain" "workforce" {
  compartment_id = var.compartment_id
  display_name   = "workforce"
  description    = "Employee sign-in for desktops and internal apps"
  home_region    = "us-ashburn-1"
  license_type   = var.domain_license_type
}

# ---------------------------------------------------------------- Desktops

resource "oci_desktops_desktop_pool" "engineering" {
  compartment_id           = var.compartment_id
  display_name             = "engineering"
  availability_domain      = var.availability_domain
  shape_name               = "Flex Low"
  maximum_size             = 50
  standby_size             = 5
  are_privileged_users     = false
  is_storage_enabled       = true
  storage_size_in_gbs      = 100
  storage_backup_policy_id = var.desktop_backup_policy_id
  contact_details          = "it-desktops@example.com"
  nsg_ids                  = [oci_core_network_security_group.desktops.id]

  image {
    image_id   = var.desktop_image_id
    image_name = "engineering-workstation"
  }

  network_configuration {
    vcn_id    = oci_core_vcn.main.id
    subnet_id = oci_core_subnet.desktops.id
  }

  private_access_details {
    subnet_id = oci_core_subnet.desktops.id
    nsg_ids   = [oci_core_network_security_group.desktops.id]
  }

  device_policy {
    audio_mode          = "TODESKTOP"
    clipboard_mode      = "NONE"
    cdm_mode            = "NONE"
    is_display_enabled  = true
    is_keyboard_enabled = true
    is_pointer_enabled  = true
    is_printing_enabled = false
  }

  availability_policy {
    start_schedule {
      cron_expression = "0 7 * * 1-5"
      timezone        = "America/New_York"
    }

    stop_schedule {
      cron_expression = "0 20 * * 1-5"
      timezone        = "America/New_York"
    }
  }

  session_lifecycle_actions {
    inactivity {
      action                  = "DISCONNECT"
      grace_period_in_minutes = 30
    }

    disconnect {
      action                  = "STOP"
      grace_period_in_minutes = 60
    }
  }
}

# ------------------------------------------------------------- Admin access

resource "oci_bastion_bastion" "admin" {
  compartment_id               = var.compartment_id
  name                         = "workforce-admin"
  bastion_type                 = "standard"
  target_subnet_id             = oci_core_subnet.desktops.id
  client_cidr_block_allow_list = [var.corporate_egress_cidr]
  max_session_ttl_in_seconds   = 3600
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-workforce"
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "workforce-alerts"
}

resource "oci_monitoring_alarm" "pool_capacity" {
  compartment_id        = var.compartment_id
  display_name          = "desktop-pool-near-capacity"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_secure_desktops"
  query                 = "DesktopPoolUtilization[15m].max() > 90"
  severity              = "WARNING"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
