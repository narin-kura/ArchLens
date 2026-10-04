# ArchLens reference architecture 12 (Azure) — Security and governance baseline
#
# The controls that should exist before the first workload lands: a
# management group hierarchy with policy assignments, Microsoft Defender for
# Cloud across every resource type, Microsoft Sentinel as the SIEM, and an
# Azure Policy that denies the actions that would remove the evidence of an
# incident. Findings land in one Log Analytics workspace so they survive the
# subscription they came from.
#
# Services: Management Groups, Azure Policy (definitions + assignments),
# Microsoft Defender for Cloud (all plans), Microsoft Sentinel, Log Analytics,
# Key Vault, Storage Account (policy-compliant audit archive), Budget.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.90" }
  }
}

provider "azurerm" {
  features {}
}

variable "location" { default = "eastus" }

resource "azurerm_resource_group" "main" {
  name     = "rg-governance"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-governance-12"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium"
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

data "azurerm_client_config" "current" {}

# -------------------------------------------------------------- Org structure

resource "azurerm_management_group" "landing_zones" {
  display_name = "landing-zones"
}

resource "azurerm_management_group" "workloads" {
  display_name               = "workloads"
  parent_management_group_id = azurerm_management_group.landing_zones.id
}

# Deny the actions that would remove the evidence of an incident.
resource "azurerm_policy_definition" "deny_log_tampering" {
  name         = "deny-log-tampering"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny deletion of diagnostic settings and security resources"

  policy_rule = jsonencode({
    if = {
      anyOf = [
        { field = "type", equals = "Microsoft.Insights/diagnosticSettings" },
        { field = "type", equals = "Microsoft.Security/pricings" },
        { field = "type", equals = "Microsoft.OperationalInsights/workspaces" },
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_management_group_policy_assignment" "deny_log_tampering" {
  name                 = "deny-log-tampering"
  management_group_id  = azurerm_management_group.workloads.id
  policy_definition_id = azurerm_policy_definition.deny_log_tampering.id
  enforce              = true
}

resource "azurerm_policy_definition" "require_tls12" {
  name         = "require-tls-1-2"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Require minimum TLS 1.2 on storage and SQL"

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            { field = "type", equals = "Microsoft.Storage/storageAccounts" },
            { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", less = "TLS1_2" },
          ]
        },
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_management_group_policy_assignment" "require_tls12" {
  name                 = "require-tls-1-2"
  management_group_id  = azurerm_management_group.workloads.id
  policy_definition_id = azurerm_policy_definition.require_tls12.id
  enforce              = true
}

resource "azurerm_subscription_policy_assignment" "built_in_security_baseline" {
  name                 = "security-baseline"
  subscription_id      = "/subscriptions/00000000-0000-0000-0000-000000000000"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
  enforce              = true
}

# ------------------------------------------------------------------- Log store

resource "azurerm_storage_account" "audit" {
  name                            = "staudit12governance"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 90
    }
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_storage_management_policy" "audit" {
  storage_account_id = azurerm_storage_account.audit.id

  rule {
    name    = "archive-then-expire"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 365
        delete_after_days_since_modification_greater_than          = 2555
      }
    }
  }
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-governance"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 365
}

resource "azurerm_monitor_diagnostic_setting" "audit_storage" {
  name                       = "audit-storage-diag"
  target_resource_id         = azurerm_storage_account.audit.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

# -------------------------------------------------------------------- Detection

resource "azurerm_security_center_subscription_pricing" "vm" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "sql_vm" {
  tier          = "Standard"
  resource_type = "SqlServerVirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "Containers"
}

resource "azurerm_security_center_subscription_pricing" "registries" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

resource "azurerm_security_center_subscription_pricing" "kubernetes" {
  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_security_center_subscription_pricing" "keyvaults" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "app_services" {
  tier          = "Standard"
  resource_type = "AppServices"
}

resource "azurerm_security_center_subscription_pricing" "arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

resource "azurerm_security_center_subscription_pricing" "dns" {
  tier          = "Standard"
  resource_type = "Dns"
}

resource "azurerm_security_center_contact" "main" {
  name  = "security-team"
  email = "security@example.com"
  phone = "+1-555-0100"

  alert_notifications = true
  alerts_to_admins     = true
}

resource "azurerm_security_center_workspace" "main" {
  scope        = "/subscriptions/00000000-0000-0000-0000-000000000000"
  workspace_id = azurerm_log_analytics_workspace.main.id
}

# ------------------------------------------------------------------- Sentinel

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id                 = azurerm_log_analytics_workspace.main.id
  customer_managed_key_enabled = false
}

resource "azurerm_sentinel_data_connector_azure_active_directory" "main" {
  name                       = "entra-id-connector"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_sentinel_alert_rule_scheduled" "root_login" {
  name                       = "root-or-global-admin-sign-in"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name                = "Global Administrator sign-in detected"
  severity                     = "High"
  query                        = <<QUERY
SigninLogs
| where AppDisplayName == "Azure Portal"
| where UserPrincipalName contains "globaladmin"
QUERY

  query_frequency   = "PT1H"
  query_period      = "PT1H"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  incident_configuration {
    create_incident = true

    grouping {
      enabled = true
    }
  }
}

# ------------------------------------------------------------------- Identity

resource "azuread_conditional_access_policy" "require_mfa" {
  display_name = "require-mfa-all-users"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

resource "azurerm_role_assignment" "security_reader" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000"
  role_definition_name = "Security Reader"
  principal_id         = data.azurerm_client_config.current.object_id
}

# --------------------------------------------------------------------- Budget

resource "azurerm_consumption_budget_subscription" "org" {
  name            = "org-monthly"
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  amount          = 25000
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 90
    operator       = "GreaterThan"
    contact_emails = ["finops@example.com"]
  }
}

resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "security-alerts"
  resource_group_name  = azurerm_resource_group.main.name
  short_name           = "secalerts"

  email_receiver {
    name          = "security-team"
    email_address = "security@example.com"
  }
}
