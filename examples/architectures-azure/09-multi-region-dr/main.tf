# ArchLens reference architecture 09 (Azure) — Multi-region active/passive DR
#
# Everything stateful replicates continuously to a paired region; everything
# stateless is deployed there too, scaled low. Front Door's priority routing
# fails traffic over without a human in the loop. The point of the pattern is
# that failover is a routing change, not a restore-from-backup project.
#
# Services: Azure SQL auto-failover group, Cosmos DB multi-region with
# automatic failover, Storage (RA-GRS), Front Door priority routing, Recovery
# Services Vault with cross-region backup, Key Vault (multi-region via
# replicated secrets), Log Analytics.
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

# East US / West US is an Azure-paired region: platform maintenance is
# sequenced across the pair, and Storage/SQL geo-replication always targets
# the paired region automatically.
variable "primary_location" { default = "eastus" }
variable "secondary_location" { default = "westus" }

resource "azurerm_resource_group" "primary" {
  name     = "rg-dr-primary"
  location = var.primary_location
}

resource "azurerm_resource_group" "secondary" {
  name     = "rg-dr-secondary"
  location = var.secondary_location
}

resource "azurerm_key_vault" "primary" {
  name                       = "kv-dr-primary-09"
  resource_group_name         = azurerm_resource_group.primary.name
  location                    = azurerm_resource_group.primary.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium"
  purge_protection_enabled    = true
  soft_delete_retention_days  = 30
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

data "azurerm_client_config" "current" {}

# ------------------------------------------------------------------- Database

resource "azurerm_mssql_server" "primary" {
  name                         = "sql-dr-primary"
  resource_group_name           = azurerm_resource_group.primary.name
  location                      = azurerm_resource_group.primary.location
  version                       = "12.0"
  minimum_tls_version            = "1.2"
  public_network_access_enabled  = false

  azuread_administrator {
    login_username = "sql-admins"
    object_id       = data.azurerm_client_config.current.object_id
  }

  identity {
    type = "SystemAssigned"
  }

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.primary.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.primary.primary_access_key
    storage_account_access_key_is_secondary = false
    retention_in_days                       = 90
  }
}

resource "azurerm_mssql_server" "secondary" {
  name                         = "sql-dr-secondary"
  resource_group_name           = azurerm_resource_group.secondary.name
  location                      = azurerm_resource_group.secondary.location
  version                       = "12.0"
  minimum_tls_version            = "1.2"
  public_network_access_enabled  = false

  azuread_administrator {
    login_username = "sql-admins"
    object_id       = data.azurerm_client_config.current.object_id
  }

  identity {
    type = "SystemAssigned"
  }

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.secondary.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.secondary.primary_access_key
    storage_account_access_key_is_secondary = false
    retention_in_days                       = 90
  }
}

resource "azurerm_mssql_database" "primary" {
  name           = "appdb"
  server_id      = azurerm_mssql_server.primary.id
  sku_name       = "S2"
  zone_redundant = true

  short_term_retention_policy {
    retention_days = 14
  }

  long_term_retention_policy {
    weekly_retention  = "P8W"
    monthly_retention = "P12M"
  }
}

# The failover group replicates the database to the secondary server and
# manages the listener endpoint — application connection strings target the
# group's DNS name, never a specific server, so failover needs no app change.
resource "azurerm_mssql_failover_group" "main" {
  name      = "sqlfg-dr-appdb"
  server_id = azurerm_mssql_server.primary.id

  databases = [azurerm_mssql_database.primary.id]

  partner_server {
    id = azurerm_mssql_server.secondary.id
  }

  read_write_endpoint_failover_policy {
    mode          = "Automatic"
    grace_minutes = 60
  }
}

# --------------------------------------------------------------------- Cosmos

resource "azurerm_cosmosdb_account" "main" {
  name                           = "cosmos-dr-09"
  resource_group_name             = azurerm_resource_group.primary.name
  location                        = azurerm_resource_group.primary.location
  offer_type                      = "Standard"
  kind                             = "GlobalDocumentDB"
  public_network_access_enabled    = false
  local_authentication_disabled    = true

  enable_automatic_failover = true
  enable_multiple_write_locations = false

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.primary.location
    failover_priority = 0
  }

  geo_location {
    location          = azurerm_resource_group.secondary.location
    failover_priority = 1
  }

  backup {
    type = "Continuous"
    tier = "Continuous30Days"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cosmosdb_sql_database" "app" {
  name                = "app"
  resource_group_name  = azurerm_resource_group.primary.name
  account_name         = azurerm_cosmosdb_account.main.name
}

resource "azurerm_cosmosdb_sql_container" "sessions" {
  name                  = "sessions"
  resource_group_name    = azurerm_resource_group.primary.name
  account_name           = azurerm_cosmosdb_account.main.name
  database_name          = azurerm_cosmosdb_sql_database.app.name
  partition_key_paths    = ["/userId"]
  default_ttl            = -1
}

# -------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "primary" {
  name                            = "stdrprimary09"
  resource_group_name              = azurerm_resource_group.primary.name
  location                         = azurerm_resource_group.primary.location
  account_tier                     = "Standard"
  account_replication_type         = "RAGZRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_storage_management_policy" "primary" {
  storage_account_id = azurerm_storage_account.primary.id

  rule {
    name    = "archive-old-data"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 30
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage_primary" {
  name                       = "storage-primary-diag"
  target_resource_id         = azurerm_storage_account.primary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

# A secondary-region bucket the application writes to directly for anything
# RA-GRS read-replication alone would not cover (e.g. region-pinned uploads).
resource "azurerm_storage_account" "secondary" {
  name                            = "stdrsecondary09"
  resource_group_name              = azurerm_resource_group.secondary.name
  location                         = azurerm_resource_group.secondary.location
  account_tier                     = "Standard"
  account_replication_type         = "RAGZRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage_secondary" {
  name                       = "storage-secondary-diag"
  target_resource_id         = azurerm_storage_account.secondary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

# ------------------------------------------------------------------- Backups

resource "azurerm_recovery_services_vault" "primary" {
  name                = "rsv-dr-primary-09"
  resource_group_name  = azurerm_resource_group.primary.name
  location             = azurerm_resource_group.primary.location
  sku                  = "Standard"
  soft_delete_enabled  = true

  storage_mode_type        = "GeoRedundant"
  cross_region_restore_enabled = true

  identity {
    type = "SystemAssigned"
  }
}

# ---------------------------------------------------------------- Traffic flow

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "afd-dr-09"
  resource_group_name  = azurerm_resource_group.primary.name
  sku_name             = "Premium_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  name                     = "dr-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
}

resource "azurerm_cdn_frontdoor_origin_group" "app" {
  name                     = "app-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/healthz"
    request_type        = "GET"
    protocol            = "Https"
    interval_in_seconds = 30
  }
}

# Priority 1 is the primary region; priority 2 only takes traffic once the
# primary origin's health probe fails — the DNS/route layer does the failover,
# nothing application-level has to change.
resource "azurerm_cdn_frontdoor_origin" "primary" {
  name                           = "primary-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.app.id
  host_name                      = "app-primary.${var.primary_location}.example.com"
  https_port                     = 443
  priority                       = 1
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_origin" "secondary" {
  name                           = "secondary-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.app.id
  host_name                      = "app-secondary.${var.secondary_location}.example.com"
  https_port                     = 443
  priority                       = 2
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  name                = "afdwaf-dr-09"
  resource_group_name  = azurerm_resource_group.primary.name
  sku_name             = azurerm_cdn_frontdoor_profile.main.sku_name
  enabled              = true
  mode                 = "Prevention"

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "main" {
  name                     = "afd-security-policy"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.main.id

      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.main.id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}

resource "azurerm_cdn_frontdoor_route" "app" {
  name                          = "app-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.main.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.app.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.primary.id, azurerm_cdn_frontdoor_origin.secondary.id]
  supported_protocols           = ["Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-dr-primary"
  resource_group_name  = azurerm_resource_group.primary.name
  location             = azurerm_resource_group.primary.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "sql_primary" {
  name                       = "sql-primary-diag"
  target_resource_id         = azurerm_mssql_server.primary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SQLSecurityAuditEvents"
  }
}

resource "azurerm_monitor_diagnostic_setting" "cosmos" {
  name                       = "cosmos-diag"
  target_resource_id         = azurerm_cosmosdb_account.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "DataPlaneRequests"
  }
}

resource "azurerm_monitor_metric_alert" "failover_group_lag" {
  name                = "sql-failover-group-replication-lag"
  resource_group_name  = azurerm_resource_group.primary.name
  scopes               = [azurerm_mssql_failover_group.main.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.Sql/servers/failoverGroups"
    metric_name      = "replication-lag"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 300
  }
}
