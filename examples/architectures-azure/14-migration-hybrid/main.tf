# ArchLens reference architecture 14 (Azure) — Migration and hybrid connectivity
#
# The landing zone a data-centre migration lands in. ExpressRoute plus a VPN
# backup carry traffic into a hub VNet; Database Migration Service replicates
# databases with change data capture so cutover is minutes rather than a
# weekend; Azure Migrate's server migration tooling lifts and shifts the
# servers that cannot be re-platformed yet; DataSync-equivalent (Storage
# Mover / Data Box) moves the file estate.
#
# Services: ExpressRoute, Site-to-Site VPN (backup path), Virtual WAN,
# Database Migration Service, Storage Mover, Recovery Services Vault
# (Site Recovery for server migration), Azure Files, Key Vault, Log Analytics.
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
variable "on_prem_cidr" { default = "192.168.0.0/16" }

resource "azurerm_resource_group" "main" {
  name     = "rg-migration"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-migration-14"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  purge_protection_enabled    = true
  soft_delete_retention_days  = 30
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

data "azurerm_client_config" "current" {}

# ------------------------------------------------------------- Hybrid network

resource "azurerm_virtual_wan" "main" {
  name                = "vwan-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  type                 = "Standard"
}

resource "azurerm_virtual_hub" "main" {
  name                = "vhub-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  virtual_wan_id       = azurerm_virtual_wan.main.id
  address_prefix       = "10.130.0.0/23"
}

resource "azurerm_virtual_network" "landing" {
  name                = "vnet-migration-landing"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.131.0.0/16"]
}

resource "azurerm_subnet" "migration" {
  name                 = "snet-migration"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.landing.name
  address_prefixes      = ["10.131.0.0/24"]
}

resource "azurerm_network_security_group" "migration" {
  name                = "nsg-migration"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowDatabaseReplication"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = var.on_prem_cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowFileShareSMB"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "445"
    source_address_prefix      = var.on_prem_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "migration" {
  subnet_id                 = azurerm_subnet.migration.id
  network_security_group_id = azurerm_network_security_group.migration.id
}

resource "azurerm_express_route_circuit" "primary" {
  name                  = "er-migration-primary"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  service_provider_name  = "Equinix"
  peering_location       = "Washington DC"
  bandwidth_in_mbps      = 1000

  sku {
    tier   = "Standard"
    family = "MeteredData"
  }
}

resource "azurerm_vpn_gateway" "main" {
  name                = "vpngw-migration-backup"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  virtual_hub_id       = azurerm_virtual_hub.main.id
}

resource "azurerm_vpn_site" "datacenter" {
  name                = "vpnsite-datacenter"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  virtual_wan_id       = azurerm_virtual_wan.main.id

  link {
    name       = "isp-primary"
    ip_address = "203.0.113.20"

    bgp {
      asn             = 65000
      peering_address = "203.0.113.21"
    }
  }
}

resource "azurerm_vpn_gateway_connection" "datacenter" {
  name               = "vpngw-connection-datacenter"
  vpn_gateway_id     = azurerm_vpn_gateway.main.id
  remote_vpn_site_id = azurerm_vpn_site.datacenter.id

  vpn_link {
    name             = "isp-primary-link"
    vpn_site_link_id = azurerm_vpn_site.datacenter.link[0].id
  }
}

resource "azurerm_flow_log" "migration" {
  name                 = "migration-flow-log"
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name   = azurerm_resource_group.main.name
  network_security_group_id = azurerm_network_security_group.migration.id

  storage_account_id = azurerm_storage_account.migration.id
  enabled             = true
  version             = 2

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id           = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region       = azurerm_log_analytics_workspace.main.location
    workspace_resource_id  = azurerm_log_analytics_workspace.main.id
  }
}

resource "azurerm_network_watcher" "main" {
  name                = "nw-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

# ------------------------------------------------------------ Database migration

resource "azurerm_database_migration_service" "main" {
  name                = "dms-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.migration.id
  sku_name             = "Premium_4vCores"
}

resource "azurerm_database_migration_project" "erp" {
  name                = "erp-to-azure-sql"
  service_name         = azurerm_database_migration_service.main.name
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  source_platform      = "SQL"
  target_platform      = "SQL"
}

resource "azurerm_mssql_server" "target" {
  name                         = "sql-migration-target-14"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
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
    storage_endpoint                        = azurerm_storage_account.migration.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.migration.primary_access_key
    storage_account_access_key_is_secondary = false
    retention_in_days                       = 90
  }
}

resource "azurerm_mssql_database" "erp" {
  name           = "erp"
  server_id      = azurerm_mssql_server.target.id
  sku_name       = "S2"
  zone_redundant = true

  short_term_retention_policy {
    retention_days = 14
  }
}

# ------------------------------------------------------------ Server migration

resource "azurerm_recovery_services_vault" "migration" {
  name                = "rsv-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"
  soft_delete_enabled  = true

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_site_recovery_fabric" "on_prem" {
  name                = "datacenter-fabric"
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.migration.name
  location             = "onpremise"
}

resource "azurerm_site_recovery_fabric" "azure" {
  name                = "azure-fabric"
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.migration.name
  location             = var.location
}

resource "azurerm_site_recovery_replication_policy" "main" {
  name                                                 = "migration-replication-policy"
  resource_group_name                                   = azurerm_resource_group.main.name
  recovery_vault_name                                   = azurerm_recovery_services_vault.migration.name
  recovery_point_retention_in_minutes                    = 24 * 60
  application_consistent_snapshot_frequency_in_minutes   = 240
}

# ---------------------------------------------------------------- File estate

resource "azurerm_storage_account" "fileshares" {
  name                            = "stmigrationshares14"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Premium"
  account_kind                     = "FileStorage"
  account_replication_type         = "ZRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_storage_share" "fileshares" {
  name                 = "migrated-fileshare"
  storage_account_name = azurerm_storage_account.fileshares.name
  quota                = 500
  enabled_protocol     = "SMB"
}

resource "azurerm_monitor_diagnostic_setting" "fileshares" {
  name                       = "fileshares-diag"
  target_resource_id         = azurerm_storage_account.fileshares.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_backup_policy_file_share" "fileshares" {
  name                = "daily-fileshares"
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.migration.name

  backup {
    frequency = "Daily"
    time      = "22:00"
  }

  retention_daily {
    count = 30
  }
}

resource "azurerm_backup_container_storage_account" "fileshares" {
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.migration.name
  storage_account_id   = azurerm_storage_account.fileshares.id
}

resource "azurerm_backup_protected_file_share" "fileshares" {
  resource_group_name       = azurerm_resource_group.main.name
  recovery_vault_name       = azurerm_recovery_services_vault.migration.name
  source_storage_account_id = azurerm_storage_account.fileshares.id
  source_file_share_name    = azurerm_storage_share.fileshares.name
  backup_policy_id          = azurerm_backup_policy_file_share.fileshares.id

  depends_on = [azurerm_backup_container_storage_account.fileshares]
}

resource "azurerm_storage_account" "migration" {
  name                            = "stmigrationlogs14"
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
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_monitor_diagnostic_setting" "migration_storage" {
  name                       = "migration-storage-diag"
  target_resource_id         = azurerm_storage_account.migration.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_storage_mover" "main" {
  name                = "stmv-migration-14"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-migration"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "dms" {
  name                       = "dms-diag"
  target_resource_id         = azurerm_database_migration_service.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SqlDBMigrationSettings"
  }
}

resource "azurerm_monitor_metric_alert" "replication_lag" {
  name                = "dms-replication-lag"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_database_migration_service.main.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.DataMigration/services"
    metric_name      = "CPUPercentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 90
  }
}
