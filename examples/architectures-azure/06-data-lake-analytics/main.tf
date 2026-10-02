# ArchLens reference architecture 06 (Azure) — Data lake and analytics
#
# Medallion layout (raw → curated → published) on Data Lake Storage Gen2,
# catalogued and transformed by Synapse pipelines, queried through a
# dedicated SQL pool and a Spark pool, governed by Microsoft Purview. Managed
# private endpoints keep every hop off the public internet.
#
# Services: Data Lake Storage Gen2, Synapse Analytics (workspace, dedicated
# SQL pool, Spark pool, pipelines), Microsoft Purview, Key Vault, Log
# Analytics, Budget.
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

variable "location" { default = "eastus2" }

resource "azurerm_resource_group" "main" {
  name     = "rg-data-lake"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-data-lake-06"
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

resource "azurerm_virtual_network" "main" {
  name                = "vnet-data-lake"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.70.0.0/16"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.70.0.0/24"]
}

# ------------------------------------------------------------- Lake storage

locals {
  layers = ["raw", "curated", "published"]
}

resource "azurerm_storage_account" "lake" {
  name                            = "stdatalakeadls06"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  account_kind                     = "StorageV2"
  is_hns_enabled                   = true
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

resource "azurerm_storage_data_lake_gen2_filesystem" "layer" {
  count              = 3
  name               = local.layers[count.index]
  storage_account_id = azurerm_storage_account.lake.id
}

resource "azurerm_storage_management_policy" "lake" {
  storage_account_id = azurerm_storage_account.lake.id

  rule {
    name    = "tier-cold-partitions"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 180
      }
      version {
        delete_after_days_since_creation = 90
      }
    }
  }
}

resource "azurerm_private_endpoint" "lake" {
  name                = "pe-lake-dfs"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "lake-dfs-connection"
    private_connection_resource_id = azurerm_storage_account.lake.id
    subresource_names              = ["dfs"]
    is_manual_connection            = false
  }
}

# --------------------------------------------------------- Synapse workspace

resource "azurerm_synapse_workspace" "main" {
  name                                 = "synw-data-lake-06"
  resource_group_name                   = azurerm_resource_group.main.name
  location                              = azurerm_resource_group.main.location
  storage_data_lake_gen2_filesystem_id  = azurerm_storage_data_lake_gen2_filesystem.layer[1].id
  sql_administrator_login               = "synapseadmin"
  sql_administrator_login_password      = random_password.synapse_admin.result
  public_network_access_enabled         = false
  managed_virtual_network_enabled        = true
  data_exfiltration_protection_enabled  = true

  identity {
    type = "SystemAssigned"
  }

  azuread_authentication_only = true
}

resource "random_password" "synapse_admin" {
  length  = 32
  special = true
}

resource "azurerm_key_vault_secret" "synapse_admin" {
  name         = "synapse-admin-password"
  value        = random_password.synapse_admin.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_synapse_firewall_rule" "allow_azure_services" {
  name                 = "AllowAllWindowsAzureIps"
  synapse_workspace_id = azurerm_synapse_workspace.main.id
  start_ip_address     = "0.0.0.0"
  end_ip_address       = "0.0.0.0"
}

resource "azurerm_private_endpoint" "synapse_sql" {
  name                = "pe-synapse-sql"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "synapse-sql-connection"
    private_connection_resource_id = azurerm_synapse_workspace.main.id
    subresource_names              = ["Sql"]
    is_manual_connection            = false
  }
}

resource "azurerm_synapse_sql_pool" "warehouse" {
  name                 = "curated"
  synapse_workspace_id  = azurerm_synapse_workspace.main.id
  sku_name              = "DW100c"
  create_mode           = "Default"

  geo_backup_policy_enabled = true
}

resource "azurerm_synapse_spark_pool" "etl" {
  name                 = "etl"
  synapse_workspace_id  = azurerm_synapse_workspace.main.id
  node_size_family      = "MemoryOptimized"
  node_size             = "Small"

  auto_scale {
    min_node_count = 3
    max_node_count = 10
  }

  auto_pause {
    delay_in_minutes = 15
  }
}

resource "azurerm_synapse_role_assignment" "etl_contributor" {
  synapse_workspace_id = azurerm_synapse_workspace.main.id
  role_name            = "Synapse Contributor"
  principal_id         = azurerm_user_assigned_identity.pipelines.principal_id
}

resource "azurerm_user_assigned_identity" "pipelines" {
  name                = "id-synapse-pipelines"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_role_assignment" "pipelines_lake_contributor" {
  scope                = azurerm_storage_account.lake.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.pipelines.principal_id
}

# --------------------------------------------------------------- Governance

resource "azurerm_purview_account" "main" {
  name                = "purview-data-lake-06"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  public_network_enabled = false

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_role_assignment" "purview_lake_reader" {
  scope                = azurerm_storage_account.lake.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_purview_account.main.identity[0].principal_id
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-data-lake"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "synapse" {
  name                       = "synapse-diag"
  target_resource_id         = azurerm_synapse_workspace.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SynapseRbacOperations"
  }
  enabled_log {
    category = "SQLSecurityAuditEvents"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "lake" {
  name                       = "lake-diag"
  target_resource_id         = azurerm_storage_account.lake.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_consumption_budget_subscription" "analytics" {
  name            = "analytics-monthly"
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  amount          = 4000
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 85
    operator       = "GreaterThan"
    contact_emails = ["data-platform@example.com"]
  }
}
