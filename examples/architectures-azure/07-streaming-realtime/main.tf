# ArchLens reference architecture 07 (Azure) — Real-time streaming pipeline
#
# One ingest path, two fan-outs: Event Hubs takes the firehose of telemetry,
# Stream Analytics does the windowed aggregation and lands the raw stream in
# Data Lake Storage for replay, and Functions handles the per-event
# enrichment. Hot query paths go to Cosmos DB.
#
# Services: Event Hubs (namespace + hub + capture), Stream Analytics,
# Functions (Event Hub trigger), Cosmos DB, Data Lake Storage Gen2, Key
# Vault, Log Analytics.
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

variable "location" { default = "northeurope" }

resource "azurerm_resource_group" "main" {
  name     = "rg-streaming"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-streaming-07"
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
  name                = "vnet-streaming"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.80.0.0/16"]
}

resource "azurerm_subnet" "functions" {
  name                 = "snet-functions"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.80.0.0/24"]

  delegation {
    name = "functions-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.80.10.0/24"]
}

# ------------------------------------------------------------------- Ingestion

resource "azurerm_eventhub_namespace" "main" {
  name                = "evhns-streaming-07"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"
  capacity             = 4
  local_authentication_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_rulesets {
    default_action = "Deny"
  }
}

resource "azurerm_eventhub" "telemetry" {
  name                = "telemetry-events"
  namespace_id        = azurerm_eventhub_namespace.main.id
  partition_count     = 8
  message_retention   = 7

  capture_description {
    enabled             = true
    encoding             = "Avro"
    interval_in_seconds  = 300
    size_limit_in_bytes  = 314572800

    destination {
      name                = "EventHubArchive.AzureBlockBlob"
      archive_name_format = "{Namespace}/{EventHub}/{PartitionId}/{Year}/{Month}/{Day}/{Hour}/{Minute}/{Second}"
      blob_container_name = azurerm_storage_data_lake_gen2_filesystem.raw.name
      storage_account_id  = azurerm_storage_account.lake.id
    }
  }
}

resource "azurerm_eventhub_consumer_group" "stream_analytics" {
  name                = "stream-analytics"
  namespace_name       = azurerm_eventhub_namespace.main.name
  eventhub_name        = azurerm_eventhub.telemetry.name
  resource_group_name  = azurerm_resource_group.main.name
}

resource "azurerm_private_endpoint" "eventhub" {
  name                = "pe-eventhub"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "eventhub-connection"
    private_connection_resource_id = azurerm_eventhub_namespace.main.id
    subresource_names              = ["namespace"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------------ Processing

resource "azurerm_stream_analytics_job" "aggregate" {
  name                = "sa-telemetry-aggregate"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  streaming_units                     = 6
  compatibility_level                 = "1.2"
  events_late_arrival_max_delay_in_seconds = 60
  events_out_of_order_max_delay_in_seconds = 50
  events_out_of_order_policy           = "Adjust"
  output_error_policy                  = "Drop"

  identity {
    type = "SystemAssigned"
  }

  transformation_query = <<QUERY
SELECT device_id, AVG(temperature) AS avg_temperature
INTO [cosmos-output]
FROM [telemetry-input] TIMESTAMP BY event_time
GROUP BY device_id, TumblingWindow(minute, 1)
QUERY
}

resource "azurerm_stream_analytics_stream_input_eventhub" "telemetry" {
  name                         = "telemetry-input"
  stream_analytics_job_name     = azurerm_stream_analytics_job.aggregate.name
  resource_group_name           = azurerm_resource_group.main.name
  eventhub_consumer_group_name  = azurerm_eventhub_consumer_group.stream_analytics.name
  eventhub_name                 = azurerm_eventhub.telemetry.name
  servicebus_namespace           = azurerm_eventhub_namespace.main.name
  shared_access_policy_key        = azurerm_eventhub_namespace.main.default_primary_key
  shared_access_policy_name       = "RootManageSharedAccessKey"

  serialization {
    type     = "Json"
    encoding = "UTF8"
  }
}

resource "azurerm_monitor_diagnostic_setting" "stream_analytics" {
  name                       = "sa-diag"
  target_resource_id         = azurerm_stream_analytics_job.aggregate.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Execution"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_user_assigned_identity" "enrich" {
  name                = "id-enrich-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_storage_account" "functions" {
  name                            = "ststreamingfn07"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
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

resource "azurerm_monitor_diagnostic_setting" "functions_storage" {
  name                       = "functions-storage-diag"
  target_resource_id         = azurerm_storage_account.functions.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_service_plan" "functions" {
  name                = "asp-enrich-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  os_type              = "Linux"
  sku_name             = "EP1"
}

resource "azurerm_application_insights" "main" {
  name                = "appi-streaming-07"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  application_type     = "web"
  workspace_id         = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_linux_function_app" "enrich" {
  name                = "func-enrich-07"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  service_plan_id      = azurerm_service_plan.functions.id

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  https_only                     = true
  virtual_network_subnet_id      = azurerm_subnet.functions.id
  public_network_access_enabled  = false

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.enrich.id]
  }

  site_config {
    minimum_tls_version    = "1.2"
    ftps_state             = "Disabled"
    vnet_route_all_enabled = true
    application_insights_connection_string = azurerm_application_insights.main.connection_string

    application_stack {
      python_version = "3.12"
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "functions" {
  name                       = "functions-diag"
  target_resource_id         = azurerm_linux_function_app.enrich.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "FunctionAppLogs"
  }
}

resource "azurerm_role_assignment" "enrich_eventhub_receive" {
  scope                = azurerm_eventhub_namespace.main.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_user_assigned_identity.enrich.principal_id
}

# ------------------------------------------------------------------ Serving

resource "azurerm_cosmosdb_account" "readings" {
  name                           = "cosmos-streaming-07"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  offer_type                      = "Standard"
  kind                             = "GlobalDocumentDB"
  public_network_access_enabled    = false
  local_authentication_disabled    = true

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }

  backup {
    type = "Continuous"
    tier = "Continuous7Days"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cosmosdb_sql_database" "telemetry" {
  name                = "telemetry"
  resource_group_name  = azurerm_resource_group.main.name
  account_name         = azurerm_cosmosdb_account.readings.name
}

resource "azurerm_cosmosdb_sql_container" "readings" {
  name                  = "readings"
  resource_group_name    = azurerm_resource_group.main.name
  account_name           = azurerm_cosmosdb_account.readings.name
  database_name          = azurerm_cosmosdb_sql_database.telemetry.name
  partition_key_paths    = ["/deviceId"]
  default_ttl            = 2592000
}

resource "azurerm_private_endpoint" "cosmos" {
  name                = "pe-cosmos"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "cosmos-connection"
    private_connection_resource_id = azurerm_cosmosdb_account.readings.id
    subresource_names              = ["Sql"]
    is_manual_connection            = false
  }
}

# -------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "lake" {
  name                            = "ststreaminglake07"
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
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_storage_data_lake_gen2_filesystem" "raw" {
  name               = "raw"
  storage_account_id = azurerm_storage_account.lake.id
}

resource "azurerm_storage_management_policy" "lake" {
  storage_account_id = azurerm_storage_account.lake.id

  rule {
    name    = "tier-raw-events"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 14
        tier_to_archive_after_days_since_modification_greater_than = 90
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

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-streaming"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "eventhub" {
  name                       = "eventhub-diag"
  target_resource_id         = azurerm_eventhub_namespace.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ArchiveLogs"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "cosmos" {
  name                       = "cosmos-diag"
  target_resource_id         = azurerm_cosmosdb_account.readings.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "DataPlaneRequests"
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

resource "azurerm_monitor_metric_alert" "sa_watermark_delay" {
  name                = "stream-analytics-falling-behind"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_stream_analytics_job.aggregate.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.StreamAnalytics/streamingjobs"
    metric_name      = "InputEventsSourcesBacklogged"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 1000
  }
}
