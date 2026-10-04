# ArchLens reference architecture 10 (Azure) — IoT fleet telemetry with edge
# processing
#
# Devices authenticate with per-device X.509 certificates (never a shared
# key), IoT Hub routes telemetry to storage and to the industrial data model,
# and Device Defender for IoT watches for a device that starts behaving
# unlike its fleet. Digital Twins holds the live state of the factory floor.
#
# Services: IoT Hub, Device Provisioning Service, Digital Twins, Defender for
# IoT, Data Lake Storage Gen2, Functions, Key Vault, Log Analytics.
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
  name     = "rg-iot-telemetry"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-iot-telemetry-10"
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
  name                = "vnet-iot-telemetry"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.100.0.0/16"]
}

resource "azurerm_subnet" "functions" {
  name                 = "snet-functions"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.100.0.0/24"]

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
  address_prefixes      = ["10.100.10.0/24"]
}

# ------------------------------------------------------------------ IoT Hub

resource "azurerm_iothub" "main" {
  name                = "iothub-telemetry-10"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  sku {
    name     = "S1"
    capacity = 2
  }

  min_tls_version              = "1.2"
  local_authentication_enabled = false
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  endpoint {
    type                       = "AzureIotHub.StorageContainer"
    connection_string          = azurerm_storage_account.telemetry.primary_blob_connection_string
    name                       = "export-to-lake"
    batch_frequency_in_seconds = 300
    max_chunk_size_in_bytes    = 314572800
    container_name             = azurerm_storage_data_lake_gen2_filesystem.raw.name
    encoding                   = "Avro"
    file_name_format           = "{iothub}/{partition}/{YYYY}/{MM}/{DD}/{HH}/{mm}"
  }

  route {
    name           = "telemetry-to-lake"
    source         = "DeviceMessages"
    condition      = "true"
    endpoint_names = ["export-to-lake"]
    enabled        = true
  }

  cloud_to_device {
    max_delivery_count = 10
    default_ttl        = "PT1H"

    feedback {
      time_to_live       = "PT1H"
      max_delivery_count = 10
      lock_duration       = "PT30S"
    }
  }
}

resource "azurerm_private_endpoint" "iothub" {
  name                = "pe-iothub"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "iothub-connection"
    private_connection_resource_id = azurerm_iothub.main.id
    subresource_names              = ["iotHub"]
    is_manual_connection            = false
  }
}

resource "azurerm_iothub_dps" "main" {
  name                = "dps-telemetry-10"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  sku {
    name     = "S1"
    capacity = 1
  }

  linked_hub {
    connection_string = azurerm_iothub.main.shared_access_policy[0].connection_string
    location           = azurerm_resource_group.main.location
  }
}

# A per-device certificate issued off this CA, rather than a shared SAS key,
# is what stops a stolen credential from impersonating every device at once.
resource "azurerm_iothub_certificate" "device_ca" {
  name                = "device-root-ca"
  resource_group_name  = azurerm_resource_group.main.name
  iothub_name          = azurerm_iothub.main.name
  certificate_content  = filebase64("device-root-ca.cer")
  is_verified          = true
}

# --------------------------------------------------------------- Guardrails

resource "azurerm_iot_security_solution" "fleet" {
  name                = "iotsec-fleet-baseline"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  display_name         = "fleet-baseline"
  iothub_ids           = [azurerm_iothub.main.id]

  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  log_unmasked_ips_enabled    = false

  recommendations_enabled {
    acr_authentication             = true
    agent_send_unutilized_msg      = true
    edge_hub_mem_optimize           = true
    edge_logging_option             = true
    inconsistent_module_settings    = true
    install_agent                   = true
    ip_filter_deny_all               = true
    ip_filter_permissive_rule        = true
    open_ports                       = true
    permissive_firewall_policy       = true
    permissive_input_firewall_rules  = true
    permissive_output_firewall_rules = true
    privileged_docker_options        = true
    shared_credentials               = true
    vulnerable_tls_cipher_suite      = true
  }
}

# --------------------------------------------------------- Industrial model

resource "azurerm_digital_twins_instance" "plant" {
  name                = "dt-plant-a"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_digital_twins_endpoint_eventhub" "telemetry" {
  name                                           = "dt-to-eventhub"
  digital_twins_id                                = azurerm_digital_twins_instance.plant.id
  eventhub_primary_connection_string               = azurerm_eventhub_namespace.main.default_primary_connection_string
  eventhub_secondary_connection_string             = azurerm_eventhub_namespace.main.default_secondary_connection_string
}

resource "azurerm_eventhub_namespace" "main" {
  name                = "evhns-digitaltwins-10"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"
  capacity             = 1
  local_authentication_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_rulesets {
    default_action = "Deny"
  }
}

# ---------------------------------------------------------------- Processing

resource "azurerm_storage_account" "functions" {
  name                            = "stiottelemetryfn10"
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
  name                = "asp-anomaly-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  os_type              = "Linux"
  sku_name             = "EP1"
}

resource "azurerm_application_insights" "main" {
  name                = "appi-iot-telemetry-10"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  application_type     = "web"
  workspace_id         = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_user_assigned_identity" "anomaly" {
  name                = "id-anomaly-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_linux_function_app" "anomaly" {
  name                = "func-anomaly-10"
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
    identity_ids = [azurerm_user_assigned_identity.anomaly.id]
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
  target_resource_id         = azurerm_linux_function_app.anomaly.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "FunctionAppLogs"
  }
}

resource "azurerm_role_assignment" "anomaly_eventhub_receive" {
  scope                = azurerm_eventhub_namespace.main.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_user_assigned_identity.anomaly.principal_id
}

# ---------------------------------------------------------------- Persistence

resource "azurerm_storage_account" "telemetry" {
  name                            = "stiottelemetrylake10"
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
  storage_account_id = azurerm_storage_account.telemetry.id
}

resource "azurerm_storage_management_policy" "telemetry" {
  storage_account_id = azurerm_storage_account.telemetry.id

  rule {
    name    = "tier-and-expire-readings"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 180
        delete_after_days_since_modification_greater_than          = 2555
      }
    }
  }
}

resource "azurerm_private_endpoint" "telemetry" {
  name                = "pe-telemetry-dfs"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "telemetry-dfs-connection"
    private_connection_resource_id = azurerm_storage_account.telemetry.id
    subresource_names              = ["dfs"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-iot-telemetry"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "iothub" {
  name                       = "iothub-diag"
  target_resource_id         = azurerm_iothub.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Connections"
  }
  enabled_log {
    category = "DeviceTelemetry"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "telemetry_storage" {
  name                       = "telemetry-storage-diag"
  target_resource_id         = azurerm_storage_account.telemetry.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_metric_alert" "throttled" {
  name                = "iothub-throttling"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_iothub.main.id]
  severity             = 2

  criteria {
    metric_namespace = "Microsoft.Devices/IotHubs"
    metric_name      = "d2c.telemetry.ingress.sendThrottle"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }
}

resource "azurerm_security_center_subscription_pricing" "iot" {
  tier          = "Standard"
  resource_type = "Iot"
}
