# ArchLens reference architecture 11 (Azure) — Real-time communication platform
#
# Voice, video and chat for a customer-support product. Communication
# Services carries the calls and messages; Event Grid fans out call-lifecycle
# events to a Function that writes call records; recordings land in a
# retention-locked container. Azure Media Services is excluded on purpose —
# Microsoft is retiring it (shutdown 30 June 2024 for new deployments, full
# retirement 2025) — Communication Services plus Event Grid is the current
# recommended pattern for anything call/chat-shaped.
#
# Services: Communication Services, Event Grid, Functions, Storage Account
# (call recordings), Key Vault, Front Door (web client), Log Analytics.
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
  name     = "rg-communications"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-comms-11"
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
  name                = "vnet-communications"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.110.0.0/16"]
}

resource "azurerm_subnet" "functions" {
  name                 = "snet-functions"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.110.0.0/24"]

  delegation {
    name = "functions-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# --------------------------------------------------------------- Communication

resource "azurerm_communication_service" "main" {
  name                = "acs-support-11"
  resource_group_name  = azurerm_resource_group.main.name
  data_location        = "United States"
}

resource "azurerm_eventgrid_event_subscription" "call_events" {
  name  = "call-lifecycle-events"
  scope = azurerm_communication_service.main.id

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.call_records.id}/functions/OnCallEvent"
  }

  included_event_types = [
    "Microsoft.Communication.CallStarted",
    "Microsoft.Communication.CallEnded",
    "Microsoft.Communication.RecordingFileStatusUpdated",
  ]

  retry_policy {
    max_delivery_attempts = 10
    event_time_to_live     = 60
  }

  delivery_identity {
    type                   = "UserAssigned"
    user_assigned_identity = azurerm_user_assigned_identity.eventgrid.id
  }
}

resource "azurerm_user_assigned_identity" "eventgrid" {
  name                = "id-eventgrid-delivery"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

# ------------------------------------------------------------------ Functions

resource "azurerm_storage_account" "functions" {
  name                            = "stcommsfn11"
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
  name                = "asp-call-records"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  os_type              = "Linux"
  sku_name             = "EP1"
}

resource "azurerm_application_insights" "main" {
  name                = "appi-comms-11"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  application_type     = "web"
  workspace_id         = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_user_assigned_identity" "call_records" {
  name                = "id-call-records-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_linux_function_app" "call_records" {
  name                = "func-call-records-11"
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
    identity_ids = [azurerm_user_assigned_identity.call_records.id]
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
  target_resource_id         = azurerm_linux_function_app.call_records.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "FunctionAppLogs"
  }
}

# ------------------------------------------------------------------- Recordings

resource "azurerm_storage_account" "recordings" {
  name                            = "stcommsrecordings11"
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
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_storage_container" "recordings" {
  name                  = "call-recordings"
  storage_account_name  = azurerm_storage_account.recordings.name
  container_access_type = "private"
}

# Call recordings are personal data: keep them only as long as the retention
# policy requires.
resource "azurerm_storage_management_policy" "recordings" {
  storage_account_id = azurerm_storage_account.recordings.id

  rule {
    name    = "retention-policy"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 30
        delete_after_days_since_modification_greater_than       = 400
      }
      version {
        delete_after_days_since_creation = 30
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "recordings" {
  name                       = "recordings-diag"
  target_resource_id         = azurerm_storage_account.recordings.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_role_assignment" "functions_recordings_writer" {
  scope                = azurerm_storage_account.recordings.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.call_records.principal_id
}

# --------------------------------------------------------------------- Web UI

resource "azurerm_storage_account" "webclient" {
  name                            = "stcommswebclient11"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  static_website {
    index_document = "index.html"
  }

  blob_properties {
    versioning_enabled = true
  }

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_monitor_diagnostic_setting" "webclient" {
  name                       = "webclient-diag"
  target_resource_id         = azurerm_storage_account.webclient.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "afd-comms-11"
  resource_group_name  = azurerm_resource_group.main.name
  sku_name             = "Premium_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  name                     = "comms-web-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
}

resource "azurerm_cdn_frontdoor_origin_group" "webclient" {
  name                     = "webclient-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/"
    request_type        = "HEAD"
    protocol            = "Https"
    interval_in_seconds = 100
  }
}

resource "azurerm_cdn_frontdoor_origin" "webclient" {
  name                           = "webclient-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.webclient.id
  host_name                      = azurerm_storage_account.webclient.primary_web_host
  origin_host_header             = azurerm_storage_account.webclient.primary_web_host
  https_port                     = 443
  certificate_name_check_enabled = true

  private_link {
    request_message        = "comms-webclient-origin"
    target_type             = "web"
    location                = azurerm_resource_group.main.location
    private_link_target_id  = azurerm_storage_account.webclient.id
  }
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  name                = "afdwaf-comms-11"
  resource_group_name  = azurerm_resource_group.main.name
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

resource "azurerm_cdn_frontdoor_route" "webclient" {
  name                          = "webclient-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.main.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.webclient.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.webclient.id]
  supported_protocols           = ["Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-communications"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "acs" {
  name                       = "acs-diag"
  target_resource_id         = azurerm_communication_service.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "CallSummary"
  }
  enabled_log {
    category = "CallDiagnostics"
  }
}

resource "azurerm_monitor_metric_alert" "call_failures" {
  name                = "acs-call-setup-failures"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_communication_service.main.id]
  severity             = 2

  criteria {
    metric_namespace = "Microsoft.Communication/CommunicationServices"
    metric_name      = "CallSetupFailures"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 10
  }
}
