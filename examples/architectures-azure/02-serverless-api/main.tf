# ArchLens reference architecture 02 (Azure) — Serverless REST API
#
# A consumption-plan API with no servers to patch: API Management in front,
# Functions handlers in a VNet, Cosmos DB for state, and Service Bus +
# Event Grid + Logic Apps for everything that should happen out of band.
# Entra ID (via an app registration + API Management's OAuth validation)
# issues the tokens the API validates.
#
# Services: API Management, Functions (Premium plan, VNet-integrated), Cosmos
# DB, Service Bus, Event Grid, Logic Apps, Entra ID (app registration),
# Application Insights, Key Vault, Storage Account, VNet, Private Endpoints.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.90" }
    azuread = { source = "hashicorp/azuread", version = "~> 2.47" }
  }
}

provider "azurerm" {
  features {}
}

variable "location" { default = "eastus" }

resource "azurerm_resource_group" "main" {
  name     = "rg-serverless-api"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-serverless-02"
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

# ------------------------------------------------------------------- Network
# Functions run with VNet integration so they reach Cosmos DB and Key Vault
# over private endpoints rather than the public internet.

resource "azurerm_virtual_network" "main" {
  name                = "vnet-serverless-api"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.30.0.0/16"]
}

resource "azurerm_subnet" "functions" {
  name                 = "snet-functions"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.30.0.0/24"]

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
  address_prefixes      = ["10.30.10.0/24"]
}

resource "azurerm_network_security_group" "functions" {
  name                = "nsg-functions"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowOutboundHTTPS"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "10.30.0.0/16"
  }
}

resource "azurerm_subnet_network_security_group_association" "functions" {
  subnet_id                 = azurerm_subnet.functions.id
  network_security_group_id = azurerm_network_security_group.functions.id
}

# ----------------------------------------------------------------- Identity

resource "azuread_application" "api" {
  display_name = "serverless-api"
}

resource "azuread_application_identifier_uri" "api" {
  application_id = azuread_application.api.id
  identifier_uri = "api://serverless-api"
}

resource "azuread_service_principal" "api" {
  client_id = azuread_application.api.client_id
}

# ---------------------------------------------------------------------- API

resource "azurerm_api_management" "main" {
  name                = "apim-serverless-02"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  publisher_name       = "Example Corp"
  publisher_email      = "api-team@example.com"
  sku_name             = "Developer_1"
  min_api_version      = "2021-08-01"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_api_management_api" "orders" {
  name                = "orders-api"
  resource_group_name  = azurerm_resource_group.main.name
  api_management_name  = azurerm_api_management.main.name
  revision             = "1"
  display_name         = "Orders API"
  path                 = "orders"
  protocols            = ["https"]
}

resource "azurerm_api_management_api_policy" "orders_jwt" {
  api_name            = azurerm_api_management_api.orders.name
  api_management_name = azurerm_api_management.main.name
  resource_group_name  = azurerm_resource_group.main.name

  xml_content = <<XML
<policies>
  <inbound>
    <validate-jwt header-name="Authorization" require-scheme="Bearer">
      <openid-config url="https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0/.well-known/openid-configuration" />
      <audiences>
        <audience>api://serverless-api</audience>
      </audiences>
    </validate-jwt>
    <rate-limit calls="200" renewal-period="60" />
  </inbound>
</policies>
XML
}

resource "azurerm_api_management_backend" "orders" {
  name                = "orders-function"
  resource_group_name  = azurerm_resource_group.main.name
  api_management_name  = azurerm_api_management.main.name
  protocol             = "http"
  url                  = "https://${azurerm_linux_function_app.orders.default_hostname}/api"

  credentials {
    header = {
      "x-functions-key" = "{{orders-function-key}}"
    }
  }
}

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "afd-serverless-02"
  resource_group_name  = azurerm_resource_group.main.name
  sku_name             = "Premium_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  name                     = "serverless-api-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
}

resource "azurerm_cdn_frontdoor_origin_group" "apim" {
  name                     = "apim-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/status-0123456789abcdef"
    request_type        = "GET"
    protocol            = "Https"
    interval_in_seconds = 30
  }
}

resource "azurerm_cdn_frontdoor_origin" "apim" {
  name                           = "apim-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.apim.id
  host_name                      = azurerm_api_management.main.gateway_url
  https_port                     = 443
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  name                = "afdwaf-serverless-02"
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

resource "azurerm_cdn_frontdoor_route" "apim" {
  name                          = "apim-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.main.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.apim.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.apim.id]
  supported_protocols           = ["Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
}

resource "azurerm_monitor_diagnostic_setting" "apim" {
  name                       = "apim-diag"
  target_resource_id         = azurerm_api_management.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "GatewayLogs"
  }
  metric {
    category = "AllMetrics"
  }
}

# ------------------------------------------------------------------ Functions

resource "azurerm_storage_account" "functions" {
  name                            = "stserverlessfn02"
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

resource "azurerm_service_plan" "functions" {
  name                = "asp-orders-fn"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  os_type              = "Linux"
  sku_name             = "EP1"
}

resource "azurerm_application_insights" "main" {
  name                = "appi-serverless-02"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  application_type     = "web"
  workspace_id         = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_linux_function_app" "orders" {
  name                = "func-orders-02"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  service_plan_id      = azurerm_service_plan.functions.id

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key

  https_only                     = true
  virtual_network_subnet_id      = azurerm_subnet.functions.id
  public_network_access_enabled  = false

  identity {
    type = "SystemAssigned"
  }

  site_config {
    minimum_tls_version        = "1.2"
    ftps_state                 = "Disabled"
    vnet_route_all_enabled     = true
    application_insights_connection_string = azurerm_application_insights.main.connection_string

    application_stack {
      python_version = "3.12"
    }
  }

  app_settings = {
    COSMOS_ENDPOINT   = azurerm_cosmosdb_account.main.endpoint
    SERVICE_BUS_TOPIC = azurerm_servicebus_topic.order_events.name
  }
}

resource "azurerm_monitor_diagnostic_setting" "functions" {
  name                       = "functions-diag"
  target_resource_id         = azurerm_linux_function_app.orders.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "FunctionAppLogs"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_key_vault_access_policy" "functions" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.orders.identity[0].principal_id

  secret_permissions = ["Get", "List"]
}

# ------------------------------------------------------------------- Messaging

resource "azurerm_servicebus_namespace" "main" {
  name                = "sb-serverless-02"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Premium"
  capacity             = 1
  local_auth_enabled   = false

  identity {
    type = "SystemAssigned"
  }

  network_rule_set {
    default_action = "Deny"
  }
}

resource "azurerm_servicebus_topic" "order_events" {
  name         = "order-events"
  namespace_id = azurerm_servicebus_namespace.main.id

  default_message_ttl = "P14D"
}

resource "azurerm_servicebus_subscription" "fulfilment" {
  name               = "fulfilment"
  topic_id           = azurerm_servicebus_topic.order_events.id
  max_delivery_count = 5

  dead_lettering_on_message_expiration        = true
  dead_lettering_on_filter_evaluation_error    = true
}

resource "azurerm_eventgrid_topic" "domain_events" {
  name                = "egt-domain-events"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  local_auth_enabled   = false

  identity {
    type = "SystemAssigned"
  }

  public_network_access_enabled = false
}

resource "azurerm_logic_app_workflow" "reconcile" {
  name                = "la-nightly-reconcile"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

# --------------------------------------------------------------------- State

resource "azurerm_cosmosdb_account" "main" {
  name                           = "cosmos-serverless-02"
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
    type                = "Continuous"
    tier                = "Continuous30Days"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cosmosdb_sql_database" "orders" {
  name                = "orders"
  resource_group_name  = azurerm_resource_group.main.name
  account_name         = azurerm_cosmosdb_account.main.name
}

resource "azurerm_cosmosdb_sql_container" "orders" {
  name                  = "orders"
  resource_group_name    = azurerm_resource_group.main.name
  account_name           = azurerm_cosmosdb_account.main.name
  database_name          = azurerm_cosmosdb_sql_database.orders.name
  partition_key_paths    = ["/customerId"]
  default_ttl            = -1
}

resource "azurerm_private_endpoint" "cosmos" {
  name                = "pe-cosmos"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "cosmos-connection"
    private_connection_resource_id = azurerm_cosmosdb_account.main.id
    subresource_names              = ["Sql"]
    is_manual_connection            = false
  }
}

resource "azurerm_private_endpoint" "keyvault" {
  name                = "pe-keyvault"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "keyvault-connection"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-serverless-02"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "cosmos" {
  name                       = "cosmos-diag"
  target_resource_id         = azurerm_cosmosdb_account.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "DataPlaneRequests"
  }
  metric {
    category = "Requests"
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

resource "azurerm_monitor_diagnostic_setting" "servicebus" {
  name                       = "servicebus-diag"
  target_resource_id         = azurerm_servicebus_namespace.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "OperationalLogs"
  }
}

resource "azurerm_monitor_metric_alert" "dlq_depth" {
  name                = "fulfilment-dlq-not-empty"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_servicebus_namespace.main.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.ServiceBus/namespaces"
    metric_name      = "DeadletteredMessages"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }
}
