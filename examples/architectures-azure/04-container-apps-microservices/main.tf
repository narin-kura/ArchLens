# ArchLens reference architecture 04 (Azure) — Event-driven microservices on
# Container Apps
#
# Two services behind an internal Container Apps ingress, talking to each
# other through Service Bus rather than direct calls, so one slow consumer
# cannot take the writer down with it. Container Apps means no node pool to
# patch; Container Registry scans every image on push; each app has its own
# managed identity, not a shared one.
#
# Services: Container Apps Environment, Container Apps, Container Registry,
# Service Bus, Event Grid, Cosmos DB, Cache for Redis, Storage Account, Key
# Vault, VNet, Log Analytics.
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

variable "location" { default = "westeurope" }

resource "azurerm_resource_group" "main" {
  name     = "rg-microservices"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-microsvc-04"
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

resource "azurerm_virtual_network" "main" {
  name                = "vnet-microservices"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.50.0.0/16"]
}

resource "azurerm_subnet" "apps" {
  name                 = "snet-container-apps"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.50.0.0/23"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.50.2.0/24"]
}

# ------------------------------------------------------------------ Registry

resource "azurerm_container_registry" "main" {
  name                = "acrmicroservices04"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Premium"
  admin_enabled        = false
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_private_endpoint" "acr" {
  name                = "pe-acr"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "acr-connection"
    private_connection_resource_id = azurerm_container_registry.main.id
    subresource_names              = ["registry"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------------- Compute

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-microservices"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-microservices"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  log_analytics_workspace_id  = azurerm_log_analytics_workspace.main.id
  infrastructure_subnet_id    = azurerm_subnet.apps.id
  internal_load_balancer_enabled = true

  zone_redundancy_enabled = true
}

resource "azurerm_user_assigned_identity" "orders" {
  name                = "id-orders-service"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_role_assignment" "orders_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.orders.principal_id
}

resource "azurerm_container_app" "orders" {
  name                         = "ca-orders"
  resource_group_name           = azurerm_resource_group.main.name
  container_app_environment_id  = azurerm_container_app_environment.main.id
  revision_mode                 = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.orders.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.orders.id
  }

  template {
    min_replicas = 2
    max_replicas = 20

    container {
      name   = "orders"
      image  = "${azurerm_container_registry.main.login_server}/orders:1.4.2"
      cpu    = 0.5
      memory = "1Gi"

      liveness_probe {
        transport = "HTTP"
        path      = "/healthz"
        port      = 8080
      }

      env {
        name  = "SERVICEBUS_NAMESPACE"
        value = azurerm_servicebus_namespace.main.name
      }
    }

    custom_scale_rule {
      name             = "servicebus-queue-length"
      custom_rule_type = "azure-servicebus"

      metadata = {
        queueName    = azurerm_servicebus_queue.shipping.name
        messageCount = "20"
      }

      authentication {
        secret_name       = "servicebus-connection"
        trigger_parameter = "connection"
      }
    }
  }

  ingress {
    external_enabled = false
    target_port      = 8080

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

resource "azurerm_user_assigned_identity" "shipping" {
  name                = "id-shipping-service"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_role_assignment" "shipping_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.shipping.principal_id
}

resource "azurerm_container_app" "shipping" {
  name                         = "ca-shipping"
  resource_group_name           = azurerm_resource_group.main.name
  container_app_environment_id  = azurerm_container_app_environment.main.id
  revision_mode                 = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.shipping.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.shipping.id
  }

  template {
    min_replicas = 1
    max_replicas = 10

    container {
      name   = "shipping"
      image  = "${azurerm_container_registry.main.login_server}/shipping:2.0.1"
      cpu    = 0.25
      memory = "0.5Gi"

      liveness_probe {
        transport = "HTTP"
        path      = "/healthz"
        port      = 8080
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "orders" {
  name                       = "orders-diag"
  target_resource_id         = azurerm_container_app.orders.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ContainerAppConsoleLogs"
  }
}

# ------------------------------------------------------------------ Messaging

resource "azurerm_servicebus_namespace" "main" {
  name                = "sb-microservices-04"
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

resource "azurerm_servicebus_queue" "shipping" {
  name         = "shipping-work"
  namespace_id = azurerm_servicebus_namespace.main.id

  max_delivery_count = 5
  lock_duration       = "PT5M"
}

resource "azurerm_role_assignment" "orders_servicebus_send" {
  scope                = azurerm_servicebus_namespace.main.id
  role_definition_name = "Azure Service Bus Data Sender"
  principal_id         = azurerm_user_assigned_identity.orders.principal_id
}

resource "azurerm_role_assignment" "shipping_servicebus_receive" {
  scope                = azurerm_servicebus_namespace.main.id
  role_definition_name = "Azure Service Bus Data Receiver"
  principal_id         = azurerm_user_assigned_identity.shipping.principal_id
}

resource "azurerm_eventgrid_topic" "domain_events" {
  name                = "egt-microservices-04"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  local_auth_enabled   = false
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }
}

# --------------------------------------------------------------------- State

resource "azurerm_cosmosdb_account" "orders" {
  name                           = "cosmos-microservices-04"
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
    tier = "Continuous30Days"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_private_endpoint" "cosmos" {
  name                = "pe-cosmos"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "cosmos-connection"
    private_connection_resource_id = azurerm_cosmosdb_account.orders.id
    subresource_names              = ["Sql"]
    is_manual_connection            = false
  }
}

resource "azurerm_redis_cache" "sessions" {
  name                = "redis-microservices-04"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  capacity             = 1
  family               = "P"
  sku_name             = "Premium"
  minimum_tls_version  = "1.2"
  public_network_access_enabled = false

  redis_configuration {
    maxmemory_policy = "volatile-lru"
  }
}

resource "azurerm_private_endpoint" "redis" {
  name                = "pe-redis"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "redis-connection"
    private_connection_resource_id = azurerm_redis_cache.sessions.id
    subresource_names              = ["redisCache"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_monitor_diagnostic_setting" "servicebus" {
  name                       = "servicebus-diag"
  target_resource_id         = azurerm_servicebus_namespace.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "OperationalLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "cosmos" {
  name                       = "cosmos-diag"
  target_resource_id         = azurerm_cosmosdb_account.orders.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "DataPlaneRequests"
  }
}

resource "azurerm_monitor_diagnostic_setting" "redis" {
  name                       = "redis-diag"
  target_resource_id         = azurerm_redis_cache.sessions.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "acr" {
  name                       = "acr-diag"
  target_resource_id         = azurerm_container_registry.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ContainerRegistryRepositoryEvents"
  }
}

resource "azurerm_security_center_subscription_pricing" "registries" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

resource "azurerm_monitor_metric_alert" "queue_backlog" {
  name                = "shipping-queue-backlog"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_servicebus_namespace.main.id]
  severity             = 2

  criteria {
    metric_namespace = "Microsoft.ServiceBus/namespaces"
    metric_name      = "Messages"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 1000
  }
}
