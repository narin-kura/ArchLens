# ArchLens reference architecture 08 (Azure) — ML training and GenAI (RAG) platform
#
# Two halves that share one data plane. The ML half trains and serves custom
# models on Azure Machine Learning; the GenAI half answers questions over the
# same documents using Azure OpenAI with a knowledge store backed by AI
# Search, behind a content-safety filter. Both run network-isolated with
# private endpoints and no public internet path.
#
# Services: Azure Machine Learning (workspace, compute instance, compute
# cluster), Azure OpenAI Service (deployment), AI Search, AI Content Safety,
# Storage Account, Container Registry, Key Vault, VNet, Log Analytics.
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
  name     = "rg-ml-platform"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-ml-platform-08"
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
  name                = "vnet-ml-platform"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.90.0.0/16"]
}

resource "azurerm_subnet" "ml" {
  name                 = "snet-ml"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.90.0.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.90.10.0/24"]
}

# ------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "datasets" {
  name                            = "stmlplatformds08"
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

resource "azurerm_storage_management_policy" "datasets" {
  storage_account_id = azurerm_storage_account.datasets.id

  rule {
    name    = "archive-old-training-data"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 60
      }
      version {
        delete_after_days_since_creation = 90
      }
    }
  }
}

resource "azurerm_private_endpoint" "datasets" {
  name                = "pe-datasets"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "datasets-connection"
    private_connection_resource_id = azurerm_storage_account.datasets.id
    subresource_names              = ["blob"]
    is_manual_connection            = false
  }
}

resource "azurerm_container_registry" "training" {
  name                = "acrmlplatform08"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Premium"
  admin_enabled        = false
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_security_center_subscription_pricing" "registries" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

# --------------------------------------------------------------- Azure ML

resource "azurerm_application_insights" "ml" {
  name                = "appi-ml-platform-08"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  application_type     = "web"
  workspace_id         = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_machine_learning_workspace" "main" {
  name                    = "mlw-platform-08"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  application_insights_id  = azurerm_application_insights.ml.id
  key_vault_id             = azurerm_key_vault.main.id
  storage_account_id       = azurerm_storage_account.datasets.id
  container_registry_id    = azurerm_container_registry.training.id
  public_network_access_enabled = false
  v1_legacy_mode_enabled         = false

  identity {
    type = "SystemAssigned"
  }

  encryption {
    key_vault_id = azurerm_key_vault.main.id
    key_id       = azurerm_key_vault_key.ml.id
  }
}

resource "azurerm_key_vault_key" "ml" {
  name         = "ml-platform-cmk"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
}

resource "azurerm_key_vault_access_policy" "ml" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_machine_learning_workspace.main.identity[0].principal_id

  key_permissions    = ["Get", "WrapKey", "UnwrapKey"]
  secret_permissions = ["Get", "List"]
}

resource "azurerm_private_endpoint" "ml" {
  name                = "pe-ml-workspace"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "ml-workspace-connection"
    private_connection_resource_id = azurerm_machine_learning_workspace.main.id
    subresource_names              = ["amlworkspace"]
    is_manual_connection            = false
  }
}

resource "azurerm_machine_learning_compute_cluster" "training" {
  name                          = "cpu-cluster"
  machine_learning_workspace_id  = azurerm_machine_learning_workspace.main.id
  location                       = azurerm_resource_group.main.location
  vm_priority                    = "Dedicated"
  vm_size                        = "STANDARD_DS3_V2"

  scale_settings {
    min_node_count                       = 0
    max_node_count                       = 10
    scale_down_nodes_after_idle_duration  = "PT30M"
  }

  subnet_resource_id = azurerm_subnet.ml.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_machine_learning_compute_instance" "notebooks" {
  name                          = "notebook-instance"
  machine_learning_workspace_id  = azurerm_machine_learning_workspace.main.id
  virtual_machine_size           = "STANDARD_DS3_V2"
  subnet_resource_id             = azurerm_subnet.ml.id

  identity {
    type = "SystemAssigned"
  }
}

# ----------------------------------------------------------------- GenAI

resource "azurerm_cognitive_account" "openai" {
  name                = "oai-ml-platform-08"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  kind                 = "OpenAI"
  sku_name             = "S0"
  custom_subdomain_name = "mlplatform08"
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_acls {
    default_action = "Deny"
  }
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "gpt-4o-deployment"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }

  sku {
    name     = "Standard"
    capacity = 50
  }
}

resource "azurerm_private_endpoint" "openai" {
  name                = "pe-openai"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "openai-connection"
    private_connection_resource_id = azurerm_cognitive_account.openai.id
    subresource_names              = ["account"]
    is_manual_connection            = false
  }
}

resource "azurerm_search_service" "knowledge" {
  name                = "srch-ml-platform-08"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "standard"
  replica_count        = 2
  partition_count      = 1
  public_network_access_enabled = false
  local_authentication_enabled   = false

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_private_endpoint" "search" {
  name                = "pe-search"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "search-connection"
    private_connection_resource_id = azurerm_search_service.knowledge.id
    subresource_names              = ["searchService"]
    is_manual_connection            = false
  }
}

resource "azurerm_cognitive_account" "content_safety" {
  name                = "cs-ml-platform-08"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  kind                 = "ContentSafety"
  sku_name             = "S0"
  custom_subdomain_name = "mlplatform08safety"
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_acls {
    default_action = "Deny"
  }
}

resource "azurerm_role_assignment" "openai_search_reader" {
  scope                = azurerm_search_service.knowledge.id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azurerm_cognitive_account.openai.identity[0].principal_id
}

resource "azurerm_role_assignment" "openai_datasets_reader" {
  scope                = azurerm_storage_account.datasets.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_cognitive_account.openai.identity[0].principal_id
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-ml-platform"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "datasets" {
  name                       = "datasets-diag"
  target_resource_id         = azurerm_storage_account.datasets.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_diagnostic_setting" "openai" {
  name                       = "openai-diag"
  target_resource_id         = azurerm_cognitive_account.openai.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "RequestResponse"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "ml" {
  name                       = "ml-diag"
  target_resource_id         = azurerm_machine_learning_workspace.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AmlComputeJobEvent"
  }
}

resource "azurerm_monitor_diagnostic_setting" "search" {
  name                       = "search-diag"
  target_resource_id         = azurerm_search_service.knowledge.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "OperationLogs"
  }
}

# GenAI spend is dominated by tokens, and token spend has no natural ceiling.
resource "azurerm_consumption_budget_subscription" "openai" {
  name            = "openai-monthly"
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  amount          = 2500
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 75
    operator       = "GreaterThan"
    contact_emails = ["ml-platform@example.com"]
  }
}
