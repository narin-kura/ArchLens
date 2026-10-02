# ArchLens reference architecture 05 (Azure) — AKS platform
#
# A Kubernetes platform an internal team can build on: private API server,
# Azure AD-integrated RBAC, workload identity instead of node-level service
# principals, a system node pool kept separate from user workloads, and the
# Azure Policy add-on enforcing baseline guardrails inside the cluster itself.
# Monitoring is Container Insights so no one has to run the monitoring stack
# inside the cluster they are monitoring.
#
# Services: AKS (private cluster), system + user node pools, Container
# Registry, Key Vault (workload identity federation), Azure Policy add-on,
# Container Insights, Azure Files (Premium, for persistent volumes), VNet,
# Log Analytics.
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

variable "location" { default = "westus2" }
variable "kubernetes_version" { default = "1.30" }

resource "azurerm_resource_group" "main" {
  name     = "rg-aks-platform"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-aks-platform-05"
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
  name                = "vnet-aks-platform"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.60.0.0/16"]
}

resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.60.0.0/20"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.60.16.0/24"]
}

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-aks"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowIntraClusterTraffic"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "10.60.0.0/16"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# ------------------------------------------------------------------ Registry

resource "azurerm_container_registry" "main" {
  name                = "acraksplatform05"
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

resource "azurerm_security_center_subscription_pricing" "registries" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

# ------------------------------------------------------------------- Cluster

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-aks-platform"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_kubernetes_cluster" "main" {
  name                    = "aks-platform"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  dns_prefix               = "aksplatform"
  kubernetes_version       = var.kubernetes_version
  private_cluster_enabled  = true
  sku_tier                 = "Standard"

  default_node_pool {
    name                   = "system"
    node_count             = 3
    vm_size                = "Standard_D4s_v5"
    vnet_subnet_id          = azurerm_subnet.aks.id
    only_critical_addons_enabled = true
    enable_auto_scaling     = true
    min_count               = 3
    max_count               = 6
    temporary_name_for_rotation = "systemtemp"
  }

  identity {
    type = "SystemAssigned"
  }

  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  azure_policy_enabled = true

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "user"
  kubernetes_cluster_id  = azurerm_kubernetes_cluster.main.id
  vm_size                = "Standard_D4s_v5"
  vnet_subnet_id         = azurerm_subnet.aks.id
  mode                   = "User"

  enable_auto_scaling = true
  min_count           = 3
  max_count            = 30

  node_taints = ["workload=general:NoSchedule"]
}

resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}

# Workload identity: application pods federate to this managed identity
# through the cluster's OIDC issuer — no node-level credential to leak.
resource "azurerm_user_assigned_identity" "workload" {
  name                = "id-platform-workload"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_federated_identity_credential" "workload" {
  name                = "platform-workload-federation"
  resource_group_name  = azurerm_resource_group.main.name
  parent_id            = azurerm_user_assigned_identity.workload.id
  audience             = ["api://AzureADTokenExchange"]
  issuer               = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject              = "system:serviceaccount:apps:workload-identity-sa"
}

resource "azurerm_key_vault_access_policy" "workload" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.workload.principal_id

  secret_permissions = ["Get", "List"]
}

# ------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "persistent_volumes" {
  name                            = "staksplatformpv05"
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

resource "azurerm_storage_share" "shared_data" {
  name                 = "shared-data"
  storage_account_name = azurerm_storage_account.persistent_volumes.name
  quota                = 100
  enabled_protocol     = "NFS"
}

resource "azurerm_recovery_services_vault" "main" {
  name                = "rsv-aks-platform-05"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"
  soft_delete_enabled  = true

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_backup_policy_file_share" "shared_data" {
  name                = "daily-shared-data"
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.main.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 30
  }
}

resource "azurerm_backup_container_storage_account" "main" {
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.main.name
  storage_account_id   = azurerm_storage_account.persistent_volumes.id
}

resource "azurerm_backup_protected_file_share" "shared_data" {
  resource_group_name       = azurerm_resource_group.main.name
  recovery_vault_name       = azurerm_recovery_services_vault.main.name
  source_storage_account_id = azurerm_storage_account.persistent_volumes.id
  source_file_share_name    = azurerm_storage_share.shared_data.name
  backup_policy_id          = azurerm_backup_policy_file_share.shared_data.id

  depends_on = [azurerm_backup_container_storage_account.main]
}

resource "azurerm_private_endpoint" "storage" {
  name                = "pe-storage"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "storage-connection"
    private_connection_resource_id = azurerm_storage_account.persistent_volumes.id
    subresource_names              = ["file"]
    is_manual_connection            = false
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "storage-diag"
  target_resource_id         = azurerm_storage_account.persistent_volumes.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "aks-diag"
  target_resource_id         = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "kube-audit"
  }
  enabled_log {
    category = "guard"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_metric_alert" "node_not_ready" {
  name                = "aks-nodes-not-ready"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_kubernetes_cluster.main.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "kube_node_status_condition"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 3
  }
}

resource "azurerm_security_center_subscription_pricing" "kubernetes" {
  tier          = "Standard"
  resource_type = "KubernetesService"
}
