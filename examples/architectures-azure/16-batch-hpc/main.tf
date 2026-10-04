# ArchLens reference architecture 16 (Azure) — Batch compute and HPC
#
# Two workloads that both care about cost per core. Azure Batch runs the
# nightly risk calculation on Spot VMs; a VM Scale Set with InfiniBand-class
# networking and Lustre-backed storage handles the tightly-coupled
# simulations. Azure Quantum is wired in for the one team experimenting with
# quantum solvers.
#
# Services: Azure Batch (account + pool + job), VM Scale Set (Spot, HPC SKU),
# NetApp Files (HPC scratch), Azure Quantum, Storage Account, Key Vault, Log
# Analytics.
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

resource "azurerm_resource_group" "main" {
  name     = "rg-batch-hpc"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-batch-hpc-16"
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
  name                = "vnet-batch-hpc"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.150.0.0/16"]
}

resource "azurerm_subnet" "compute" {
  name                 = "snet-compute"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.150.0.0/22"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.150.10.0/24"]
}

resource "azurerm_network_security_group" "compute" {
  name                = "nsg-batch-hpc"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowIntraClusterMPI"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "10.150.0.0/22"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "compute" {
  subnet_id                 = azurerm_subnet.compute.id
  network_security_group_id = azurerm_network_security_group.compute.id
}

# --------------------------------------------------------------- Batch on Spot

resource "azurerm_storage_account" "batch" {
  name                            = "stbatchhpc16"
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

resource "azurerm_storage_management_policy" "batch" {
  storage_account_id = azurerm_storage_account.batch.id

  rule {
    name    = "tier-results"
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

resource "azurerm_monitor_diagnostic_setting" "batch_storage" {
  name                       = "batch-storage-diag"
  target_resource_id         = azurerm_storage_account.batch.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_user_assigned_identity" "batch" {
  name                = "id-batch-pool"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_batch_account" "main" {
  name                = "batchhpc16"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  pool_allocation_mode = "BatchService"
  storage_account_id   = azurerm_storage_account.batch.id

  encryption {
    key_vault_key_id = azurerm_key_vault_key.batch.id
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.batch.id]
  }

  key_vault_reference {
    id  = azurerm_key_vault.main.id
    url = azurerm_key_vault.main.vault_uri
  }

  public_network_access_enabled = false
}

resource "azurerm_key_vault_key" "batch" {
  name         = "batch-account-cmk"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
}

resource "azurerm_key_vault_access_policy" "batch" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.batch.principal_id

  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}

resource "azurerm_batch_pool" "risk" {
  name                = "risk-pool"
  resource_group_name  = azurerm_resource_group.main.name
  account_name         = azurerm_batch_account.main.name
  display_name         = "nightly-risk-calc"
  vm_size              = "Standard_D4s_v5"
  node_agent_sku_id    = "batch.node.ubuntu 22.04"

  # Spot is never pay more than on-demand for interruptible batch capacity.
  fixed_scale {
    target_dedicated_nodes    = 0
    target_low_priority_nodes = 20
    resize_timeout            = "PT15M"
  }

  storage_image_reference {
    publisher = "canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  network_configuration {
    subnet_id = azurerm_subnet.compute.id
  }

  start_task {
    command_line         = "echo starting"
    wait_for_success      = true

    user_identity {
      auto_user {
        elevation_level = "NonAdmin"
        scope           = "Task"
      }
    }
  }
}

resource "azurerm_batch_job" "nightly_risk" {
  name          = "nightly-risk"
  batch_pool_id = azurerm_batch_pool.risk.id
  priority      = 0

  task {
    name           = "run-risk-model"
    command_line   = "python3 risk_model.py"

    container_settings {
      image_name = "${azurerm_container_registry.main.login_server}/risk:4.2.0"
    }
  }
}

resource "azurerm_container_registry" "main" {
  name                = "acrbatchhpc16"
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

# ------------------------------------------------------------------------- HPC

resource "azurerm_netapp_account" "main" {
  name                = "anf-batch-hpc-16"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_netapp_pool" "scratch" {
  name                = "hpc-scratch-pool"
  account_name         = azurerm_netapp_account.main.name
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  service_level        = "Ultra"
  size_in_tib          = 4
}

resource "azurerm_netapp_volume" "scratch" {
  name                = "hpc-scratch"
  account_name         = azurerm_netapp_account.main.name
  pool_name            = azurerm_netapp_pool.scratch.name
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  service_level        = "Ultra"
  subnet_id            = azurerm_subnet.private_endpoints.id
  volume_path          = "hpc-scratch"
  storage_quota_in_gb  = 4096
  protocols            = ["NFSv4.1"]

  export_policy_rule {
    rule_index        = 1
    allowed_clients    = ["10.150.0.0/22"]
    protocols_enabled  = ["NFSv4.1"]
    unix_read_only     = false
    unix_read_write    = true
  }

  data_protection_backup_policy {
    backup_vault_id  = azurerm_netapp_backup_vault.main.id
    backup_policy_id = azurerm_netapp_backup_policy.main.id
    policy_enabled   = true
  }
}

resource "azurerm_netapp_backup_vault" "main" {
  name                = "anf-backup-vault-16"
  account_name         = azurerm_netapp_account.main.name
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_netapp_backup_policy" "main" {
  name                = "anf-backup-policy-16"
  account_name         = azurerm_netapp_account.main.name
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  daily_backups_to_keep = 7
  enabled               = true
}

resource "azurerm_linux_virtual_machine_scale_set" "hpc" {
  name                = "vmss-hpc-sim"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard_HB176rs_v4"
  instances            = 4
  admin_username       = "hpcuser"
  priority             = "Spot"
  eviction_policy      = "Deallocate"
  single_placement_group = false

  admin_ssh_key {
    username   = "hpcuser"
    public_key = file("ssh_key.pub")
  }

  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "Premium_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.main.id
  }

  source_image_reference {
    publisher = "microsoft-dsvm"
    offer     = "ubuntu-hpc"
    sku       = "2204"
    version   = "latest"
  }

  network_interface {
    name                          = "hpc-nic"
    primary                       = true
    accelerated_networking_enabled = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.compute.id
    }
  }

  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.batch.primary_blob_endpoint
  }
}

resource "azurerm_monitor_autoscale_setting" "hpc" {
  name                = "autoscale-hpc-sim"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  target_resource_id   = azurerm_linux_virtual_machine_scale_set.hpc.id

  profile {
    name = "default"

    capacity {
      default = 4
      minimum = 0
      maximum = 64
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_linux_virtual_machine_scale_set.hpc.id
        time_grain          = "PT1M"
        statistic            = "Average"
        time_window          = "PT5M"
        time_aggregation      = "Average"
        operator              = "GreaterThan"
        threshold             = 75
      }

      scale_action {
        direction = "Increase"
        type      = "ChangeCount"
        value     = "4"
        cooldown  = "PT5M"
      }
    }
  }
}

resource "azurerm_disk_encryption_set" "main" {
  name                = "des-batch-hpc-16"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  key_vault_key_id     = azurerm_key_vault_key.hpc_disks.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_key" "hpc_disks" {
  name         = "hpc-disks-cmk"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
}

resource "azurerm_key_vault_access_policy" "des" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_disk_encryption_set.main.identity[0].principal_id

  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}

resource "azurerm_quantum_workspace" "research" {
  name                = "qw-batch-hpc-16"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  storage_account_id   = azurerm_storage_account.batch.id

  identity {
    type = "SystemAssigned"
  }

  providers {
    provider_id   = "microsoft-elements"
    sku           = "learnandecalc"
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-batch-hpc"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "batch" {
  name                       = "batch-account-diag"
  target_resource_id         = azurerm_batch_account.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ServiceLog"
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

resource "azurerm_monitor_metric_alert" "job_failures" {
  name                = "batch-task-failures"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_batch_account.main.id]
  severity             = 2

  criteria {
    metric_namespace = "Microsoft.Batch/batchAccounts"
    metric_name      = "TaskFailEvent"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 5
  }
}
