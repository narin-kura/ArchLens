# ArchLens reference architecture 15 (Azure) — Virtual desktops and customer
# contact centre
#
# The internal-facing half of an Azure estate. Azure Virtual Desktop gives
# contractors a managed desktop that never holds data locally, backed by
# FSLogix profile storage on Premium Azure Files; Communication Services
# carries the contact-centre voice and chat traffic with AI Language doing
# sentiment analysis on transcripts. Entra Domain Services provides the
# directory both the desktops and the file share authenticate against.
#
# Services: Entra Domain Services, Azure Virtual Desktop (host pool,
# workspace, application group), Azure Files Premium (FSLogix), Communication
# Services, AI Language, Key Vault, Log Analytics, Budget.
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
  name     = "rg-workforce"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-workforce-15"
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
  name                = "vnet-workforce"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.140.0.0/16"]
}

resource "azurerm_subnet" "desktops" {
  name                 = "snet-avd"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.140.0.0/22"]
}

resource "azurerm_subnet" "domain_services" {
  name                 = "snet-aadds"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.140.10.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.140.20.0/24"]
}

resource "azurerm_network_security_group" "desktops" {
  name                = "nsg-avd"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowSMBToFileShare"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "445"
    source_address_prefix      = "10.140.0.0/22"
    destination_address_prefix = "10.140.20.0/24"
  }
}

resource "azurerm_subnet_network_security_group_association" "desktops" {
  subnet_id                 = azurerm_subnet.desktops.id
  network_security_group_id = azurerm_network_security_group.desktops.id
}

# ------------------------------------------------------------------ Directory

resource "azurerm_active_directory_domain_service" "main" {
  name                = "corp.example.com"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"

  initial_replica_set {
    subnet_id = azurerm_subnet.domain_services.id
  }

  notifications {
    additional_recipients = ["it-ops@example.com"]
    notify_dc_admins       = true
    notify_global_admins   = true
  }

  security {
    sync_kerberos_passwords = true
    sync_ntlm_passwords     = true
    sync_on_prem_passwords  = true
    tls_ciphers_1_1_enabled = false
    tls_ciphers_1_2_enabled = true
  }
}

# -------------------------------------------------------------- Virtual Desktop

resource "azurerm_virtual_desktop_host_pool" "main" {
  name                     = "avdhp-workforce-15"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  type                      = "Pooled"
  load_balancer_type        = "DepthFirst"
  maximum_sessions_allowed  = 4
  start_vm_on_connect       = true

  scheduled_agent_updates {
    enabled = true

    schedule {
      day_of_week  = "Sunday"
      hour_of_day  = 3
    }
  }
}

resource "azurerm_virtual_desktop_host_pool_registration_info" "main" {
  hostpool_id     = azurerm_virtual_desktop_host_pool.main.id
  expiration_date = timeadd(timestamp(), "48h")
}

resource "azurerm_virtual_desktop_workspace" "main" {
  name                = "avdws-workforce-15"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_virtual_desktop_application_group" "desktop" {
  name                = "avdag-full-desktop"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  type                 = "Desktop"
  host_pool_id         = azurerm_virtual_desktop_host_pool.main.id
}

resource "azurerm_virtual_desktop_workspace_application_group_association" "main" {
  workspace_id          = azurerm_virtual_desktop_workspace.main.id
  application_group_id  = azurerm_virtual_desktop_application_group.desktop.id
}

resource "azurerm_virtual_desktop_scaling_plan" "business_hours" {
  name                = "avdsp-business-hours"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  time_zone            = "Eastern Standard Time"

  schedule {
    name                                 = "weekdays"
    days_of_week                          = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    ramp_up_start_time                    = "07:00"
    ramp_up_load_balancing_algorithm       = "BreadthFirst"
    ramp_up_minimum_hosts_percent          = 20
    ramp_up_capacity_threshold_percent     = 60
    peak_start_time                       = "09:00"
    peak_load_balancing_algorithm          = "DepthFirst"
    ramp_down_start_time                  = "18:00"
    ramp_down_load_balancing_algorithm      = "DepthFirst"
    ramp_down_minimum_hosts_percent         = 10
    ramp_down_capacity_threshold_percent    = 90
    ramp_down_force_logoff_users            = false
    ramp_down_wait_time_minutes             = 30
    ramp_down_notification_message          = "Session ending soon, please save your work."
    off_peak_start_time                    = "20:00"
    off_peak_load_balancing_algorithm       = "DepthFirst"
  }

  host_pool {
    hostpool_id          = azurerm_virtual_desktop_host_pool.main.id
    scaling_plan_enabled = true
  }
}

# --------------------------------------------------------------- FSLogix profiles

resource "azurerm_storage_account" "profiles" {
  name                            = "stworkforceprofiles15"
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

resource "azurerm_storage_share" "fslogix" {
  name                 = "fslogix-profiles"
  storage_account_name = azurerm_storage_account.profiles.name
  quota                = 1024
  enabled_protocol     = "SMB"
}

resource "azurerm_private_endpoint" "profiles" {
  name                = "pe-profiles"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "profiles-connection"
    private_connection_resource_id = azurerm_storage_account.profiles.id
    subresource_names              = ["file"]
    is_manual_connection            = false
  }
}

resource "azurerm_recovery_services_vault" "main" {
  name                = "rsv-workforce-15"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard"
  soft_delete_enabled  = true

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_backup_policy_file_share" "profiles" {
  name                = "daily-profiles"
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.main.name

  backup {
    frequency = "Daily"
    time      = "02:00"
  }

  retention_daily {
    count = 30
  }
}

resource "azurerm_backup_container_storage_account" "profiles" {
  resource_group_name  = azurerm_resource_group.main.name
  recovery_vault_name  = azurerm_recovery_services_vault.main.name
  storage_account_id   = azurerm_storage_account.profiles.id
}

resource "azurerm_backup_protected_file_share" "profiles" {
  resource_group_name       = azurerm_resource_group.main.name
  recovery_vault_name       = azurerm_recovery_services_vault.main.name
  source_storage_account_id = azurerm_storage_account.profiles.id
  source_file_share_name    = azurerm_storage_share.fslogix.name
  backup_policy_id          = azurerm_backup_policy_file_share.profiles.id

  depends_on = [azurerm_backup_container_storage_account.profiles]
}

resource "azurerm_monitor_diagnostic_setting" "profiles" {
  name                       = "profiles-diag"
  target_resource_id         = azurerm_storage_account.profiles.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

# ------------------------------------------------------------- Contact centre

resource "azurerm_communication_service" "support" {
  name                = "acs-workforce-support-15"
  resource_group_name  = azurerm_resource_group.main.name
  data_location        = "United States"
}

resource "azurerm_cognitive_account" "language" {
  name                = "lang-workforce-15"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  kind                 = "TextAnalytics"
  sku_name             = "S"
  custom_subdomain_name = "workforce15lang"
  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  network_acls {
    default_action = "Deny"
  }
}

resource "azurerm_private_endpoint" "language" {
  name                = "pe-language"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "language-connection"
    private_connection_resource_id = azurerm_cognitive_account.language.id
    subresource_names              = ["account"]
    is_manual_connection            = false
  }
}

resource "azurerm_monitor_diagnostic_setting" "acs" {
  name                       = "acs-diag"
  target_resource_id         = azurerm_communication_service.support.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "CallSummary"
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-workforce"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "hostpool" {
  name                       = "hostpool-diag"
  target_resource_id         = azurerm_virtual_desktop_host_pool.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Checkpoint"
  }
  enabled_log {
    category = "Error"
  }
  enabled_log {
    category = "Connection"
  }
}

resource "azurerm_monitor_metric_alert" "session_host_health" {
  name                = "avd-session-host-unavailable"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_virtual_desktop_host_pool.main.id]
  severity             = 1

  criteria {
    metric_namespace = "Microsoft.DesktopVirtualization/hostpools"
    metric_name      = "SessionHostShutdown"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }
}

resource "azurerm_consumption_budget_subscription" "workforce" {
  name            = "workforce-monthly"
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  amount          = 6000
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 85
    operator       = "GreaterThan"
    contact_emails = ["it-ops@example.com"]
  }
}
