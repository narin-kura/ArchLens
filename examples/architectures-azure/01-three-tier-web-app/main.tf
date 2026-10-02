# ArchLens reference architecture 01 (Azure) — Three-tier web application
#
# The classic production web stack on Azure: public edge (Front Door + WAF +
# Application Gateway), private application tier (VM Scale Set), and an
# isolated data tier (Azure SQL + Cache for Redis). Secure-by-default: TDE is
# always on for SQL, TLS 1.2 is enforced everywhere, nothing in the data tier
# has a public endpoint, and every tier ships diagnostics to Log Analytics.
#
# Services: Virtual Network, Subnets, NSGs, NAT Gateway, Application Gateway,
# WAF Policy, Front Door, Azure Firewall-free (NSG only), VM Scale Set, Azure
# SQL (server + database), Cache for Redis, Storage Account, Key Vault,
# Managed Identity, Log Analytics, Microsoft Defender for Cloud.
#
# Expected ArchLens findings: the public Application Gateway NSG rule
# intentionally accepts "*" on 443 — that is what a public web tier is for.
# Everything else should come back clean.

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
variable "domain_name" { default = "app.example.com" }

resource "azurerm_resource_group" "main" {
  name     = "rg-three-tier"
  location = var.location
}

# ---------------------------------------------------------------- Encryption

resource "azurerm_key_vault" "main" {
  name                       = "kv-three-tier-01"
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

resource "azurerm_key_vault_key" "main" {
  name         = "three-tier-cmk"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
}

# --------------------------------------------------------------------- Network

resource "azurerm_virtual_network" "main" {
  name                = "vnet-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "public" {
  name                 = "snet-public"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.20.0.0/24"]
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.20.10.0/24"]
}

resource "azurerm_subnet" "data" {
  name                 = "snet-data"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.20.20.0/24"]

  delegation {
    name = "sql-delegation"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
    }
  }
}

resource "azurerm_public_ip" "nat" {
  name                = "pip-nat"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  allocation_method    = "Static"
  sku                  = "Standard"
}

resource "azurerm_nat_gateway" "main" {
  name                = "natgw-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku_name             = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "main" {
  nat_gateway_id       = azurerm_nat_gateway.main.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "app" {
  subnet_id      = azurerm_subnet.app.id
  nat_gateway_id = azurerm_nat_gateway.main.id
}

resource "azurerm_network_security_group" "appgw" {
  name                = "nsg-appgw"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowHTTPSInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Application Gateway v2 requires this port open from GatewayManager for
  # the platform's own health probes — not a finding, it is a hard requirement.
  security_rule {
    name                       = "AllowGatewayManager"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "appgw" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.appgw.id
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                         = "AllowFromAppGateway"
    priority                     = 100
    direction                    = "Inbound"
    access                       = "Allow"
    protocol                     = "Tcp"
    source_port_range            = "*"
    destination_port_range       = "8080"
    source_address_prefix        = "10.20.0.0/24"
    destination_address_prefix   = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_network_security_group" "data" {
  name                = "nsg-data"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  security_rule {
    name                       = "AllowFromAppTier"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "6380"
    source_address_prefix      = "10.20.10.0/24"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data.id
}

# ------------------------------------------------------------------- Edge tier

resource "azurerm_web_application_firewall_policy" "main" {
  name                = "waf-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  policy_settings {
    enabled                     = true
    mode                        = "Prevention"
    request_body_check           = true
    file_upload_limit_in_mb      = 100
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}

resource "azurerm_public_ip" "appgw" {
  name                = "pip-appgw"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  allocation_method    = "Static"
  sku                  = "Standard"
}

resource "azurerm_application_gateway" "main" {
  name                = "agw-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  firewall_policy_id   = azurerm_web_application_firewall_policy.main.id

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 2
    max_capacity = 10
  }

  gateway_ip_configuration {
    name      = "appgw-ipconfig"
    subnet_id = azurerm_subnet.public.id
  }

  frontend_ip_configuration {
    name                 = "appgw-frontend"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  frontend_port {
    name = "port-443"
    port = 443
  }

  backend_address_pool {
    name = "app-pool"
  }

  backend_http_settings {
    name                  = "app-http-settings"
    cookie_based_affinity = "Disabled"
    port                  = 8080
    protocol              = "Http"
    request_timeout       = 30
  }

  http_listener {
    name                           = "https-listener"
    frontend_ip_configuration_name = "appgw-frontend"
    frontend_port_name             = "port-443"
    protocol                       = "Https"
    ssl_certificate_name           = "app-cert"
  }

  ssl_certificate {
    name                = "app-cert"
    key_vault_secret_id = azurerm_key_vault_key.main.id
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"
  }

  request_routing_rule {
    name                       = "https-rule"
    rule_type                  = "Basic"
    http_listener_name         = "https-listener"
    backend_address_pool_name  = "app-pool"
    backend_http_settings_name = "app-http-settings"
    priority                   = 100
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appgw.id]
  }
}

resource "azurerm_user_assigned_identity" "appgw" {
  name                = "id-appgw"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_key_vault_access_policy" "appgw" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.appgw.principal_id

  secret_permissions = ["Get"]
  key_permissions     = ["Get"]
}

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "afd-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  sku_name             = "Premium_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  name                     = "three-tier-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
}

resource "azurerm_cdn_frontdoor_origin_group" "main" {
  name                     = "app-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/healthz"
    request_type        = "GET"
    protocol            = "Https"
    interval_in_seconds = 30
  }
}

resource "azurerm_cdn_frontdoor_origin" "main" {
  name                           = "app-gateway-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.main.id
  host_name                      = azurerm_public_ip.appgw.ip_address
  https_port                     = 443
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  name                = "afdwaf-three-tier"
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

resource "azurerm_cdn_frontdoor_route" "main" {
  name                          = "app-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.main.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.main.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.main.id]
  supported_protocols           = ["Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
}

# ------------------------------------------------------------ Application tier

resource "azurerm_user_assigned_identity" "app" {
  name                = "id-app-vmss"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_key_vault_access_policy" "app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.app.principal_id

  secret_permissions = ["Get", "List"]
}

resource "azurerm_linux_virtual_machine_scale_set" "app" {
  name                = "vmss-app"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "Standard_D2s_v5"
  instances            = 3
  admin_username       = "azureuser"

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("ssh_key.pub")
  }

  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "Premium_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.main.id
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  network_interface {
    name    = "app-nic"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.app.id
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.diagnostics.primary_blob_endpoint
  }

  upgrade_mode = "Rolling"

  rolling_upgrade_policy {
    max_batch_instance_percent              = 20
    max_unhealthy_instance_percent          = 20
    max_unhealthy_upgraded_instance_percent = 20
    pause_time_between_batches              = "PT30S"
  }

  automatic_os_upgrade_policy {
    disable_automatic_rollback  = false
    enable_automatic_os_upgrade = true
  }
}

resource "azurerm_disk_encryption_set" "main" {
  name                = "des-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  key_vault_key_id     = azurerm_key_vault_key.main.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_access_policy" "des" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_disk_encryption_set.main.identity[0].principal_id

  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}

resource "azurerm_monitor_autoscale_setting" "app" {
  name                = "autoscale-app"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  target_resource_id   = azurerm_linux_virtual_machine_scale_set.app.id

  profile {
    name = "default"

    capacity {
      default = 3
      minimum = 3
      maximum = 10
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_linux_virtual_machine_scale_set.app.id
        time_grain          = "PT1M"
        statistic            = "Average"
        time_window          = "PT5M"
        time_aggregation      = "Average"
        operator              = "GreaterThan"
        threshold             = 65
      }

      scale_action {
        direction = "Increase"
        type      = "ChangeCount"
        value     = "2"
        cooldown  = "PT5M"
      }
    }
  }
}

# ------------------------------------------------------------------- Data tier

resource "azurerm_mssql_server" "main" {
  name                         = "sql-three-tier"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "12.0"
  minimum_tls_version            = "1.2"
  public_network_access_enabled  = false

  azuread_administrator {
    login_username = "sql-admins"
    object_id       = data.azurerm_client_config.current.object_id
  }

  identity {
    type = "SystemAssigned"
  }

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.diagnostics.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.diagnostics.primary_access_key
    storage_account_access_key_is_secondary = false
    retention_in_days                       = 90
  }
}

resource "azurerm_mssql_database" "main" {
  name           = "appdb"
  server_id      = azurerm_mssql_server.main.id
  sku_name       = "S2"
  zone_redundant = true

  short_term_retention_policy {
    retention_days = 14
  }

  long_term_retention_policy {
    weekly_retention  = "P8W"
    monthly_retention = "P12M"
  }
}

resource "azurerm_private_endpoint" "sql" {
  name                = "pe-sql"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.data.id

  private_service_connection {
    name                           = "sql-connection"
    private_connection_resource_id = azurerm_mssql_server.main.id
    subresource_names              = ["sqlServer"]
    is_manual_connection            = false
  }
}

resource "azurerm_redis_cache" "main" {
  name                = "redis-three-tier"
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
  subnet_id            = azurerm_subnet.data.id

  private_service_connection {
    name                           = "redis-connection"
    private_connection_resource_id = azurerm_redis_cache.main.id
    subresource_names              = ["redisCache"]
    is_manual_connection            = false
  }
}

# -------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "assets" {
  name                            = "stthreetierassets"
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

resource "azurerm_storage_management_policy" "assets" {
  storage_account_id = azurerm_storage_account.assets.id

  rule {
    name    = "tier-and-expire"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 120
      }
      version {
        delete_after_days_since_creation = 90
      }
    }
  }
}

resource "azurerm_storage_account" "diagnostics" {
  name                            = "stthreetierdiag"
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

# ------------------------------------------------------------------------ IAM

resource "azurerm_role_assignment" "app_sql" {
  scope                = azurerm_mssql_server.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-three-tier"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "appgw-diag"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }
  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "sql" {
  name                       = "sql-diag"
  target_resource_id         = azurerm_mssql_server.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SQLSecurityAuditEvents"
  }
}

resource "azurerm_monitor_diagnostic_setting" "redis" {
  name                       = "redis-diag"
  target_resource_id         = azurerm_redis_cache.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ConnectedClientList"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "storage-diag"
  target_resource_id         = azurerm_storage_account.assets.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

# Routing a storage account's own diagnostics to Log Analytics is not a
# feedback loop the way an S3 bucket logging to itself would be — Azure
# diagnostic settings ship to Monitor, never back into the account's blobs.
resource "azurerm_monitor_diagnostic_setting" "diagnostics_storage" {
  name                       = "diag-storage-diag"
  target_resource_id         = azurerm_storage_account.diagnostics.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_metric_alert" "appgw_5xx" {
  name                = "appgw-5xx-rate"
  resource_group_name  = azurerm_resource_group.main.name
  scopes               = [azurerm_application_gateway.main.id]
  severity             = 2

  criteria {
    metric_namespace = "Microsoft.Network/applicationGateways"
    metric_name      = "ResponseStatus"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 50
  }
}

resource "azurerm_security_center_subscription_pricing" "vm" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  tier          = "Standard"
  resource_type = "SqlServers"
}
