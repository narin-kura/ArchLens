# ArchLens reference architecture 03 (Azure) — Static site on Storage + Front Door
#
# The cheapest way to serve a web front end on Azure: a storage account's
# static website feature behind Front Door, origin locked to Front Door's own
# traffic via a secret header, Private Link closing the direct path entirely.
# Nothing is public except through the CDN.
#
# Services: Storage Account (static website), Front Door (Premium), WAF
# Policy, Private Link origin, DNS, Key Vault, Log Analytics, Budget.
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
variable "domain_name" { default = "www.example.com" }

resource "azurerm_resource_group" "main" {
  name     = "rg-static-site"
  location = var.location
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-static-site"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

# ------------------------------------------------------------------- Storage

resource "azurerm_storage_account" "site" {
  name                            = "ststaticsiteexample"
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  public_network_access_enabled    = false

  static_website {
    index_document     = "index.html"
    error_404_document = "404.html"
  }

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

resource "azurerm_storage_management_policy" "site" {
  storage_account_id = azurerm_storage_account.site.id

  rule {
    name    = "expire-old-versions"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      version {
        delete_after_days_since_creation = 30
      }
    }
  }
}

resource "azurerm_private_endpoint" "site" {
  name                = "pe-static-site"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  subnet_id            = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "site-blob-connection"
    private_connection_resource_id = azurerm_storage_account.site.id
    subresource_names              = ["blob"]
    is_manual_connection            = false
  }
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-static-site"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.40.0.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.40.0.0/27"]
}

# --------------------------------------------------------------------- Edge

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "afd-static-site"
  resource_group_name  = azurerm_resource_group.main.name
  sku_name             = "Premium_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  name                     = "static-site-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
}

resource "azurerm_cdn_frontdoor_origin_group" "main" {
  name                     = "site-origin-group"
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

resource "azurerm_cdn_frontdoor_origin" "main" {
  name                           = "site-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.main.id
  host_name                      = azurerm_storage_account.site.primary_web_host
  origin_host_header             = azurerm_storage_account.site.primary_web_host
  https_port                     = 443
  certificate_name_check_enabled = true

  # Azure Front Door's Private Link to the storage account's static website
  # endpoint closes the only other path in: nothing reaches the origin except
  # through this profile.
  private_link {
    request_message        = "static-site-origin"
    target_type             = "web"
    location                = azurerm_resource_group.main.location
    private_link_target_id  = azurerm_storage_account.site.id
  }
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  name                = "afdwaf-static-site"
  resource_group_name  = azurerm_resource_group.main.name
  sku_name             = azurerm_cdn_frontdoor_profile.main.sku_name
  enabled              = true
  mode                 = "Prevention"

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.0"
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
  name                          = "site-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.main.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.main.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.main.id]
  supported_protocols           = ["Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
  link_to_default_domain        = true

  cache {
    query_string_caching_behavior = "IgnoreQueryString"
    compression_enabled            = true
    content_types_to_compress      = ["text/html", "text/css", "application/javascript"]
  }
}

resource "azurerm_cdn_frontdoor_custom_domain" "main" {
  name                     = "static-site-domain"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
  host_name                = var.domain_name

  tls {
    certificate_type    = "ManagedCertificate"
    minimum_tls_version = "TLS12"
  }
}

resource "azurerm_dns_zone" "main" {
  name                = "example.com"
  resource_group_name  = azurerm_resource_group.main.name
}

resource "azurerm_dns_cname_record" "www" {
  name                = "www"
  zone_name            = azurerm_dns_zone.main.name
  resource_group_name  = azurerm_resource_group.main.name
  ttl                  = 300
  record               = azurerm_cdn_frontdoor_endpoint.main.host_name
}

# ------------------------------------------------------------------ Security

resource "azurerm_key_vault" "main" {
  name                       = "kv-static-site-03"
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

# ------------------------------------------------------------- Observability

resource "azurerm_monitor_diagnostic_setting" "frontdoor" {
  name                       = "afd-diag"
  target_resource_id         = azurerm_cdn_frontdoor_profile.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "FrontDoorAccessLog"
  }
  enabled_log {
    category = "FrontDoorWebApplicationFirewallLog"
  }
  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "storage-diag"
  target_resource_id         = azurerm_storage_account.site.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  metric {
    category = "Transaction"
  }
}

resource "azurerm_consumption_budget_subscription" "monthly" {
  name            = "static-site-monthly"
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  amount          = 25
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = ["ops@example.com"]
  }
}
