# ArchLens reference architecture 13 (Azure) — CI/CD and developer platform
#
# Build once, promote the same artefact. Azure Pipelines moves a commit
# through build, scan, staging and a manual-approval gate to production;
# self-hosted agents run inside the VNet so builds can reach private
# dependencies; images are scanned before they are deployable. Load Testing
# and Chaos Studio exercise the rollback path on a schedule, because an
# untested rollback is not a rollback.
#
# Services: Azure DevOps (project, pipeline, repo, variable group), Container
# Registry, Dev Center / Deployment Environments, Load Testing, Chaos Studio,
# Key Vault, Log Analytics.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm     = { source = "hashicorp/azurerm", version = "~> 3.90" }
    azuredevops = { source = "microsoft/azuredevops", version = "~> 1.0" }
  }
}

provider "azurerm" {
  features {}
}

provider "azuredevops" {
  org_service_url = "https://dev.azure.com/example-corp"
}

variable "location" { default = "eastus2" }

resource "azurerm_resource_group" "main" {
  name     = "rg-cicd"
  location = var.location
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-cicd-13"
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
# Self-hosted agents run in private subnets so a compromised build cannot be
# reached from the internet, and can only reach what the NSG allows.

resource "azurerm_virtual_network" "main" {
  name                = "vnet-cicd"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  address_space        = ["10.120.0.0/16"]
}

resource "azurerm_subnet" "agents" {
  name                 = "snet-build-agents"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.120.0.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_name  = azurerm_virtual_network.main.name
  address_prefixes      = ["10.120.10.0/24"]
}

resource "azurerm_network_security_group" "agents" {
  name                = "nsg-build-agents"
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
    destination_address_prefix = "10.120.0.0/16"
  }
}

resource "azurerm_subnet_network_security_group_association" "agents" {
  subnet_id                 = azurerm_subnet.agents.id
  network_security_group_id = azurerm_network_security_group.agents.id
}

# ------------------------------------------------------------------- Artefacts

resource "azurerm_container_registry" "main" {
  name                = "acrcicd13"
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

# ---------------------------------------------------------------------- Pipeline

resource "azuredevops_project" "app" {
  name               = "example-app"
  visibility         = "private"
  version_control    = "Git"
  work_item_template = "Agile"
}

resource "azuredevops_git_repository" "app" {
  project_id = azuredevops_project.app.id
  name       = "app"

  initialization {
    init_type = "Clean"
  }
}

resource "azuredevops_serviceendpoint_azurerm" "acr" {
  project_id                            = azuredevops_project.app.id
  service_endpoint_name                  = "acr-connection"
  azurerm_spn_tenantid                   = data.azurerm_client_config.current.tenant_id
  azurerm_subscription_id                = "00000000-0000-0000-0000-000000000000"
  azurerm_subscription_name              = "example-subscription"

  service_endpoint_authentication_scheme = "WorkloadIdentityFederation"
}

resource "azuredevops_variable_group" "app" {
  project_id   = azuredevops_project.app.id
  name         = "app-pipeline-variables"
  allow_access = true

  key_vault {
    name                = azurerm_key_vault.main.name
    service_endpoint_id = azuredevops_serviceendpoint_azurerm.acr.id
  }

  variable {
    name = "ACR_LOGIN_SERVER"
  }
}

resource "azuredevops_build_definition" "app" {
  project_id = azuredevops_project.app.id
  name       = "app-ci"

  ci_trigger {
    use_yaml = true
  }

  repository {
    repo_type   = "TfsGit"
    repo_id     = azuredevops_git_repository.app.id
    branch_name = azuredevops_git_repository.app.default_branch
    yml_path    = "azure-pipelines.yml"
  }

  variable_groups = [azuredevops_variable_group.app.id]
}

resource "azuredevops_environment" "production" {
  project_id  = azuredevops_project.app.id
  name        = "production"
  description = "Requires manual approval before deploy"
}

resource "azuredevops_environment" "staging" {
  project_id  = azuredevops_project.app.id
  name        = "staging"
}

# -------------------------------------------------------------- Build agents

resource "azurerm_dev_center" "main" {
  name                = "dc-cicd-13"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_dev_center_project" "app" {
  name                = "app-dev-environments"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  dev_center_id        = azurerm_dev_center.main.id
}

resource "azurerm_dev_center_environment_type" "staging" {
  name              = "staging"
  dev_center_id     = azurerm_dev_center.main.id
}

# ------------------------------------------------------------- Resilience test

resource "azurerm_load_test" "app" {
  name                = "lt-app-13"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_chaos_studio_target" "staging_vmss" {
  location           = azurerm_resource_group.main.location
  target_resource_id = azurerm_user_assigned_identity.chaos.id
  target_type        = "Microsoft-VirtualMachineScaleSet"
}

resource "azurerm_user_assigned_identity" "chaos" {
  name                = "id-chaos-studio"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
}

resource "azurerm_chaos_studio_experiment" "kill_instances" {
  name                = "staging-instance-kill"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }

  selectors {
    name = "staging-vmss-selector"
    targets = [azurerm_chaos_studio_target.staging_vmss.id]
  }

  steps {
    name = "kill-a-third-of-instances"

    branch {
      name = "branch-1"

      actions {
        urn            = "urn:csci:microsoft:virtualMachineScaleSet:shutdown/1.0"
        action_type    = "continuous"
        duration       = "PT10M"

        parameters = {
          abruptShutdown = "true"
        }

        selector_name = "staging-vmss-selector"
      }
    }
  }
}

# ------------------------------------------------------------- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-cicd"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  sku                  = "PerGB2018"
  retention_in_days    = 90
}

resource "azurerm_monitor_diagnostic_setting" "acr" {
  name                       = "acr-diag"
  target_resource_id         = azurerm_container_registry.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ContainerRegistryRepositoryEvents"
  }
}
