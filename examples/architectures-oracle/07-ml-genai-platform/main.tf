# ArchLens reference architecture 07 (OCI) — ML / GenAI platform
#
# Two halves. Classic ML: a Data Science project with a private notebook
# session and a private, autoscaling model deployment. GenAI: a hosting
# Dedicated AI Cluster serving a model behind a private endpoint with content
# moderation on, and a Generative AI Agent doing RAG over company documents
# in Object Storage. The agent endpoint blocks prompt injection, PII and
# unsafe content on input and output — guardrails are not optional extras on
# an internet-adjacent LLM.
#
# Services: Data Science (project, notebook session, model deployment),
# Generative AI (dedicated AI cluster, endpoint, private endpoint), Generative
# AI Agents (agent, knowledge base, data source, endpoint), Object Storage,
# Vault (KMS), Logging, Monitoring, Notifications.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "tenancy_namespace" {}
variable "base_model_id" {}
variable "model_id" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.60.0.0/16"]
  display_name   = "vcn-ml-platform"
}

resource "oci_core_subnet" "ml" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.60.0.0/24"
  display_name               = "snet-ml"
  prohibit_public_ip_on_vnic = true
}

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "vault-ml"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "ml" {
  compartment_id      = var.compartment_id
  display_name        = "key-ml"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

# -------------------------------------------------------------- Classic ML

resource "oci_datascience_project" "main" {
  compartment_id = var.compartment_id
  display_name   = "ml-platform"
}

resource "oci_datascience_notebook_session" "workbench" {
  compartment_id = var.compartment_id
  project_id     = oci_datascience_project.main.id
  display_name   = "ml-workbench"

  notebook_session_config_details {
    shape                     = "VM.Standard.E5.Flex"
    subnet_id                 = oci_core_subnet.ml.id
    block_storage_size_in_gbs = 100

    notebook_session_shape_config_details {
      ocpus         = 4
      memory_in_gbs = 32
    }
  }
}

resource "oci_datascience_model_deployment" "churn" {
  compartment_id = var.compartment_id
  project_id     = oci_datascience_project.main.id
  display_name   = "churn-model"

  model_deployment_configuration_details {
    deployment_type = "SINGLE_MODEL"

    model_configuration_details {
      model_id = var.model_id

      instance_configuration {
        instance_shape_name = "VM.Standard.E5.Flex"
        subnet_id           = oci_core_subnet.ml.id

        model_deployment_instance_shape_config_details {
          ocpus         = 2
          memory_in_gbs = 16
        }
      }

      scaling_policy {
        policy_type = "AUTOSCALING"

        auto_scaling_policies {
          auto_scaling_policy_type = "THRESHOLD"
          initial_instance_count   = 1
          minimum_instance_count   = 1
          maximum_instance_count   = 4

          rules {
            metric_expression_rule_type = "PREDEFINED_EXPRESSION"
            metric_type                 = "CPU_UTILIZATION"

            scale_in_configuration {
              instance_count_adjustment = 1
              threshold                 = 20
            }

            scale_out_configuration {
              instance_count_adjustment = 1
              threshold                 = 70
            }
          }
        }
      }
    }
  }

  category_log_details {
    access {
      log_group_id = oci_logging_log_group.main.id
      log_id       = oci_logging_log.model_access.id
    }

    predict {
      log_group_id = oci_logging_log_group.main.id
      log_id       = oci_logging_log.model_predict.id
    }
  }
}

# ------------------------------------------------------------------ GenAI

resource "oci_generative_ai_dedicated_ai_cluster" "hosting" {
  compartment_id = var.compartment_id
  display_name   = "genai-hosting"
  type           = "HOSTING"
  unit_shape     = "LARGE_COHERE_V2"
  unit_count     = 1
}

resource "oci_generative_ai_generative_ai_private_endpoint" "main" {
  compartment_id = var.compartment_id
  display_name   = "genai-pe"
  dns_prefix     = "genai"
  subnet_id      = oci_core_subnet.ml.id
}

resource "oci_generative_ai_endpoint" "chat" {
  compartment_id                    = var.compartment_id
  display_name                      = "chat-endpoint"
  dedicated_ai_cluster_id           = oci_generative_ai_dedicated_ai_cluster.hosting.id
  model_id                          = var.base_model_id
  generative_ai_private_endpoint_id = oci_generative_ai_generative_ai_private_endpoint.main.id

  content_moderation_config {
    is_enabled = true
    mode       = "BLOCK"
  }
}

# ------------------------------------------------------------------ Agents

resource "oci_objectstorage_bucket" "docs" {
  compartment_id = var.compartment_id
  namespace      = var.tenancy_namespace
  name           = "agent-knowledge-docs"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  kms_key_id     = oci_kms_key.ml.id
}

resource "oci_generative_ai_agent_knowledge_base" "docs" {
  compartment_id = var.compartment_id
  display_name   = "company-docs"

  index_config {
    index_config_type           = "DEFAULT_INDEX_CONFIG"
    should_enable_hybrid_search = true
  }
}

resource "oci_generative_ai_agent_data_source" "docs" {
  compartment_id    = var.compartment_id
  knowledge_base_id = oci_generative_ai_agent_knowledge_base.docs.id
  display_name      = "docs-bucket"

  data_source_config {
    data_source_config_type = "OCI_OBJECT_STORAGE"

    object_storage_prefixes {
      bucket    = oci_objectstorage_bucket.docs.name
      namespace = var.tenancy_namespace
      prefix    = "published/"
    }
  }
}

resource "oci_generative_ai_agent_agent" "helpdesk" {
  compartment_id     = var.compartment_id
  display_name       = "helpdesk-agent"
  knowledge_base_ids = [oci_generative_ai_agent_knowledge_base.docs.id]
  welcome_message    = "How can I help?"
}

resource "oci_generative_ai_agent_agent_endpoint" "helpdesk" {
  compartment_id = var.compartment_id
  agent_id       = oci_generative_ai_agent_agent.helpdesk.id
  display_name   = "helpdesk-endpoint"

  guardrail_config {
    content_moderation_config {
      input_guardrail_mode  = "BLOCK"
      output_guardrail_mode = "BLOCK"
    }

    personally_identifiable_information_config {
      input_guardrail_mode  = "BLOCK"
      output_guardrail_mode = "BLOCK"
    }

    prompt_injection_config {
      input_guardrail_mode = "BLOCK"
    }
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-ml-platform"
}

resource "oci_logging_log" "model_access" {
  display_name = "model-access"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "CUSTOM"
}

resource "oci_logging_log" "model_predict" {
  display_name = "model-predict"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "CUSTOM"
}

resource "oci_logging_log" "docs_reads" {
  display_name = "docs-reads"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "read"
      resource    = oci_objectstorage_bucket.docs.name
      service     = "objectstorage"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_ons_notification_topic" "alerts" {
  compartment_id = var.compartment_id
  name           = "ml-platform-alerts"
}

resource "oci_budget_budget" "genai" {
  compartment_id = var.compartment_id
  display_name   = "genai-monthly"
  amount         = 5000
  reset_period   = "MONTHLY"
  target_type    = "COMPARTMENT"
  targets        = [var.compartment_id]
}

resource "oci_monitoring_alarm" "deployment_latency" {
  compartment_id        = var.compartment_id
  display_name          = "model-latency"
  metric_compartment_id = var.compartment_id
  namespace             = "oci_datascience_modeldeploy"
  query                 = "PredictLatency[5m].mean() > 2000"
  severity              = "WARNING"
  destinations          = [oci_ons_notification_topic.alerts.id]
  is_enabled            = true
}
