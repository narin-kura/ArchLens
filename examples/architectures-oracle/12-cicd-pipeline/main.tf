# ArchLens reference architecture 12 (OCI) — CI/CD with OCI DevOps
#
# A push to the main branch of an OCI DevOps code repository triggers a
# build pipeline whose build runner sits in a private subnet (it can reach
# internal dependencies, nothing can reach it), pushes the image to a
# private immutable OCIR repo, then hands off to a deploy pipeline: staging
# rollout, a two-person manual approval gate, then production — each OKE
# stage rolls itself back automatically on failure.
#
# Services: DevOps (project, repository, protected branch, build pipeline +
# stages, deploy pipeline + stages, artifacts, environments, trigger), OCIR,
# Notifications, Logging.
#
# Expected ArchLens findings: clean.

terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 6.0" }
  }
}

variable "compartment_id" {}
variable "staging_cluster_id" {}
variable "prod_cluster_id" {}
variable "ocir_image_uri" {}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.90.0.0/16"]
  display_name   = "vcn-cicd"
}

resource "oci_core_subnet" "build" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.90.0.0/24"
  display_name               = "snet-build-runners"
  prohibit_public_ip_on_vnic = true
}

resource "oci_ons_notification_topic" "devops" {
  compartment_id = var.compartment_id
  name           = "devops-events"
}

resource "oci_devops_project" "app" {
  compartment_id = var.compartment_id
  name           = "app"

  notification_config {
    topic_id = oci_ons_notification_topic.devops.id
  }
}

resource "oci_devops_repository" "app" {
  project_id      = oci_devops_project.app.id
  name            = "app"
  repository_type = "HOSTED"
  default_branch  = "refs/heads/main"
}

resource "oci_artifacts_container_repository" "app" {
  compartment_id = var.compartment_id
  display_name   = "cicd/app"
  is_public      = false
  is_immutable   = true
}

# ------------------------------------------------------------------- Build

resource "oci_devops_build_pipeline" "app" {
  project_id   = oci_devops_project.app.id
  display_name = "app-build"
}

resource "oci_devops_build_pipeline_stage" "build" {
  build_pipeline_id         = oci_devops_build_pipeline.app.id
  build_pipeline_stage_type = "BUILD"
  display_name              = "build-and-test"
  image                     = "OL7_X86_64_STANDARD_10"
  build_spec_file           = "build_spec.yaml"
  primary_build_source      = "app"

  build_pipeline_stage_predecessor_collection {
    items {
      id = oci_devops_build_pipeline.app.id
    }
  }

  build_source_collection {
    items {
      name            = "app"
      connection_type = "DEVOPS_CODE_REPOSITORY"
      repository_id   = oci_devops_repository.app.id
      repository_url  = oci_devops_repository.app.http_url
      branch          = "main"
    }
  }

  private_access_config {
    network_channel_type = "PRIVATE_ENDPOINT_CHANNEL"
    subnet_id            = oci_core_subnet.build.id
  }
}

resource "oci_devops_deploy_artifact" "image" {
  project_id                 = oci_devops_project.app.id
  display_name               = "app-image"
  deploy_artifact_type       = "DOCKER_IMAGE"
  argument_substitution_mode = "SUBSTITUTE_PLACEHOLDERS"

  deploy_artifact_source {
    deploy_artifact_source_type = "OCIR"
    image_uri                   = "${var.ocir_image_uri}:$${BUILDRUN_HASH}"
  }
}

resource "oci_devops_deploy_artifact" "manifest" {
  project_id                 = oci_devops_project.app.id
  display_name               = "app-manifest"
  deploy_artifact_type       = "KUBERNETES_MANIFEST"
  argument_substitution_mode = "SUBSTITUTE_PLACEHOLDERS"

  deploy_artifact_source {
    deploy_artifact_source_type = "INLINE"
    base64encoded_content       = filebase64("k8s/app.yaml")
  }
}

resource "oci_devops_build_pipeline_stage" "deliver" {
  build_pipeline_id         = oci_devops_build_pipeline.app.id
  build_pipeline_stage_type = "DELIVER_ARTIFACT"
  display_name              = "push-image"

  build_pipeline_stage_predecessor_collection {
    items {
      id = oci_devops_build_pipeline_stage.build.id
    }
  }

  deliver_artifact_collection {
    items {
      artifact_id   = oci_devops_deploy_artifact.image.id
      artifact_name = "app_image"
    }
  }
}

resource "oci_devops_build_pipeline_stage" "trigger_deploy" {
  build_pipeline_id              = oci_devops_build_pipeline.app.id
  build_pipeline_stage_type      = "TRIGGER_DEPLOYMENT_PIPELINE"
  display_name                   = "start-deploy"
  deploy_pipeline_id             = oci_devops_deploy_pipeline.app.id
  is_pass_all_parameters_enabled = true

  build_pipeline_stage_predecessor_collection {
    items {
      id = oci_devops_build_pipeline_stage.deliver.id
    }
  }
}

resource "oci_devops_trigger" "main" {
  project_id     = oci_devops_project.app.id
  display_name   = "on-push-main"
  trigger_source = "DEVOPS_CODE_REPOSITORY"
  repository_id  = oci_devops_repository.app.id

  actions {
    type              = "TRIGGER_BUILD_PIPELINE"
    build_pipeline_id = oci_devops_build_pipeline.app.id

    trigger_filter {
      trigger_source = "DEVOPS_CODE_REPOSITORY"
      events         = ["PUSH"]

      include {
        head_ref = "main"
      }
    }
  }
}

# ------------------------------------------------------------------ Deploy

resource "oci_devops_deploy_environment" "staging" {
  project_id              = oci_devops_project.app.id
  display_name            = "staging"
  deploy_environment_type = "OKE_CLUSTER"
  cluster_id              = var.staging_cluster_id
}

resource "oci_devops_deploy_environment" "production" {
  project_id              = oci_devops_project.app.id
  display_name            = "production"
  deploy_environment_type = "OKE_CLUSTER"
  cluster_id              = var.prod_cluster_id
}

resource "oci_devops_deploy_pipeline" "app" {
  project_id   = oci_devops_project.app.id
  display_name = "app-deploy"
}

resource "oci_devops_deploy_stage" "staging" {
  deploy_pipeline_id                      = oci_devops_deploy_pipeline.app.id
  deploy_stage_type                       = "OKE_DEPLOYMENT"
  display_name                            = "deploy-staging"
  oke_cluster_deploy_environment_id       = oci_devops_deploy_environment.staging.id
  kubernetes_manifest_deploy_artifact_ids = [oci_devops_deploy_artifact.manifest.id]

  deploy_stage_predecessor_collection {
    items {
      id = oci_devops_deploy_pipeline.app.id
    }
  }

  rollback_policy {
    policy_type = "AUTOMATED_STAGE_ROLLBACK_POLICY"
  }
}

resource "oci_devops_deploy_stage" "approval" {
  deploy_pipeline_id = oci_devops_deploy_pipeline.app.id
  deploy_stage_type  = "MANUAL_APPROVAL"
  display_name       = "production-approval"

  deploy_stage_predecessor_collection {
    items {
      id = oci_devops_deploy_stage.staging.id
    }
  }

  approval_policy {
    approval_policy_type         = "COUNT_BASED_APPROVAL"
    number_of_approvals_required = 2
  }
}

resource "oci_devops_deploy_stage" "production" {
  deploy_pipeline_id                      = oci_devops_deploy_pipeline.app.id
  deploy_stage_type                       = "OKE_DEPLOYMENT"
  display_name                            = "deploy-production"
  oke_cluster_deploy_environment_id       = oci_devops_deploy_environment.production.id
  kubernetes_manifest_deploy_artifact_ids = [oci_devops_deploy_artifact.manifest.id]

  deploy_stage_predecessor_collection {
    items {
      id = oci_devops_deploy_stage.approval.id
    }
  }

  rollback_policy {
    policy_type = "AUTOMATED_STAGE_ROLLBACK_POLICY"
  }
}

# ------------------------------------------------------------- Observability

resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_id
  display_name   = "lg-cicd"
}

resource "oci_logging_log" "devops" {
  display_name = "devops-runs"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "all"
      resource    = oci_devops_project.app.id
      service     = "devops"
      source_type = "OCISERVICE"
    }
  }
}
