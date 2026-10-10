# Installation still owns namespace, identity, storage, edge and pod guardrails.
# Once enabled on an installed workload, take software fields from the live
# release instead of restoring the bootstrap candidate during an infra apply.
# That includes everything provider-credential registration derives from the
# released instance: its image, its metadata ConfigMap and the files it copies.
variable "release_managed" {
  description = "Hand software deployment to day2-gke-release on an already installed app-call workload. Bootstrap with false, then enable. Provider credentials keep their installed key set while enabled; OAuth runtime is not in this release profile."
  type        = bool
  default     = false
}

# The live workload, read for every app: a list, so the first install (no
# StatefulSet yet) reads empty instead of failing.
data "kubernetes_resources" "workload" {
  api_version    = "apps/v1"
  kind           = "StatefulSet"
  namespace      = var.namespace
  field_selector = "metadata.name=${local.workload_name}"
}

locals {
  # Null before the first install.
  live = try(one(data.kubernetes_resources.workload.objects), null)
  # `day2 platform maintain activate` leaves the app at zero replicas and
  # stamps the artifact its database now runs. Until the workload is rolled to
  # it, the live (old) image must not restart on the migrated state. A stamp
  # equal to the live artifact is inert.
  activated_artifact = try(local.live.metadata.annotations["day2.dev/activated-artifact"], null)
  activation_pending = local.activated_artifact != null && local.activated_artifact != try(local.live.spec.template.metadata.annotations["day2.dev/artifact"], null)
  # A release-managed workload waits for day2-gke-release at its live replicas;
  # an infrastructure apply never starts the old image. Otherwise the profile's one.
  replicas = var.release_managed && local.activation_pending ? local.live.spec.replicas : 1

  released = var.release_managed ? local.live : null
  # day2.dev/activated-artifact: `day2 platform maintain activate` stamps it and
  # the release that rolls the workload to that artifact removes it. A directly
  # deployed app never declares it: the kubernetes provider removes annotations
  # the stack does not declare, so the apply that rolls the workload to the
  # activated artifact consumes the stamp too. Were it kept, it would equal the
  # live artifact and be inert.
  release_annotations = var.release_managed ? merge({ "day2.dev/release-managed" = "true" }, {
    for key, value in try(local.released.metadata.annotations, {}) : key => value
    if contains(["day2.dev/release-effect", "day2.dev/release-id", "day2.dev/activated-artifact"], key)
  }) : {}
  release_template_annotations = var.release_managed ? {
    for key, value in local.released.spec.template.metadata.annotations : key => value
    if contains(["day2.dev/artifact", "day2.dev/instance-sha256", "day2.dev/release-id", "day2.dev/credentials-sha256"], key)
  } : {}
  release_image = var.release_managed ? one([
    for container in local.released.spec.template.spec.containers : container.image if container.name == "day2"
  ]) : var.image
  release_artifact = var.release_managed ? local.released.spec.template.metadata.annotations["day2.dev/artifact"] : "sha256:${var.artifact_id}"
  release_instance = var.release_managed ? one([
    for volume in local.released.spec.template.spec.volumes : volume.configMap.name if volume.name == "instance"
  ]) : kubernetes_config_map_v1.instance.metadata[0].name

  # The release owns these; null when the live workload has no credentials.
  release_credential_image = try(one([
    for init in local.released.spec.template.spec.initContainers : init.image if init.name == "credential-registration"
  ]), null)
  release_credential_args = try(one([
    for init in local.released.spec.template.spec.initContainers : init.args if init.name == "credential-registration"
  ]), null)
  release_credential_files = try(one([
    for init in local.released.spec.template.spec.initContainers : init.command if init.name == "credential-files"
  ]), null)
  release_credential_keys = try([
    for source in local.release_credential_files : trimprefix(source, "${local.credential_source_dir}/")
    if startswith(source, "${local.credential_source_dir}/")
  ], [])
  release_credential_metadata = try(one([
    for volume in local.released.spec.template.spec.volumes : volume.configMap.name if volume.name == "credential-metadata"
  ]), null)
  release_credential_sources = try(one([
    for volume in local.released.spec.template.spec.volumes : volume.csi.volumeAttributes.secretProviderClass if volume.name == "credential-sources"
  ]), null)
}

resource "terraform_data" "release_admission" {
  lifecycle {
    # A directly deployed app is rolled by this apply, so it must roll exactly
    # the build the app's database activated, or wait.
    precondition {
      condition     = var.release_managed || !local.activation_pending || local.activated_artifact == "sha256:${var.artifact_id}"
      error_message = "${var.app_id}: `day2 platform maintain activate` activated ${coalesce(local.activated_artifact, "-")} and stopped ${local.workload_name}; its database no longer runs the deployed build. Set image and artifact_id to that build (artifact_id = ${trimprefix(coalesce(local.activated_artifact, "-"), "sha256:")}) and apply again."
    }

    precondition {
      condition = !var.release_managed || try(
        var.app_calls != null && var.oauth_instance_json == null &&
        local.released.metadata.name == local.workload_name && local.released.metadata.namespace == var.namespace &&
        local.released.spec.template.metadata.annotations["day2.dev/installation"] == var.installation &&
        local.released.spec.template.metadata.annotations["day2.dev/environment"] == var.environment &&
        local.released.spec.template.metadata.annotations["day2.dev/app"] == var.app_id &&
        can(regex("^sha256:[0-9a-f]{64}$", local.release_artifact)) &&
        can(regex("@sha256:[0-9a-f]{64}$", local.release_image)) &&
        one([for container in local.released.spec.template.spec.containers : one([
          for entry in container.env : entry.value if entry.name == "DAY2_EXPECTED_ARTIFACT"
        ]) if container.name == "day2"]) == local.release_artifact,
      false)
      error_message = "Release handoff requires the installed single-app, two-key app-call profile (no OAuth runtime) with matching scope and immutable image/artifact guard."
    }

    # An infrastructure apply keeps the released registration image, metadata
    # and copied files, so it must not change what they register. Rotating or
    # adding a provider credential is not a release-managed change yet.
    precondition {
      condition = !var.release_managed || try(
        local.has_credentials == (local.release_credential_image != null) &&
        local.has_credentials == (local.release_credential_metadata != null) && (!local.has_credentials || (
          local.release_credential_image == local.release_image &&
          local.release_credential_sources == "${local.workload_name}-credentials" &&
          jsonencode(local.release_credential_args) == jsonencode(local.credential_registration_args) &&
          length(local.release_credential_keys) == length(local.credentials) &&
          toset(local.release_credential_keys) == toset([for credential in local.credentials : credential.key]) &&
          alltrue([for credential in local.credentials : can(regex("^projects/[0-9]+/", credential.secret_version))])
        )),
      false)
      error_message = "A release-managed workload keeps its installed provider credential set, registrant and released registration image, and names credential versions by project number. Disable release_managed to add, remove or rotate a provider credential."
    }
  }
}

check "maintenance_activation" {
  assert {
    condition     = !(var.release_managed && local.activation_pending)
    error_message = "${var.app_id}: activation of ${coalesce(local.activated_artifact, "-")} pending; replicas held at ${try(local.live.spec.replicas, 0)} until day2-gke-release rolls it."
  }
}
