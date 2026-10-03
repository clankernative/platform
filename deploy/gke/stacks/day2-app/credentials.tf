# Provider credentials for apps whose grants or signed endpoints need them.
#
# Secret bytes never pass through OpenTofu. This root names exact Secret
# Manager versions and the fingerprints an operator reviewed; the GKE Secret
# Manager CSI add-on reads the versions with the runtime service account's
# Workload Identity (app-edge's runtime_secret_ids grants it). Before
# day2-serve starts:
#
#   credential-files         copies each version into an in-memory directory
#                            as a regular 10001-owned 0400 file. Day2 refuses
#                            symlinks and group/world-readable secrets, and the
#                            add-on writes root-owned files behind symlinks.
#   credential-registration  runs the runtime image's day2-provision-credentials
#                            against the reviewed plan rendered below, as an
#                            operator-only instance that asserts
#                            credential_operator and nothing else.
#
# Registration is idempotent for an unchanged version and refuses a changed
# one, so both run on every start. Rotating a secret means a new Secret Manager
# version, a new day2 credential revision in the catalog, and a new fingerprint.

variable "provider_credentials" {
  description = "Secrets the app's grants and signed endpoints (paused ones too) need: the day2 credential reference a catalog connection declares (credential_ref or signing_secret_ref), the exact Secret Manager version holding it, and its reviewed fingerprint (sha256: of the value without trailing newlines)."
  type = list(object({
    credential_ref = object({ id = string, revision = number })
    secret_version = string
    fingerprint    = string
  }))
  default = []

  validation {
    condition = alltrue([
      for credential in var.provider_credentials :
      trimspace(credential.credential_ref.id) != "" && credential.credential_ref.revision >= 1 &&
      can(regex("^projects/[a-z0-9-]{1,63}/secrets/[A-Za-z0-9_-]{1,255}/versions/[1-9][0-9]*$", credential.secret_version)) &&
      can(regex("^sha256:[0-9a-f]{64}$", credential.fingerprint))
    ])
    error_message = "Each provider credential needs a credential reference, an exact numbered Secret Manager version (never latest) and a sha256: fingerprint."
  }

  validation {
    condition     = length(distinct([for credential in var.provider_credentials : credential.credential_ref])) == length(var.provider_credentials)
    error_message = "Each credential reference may be provided once."
  }
}

variable "credential_operator" {
  description = "The installation administrator that registers provider_credentials. It appears only in the operator-only registration instance, never in the serving instance."
  type        = string
  default     = ""
}

locals {
  has_credentials       = length(var.provider_credentials) > 0
  credential_dir        = "/run/day2/credentials"
  credential_source_dir = "/run/day2/credential-sources"
  provisioning_dir      = "${local.root_dir}/provisioning"
  operator_instance     = "${local.root_dir}/operator-instance.json"
  provisioning_plan     = "${local.root_dir}/provisioning.json"

  # Connections have provider-specific shapes, so this stays a tuple.
  catalog_lives = [
    for id, connection in try(var.resource_catalog.connections, {}) : connection.live if try(connection.live, null) != null
  ]

  credentials = [
    for credential in var.provider_credentials : {
      credential_ref = credential.credential_ref
      secret_version = credential.secret_version
      fingerprint    = credential.fingerprint
      # day2's reference key: SHA-256 of the reference's compact JSON, whose
      # fields jsonencode orders as serde does (id, revision).
      key = sha256(jsonencode({ id = credential.credential_ref.id, revision = credential.credential_ref.revision }))
      # The connection that declares this secret: as its outbound credential,
      # or as the verification secret of its signed deliveries.
      outbound  = distinct([for live in local.catalog_lives : live if live.credential_ref == credential.credential_ref])
      verifying = distinct([for live in local.catalog_lives : live if try(live.signing_secret_ref, null) == credential.credential_ref])
    }
  ]

  # integration_host::Mount. A verification secret names its reference so that
  # registration cannot install it as the connection's bearer token.
  provisioning_inputs = {
    for credential in local.credentials : "credential-${credential.key}.json" => jsonencode(merge(
      {
        connection           = length(credential.outbound) == 1 ? credential.outbound[0] : try(credential.verifying[0], null)
        credential_file      = "${local.credential_dir}/${credential.key}"
        expected_fingerprint = credential.fingerprint
      },
      length(credential.outbound) == 1 ? {} : { reference = credential.credential_ref },
    ))
  }

  # The serving instance plus an operator-only control section, as packaging
  # writes it (packaging_credentials.rs); provisioning_inputs refuses any other
  # control authority.
  operator_instance_json = jsonencode(merge(local.base_instance, {
    control = {
      version         = 1
      state_directory = "${local.state_dir}/operator-control"
      operators       = [var.credential_operator]
      sources         = {}
      apps            = {}
    }
  }))

  provisioning_plan_json = jsonencode({
    version         = 1
    app             = var.app_id
    operator        = var.credential_operator
    instance_digest = "sha256:${sha256(local.operator_instance_json)}"
    inputs = [
      for credential in local.credentials : {
        file              = "credential-${credential.key}.json"
        digest            = "sha256:${sha256(local.provisioning_inputs["credential-${credential.key}.json"])}"
        credential_digest = credential.fingerprint
      }
    ]
  })
}

resource "kubernetes_config_map_v1" "credentials" {
  count = local.has_credentials ? 1 : 0

  metadata {
    name      = "${local.workload_name}-credentials"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name"       = local.workload_name
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }

  # Metadata only: references, paths and fingerprints, never secret bytes.
  data = merge(local.provisioning_inputs, {
    "operator-instance.json" = local.operator_instance_json
    "provisioning.json"      = local.provisioning_plan_json
  })

  lifecycle {
    precondition {
      condition     = var.resource_catalog != null && trimspace(var.credential_operator) != ""
      error_message = "provider_credentials need a resource_catalog whose connections declare them and a credential_operator."
    }

    precondition {
      condition = alltrue([
        for credential in local.credentials : length(credential.outbound) + length(credential.verifying) == 1
      ])
      error_message = "Each provider credential must be declared by exactly one connection profile, as its credential_ref or its signing_secret_ref. Connections sharing a secret must have identical live profiles."
    }

    precondition {
      condition     = var.state_ownership_init_enabled
      error_message = "provider_credentials are copied by the root init container image; state_ownership_init_enabled must stay true."
    }

    precondition {
      condition     = length(jsonencode(local.provisioning_inputs)) + length(local.operator_instance_json) + length(local.provisioning_plan_json) <= 1000000
      error_message = "The credential provisioning metadata exceeds a ConfigMap's 1 MiB."
    }
  }
}

resource "kubernetes_manifest" "credentials" {
  count = local.has_credentials ? 1 : 0

  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "${local.workload_name}-credentials"
      namespace = var.namespace
      labels = {
        "app.kubernetes.io/name"       = local.workload_name
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      provider = "gke"
      parameters = {
        secrets = yamlencode([
          for credential in local.credentials : {
            resourceName = credential.secret_version
            path         = credential.key
          }
        ])
      }
    }
  }
}
