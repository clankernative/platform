# App CI's workload identity federation (docs/INSTANCE.md, "App CI"), once per
# instance. git-oidc mints the forge's Actions jobs their OIDC tokens; this
# provider admits only the required org-scoped workflow of <org>/day2-ci, run
# for a push to the main branch of a repository in the instance's org, with the
# workflow's source and the org pinned by their native forge ids.
#
# The pool impersonates no service account and grants nothing itself. Each
# app's CI results bucket (app-edge) grants objects to the principal set of its
# own repository's id, attribute.repository_id/<id>, so a run reaches only its
# own app's results.
#
# It is part of the project layer because it is the instance's identity, made
# once: applied first, so the pool exists before any app edge names its
# principal sets, and beside the IAM, STS and IAM credentials APIs it needs.
# The instance's own CI federation (deploy/integrations/gitea-instance-ci)
# stays opt-in and separate.
#
# Without forge.oidc, app_ci is null and nothing here exists.

locals {
  # InstanceSpec's derived pool and provider; the store step's audience names both.
  app_ci_pool_id     = "day2-ci"
  app_ci_provider_id = "gitea"
  app_ci_workflow    = var.app_ci == null ? "" : "${var.app_ci.repository}/.gitea/scoped_workflows/verification.yml@"
}

resource "google_iam_workload_identity_pool" "app_ci" {
  count = var.app_ci == null ? 0 : 1

  project                   = var.project_id
  workload_identity_pool_id = local.app_ci_pool_id
  display_name              = "day2 app CI"
  description               = "Push runs on main of the required app workflow in ${var.app_ci.repository}: one principal set per app repository id."

  depends_on = [google_project_service.api]
}

resource "google_iam_workload_identity_pool_provider" "app_ci" {
  count = var.app_ci == null ? 0 : 1

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.app_ci[0].workload_identity_pool_id
  workload_identity_pool_provider_id = local.app_ci_provider_id
  display_name                       = "Gitea app CI"
  description                        = "Workflow tokens of ${var.app_ci.repository} (id ${var.app_ci_forge.repository_id}) for repositories of org id ${var.app_ci_forge.owner_id}."

  # The subject is gitea:repo:<org>/<app>:ref:refs/heads/main, at most 76 bytes
  # for a 24-byte org and a 20-byte app ID: under Google's 127-byte limit.
  attribute_mapping = {
    "google.subject"          = "'gitea:' + assertion.sub"
    "attribute.repository_id" = "assertion.repository_id"
  }

  # git-oidc mints is_scoped and the workflow_* claims from the run record; a
  # token without them is refused here.
  attribute_condition = join(" && ", [
    "assertion.is_scoped == 'true'",
    "assertion.workflow_repository_id == '${var.app_ci_forge.repository_id}'",
    "assertion.repository_owner_id == '${var.app_ci_forge.owner_id}'",
    "assertion.workflow_ref.startsWith('${local.app_ci_workflow}')",
    "assertion.event_name == 'push'",
    "assertion.ref == 'refs/heads/main'",
  ])

  oidc {
    issuer_uri = var.app_ci.issuer_uri
    # The canonical provider URL, which `day2 ci store` requests as its audience.
    allowed_audiences = ["https://iam.googleapis.com/${google_iam_workload_identity_pool.app_ci[0].name}/providers/${local.app_ci_provider_id}"]
  }
}
