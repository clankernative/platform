output "selection" {
  description = "Selected names/provider metadata only. No epoch, holder, P3, effective-IAM or serving authority."
  value = {
    project = var.project_id
    scope   = var.authority_scope
    actors = {
      for key, actor in local.actors : key => {
        namespace       = actor.namespace
        service_account = actor.account
        workload        = actor.workload
        google_account  = local.observed_accounts[key].email
        google_uid      = local.observed_accounts[key].unique_id
      }
    }
    storage = var.storage
  }
}
