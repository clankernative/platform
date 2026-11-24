# Native runtime handoff owns the adopted pod's entrypoint and immutable
# selection. Preserve that selection while reconciling infrastructure.
locals {
  runtime_pair_selection = try(local.live.spec.template.metadata.labels["day2.dev/runtime-pair"], null)
  runtime_pair_args      = [local.instance_path, var.app_id, "--runtime-candidate", "/run/day2-pair/candidate.json", "/tmp/day2-runtime-pair"]
  runtime_pair_files     = ["candidate.json", "source.json"]
  runtime_pair_container = try(one([for c in local.live.spec.template.spec.containers : c if c.name == "day2"]), null)
  runtime_pair_term      = try(one(local.live.spec.template.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms), null)
  runtime_pair_node      = try(one(distinct(flatten([for f in local.runtime_pair_term.matchFields : f.values]))), null)
  runtime_pair_enabled   = var.rolling_deploys && var.release_managed && local.runtime_pair_selection != null
}
