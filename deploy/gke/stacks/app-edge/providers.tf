locals {
  kubeconfig_path_value = try(trimspace(var.kubeconfig_path), "")
  kube_context_value    = try(trimspace(var.kube_context), "")
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Reads CLOUDFLARE_API_TOKEN from the environment. The token needs DNS edit on
# cloudflare_zone_id only.
provider "cloudflare" {}

# An operator or CI job that already ran `gcloud container clusters
# get-credentials` for the target cluster points this at its kubeconfig/context.
provider "kubernetes" {
  config_path    = local.kubeconfig_path_value != "" ? pathexpand(local.kubeconfig_path_value) : null
  config_context = local.kube_context_value != "" ? local.kube_context_value : null
}
