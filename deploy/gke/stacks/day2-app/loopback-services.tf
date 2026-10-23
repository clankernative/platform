variable "loopback_services" {
  description = "Optional private companion containers in the day2 pod. Each config is read from one exact Secret Manager version, its state is isolated under .state/companions, and CPU/memory requests equal limits."
  type = map(object({
    image                 = string
    port                  = number
    config_secret_version = string
    state_subpath         = string
    state_database_file   = optional(string)
    health_check = object({
      path    = string
      command = list(string)
    })
    resources = object({
      cpu_millis = number
      memory_mib = number
    })
  }))
  default = {}

  validation {
    condition = length(var.loopback_services) <= 8 && alltrue([
      for name, service in var.loopback_services :
      can(regex("^[a-z][a-z0-9-]{0,14}$", name)) &&
      can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$", service.image)) &&
      service.port == floor(service.port) && service.port >= 1024 && service.port <= 65535 && service.port != 8080 &&
      can(regex("^projects/[a-z0-9-]{1,63}/secrets/[A-Za-z0-9_-]{1,255}/versions/[1-9][0-9]*$", service.config_secret_version)) &&
      can(regex("^companions/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$", service.state_subpath)) &&
      length(split("/", service.state_subpath)) <= 5 &&
      alltrue([for part in split("/", service.state_subpath) : part != "" && part != "." && part != ".."]) &&
      (service.state_database_file == null || (
        can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$", service.state_database_file)) &&
        endswith(service.state_database_file, ".sqlite") &&
        length(split("/", service.state_database_file)) <= 10 &&
        alltrue([for part in split("/", service.state_database_file) : part != "" && part != "." && part != ".."])
      )) &&
      can(regex("^/[A-Za-z0-9][A-Za-z0-9/_-]{0,254}$", service.health_check.path)) &&
      !anytrue([for part in split("/", service.health_check.path) : part == ".." || part == "."]) &&
      length(service.health_check.command) >= 1 && length(service.health_check.command) <= 8 &&
      alltrue([for argument in service.health_check.command : trimspace(argument) != "" && length(argument) <= 512]) &&
      service.resources.cpu_millis == floor(service.resources.cpu_millis) && service.resources.cpu_millis >= 50 && service.resources.cpu_millis <= 4000 &&
      service.resources.memory_mib == floor(service.resources.memory_mib) && service.resources.memory_mib >= 32 && service.resources.memory_mib <= 4096
    ])
    error_message = "Each loopback service needs a DNS port name, digest-pinned image, unique non-8080 port, exact numbered Secret Manager version, safe companions/ state path, optional safe .sqlite filename, absolute health path and bounded non-empty probe command, and bounded integer CPU/memory limits."
  }

  validation {
    condition = (
      length(distinct([for service in values(var.loopback_services) : service.port])) == length(var.loopback_services) &&
      length(distinct([for service in values(var.loopback_services) : service.state_subpath])) == length(var.loopback_services) &&
      alltrue([
        for service in values(var.loopback_services) :
        !anytrue([
          for other in values(var.loopback_services) :
          service.state_subpath != other.state_subpath && startswith(other.state_subpath, "${service.state_subpath}/")
        ])
      ])
    )
    error_message = "Loopback service ports and state subpaths must be unique and state subpaths must not overlap."
  }
}

locals {
  loopback_services = {
    for name, service in var.loopback_services : name => merge(service, {
      config_key    = "${name}.json"
      config_source = "/run/day2/loopback-config-sources/${name}.json"
      config_staged = "/run/day2/loopback-service-configs/${name}.json"
    })
  }

  loopback_state_subpaths = [for service in values(local.loopback_services) : service.state_subpath]
  loopback_sqlite_state   = [for service in values(local.loopback_services) : "${service.state_subpath}/${service.state_database_file}" if service.state_database_file != null]
}

resource "kubernetes_manifest" "loopback_service_secrets" {
  count = length(local.loopback_services) == 0 ? 0 : 1

  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "${local.workload_name}-loopback-services"
      namespace = var.namespace
      labels = {
        "app.kubernetes.io/name"       = local.workload_name
        "app.kubernetes.io/managed-by" = "opentofu"
      }
    }
    spec = {
      provider = "gke"
      parameters = {
        secrets = jsonencode([
          for name in sort(keys(local.loopback_services)) : {
            resourceName = local.loopback_services[name].config_secret_version
            path         = local.loopback_services[name].config_key
          }
        ])
      }
    }
  }
}
