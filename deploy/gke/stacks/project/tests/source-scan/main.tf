# Test helper: lists the block types the project root declares, read from its
# source, so a test can pin them. Not a deployable module.

locals {
  root  = "${path.module}/../.."
  files = [for name in fileset(local.root, "*.tf") : file("${local.root}/${name}")]

  resource_types = toset(flatten([
    for content in local.files : regexall("(?m)^resource \"([a-z0-9_]+)\"", content)
  ]))
  data_sources = flatten([
    for content in local.files : regexall("(?m)^data \"([a-z0-9_]+)\"", content)
  ])
  modules = flatten([
    for content in local.files : regexall("(?m)^module \"([a-z0-9_-]+)\"", content)
  ])
}

output "resource_types" {
  value = local.resource_types
}

output "data_sources" {
  value = local.data_sources
}

output "modules" {
  value = local.modules
}
