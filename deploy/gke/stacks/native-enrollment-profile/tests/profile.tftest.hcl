mock_provider "kubernetes" {}
variables {
  namespace               = "native-profiles"
  pool_name               = "native-enrollment"
  profile                 = "calendar"
  loader_image            = "gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750"
  client_executable_paths = ["/usr/local/bin/day2-host"]
}
run "scoped_loader_has_only_policy_admin_and_no_workload_credentials" {
  command = plan
  assert {
    condition = (
      kubernetes_manifest.loader.manifest.spec.template.spec.nodeSelector["cloud.google.com/gke-nodepool"] == var.pool_name &&
      kubernetes_manifest.loader.manifest.spec.template.spec.nodeSelector["day2.dev.node-restriction.kubernetes.io/enrollment"] == var.profile &&
      kubernetes_manifest.loader.manifest.spec.template.spec.tolerations[0].value == var.profile &&
      !kubernetes_manifest.loader.manifest.spec.template.spec.automountServiceAccountToken &&
      !contains(keys(kubernetes_manifest.loader.manifest.spec.template.spec), "hostPID") &&
      !contains(keys(kubernetes_manifest.loader.manifest.spec.template.spec), "hostNetwork") &&
      kubernetes_manifest.loader.manifest.spec.template.spec.initContainers[0].securityContext.capabilities.add == ["MAC_ADMIN"] &&
      kubernetes_manifest.loader.manifest.spec.template.spec.initContainers[0].securityContext.appArmorProfile.type == "RuntimeDefault" &&
      kubernetes_manifest.loader.manifest.spec.template.spec.containers[0].securityContext.runAsUser == 0 &&
      kubernetes_manifest.loader.manifest.spec.template.spec.containers[0].securityContext.capabilities.drop == ["ALL"] &&
      kubernetes_manifest.loader.manifest.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem &&
      kubernetes_manifest.loader.manifest.spec.template.spec.containers[0].volumeMounts[0].readOnly
    )
    error_message = "Only the selected node's init loader may administer AppArmor; the persistent readiness process has no credentials or policy write mount."
  }
  assert {
    condition = (
      strcontains(local.policy, "ptrace (read) peer=unconfined,") &&
      strcontains(local.policy, "deny ptrace (trace,tracedby),") &&
      strcontains(local.policy, "deny /proc/@{PIDS}/{mem,environ,cmdline,stack,syscall,io} rw,") &&
      !strcontains(local.policy, "\n  file,") &&
      !strcontains(local.policy, "\n  capability,\n") &&
      !strcontains(local.policy, "\n  /** r,")
    )
    error_message = "The observation policy must retain its specific read permissions and explicit trace/memory denials."
  }
}
run "refuses_mutable_loader_image" {
  command = plan
  variables { loader_image = "example/loader:latest" }
  expect_failures = [var.loader_image]
}
run "refuses_policy_injection_or_unrelated_client_path" {
  command = plan
  variables { client_executable_paths = ["/usr/local/bin/day2-host\n/** rw,"] }
  expect_failures = [var.client_executable_paths]
}
