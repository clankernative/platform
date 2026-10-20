mock_provider "kubernetes" {}

variables {
  pool_name    = "oauth-native"
  profile      = "oauthcalendar"
  kube_context = "selected-test-context"
  image        = "example.test/day2@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  policy_json = jsonencode({
    root = {
      public_key = "K1LWBLgueNdsJ1JDGau-QH1rmS3zMub7JfnFMnIQTgI"
      version    = "projects/example/locations/us-central1/keyRings/enrollment/cryptoKeys/root/cryptoKeyVersions/1"
    }
    runtime = { node_name = "selected-node" }
    bootstrap = {
      app        = { namespace = { name = "app" }, kubernetes_service_account = { name = "runtime" }, workload = { name = "app" } }
      shell      = { namespace = { name = "shell" }, kubernetes_service_account = { name = "shell" }, workload = { name = "shell" } }
      controller = { namespace = { name = "day2-native-enrollment" }, kubernetes_service_account = { name = "controller" }, workload = { name = "controller" } }
    }
  })
}

run "fixed_issuer_has_only_selected_observation_privileges" {
  command = plan
  assert {
    condition = (
      kubernetes_manifest.issuer.manifest.spec.template.spec.hostPID &&
      !contains(keys(kubernetes_manifest.issuer.manifest.spec.template.spec), "hostNetwork") &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.nodeSelector["kubernetes.io/hostname"] == "selected-node" &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].command == ["/usr/local/bin/day2-native-enrollment"] &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].securityContext.capabilities.drop == ["ALL"] &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].securityContext.capabilities.add == ["SYS_PTRACE", "CHOWN"] &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].securityContext.appArmorProfile.localhostProfile == "day2-native-enrollment" &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem &&
      !kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].volumeMounts[0].subPath == "native-enrollment.json" &&
      kubernetes_manifest.issuer.manifest.spec.template.spec.containers[0].volumeMounts[2].readOnly &&
      kubernetes_config_map_v1.policy.immutable
    )
    error_message = "The issuer must retain fixed code, node, immutable policy, narrow capabilities and Localhost AppArmor."
  }
  assert {
    condition = alltrue(concat(
      [for rule in kubernetes_cluster_role_v1.observer.rule : length(rule.verbs) == 1 && contains(rule.verbs, "get")],
      flatten([for role in kubernetes_role_v1.observer : [for rule in role.rule : length(rule.verbs) == 1 && contains(rule.verbs, "get")]])
    ))
    error_message = "Enrollment may read selected metadata; it must never grant Kubernetes mutations or token creation."
  }
}

run "mutable_issuer_image_refuses" {
  command = plan
  variables { image = "example.test/day2:latest" }
  expect_failures = [var.image]
}
