//! Independent fixed kernel/response DATA fixtures. Actual retained descriptors
//! require Linux cases; no fixture promotes JSON/IDs into runtime authority.

use super::{identity_protocol::ReviewedSubject, namespace_protocol as proc, runtime_profile};
use day2_capabilities::{Digest, security_epoch::bootstrap::GkeRoleSelection};
use serde_json::{Value, json};

fn stat(pid: u32, start: u64) -> Vec<u8> {
    let mut columns = vec!["0".to_owned(); 50];
    columns[0] = "R".to_owned();
    columns[19] = start.to_string();
    format!("{pid} (native ) worker) {}\n", columns.join(" ")).into_bytes()
}

#[test]
fn task_parser_joins_tgid_tid_and_full_starttime_without_comm_column_guessing() {
    let good = stat(79, 987654321);
    let status = b"Name:\tnative\nTgid:\t77\nPid:\t79\n";
    let facts = proc::task(&good, status).unwrap();
    assert_eq!(facts.process, 77);
    assert_eq!(facts.thread, 79);
    assert_eq!(facts.start_ticks, 987654321);
    for bad in [
        &b"Tgid:\t77\nPid:\t78\n"[..],
        &b"Tgid:\t77\nTgid:\t77\nPid:\t79\n"[..],
        &b"Tgid:\t077\nPid:\t79\n"[..],
        &b"Tgid:\t77\nPid:\t79"[..],
    ] {
        assert!(proc::task(&good, bad).is_err());
    }
    assert!(proc::task(&stat(79, 0), status).is_err());
    assert!(proc::task(&vec![b'x'; 16_385], status).is_err());
    let prefix = format!("79 (native) R {} 987654321\n", vec!["0"; 18].join(" "));
    assert!(proc::task(prefix.as_bytes(), status).is_err());
    let extended = String::from_utf8(good.clone())
        .unwrap()
        .trim_end()
        .to_owned()
        + " 0\n";
    assert!(proc::task(extended.as_bytes(), status).is_err());
    let malformed = String::from_utf8(good)
        .unwrap()
        .replacen("R 0 ", "R +0 ", 1);
    assert!(proc::task(malformed.as_bytes(), status).is_err());
}

#[test]
fn time_namespace_offsets_are_complete_canonical_and_never_a_clock_or_root_proof() {
    let zero = proc::offsets(b"monotonic 0 0\nboottime 0 0\n").unwrap();
    proc::require_zero(&zero).unwrap();
    for bad in [
        &b"monotonic 0 0\n"[..],
        &b"monotonic 0 0\nmonotonic 0 0\n"[..],
        &b"monotonic 0 0\nboottime 0 1000000000\n"[..],
        &b"monotonic 00 0\nboottime 0 0\n"[..],
        &b"monotonic +0 0\nboottime 0 0\n"[..],
        &b"monotonic 0 0\n7 0 0\n"[..],
    ] {
        assert!(proc::offsets(bad).is_err());
    }
    let shifted = proc::offsets(b"monotonic -1 1\nboottime 5 0\n").unwrap();
    assert!(proc::require_zero(&shifted).is_err());
    assert!(proc::offsets(&vec![b'x'; 1025]).is_err());
}

#[test]
fn complete_mapping_parser_preserves_paths_and_refuses_overlap_shape_and_truncation() {
    let good=b"00400000-00401000 r-xp 00000000 08:01 73 /usr/lib/native library.so\n00401000-00402000 rw-p 00001000 00:00 0\n";
    let values = proc::mappings(good).unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(
        values[0].path.as_deref(),
        Some("/usr/lib/native library.so")
    );
    assert_eq!(values[1].path, None);
    for bad in [
        &b"00400000-00401000 r-xp 0 08:01 73\n00400800-00402000 r-xp 0 08:01 73\n"[..],
        &b"00400000-00401000 rwxp 0 08:01 73"[..],
        &b"00400000-00401000 r-xz 0 08:01 73\n"[..],
        &b"00400000-00401000 r-xp 0 08:01 -1\n"[..],
    ] {
        assert!(proc::mappings(bad).is_err());
    }
    assert!(proc::mappings(&vec![b'x'; 1_048_577]).is_err());
    let many = (0..4097)
        .map(|i| format!("{:08x}-{:08x} r-xp 0 00:00 0\n", i * 4096, (i + 1) * 4096))
        .collect::<String>();
    assert!(proc::mappings(many.as_bytes()).is_err());
    let full = many.lines().take(4096).collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(proc::mappings(full.as_bytes()).unwrap().len(), 4096);
    // Mapping permissions are DATA. Even r-xp cannot certify immutable memory.
    assert!(proc::mappings(b"00400000-00401000 rwxp 0 08:01 73 /native\n").is_ok());
}

fn fixture() -> (GkeRoleSelection, ReviewedSubject, Value) {
    let role: GkeRoleSelection=serde_json::from_value(json!({
        "namespace":{"name":"native","uid":"namespace-uid"},"kubernetes_service_account":{"name":"controller","uid":"ksa-uid"},
        "google_service_account":{"kind":"gke_workload_identity_v1","service_account":"controller@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"},
        "workload_kind":"deployment_v1","workload":{"name":"controller","uid":"deployment-uid"},
        "container":{"name":"day2","image":Digest::new(b"image")},"token_review_audience":"https://native.example/subject"
    })).unwrap();
    let subject = ReviewedSubject {
        pod_name: "controller-abc".into(),
        pod_uid: "pod-uid".into(),
    };
    let image = role.container.image.clone();
    let value = json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"controller-abc","uid":"pod-uid","namespace":"native",
        "ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"controller-rs","uid":"replica-uid","controller":true}]},
        "spec":{"serviceAccountName":"controller","nodeName":"node-seven","containers":[{"name":"day2","image":format!("registry/native@{}",image.as_str())}]},
        "status":{"phase":"Running","containerStatuses":[{"name":"day2","started":true,"ready":true,"state":{"running":{"startedAt":"2026-10-14T00:00:00Z"}},
            "containerID":format!("containerd://{}","7".repeat(64)),"imageID":format!("docker-pullable://registry/native@{}",image.as_str()),"restartCount":0}]}});
    (role, subject, value)
}

// The DATA tests cannot construct a native issuer. This finite AST guard binds
// their projection to its actual caller and rejects the historical duplicate
// calls. It is not a general alias resolver or call-graph proof.
fn issuer_pod_projection_shape(native: &str, profile: &str, identity: &str) -> bool {
    use syn::visit::Visit;

    fn is_name(value: &syn::Expr, name: &str) -> bool {
        matches!(value, syn::Expr::Path(path) if path.path.is_ident(name))
    }

    fn is_ref(value: &syn::Expr, name: &str) -> bool {
        matches!(value, syn::Expr::Reference(reference)
            if reference.mutability.is_none() && is_name(&reference.expr, name))
    }

    struct Calls {
        profile: bool,
        events: Vec<&'static str>,
        arguments: bool,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*node.func {
                let names = path.path.segments.iter().rev().take(2).collect::<Vec<_>>();
                if names.len() == 2 {
                    let args = node.args.iter().collect::<Vec<_>>();
                    if names[1].ident == "runtime_profile" && names[0].ident == "container" {
                        self.events.push("container");
                        self.arguments &= args.len() == 3
                            && is_name(args[0], "selected")
                            && is_ref(args[1], "reviewed")
                            && is_ref(args[2], "pod");
                    } else if names[1].ident == "identity_protocol" && names[0].ident == "pod" {
                        self.events.push("pod");
                        self.arguments &= self.profile
                            && args.len() == 3
                            && is_name(args[0], "role")
                            && is_name(args[1], "reviewed")
                            && is_name(args[2], "bytes");
                    } else if names[1].ident == "identity_protocol" && names[0].ident == "workload"
                    {
                        self.events.push("workload");
                        self.arguments &= args.len() == 4
                            && is_name(args[0], "selected")
                            && is_ref(args[1], "owner");
                    } else if self.profile && names[1].ident == "json" && names[0].ident == "decode"
                    {
                        self.events.push("decode");
                        self.arguments &= args.len() == 1 && is_name(args[0], "bytes");
                    }
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    fn calls(source: &str, name: &str, profile: bool) -> Calls {
        let source = syn::parse_file(source).expect("actual production source must parse");
        let methods = source
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1, "one actual projection caller/helper");
        let mut result = Calls {
            profile,
            events: Vec::new(),
            arguments: true,
        };
        result.visit_block(&methods[0].block);
        result
    }

    let caller = calls(native, "kubernetes", false);
    let helper = calls(profile, "container", true);
    caller.arguments
        && helper.arguments
        && caller.events == ["container", "workload"]
        && helper.events == ["pod"]
        && pod_decode_shape(identity)
}

fn pod_decode_shape(source: &str) -> bool {
    use syn::visit::Visit;
    struct Decodes {
        events: Vec<&'static str>,
        args: bool,
    }
    impl<'ast> Visit<'ast> for Decodes {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let name = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                if name == "decode" {
                    self.events.push("bounded");
                    self.args &= call.args.len() == 1
                        && matches!(call.args.first(), Some(syn::Expr::Path(p)) if p.path.is_ident("bytes"));
                } else if name == "controlling_owner" {
                    self.events.push("owner");
                    self.args &= call.args.len() == 1
                        && matches!(call.args.first(), Some(syn::Expr::Reference(r)) if matches!(&*r.expr, syn::Expr::Path(p) if p.path.is_ident("value")));
                } else if name.ends_with("json::decode") || name.ends_with("serde_json::from_slice")
                {
                    self.events.push("unchecked");
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let source = syn::parse_file(source).unwrap();
    let functions = source
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f) if f.sig.ident == "pod" => Some(f),
            _ => None,
        })
        .collect::<Vec<_>>();
    if functions.len() != 1 {
        return false;
    }
    let mut visitor = Decodes {
        events: Vec::new(),
        args: true,
    };
    visitor.visit_block(&functions[0].block);
    visitor.args && visitor.events == ["bounded", "owner"]
}

#[test]
fn issuer_pod_projection_uses_one_identity_validation_in_the_actual_path() {
    assert!(issuer_pod_projection_shape(
        include_str!("native_enrollment/runtime.rs"),
        include_str!("runtime_profile.rs"),
        include_str!("identity_protocol.rs"),
    ));
}

#[test]
fn issuer_pod_projection_guard_rejects_restored_duplicates_and_decode_reordering() {
    let native = include_str!("native_enrollment/runtime.rs");
    let profile = include_str!("runtime_profile.rs");
    let identity = include_str!("identity_protocol.rs");
    let replace = |source: &str, old: &str, new: &str| {
        assert_eq!(source.matches(old).count(), 1, "exact restoration control");
        source.replacen(old, new, 1)
    };
    let caller = "    let observed = runtime_profile::container(selected, &reviewed, &pod)?;";
    let restored = replace(
        native,
        caller,
        &format!("    let _ = identity_protocol::pod(selected, &reviewed, &pod)?;\n{caller}"),
    );
    assert!(!issuer_pod_projection_shape(&restored, profile, identity));

    let validator =
        "    let (value, owner) = identity_protocol::pod(role, reviewed, bytes)?.into_parts();";
    let restored = replace(
        profile,
        validator,
        &format!("{validator}\n    let _ = identity_protocol::pod(role, reviewed, bytes)?;"),
    );
    assert!(!issuer_pod_projection_shape(native, &restored, identity));

    let foreign_body = replace(
        native,
        caller,
        "    let observed = runtime_profile::container(selected, &reviewed, &ca)?;",
    );
    assert!(!issuer_pod_projection_shape(
        &foreign_body,
        profile,
        identity
    ));

    let decoding = "    let value: Value = crate::json::decode(bytes)?;";
    for replacement in [
        format!("{decoding}\n{validator}"),
        format!("{validator}\n{decoding}"),
        decoding.to_owned(),
    ] {
        let restored = replace(profile, validator, &replacement);
        assert!(!issuer_pod_projection_shape(native, &restored, identity));
    }
    let bounded = "    let value = decode(bytes)?;";
    // Limit the mutation to the actual Pod function: other identity codecs
    // independently retain their same bounded decoder.
    let start = identity.find("pub(super) fn pod(").unwrap();
    let end = start + identity[start..].find("\nfn controlling_owner(").unwrap();
    let (prefix, remaining) = identity.split_at(start);
    let (pod, suffix) = remaining.split_at(end - start);
    for replacement in [
        format!("{bounded}\n    let _ = decode(bytes)?;"),
        "    let value = crate::json::decode(bytes)?;".to_owned(),
    ] {
        let restored = format!("{prefix}{}{suffix}", replace(pod, bounded, &replacement));
        assert!(!issuer_pod_projection_shape(native, profile, &restored));
    }
}

#[test]
fn container_facts_and_owner_require_the_same_checked_pod_body() {
    let (role, subject, good) = fixture();
    let observed =
        runtime_profile::container(&role, &subject, &serde_json::to_vec(&good).unwrap()).unwrap();
    assert_eq!(observed.facts.pod_uid, subject.pod_uid);
    assert_eq!(
        observed.owner["uid"],
        good["metadata"]["ownerReferences"][0]["uid"]
    );
    for change in 0..3 {
        let mut bad = good.clone();
        match change {
            0 => bad["metadata"]["ownerReferences"] = json!([]),
            1 => bad["metadata"]["ownerReferences"][0]["controller"] = json!(false),
            _ => {
                let second = bad["metadata"]["ownerReferences"][0].clone();
                bad["metadata"]["ownerReferences"]
                    .as_array_mut()
                    .unwrap()
                    .push(second);
            }
        }
        assert!(
            runtime_profile::container(&role, &subject, &serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
    let mut foreign = good.clone();
    foreign["metadata"]["uid"] = json!("other-pod");
    assert!(
        runtime_profile::container(&role, &subject, &serde_json::to_vec(&foreign).unwrap())
            .is_err()
    );
}

#[test]
fn single_pod_decode_keeps_byte_depth_object_and_duplicate_key_refusals() {
    let (role, subject, good) = fixture();
    let encoded = serde_json::to_vec(&good).unwrap();
    let (parsed, owner) = super::identity_protocol::pod(&role, &subject, &encoded)
        .unwrap()
        .into_parts();
    assert_eq!(parsed, good);
    assert_eq!(owner, good["metadata"]["ownerReferences"][0]);

    let mut at_limit = encoded.clone();
    at_limit.resize(65_536, b' ');
    assert!(runtime_profile::container(&role, &subject, &at_limit).is_ok());
    at_limit.push(b' ');
    assert!(runtime_profile::container(&role, &subject, &at_limit).is_err());

    for invalid in [b"[]".as_slice(), b"null", b"{", b"{} trailing"] {
        assert!(runtime_profile::container(&role, &subject, invalid).is_err());
    }
    let text = std::str::from_utf8(&encoded).unwrap();
    for key in ["metadata", "\\u006detadata"] {
        let duplicate = format!("{{\"{key}\":{{}},{}", &text[1..]);
        assert!(runtime_profile::container(&role, &subject, duplicate.as_bytes()).is_err());
    }
    let mut nested = json!(null);
    for _ in 0..40 {
        nested = json!([nested]);
    }
    let mut too_deep = good;
    too_deep["extra"] = nested;
    assert!(
        runtime_profile::container(&role, &subject, &serde_json::to_vec(&too_deep).unwrap())
            .is_err()
    );
}

#[test]
fn selected_container_response_is_data_and_refuses_replacement_ambiguous_or_unpinned_image() {
    let (role, subject, good) = fixture();
    let bytes = serde_json::to_vec(&good).unwrap();
    let observed = runtime_profile::container(&role, &subject, &bytes).unwrap();
    assert_eq!(observed.owner["uid"], "replica-uid");
    let facts = observed.facts;
    assert_eq!(facts.pod_uid, "pod-uid");
    assert_eq!(facts.image, role.container.image);
    let mut not_ready = good.clone();
    not_ready["status"]["containerStatuses"][0]["started"] = json!(false);
    not_ready["status"]["containerStatuses"][0]["ready"] = json!(false);
    assert!(
        runtime_profile::container(&role, &subject, &serde_json::to_vec(&not_ready).unwrap())
            .is_ok()
    );
    for (pointer, value) in [
        ("/metadata/uid", json!("replacement")),
        ("/status/containerStatuses/0/state", json!({"waiting":{}})),
        (
            "/status/containerStatuses/0/containerID",
            json!("docker://not-qualified"),
        ),
        ("/spec/containers/0/image", json!("native:latest")),
        (
            "/status/containerStatuses/0/imageID",
            json!(format!(
                "registry/native@{}",
                Digest::new(b"other").as_str()
            )),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            runtime_profile::container(&role, &subject, &serde_json::to_vec(&bad).unwrap())
                .is_err(),
            "{pointer}"
        );
    }
    let mut duplicate = good.clone();
    let extra = duplicate["status"]["containerStatuses"][0].clone();
    duplicate["status"]["containerStatuses"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(
        runtime_profile::container(&role, &subject, &serde_json::to_vec(&duplicate).unwrap())
            .is_err()
    );
    // No CurrentRuntimeBinding factory or role permission exists in this codec.
}

#[test]
fn selected_container_profile_refuses_malformed_names_and_digest_references() {
    let (role, subject, good) = fixture();
    for name in ["-day2", "day2-", "Day2", "day2..other", ""] {
        let mut bad = role.clone();
        bad.container.name = name.into();
        assert!(
            runtime_profile::container(&bad, &subject, &serde_json::to_vec(&good).unwrap())
                .unwrap_err()
                .to_string()
                .contains("container_selection")
        );
    }
    for node in [
        "node..seven",
        "-node",
        "node-",
        "node.",
        ".node",
        "node/other",
        "",
    ] {
        let mut bad = good.clone();
        bad["spec"]["nodeName"] = json!(node);
        assert!(
            runtime_profile::container(&role, &subject, &serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
    for repository in [
        "",
        "registry@other",
        "https://registry/native",
        "registry/native path",
    ] {
        let mut bad = good.clone();
        bad["status"]["containerStatuses"][0]["imageID"] =
            json!(format!("{repository}@{}", role.container.image.as_str()));
        assert!(
            runtime_profile::container(&role, &subject, &serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
}

#[test]
fn container_response_cannot_replace_the_workload_selected_container() {
    let (role, subject, good) = fixture();
    let bytes = serde_json::to_vec(&good).unwrap();
    let mut replacement = role.clone();
    replacement.container.name = "security-shell".into();
    assert!(runtime_profile::container(&replacement, &subject, &bytes).is_err());
    let mut replacement = role.clone();
    replacement.container.image = Digest::new(b"different-selected-image");
    assert!(runtime_profile::container(&replacement, &subject, &bytes).is_err());
    assert!(runtime_profile::container(&role, &subject, &bytes).is_ok());
}

#[test]
fn native_reader_selection_keeps_shell_refused_and_app_code_distinct() {
    use day2_capabilities::security_epoch::bootstrap::NativeRole;
    let store = super::tests::selection();
    let policy = super::control_slot_tests::policy(&store);
    // This selection is DATA. AuthenticatedReads now additionally REQUIRES a
    // borrowing real EnrolledRoleStage; code/image selections cannot call its
    // constructor alone or become an enrolled-stage fallback.
    let selected =
        super::authenticated_reads::reader_selection(&policy, NativeRole::AppHost).unwrap();
    assert_eq!(selected.code, &policy.runtime_profile.app_host_code);
    assert_ne!(selected.code, &policy.runtime_profile.app_artifact);
    assert_eq!(selected.workload, &policy.app);
    assert!(
        super::authenticated_reads::reader_selection(&policy, NativeRole::SecurityShell).is_err()
    );
}

#[test]
fn process_time_offsets_require_exact_current_thread_namespace_join() {
    use super::native_namespace::{NamespaceIdentity, require_process_time_join_data};
    let current = NamespaceIdentity {
        device: 5,
        inode: 17,
    };
    let other = NamespaceIdentity {
        device: 5,
        inode: 23,
    };
    let other_device = NamespaceIdentity {
        device: 7,
        inode: 17,
    };
    let zero = NamespaceIdentity {
        device: 5,
        inode: 0,
    };
    assert!(require_process_time_join_data(&current, &current, &current).is_ok());
    assert!(require_process_time_join_data(&current, &other, &current).is_err());
    assert!(require_process_time_join_data(&current, &current, &other).is_err());
    assert!(require_process_time_join_data(&current, &other_device, &other_device).is_err());
    assert!(require_process_time_join_data(&zero, &zero, &zero).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_namespace_observation_refuses_original_acquisition() {
    use super::{native_clock::NativeAcquisition, native_namespace::NativeNamespaceObservation};
    let mut acquisition = NativeAcquisition::fixture(
        Digest::new(b"domain"),
        std::process::id(),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    );
    assert!(NativeNamespaceObservation::acquire(&mut acquisition).is_err());
    assert!(acquisition.remaining().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn actual_linux_namespace_observation_retains_self_descriptors_with_no_pod_authority() {
    use super::{native_clock::NativeAcquisition, native_namespace::NativeNamespaceObservation};
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    let mut observed = NativeNamespaceObservation::acquire(&mut acquisition).unwrap();
    observed.check(&mut acquisition).unwrap();
    let maps = observed.mappings(&mut acquisition).unwrap();
    assert!(!maps.is_empty());
    let data = observed.into_data();
    assert_eq!(data.task.process, std::process::id());
    assert_eq!(data.namespaces.len(), 6);
    // This Linux descriptor test does not qualify the missing node runtime join.
}
