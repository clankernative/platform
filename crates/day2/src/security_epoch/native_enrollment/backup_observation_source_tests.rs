//! Portable mutation checks of the actual fixed Linux service. No native owner
//! is fabricated here; real kernel/resource conformance is Linux-only.
use quote::ToTokens;

#[test]
fn actual_submit_clock_join_rejects_a_renewed_request_on_the_same_connection() {
    use super::owner::BackupSubmitOriginal;
    use crate::security_epoch::native_clock::{NativeAcquisition, fixture_observe_at};
    use day2_capabilities::Digest;
    use std::time::Duration;
    let fixture = |name: &[u8], at: u64| {
        NativeAcquisition::fixture(
            Digest::new(name),
            std::process::id(),
            Duration::from_secs(at),
            Duration::from_secs(5),
        )
    };
    let admission = fixture(b"connection", 100);
    let mut connection = admission.into_connection_clock().unwrap();
    let mut first = connection
        .bind_captured_current(fixture(b"first", 102))
        .unwrap();
    let mut captured = BackupSubmitOriginal::capture(&mut first).unwrap();
    captured.check(&mut first).unwrap();
    let connection_identity = first.identity_domain().unwrap();
    let mut second = connection
        .bind_captured_current(fixture(b"second", 103))
        .unwrap();
    assert_eq!(connection_identity, second.identity_domain().unwrap());
    assert_ne!(
        first.historical_interval_observation().0,
        second.historical_interval_observation().0
    );
    assert!(captured.check(&mut second).is_err());
    assert!(first.remaining().is_err());
    assert!(second.remaining().is_err());
    fixture_observe_at(&mut first, Duration::from_secs(103));
    assert!(captured.check(&mut first).is_err());

    for cut in 0..4 {
        let mut original = fixture(b"original", 100);
        let mut captured = BackupSubmitOriginal::capture(&mut original).unwrap();
        captured.check(&mut original).unwrap();
        match cut {
            0 => fixture_observe_at(&mut original, Duration::from_secs(99)),
            1 => fixture_observe_at(&mut original, Duration::from_secs(105)),
            2 => fixture_observe_at(&mut original, Duration::from_secs(106)),
            _ => original.refuse(),
        }
        assert!(captured.check(&mut original).is_err());
        fixture_observe_at(&mut original, Duration::from_secs(101));
        assert!(captured.check(&mut original).is_err());
    }
    let mut first = fixture(b"equal", 100);
    let mut copy = fixture(b"equal", 100);
    let mut captured = BackupSubmitOriginal::capture(&mut first).unwrap();
    assert!(captured.check(&mut copy).is_err());
}

#[test]
fn actual_submit_clock_guard_keeps_narrower_ceiling_and_refuses_retirement() {
    use super::owner::BackupSubmitOriginal;
    use crate::security_epoch::native_clock::{NativeAcquisition, fixture_observe_at};
    use day2_capabilities::Digest;
    use std::time::Duration;
    let fixture = || {
        NativeAcquisition::fixture(
            Digest::new(b"request"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        )
    };
    for cut in [100, 102] {
        let mut root = fixture();
        let mut short = root.narrow(1, Duration::from_secs(105)).unwrap();
        let mut captured = BackupSubmitOriginal::capture(&mut short).unwrap();
        captured.check(&mut short).unwrap();
        fixture_observe_at(&mut root, Duration::from_secs(cut));
        assert!(captured.check(&mut root).is_err());
        fixture_observe_at(&mut short, Duration::from_secs(100));
        assert!(captured.check(&mut short).is_err());
    }
    // A legitimate narrowing may proceed, but no later wider view can undo it.
    let mut root = fixture();
    let mut captured = BackupSubmitOriginal::capture(&mut root).unwrap();
    let mut short = root.narrow(1, Duration::from_secs(105)).unwrap();
    captured.check(&mut short).unwrap();
    assert!(captured.check(&mut root).is_err());
    let admission = NativeAcquisition::fixture(
        Digest::new(b"retire-connection"),
        std::process::id(),
        Duration::from_secs(100),
        Duration::from_secs(5),
    );
    let mut connection = admission.into_connection_clock().unwrap();
    let mut request = connection.bind_captured_current(fixture()).unwrap();
    let mut request_guard = BackupSubmitOriginal::capture(&mut request).unwrap();
    connection.retire_checked(&mut request).unwrap();
    assert!(request_guard.check(&mut request).is_err());
}

fn socket_resource_contract(socket: &str, directory: &str, birth: &str) -> bool {
    [
        "const PATH: &str = \"/run/day2-native-enrollment/scheduled-backup/request.sock\";",
        "stage.storage()?.scheduled_backup_root_selection()?;",
        "ScheduledBackupSocketDirectory::observe(&root)?",
        "net::bind(&socket, &net::SocketAddrUnix::new(PATH)?)?;",
        "net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?",
        "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { stage.check_serving_acquisition(original) }));",
        "stage.refuse_serving(); original.refuse();",
        "finish_checked(requested, checked)",
        "self.directory.check(&self.root)?;",
        "let held = self.name.metadata()?; require_socket_name(&held)?;",
        "(held.dev(), held.ino()) == self.identity",
        "let named = std::fs::symlink_metadata(PATH)?; require_socket_name(&named)?;",
        "(named.dev(), named.ino()) == self.identity",
        "metadata.uid() == 10001 && metadata.gid() == 10001 && metadata.mode() & 0o7777 == 0o600",
        "!self.refused.get() && self.process == std::process::id() && self.thread == std::thread::current().id()",
        "net::sockopt::socket_passcred(&self.socket)? && net::sockopt::socket_passpidfd(&self.socket)?",
    ].iter().enumerate().all(|(index, required)| {
        let found = socket.contains(&fragment(required));
        if !found { eprintln!("socket required index {index}"); }
        found
    })
        && socket.matches(&fragment("finish_checked(requested, checked)")).count() == 3
        && socket.matches(&fragment("stage.storage()?.scheduled_backup_root_selection()?;")).count() == 3
        && socket.matches(&fragment("stage.refuse_serving(); original.refuse();")).count() == 3
        && socket.matches(&fragment("let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { stage.check_serving_acquisition(original) })); ")).count() == 3
        && !["remove_file", "unlink", "receive_issuer", "ProtectedRestoreAdmission", "SignedStage"].iter().any(|forbidden| socket.contains(forbidden))
        && !socket.contains(&fragment("NativeAcquisition::begin"))
        && [
            "Self::Storage => CHILD",
            "Self::ScheduledBackup => \"scheduled-backup\"",
            "Self::observe_selected(root, Child::Storage)",
            "Self::prepare_selected(root, Child::Storage)",
            "StorageSocketDirectory::observe_selected(root, Child::ScheduledBackup)?",
            "StorageSocketDirectory::prepare_selected(root, Child::ScheduledBackup)?",
            "fn observe_selected(root: &File, selected: Child) -> Result<Self>",
            "fn prepare_selected(root: &File, child: Child) -> Result<Self>",
            "child_identity(&open_child(reference, self.child)?)? == self.identity",
            "child_identity(&open_mounted_child(root, self.child)?)? == self.identity",
            "ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV",
        ].iter().enumerate().all(|(index, required)| {
            let found = directory.contains(&fragment(required));
            if !found { eprintln!("directory required index {index}"); }
            found
        })
        && birth.contains(&fragment("let scheduled_backup = if policy.scheduled_backup.is_some() { Some(ScheduledBackupSocketDirectory::prepare(&directory)?) } else { None };"))
        && birth.contains(&fragment("if let Some(directory) = &self.birth.scheduled_backup { directory.check(&self.directory)?; }"))
}

#[test]
fn dedicated_socket_keeps_fixed_child_actual_name_original_posts_and_no_permission_factory() {
    let socket = canonical(
        syn::parse_file(include_str!("channel/scheduled_backup.rs"))
            .unwrap()
            .to_token_stream(),
    )
    .to_string();
    let directory = canonical(
        syn::parse_file(include_str!("storage_socket_directory.rs"))
            .unwrap()
            .to_token_stream(),
    )
    .to_string();
    let birth = canonical(
        syn::parse_file(include_str!("birth.rs"))
            .unwrap()
            .to_token_stream(),
    )
    .to_string();
    assert!(socket_resource_contract(&socket, &directory, &birth));
    for (from, to) in [
        (
            "\"/run/day2-native-enrollment/scheduled-backup/request.sock\"",
            "\"/run/day2-native-enrollment/storage/request.sock\"",
        ),
        ("ScheduledBackupSocketDirectory::observe(&root)?", "Ok(())?"),
        ("self.directory.check(&self.root)?;", ""),
        ("(held.dev(), held.ino()) == self.identity", "true"),
        ("(named.dev(), named.ino()) == self.identity", "true"),
        ("metadata.mode() & 0o7777 == 0o600", "true"),
        ("stage.refuse_serving();", ""),
        (
            "finish_checked(requested, checked)",
            "finish_checked(requested, Ok(Ok(())))",
        ),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert!(socket.contains(&from), "mutation target");
        assert!(!socket_resource_contract(
            &socket.replacen(&from, &to, 1),
            &directory,
            &birth
        ));
    }
    for (from, to) in [
        (
            "Self::ScheduledBackup => \"scheduled-backup\"",
            "Self::ScheduledBackup => CHILD",
        ),
        (
            "open_child(reference, self.child)",
            "open_child(reference, Child::Storage)",
        ),
        ("| ResolveFlags::NO_XDEV", ""),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(directory.matches(&from).count(), 1, "mutation target");
        assert!(!socket_resource_contract(
            &socket,
            &directory.replacen(&from, &to, 1),
            &birth
        ));
    }
    let from = fragment("if policy.scheduled_backup.is_some()");
    assert_eq!(birth.matches(&from).count(), 1);
    assert!(!socket_resource_contract(
        &socket,
        &directory,
        &birth.replacen(&from, &fragment("if true"), 1)
    ));
}

fn selected_method(source: &str, owner: &str, name: &str) -> String {
    let file = syn::parse_file(source).unwrap();
    let mut matches = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) if item.self_ty.to_token_stream().to_string() == owner => {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| &item.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        });
    let found = canonical(matches.next().unwrap().to_token_stream()).to_string();
    assert!(matches.next().is_none());
    found
}

fn submit_contract(receive: &str, check: &str, sender_receive: &str, sender_check: &str) -> bool {
    let mut next = 0;
    for required in [
        "self, stage: &mut EnrolledRoleStage<'_>, original: &mut NativeAcquisition",
        "let captured = BackupSubmitOriginal::capture(original)?;",
        "let selected = stage.storage()?.scheduled_backup_root_selection()?;",
        "stage.check_serving_acquisition(original)?;",
        "self.check_resources()?;",
        "original.remaining()?;",
        "net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)])",
        "ScheduledJobSender::receive(received, Rc::clone(&self.socket), &selected.executable, original)?",
        "crate::security_epoch::scheduled_backup::requester::decode_submit_data(&bytes[..count])?",
        "CapturedScheduledBackupSubmit { connection: self, sender, intent, original: captured, refused: false }",
        "submit.check(original)?;",
        "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { stage.check_serving_acquisition(original) }));",
        "stage.refuse_serving(); original.refuse();",
        "finish_checked(requested, checked)",
    ] {
        let required = fragment(required);
        let Some(position) = receive[next..].find(&required) else {
            eprintln!("submit required before position {next}");
            return false;
        };
        next += position + required.len();
    }
    [
        "self.original.check(original)?;",
        "self.connection.check_resources()?; self.sender.check(original)?;",
        "self.original.check_intent(original, &self.intent)?;",
        "self.refused = true; self.original.refuse(); self.sender.refuse(); self.connection.refused.set(true); original.refuse();",
    ].iter().all(|needle| check.contains(&fragment(needle)))
        && [
            "MessageProcess::receive(received, expected_code, original, &costs)?",
            "let proc = require_proc_view(original)?;",
            "pid.get() == process.data.process && credentials.uid() == 10001 && credentials.gid() == 10001",
            "require_pidfd(&proc, &process.pidfd, pid, original)?;",
            "require_pidfd(&proc, &connector_fd, pid, original)?;",
            "connector.pidfd = connector_fd;",
            "MessageProcess::check_same_actor(&mut [&mut process, &mut connector], original, &costs)?;",
            "sender.check(original)?;",
        ].iter().all(|needle| sender_receive.contains(&fragment(needle)))
        && [
            "require_process_views(&self.proc, &self.process, &self.connector, original)?;",
            "require_pidfd(&self.proc, &self.process.pidfd, pid, original)?;",
            "require_pidfd(&self.proc, &self.connector.pidfd, pid, original)?;",
            "rustix::net::sockopt::socket_cookie(&self.socket)? == self.cookie",
            "MessageProcess::check_same_actor(&mut [&mut self.process, &mut self.connector], original, &HashCosts::disabled())?;",
            "self.refused = true; original.refuse();",
        ].iter().all(|needle| sender_check.contains(&fragment(needle)))
        && !receive.contains(&fragment("NativeAcquisition::begin"))
        && !receive.contains("recv_pidfd_rights_packet")
}

#[test]
fn actual_submit_consumes_connection_and_keeps_same_original_and_kernel_sender() {
    let socket = include_str!("channel/scheduled_backup.rs");
    let sender = include_str!("process/backup_anchor.rs");
    let receive = selected_method(socket, "ScheduledBackupConnection", "receive_submit");
    let check = selected_method(socket, "CapturedScheduledBackupSubmit", "check");
    let sender_receive = selected_method(sender, "ScheduledJobSender", "receive");
    let sender_check = selected_method(sender, "ScheduledJobSender", "check");
    assert!(submit_contract(
        &receive,
        &check,
        &sender_receive,
        &sender_check
    ));
    for (from, to) in [
        (
            "let captured = BackupSubmitOriginal::capture(original)?;",
            "let captured = untrusted_original();",
        ),
        (
            "ScheduledJobSender::receive(received, Rc::clone(&self.socket), &selected.executable, original)?",
            "untrusted_sender_data()?",
        ),
        ("original: captured", "original: untrusted_original()"),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(receive.matches(&from).count(), 1, "mutation target");
        assert!(!submit_contract(
            &receive.replacen(&from, &to, 1),
            &check,
            &sender_receive,
            &sender_check
        ));
    }
    for (from, to) in [
        ("self.original.check(original)?;", ""),
        ("self.sender.check(original)?;", ""),
        ("self.sender.refuse();", ""),
        ("self.original.check_intent(original, &self.intent)?;", ""),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(check.matches(&from).count(), 1, "mutation target");
        assert!(!submit_contract(
            &receive,
            &check.replacen(&from, &to, 1),
            &sender_receive,
            &sender_check
        ));
    }
    for (from, to) in [
        (
            "MessageProcess::receive(received, expected_code, original, &costs)?",
            "process_from_numeric_pid()?",
        ),
        ("require_pidfd(&proc, &connector_fd, pid, original)?;", ""),
        ("pid.get() == process.data.process", "true"),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(sender_receive.matches(&from).count(), 1, "mutation target");
        assert!(!submit_contract(
            &receive,
            &check,
            &sender_receive.replacen(&from, &to, 1),
            &sender_check
        ));
    }
    let from = fragment("require_pidfd(&self.proc, &self.process.pidfd, pid, original)?;");
    assert_eq!(sender_check.matches(&from).count(), 1);
    assert!(!submit_contract(
        &receive,
        &check,
        &sender_receive,
        &sender_check.replacen(&from, "", 1)
    ));
}

fn canonical(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    stream
        .into_iter()
        .filter_map(|token| match token {
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => None,
            proc_macro2::TokenTree::Punct(p) if p.as_char() == '?' => {
                Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                    '?',
                    proc_macro2::Spacing::Alone,
                )))
            }
            proc_macro2::TokenTree::Group(g) => Some(proc_macro2::TokenTree::Group(
                proc_macro2::Group::new(g.delimiter(), canonical(g.stream())),
            )),
            proc_macro2::TokenTree::Punct(p) => Some(proc_macro2::TokenTree::Punct(
                proc_macro2::Punct::new(p.as_char(), proc_macro2::Spacing::Alone),
            )),
            other => Some(other),
        })
        .collect()
}

fn observer_source() -> String {
    let file = syn::parse_file(include_str!("service.rs")).unwrap();
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "backup_observe" => Some(function),
        _ => None,
    });
    let function = functions.next().unwrap();
    assert!(functions.next().is_none());
    canonical(function.to_token_stream()).to_string()
}

fn fragment(source: &str) -> String {
    canonical(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
}

fn observing_contract(source: &str) -> bool {
    // The caller normalizes once. Commas removed for token comparison must
    // never be reparsed as Rust (argument/field separators no longer exist).
    let actual = source;
    let required = [
        "issuance.require_open()?;",
        "let existing = enrolled.get(&key).context(\"native_backup_enrolled_controller_required\")?;",
        "existing.public_key == hello.public_key && existing.process == *controller.data()",
        "runtime::current(&issuer.policy, NativeRole::EpochController, controller, original, costs)",
        "actual == existing.runtime",
        "requester::intent_digest_data(hello.intent.as_bytes())?",
        "channel.send(&Packet::BackupObserveNonce {request:hello.request.clone(), challenge:challenge.clone()}, original)?;",
        "channel.receive_backup_anchors(controller, &job_code, original, &costs.hashes(Subject::Requester))?",
        "protocol::verify(&hello.public_key, \"scheduled-backup-observe-bind\", &(&hello.policy, &hello.public_key, &hello.request, &challenge, &intent), &signature)?;",
        "requester::validate_process_commitments_data(hello.intent.as_bytes(), &job, &controller_commitment)? == intent",
        "anchors.observe_runtime(&issuer.policy, hello.intent.as_bytes(), original, costs)?",
        "birth::load_policy(original)? == issuer.policy",
        "issuer.certificate.verify(&issuer.policy)?;",
        "issuer.key.sign(\"scheduled-backup-observation\", &data)?",
        "channel.send(&Packet::BackupObserveGrant {observation:Box::new(observation)}, original)?;",
    ];
    let mut next = 0;
    for statement in required {
        let needle = fragment(statement);
        let Some(relative) = actual[next..].find(&needle) else {
            return false;
        };
        next += relative + needle.len();
    }
    let mut tail = &actual[next..];
    for required in [
        "anchors.check(original, &costs.hashes(Subject::Requester))?;",
        "controller.check_identity(original, &costs.hashes(Subject::Requester))?;",
        "current.check(original)?;",
        "issuer.parent.check_identity(original, &costs.hashes(Subject::ParentBefore))?;",
        "original.remaining()?;",
        "if requested.is_err() { channel.refuse(); original.refuse(); }",
    ] {
        let needle = fragment(required);
        let Some(position) = tail.find(&needle) else {
            return false;
        };
        tail = &tail[position + needle.len()..];
    }
    !actual.contains(&fragment("NativeAcquisition::begin")) && !actual.contains("SignedStage")
}

#[test]
fn actual_observation_requires_enrolled_current_controller_and_same_original_through_final_posts() {
    let source = observer_source();
    assert!(observing_contract(&source));
    let parent_post =
        fragment("issuer.parent.check_identity(original, &costs.hashes(Subject::ParentBefore))?;");
    let last = source.rfind(&parent_post).unwrap();
    let mut missing_parent_post = source.clone();
    missing_parent_post.replace_range(last..last + parent_post.len(), "");
    assert!(!observing_contract(&missing_parent_post));

    for (from, to) in [
        ("issuance.require_open()?;", ""),
        (
            "existing.public_key == hello.public_key && existing.process == *controller.data()",
            "true",
        ),
        ("actual == existing.runtime", "true"),
        (
            "&hello.request, &challenge, &intent",
            "&hello.request, &challenge",
        ),
        ("birth::load_policy(original)? == issuer.policy", "true"),
        (
            "anchors.observe_runtime(&issuer.policy, hello.intent.as_bytes(), original, costs)?",
            "untrusted_runtime_data()",
        ),
        (
            "if requested.is_err() { channel.refuse(); original.refuse(); }",
            "",
        ),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(source.matches(&from).count(), 1, "mutation target");
        assert!(!observing_contract(&source.replacen(&from, &to, 1)));
    }
}

#[test]
fn rights_receiver_is_fixed_to_bind_and_two_anchors_with_no_general_mode() {
    let file = syn::parse_file(include_str!("channel.rs")).unwrap();
    let body = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "receive_backup_anchors" => {
                Some(canonical(item.block.to_token_stream()).to_string())
            }
            _ => None,
        })
        .unwrap();
    for needle in [
        "net::PidfdRightsCount::Two",
        "Packet::BackupObserveBind { .. }",
        "ForwardedJobAnchors::receive(received, controller, code, acquisition, costs)?",
        "self.refuse(); acquisition.refuse();",
    ] {
        assert!(body.contains(&fragment(needle)));
    }
    assert!(!body.contains(&fragment("NativeAcquisition::begin")));
    let ordinary = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "receive_kernel" => {
                Some(canonical(item.block.to_token_stream()).to_string())
            }
            _ => None,
        })
        .unwrap();
    assert!(ordinary.contains(&fragment("net::recv_pidfd_packet")));
    assert!(!ordinary.contains("recv_pidfd_rights_packet"));
}

#[test]
fn optional_policy_is_disabled_without_changing_the_ordinary_policy_digest() -> anyhow::Result<()> {
    let root = super::protocol::KeyOwner::generate()?;
    let policy = super::tests::policy(&root);
    let value = serde_json::to_value(&policy)?;
    assert!(value.get("scheduled_backup").is_none());
    let decoded: super::policy::EnrollmentPolicy =
        crate::json::decode(&serde_json::to_vec(&value)?)?;
    assert_eq!(decoded, policy);
    assert_eq!(decoded.digest()?, policy.digest()?);
    let mut unknown = value;
    unknown["scheduled_backup"] = serde_json::json!({"enabled":true});
    assert!(
        crate::json::decode::<super::policy::EnrollmentPolicy>(&serde_json::to_vec(&unknown)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn new_wire_is_closed_comparison_data_without_a_stage_or_clock_constructor() -> anyhow::Result<()> {
    use super::protocol::{self, Packet};
    use day2_capabilities::Digest;
    let packet = Packet::BackupObserveBind {
        request: Digest::new(b"request"),
        challenge: Digest::new(b"challenge"),
        signature: "opaque-fixture-not-authority".into(),
    };
    let encoded = serde_json::to_vec(&packet)?;
    assert!(matches!(
        protocol::decode(&encoded)?,
        Packet::BackupObserveBind { .. }
    ));
    let mut extra = serde_json::to_value(&packet)?;
    extra["role"] = serde_json::json!("app_host");
    assert!(protocol::decode(&serde_json::to_vec(&extra)?).is_err());
    assert!(
        protocol::decode(b"{\"kind\":\"backup_observe_bind\",\"kind\":\"stage_bind\"}").is_err()
    );
    assert!(protocol::decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
    Ok(())
}

#[test]
fn actual_linux_service_keeps_production_items_before_inline_test_modules() {
    fn ordered(file: &syn::File) -> bool {
        let mut test = false;
        for item in &file.items {
            let is_test = match item {
                syn::Item::Mod(m) => {
                    m.content.is_some()
                        && m.attrs.iter().any(|a| {
                            a.path().is_ident("cfg")
                                && a.meta.to_token_stream().to_string() == "cfg (test)"
                        })
                }
                _ => false,
            };
            if is_test {
                test = true;
            } else if test {
                return false;
            }
        }
        true
    }
    let mut actual = syn::parse_file(include_str!("service.rs")).unwrap();
    assert!(ordered(&actual));
    let mut moved = Vec::new();
    for name in ["BackupObservationHello", "backup_observe"] {
        let indices = actual
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| match item {
                syn::Item::Struct(s) if s.ident == name => Some(i),
                syn::Item::Fn(f) if f.sig.ident == name => Some(i),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(indices.len(), 1, "actual moved declaration {name}");
        moved.push(actual.items.remove(indices[0]));
    }
    actual.items.extend(moved);
    assert!(!ordered(&actual));
}
