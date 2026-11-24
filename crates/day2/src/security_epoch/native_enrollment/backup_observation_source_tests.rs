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

fn socket_resource_source(source: &str) -> String {
    let mut file = syn::parse_file(source).unwrap();
    let mut removed = 0;
    let mut admission_removed = 0;
    file.items.retain_mut(|item| {
        let syn::Item::Impl(item) = item else { return true; };
        if matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("AdmittedScheduledBackupRequest")) {
            admission_removed += 1; return false;
        }
        if matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("ObservedScheduledBackupSubmit")) {
            removed += 1; return false;
        }
        if matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("CapturedScheduledBackupSubmit")) {
            item.items.retain(|member| {
                let remove = matches!(member, syn::ImplItem::Fn(method) if method.sig.ident=="observe_issuer");
                removed += usize::from(remove); !remove
            });
        }
        true
    });
    assert_eq!(removed, 3, "exact separately checked client/check/drop");
    assert_eq!(
        admission_removed, 2,
        "exact independently checked request impl/drop"
    );
    canonical(file.to_token_stream()).to_string()
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
        // Three original outer boundaries plus the new independent Offer posts.
        && socket.matches(&fragment("stage.refuse_serving(); original.refuse();")).count() == 4
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
    let socket = socket_resource_source(include_str!("channel/scheduled_backup.rs"));
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

fn admission_post(source: &str, owner: &str, method: &str, local: &str, expected: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let mut bodies = file
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
            syn::ImplItem::Fn(item) if item.sig.ident == method => Some(&item.block),
            _ => None,
        });
    let Some(body) = bodies.next() else {
        return false;
    };
    if bodies.next().is_some() {
        return false;
    }
    let Some(init) = body.stmts.iter().find_map(|statement| match statement {
        syn::Stmt::Local(item) if matches!(&item.pat, syn::Pat::Ident(p) if p.ident == local) => {
            item.init.as_ref()
        }
        _ => None,
    }) else {
        return false;
    };
    let syn::Expr::Call(catch) = init.expr.as_ref() else {
        return false;
    };
    if catch.func.to_token_stream().to_string() != "std :: panic :: catch_unwind"
        || catch.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Call(safe)) = catch.args.first() else {
        return false;
    };
    if safe.func.to_token_stream().to_string() != "std :: panic :: AssertUnwindSafe"
        || safe.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Closure(closure)) = safe.args.first() else {
        return false;
    };
    if !closure.inputs.is_empty() {
        return false;
    }
    let mut actual = closure.body.as_ref();
    while let syn::Expr::Block(block) = actual {
        if !block.attrs.is_empty() || block.label.is_some() {
            return false;
        }
        let [syn::Stmt::Expr(inner, None)] = block.block.stmts.as_slice() else {
            return false;
        };
        actual = inner;
    }
    canonical(actual.to_token_stream()).to_string() == fragment(expected)
}

fn closed_admission_contract(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    for (name, fields) in [
        (
            "ProtectedScheduledCreate",
            vec![
                ("_unavailable", "std::convert::Infallible"),
                ("_local", "std::marker::PhantomData<Rc<()>>"),
            ],
        ),
        (
            "AdmittedScheduledBackupRequest",
            vec![
                ("observation", "ObservedScheduledBackupSubmit"),
                ("create", "ProtectedScheduledCreate"),
                ("refused", "bool"),
            ],
        ),
    ] {
        let structs = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        if structs.len() != 1
            || structs[0].fields.len() != fields.len()
            || structs[0]
                .attrs
                .iter()
                .any(|attribute| !attribute.path().is_ident("doc"))
        {
            return false;
        }
        if structs[0]
            .fields
            .iter()
            .zip(fields)
            .any(|(actual, (name, ty))| {
                !matches!(actual.vis, syn::Visibility::Inherited)
                    || !actual.attrs.is_empty()
                    || actual.ident.as_ref().is_none_or(|id| id != name)
                    || canonical(actual.ty.to_token_stream()).to_string() != fragment(ty)
            })
        {
            return false;
        }
    }
    let refused = "Err(anyhow::anyhow!(\"scheduled_backup_create_source_unqualified\"))";
    let acquire = selected_method(source, "ProtectedScheduledCreate", "acquire");
    let proof_check = selected_method(source, "ProtectedScheduledCreate", "check");
    if acquire != fragment(&format!("fn acquire() -> Result<Self> {{ {refused} }}"))
        || proof_check != fragment(&format!("fn check(&self) -> Result<()> {{ {refused} }}"))
    {
        return false;
    }
    let factory = selected_method(source, "ObservedScheduledBackupSubmit", "try_admit_request");
    let check = selected_method(source, "AdmittedScheduledBackupRequest", "check");
    let ordered = |text: &str, pieces: &[&str]| {
        let mut tail = text;
        for piece in pieces {
            let token = fragment(piece);
            let Some((_, rest)) = tail.split_once(&token) else {
                return false;
            };
            tail = rest;
        }
        true
    };
    ordered(
        &factory,
        &[
            "self.check(stage, original)?;",
            "ProtectedScheduledCreate::acquire()",
            "let checked",
            "let stage_checked",
            "self.refuse();",
            "stage.refuse_serving();",
            "original.refuse();",
            "finish_checked(requested, checked)",
            "finish_checked(Ok(create), stage_checked)?",
            "AdmittedScheduledBackupRequest { observation: self, create, refused: false }",
        ],
    ) && admission_post(
        source,
        "ObservedScheduledBackupSubmit",
        "try_admit_request",
        "checked",
        "self.check(stage, original)",
    ) && admission_post(
        source,
        "ObservedScheduledBackupSubmit",
        "try_admit_request",
        "stage_checked",
        "stage.check_serving_acquisition(original)",
    ) && ordered(
        &check,
        &[
            "self.observation.check(stage, original)?;",
            "self.create.check()?;",
            "self.observation.check(stage, original)",
            "let checked",
            "self.refuse();",
            "stage.refuse_serving();",
            "original.refuse();",
            "finish_checked(requested, checked)",
        ],
    ) && admission_post(
        source,
        "AdmittedScheduledBackupRequest",
        "check",
        "checked",
        "stage.check_serving_acquisition(original)",
    ) && !factory.contains(&fragment("NativeAcquisition::begin"))
        && !factory.contains(&fragment("BackupSubmitOriginal::capture"))
        && !factory.contains(&fragment("identity_domain"))
        && selected_method(source, "AdmittedScheduledBackupRequest", "refuse")
            == fragment("fn refuse(&mut self) { self.refused = true; self.observation.refuse(); }")
        && selected_method(source, "AdmittedScheduledBackupRequest", "drop")
            == fragment("fn drop(&mut self) { self.refuse(); }")
}

#[test]
fn actual_request_admission_has_an_uninhabited_create_gate_and_same_whole_observation() {
    let source = include_str!("channel/scheduled_backup.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    assert!(closed_admission_contract(source));
    for (old, new) in [
        (
            "_unavailable: std::convert::Infallible",
            "_unavailable: bool",
        ),
        ("_local: std::marker::PhantomData<Rc<()>>", "_local: ()"),
        (
            "observation: ObservedScheduledBackupSubmit",
            "observation: NativeOriginalRefusal",
        ),
        ("observation: self", "observation: fresh_request()"),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        assert!(!closed_admission_contract(&source.replacen(old, new, 1)));
    }
    for method in ["acquire", "check"] {
        let mut file = syn::parse_file(source).unwrap();
        let mut changed = 0;
        for item in &mut file.items {
            if let syn::Item::Impl(item) = item
                && item.self_ty.to_token_stream().to_string() == "ProtectedScheduledCreate"
            {
                for item in &mut item.items {
                    if let syn::ImplItem::Fn(item) = item
                        && item.sig.ident == method
                    {
                        item.block = syn::parse_quote!({ Ok(unqualified_value()) });
                        changed += 1;
                    }
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!closed_admission_contract(
            &file.to_token_stream().to_string()
        ));
    }
    for (owner, method, local) in [
        (
            "ObservedScheduledBackupSubmit",
            "try_admit_request",
            "checked",
        ),
        (
            "ObservedScheduledBackupSubmit",
            "try_admit_request",
            "stage_checked",
        ),
        ("AdmittedScheduledBackupRequest", "check", "checked"),
    ] {
        let mut file = syn::parse_file(source).unwrap();
        let mut changed = 0;
        for item in &mut file.items {
            if let syn::Item::Impl(item) = item
                && item.self_ty.to_token_stream().to_string() == owner
            {
                for member in &mut item.items {
                    if let syn::ImplItem::Fn(member) = member
                        && member.sig.ident == method
                    {
                        for statement in &mut member.block.stmts {
                            if let syn::Stmt::Local(statement) = statement
                                && matches!(&statement.pat, syn::Pat::Ident(id) if id.ident == local)
                            {
                                *statement.init.as_mut().unwrap().expr =
                                    syn::parse_quote!(Ok(Ok(())));
                                changed += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!closed_admission_contract(
            &file.to_token_stream().to_string()
        ));
    }
}

fn submit_accept_contract(accept: &str) -> bool {
    let mut tail = accept;
    for text in [
        "BackupSubmitOriginal::capture(original)",
        "scheduled_backup_root_selection",
        "check_serving_acquisition",
        "net::accept_with",
        "original: Some(captured)",
        "connection.check_resources",
        "self.check",
    ] {
        let token = fragment(text);
        let Some((_, remaining)) = tail.split_once(&token) else {
            return false;
        };
        tail = remaining;
    }
    true
}

fn submit_contract(
    accept: &str,
    receive: &str,
    check: &str,
    sender_receive: &str,
    sender_check: &str,
) -> bool {
    let mut next = 0;
    for required in [
        "mut self, stage: &mut EnrolledRoleStage<'_>, original: &mut NativeAcquisition",
        "let mut captured = self.original.take().ok_or_else(|| anyhow::anyhow!(\"backup_submit_original_missing\"))?;",
        "captured.check(original)?;",
        "let selected = stage.storage()?.scheduled_backup_root_selection()?;",
        "stage.check_serving_acquisition(original)?;",
        "self.check_resources()?;",
        "original.remaining()?;",
        "net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut hello_bytes)])",
        "let mut hello_sender = ScheduledJobSender::receive(hello_received, Rc::clone(&self.socket), &selected.executable, original)?;",
        "requester::decode_hello_data(&hello_bytes[..hello_count])?",
        "stage.storage()?.backup_observer_identity_data(original)?",
        "hello_sender.commitment_data(original)?",
        "protocol::nonce(\"scheduled-backup-submit-offer\")?",
        "captured.check(original)?;",
        "original.historical_interval_observation().0",
        "SubmitOfferData::new_data",
        "net::sockopt::socket_cookie(&self.socket)?",
        "requester::encode_offer_data(&offer)?",
        "captured.check(original)?;",
        "hello_sender.check(original)?;",
        "stage.check_serving_acquisition(original)?;",
        "net::send(&self.socket, &offer_bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL)",
        "ensure!(count == offer_bytes.len(), \"backup_offer_partial_send\")",
        "let sender_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { hello_sender.check(original) }));",
        "let stage_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { stage.check_serving_acquisition(original) }));",
        "hello_sender.refuse(); stage.refuse_serving(); original.refuse();",
        "finish_checked(sent, sender_post)",
        "finish_checked(Ok(sent), stage_post)?",
        "net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)])",
        "ScheduledJobSender::receive(received, Rc::clone(&self.socket), &selected.executable, original)?",
        "hello_sender.check_same_submit_actor(&mut sender, original)?;",
        "crate::security_epoch::scheduled_backup::requester::decode_submit_data(&bytes[..count])?",
        "requester::require_submit_offer_data(&intent, &offer)?;",
        "CapturedScheduledBackupSubmit { connection: self, sender, hello_sender, offer, intent, original: captured, refused: false }",
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
        "self.hello_sender.check_same_submit_actor(&mut self.sender, original)?;",
        "self.offer.require_connection_data(net::sockopt::socket_cookie(&self.connection.socket)?)?;",
        "requester::require_submit_offer_data(&self.intent, &self.offer)?;",
        "self.original.check_intent(original, &self.intent)?;",
        "self.refused = true; self.original.refuse(); self.sender.refuse(); self.hello_sender.refuse(); self.connection.refused.set(true); original.refuse();",
    ].iter().all(|needle| check.contains(&fragment(needle)))
        && submit_accept_contract(accept)
        && accept.matches(&fragment("BackupSubmitOriginal::capture(original)")).count() == 1
        && !receive.contains(&fragment("BackupSubmitOriginal::capture(original)"))
        && receive.matches(&fragment("net::recv_pidfd_packet")).count() == 2
        && receive.matches(&fragment("requester::decode_hello_data")).count() == 1
        && receive.matches(&fragment("requester::decode_submit_data")).count() == 1
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
        && !receive.contains("receive_issuer")
}

#[test]
fn actual_submit_consumes_connection_and_keeps_same_original_and_kernel_sender() {
    let socket = include_str!("channel/scheduled_backup.rs");
    let sender = include_str!("process/backup_anchor.rs");
    let accept = selected_method(socket, "ScheduledBackupSocketListener", "accept");
    let receive = selected_method(socket, "ScheduledBackupConnection", "receive_submit");
    let check = selected_method(socket, "CapturedScheduledBackupSubmit", "check");
    let sender_receive = selected_method(sender, "ScheduledJobSender", "receive");
    let sender_check = selected_method(sender, "ScheduledJobSender", "check");
    assert!(submit_contract(
        &accept,
        &receive,
        &check,
        &sender_receive,
        &sender_check
    ));
    for (before, after) in [
        (
            "let captured = BackupSubmitOriginal::capture(original)?;",
            "let captured = untrusted_original();",
        ),
        ("original: Some(captured)", "original: None"),
    ] {
        let before = fragment(before);
        assert_eq!(accept.matches(&before).count(), 1);
        assert!(!submit_contract(
            &accept.replacen(&before, &fragment(after), 1),
            &receive,
            &check,
            &sender_receive,
            &sender_check
        ));
    }
    let changed = receive.replacen(
        &fragment("self.check_resources()?;"),
        &fragment("self.check_resources()?; channel.receive_issuer(original)?;"),
        1,
    );
    assert_ne!(changed, receive);
    assert!(!submit_contract(
        &accept,
        &changed,
        &check,
        &sender_receive,
        &sender_check
    ));
    for (from, to) in [
        (
            "let mut captured = self.original.take().ok_or_else(|| anyhow::anyhow!(\"backup_submit_original_missing\"))?;",
            "let mut captured = untrusted_original();",
        ),
        (
            "ScheduledJobSender::receive(received, Rc::clone(&self.socket), &selected.executable, original)?",
            "untrusted_sender_data()?",
        ),
        ("original: captured", "original: untrusted_original()"),
        (
            "let sender_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { hello_sender.check(original) }));",
            "let sender_post = Ok(Ok(()));",
        ),
        (
            "let stage_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { stage.check_serving_acquisition(original) }));",
            "let stage_post = Ok(Ok(()));",
        ),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(receive.matches(&from).count(), 1, "mutation target");
        assert!(!submit_contract(
            &accept,
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
        (
            "self.hello_sender.check_same_submit_actor(&mut self.sender, original)?;",
            "",
        ),
        (
            "requester::require_submit_offer_data(&self.intent, &self.offer)?;",
            "",
        ),
        ("self.original.check_intent(original, &self.intent)?;", ""),
    ] {
        let from = fragment(from);
        let to = fragment(to);
        assert_eq!(check.matches(&from).count(), 1, "mutation target");
        assert!(!submit_contract(
            &accept,
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
            &accept,
            &receive,
            &check,
            &sender_receive.replacen(&from, &to, 1),
            &sender_check
        ));
    }
    let from = fragment("require_pidfd(&self.proc, &self.process.pidfd, pid, original)?;");
    assert_eq!(sender_check.matches(&from).count(), 1);
    assert!(!submit_contract(
        &accept,
        &receive,
        &check,
        &sender_receive,
        &sender_check.replacen(&from, "", 1)
    ));
}

fn two_message_sender_contract(commitment: &str, joined: &str) -> bool {
    let ordered_tokens = |text: &str, expected: &[&str]| {
        let mut tail = text;
        for needle in expected {
            let needle = fragment(needle);
            let Some((_, rest)) = tail.split_once(&needle) else {
                return false;
            };
            tail = rest;
        }
        true
    };
    ordered_tokens(
        commitment,
        &[
            "self.check(original)?;",
            "Digest::of(&(\"day2-scheduled-backup-process-v1\", &self.process.data))",
            "let checked = self.check(original)",
            "self.refuse()",
            "original.refuse()",
            "let commitment = requested?",
            "checked?",
            "Ok(commitment)",
        ],
    ) && ordered_tokens(
        joined,
        &[
            "self.check(original)?",
            "other.check(original)?",
            "Rc::ptr_eq(&self.socket, &other.socket)",
            "self.cookie == other.cookie",
            "MessageProcess::check_same_actor(&mut [&mut self.process, &mut self.connector, &mut other.process, &mut other.connector], original, &HashCosts::disabled())",
            "let first = std::panic::catch_unwind",
            "let second = std::panic::catch_unwind",
            "self.refuse()",
            "other.refuse()",
            "original.refuse()",
            "match requested",
            "match first",
            "match second",
        ],
    ) && joined.matches(&fragment("self.check(original)")).count() == 2
        && joined.matches(&fragment("other.check(original)")).count() == 2
        && !joined.contains(&fragment("NativeAcquisition::begin"))
}

#[test]
fn actual_hello_submit_join_keeps_both_kernel_actors_and_independent_posts() {
    let source = include_str!("process/backup_anchor.rs");
    let commitment = selected_method(source, "ScheduledJobSender", "commitment_data");
    let join = selected_method(source, "ScheduledJobSender", "check_same_submit_actor");
    assert!(two_message_sender_contract(&commitment, &join));
    for (before, after) in [
        ("Rc::ptr_eq(&self.socket, &other.socket)", "true"),
        ("self.cookie == other.cookie", "true"),
        (
            "MessageProcess::check_same_actor(&mut [&mut self.process, &mut self.connector, &mut other.process, &mut other.connector], original, &HashCosts::disabled())",
            "Ok(())",
        ),
        (
            "let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check(original)));",
            "let first = Ok(Ok(()));",
        ),
        (
            "let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| other.check(original)));",
            "let second = Ok(Ok(()));",
        ),
        ("other.refuse();", ""),
    ] {
        let before = fragment(before);
        assert_eq!(
            join.matches(&before).count(),
            1,
            "actual join mutation target"
        );
        assert!(!two_message_sender_contract(
            &commitment,
            &join.replacen(&before, &fragment(after), 1)
        ));
    }
    let before =
        fragment("Digest::of(&(\"day2-scheduled-backup-process-v1\", &self.process.data))");
    assert_eq!(commitment.matches(&before).count(), 1);
    assert!(!two_message_sender_contract(
        &commitment.replacen(&before, &fragment("Digest::new(b\"untrusted\")"), 1),
        &join
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

#[test]
fn completed_observer_cursor_is_same_original_and_has_no_later_transport_step() {
    use super::handshake::{Actor, Observation, Protocol, Transcript, Transport};
    use day2_capabilities::Digest;
    use std::time::Duration;
    let at = |now| Observation {
        domain: Digest::new(b"same-real-original-data"),
        origin: Duration::from_secs(100),
        deadline: Duration::from_secs(105),
        now: Duration::from_secs(now),
    };
    let mut complete = Transcript::new(Protocol::Enrollment, Actor::Client);
    for _ in 0..4 {
        let (direction, frame) = complete.next().unwrap();
        complete.begin(direction, at(100)).unwrap();
        complete.delivered(frame, at(100)).unwrap();
    }
    complete
        .require_completed_backup_observation_data(at(101))
        .unwrap();
    assert!(complete.complete());
    assert!(complete.next().is_none());
    // Ordinary peer EOF has no new frame. No poll/read/transport operation is
    // called by the completed comparison check, and it remains local DATA.
    complete
        .require_completed_backup_observation_data(at(102))
        .unwrap();
    for cut in 0..6 {
        let mut changed = complete.clone();
        let mut observed = at(103);
        match cut {
            0 => observed.domain = Digest::new(b"another-original"),
            1 => observed.origin = Duration::from_secs(99),
            2 => observed.deadline = Duration::from_secs(106),
            3 => observed.now = Duration::from_secs(105),
            4 => observed.now = Duration::from_secs(101),
            _ => changed.refuse(),
        }
        assert!(
            changed
                .require_completed_backup_observation_data(observed)
                .is_err()
        );
        assert!(
            changed
                .require_completed_backup_observation_data(at(103))
                .is_err()
        );
    }
    for count in 0..4 {
        let mut partial = Transcript::new(Protocol::Enrollment, Actor::Client);
        for _ in 0..count {
            let (direction, frame) = partial.next().unwrap();
            partial.begin(direction, at(100)).unwrap();
            partial.delivered(frame, at(100)).unwrap();
        }
        assert!(
            partial
                .require_completed_backup_observation_data(at(101))
                .is_err()
        );
    }
    let mut busy = Transcript::new(Protocol::Enrollment, Actor::Client);
    let (direction, _) = busy.next().unwrap();
    busy.begin(direction, at(100)).unwrap();
    busy.transport(Transport::WouldBlock, at(100)).unwrap();
    assert!(
        busy.require_completed_backup_observation_data(at(101))
            .is_err()
    );
}

fn completed_channel_contract(source: &str) -> bool {
    let mut cursor = 0;
    for expected in [
        "self.original.check(original)?;",
        "!self.channel.refused.get()",
        "require_idle_socket_profile(&self.channel.socket)?;",
        "net::sockopt::socket_passcred(&self.channel.socket)?",
        "net::sockopt::socket_passpidfd(&self.channel.socket)?",
        "fcntl_getfl(&self.channel.socket)?.contains(OFlags::NONBLOCK)",
        "require_completed_backup_observation_data(Channel::observation(original))?;",
        "original.remaining()?;",
        "self.refuse(); original.refuse();",
    ] {
        let expected = fragment(expected);
        let Some(at) = source[cursor..].find(&expected) else {
            return false;
        };
        cursor += at + expected.len();
    }
    ![
        "require_connected",
        "idle_open",
        "poll",
        "recv",
        "receive",
        "send",
        "wait",
        "connect",
    ]
    .iter()
    .any(|forbidden| source.contains(forbidden))
        && !source.contains(&fragment("NativeAcquisition::begin"))
}

#[test]
fn actual_completed_observation_channel_has_no_post_grant_io_or_hup_dependency() {
    let socket = include_str!("channel/scheduled_backup.rs");
    let checked = selected_method(socket, "CompletedBackupObservationChannel", "check");
    assert!(completed_channel_contract(&checked));
    for extra in [
        "super::require_connected(&self.channel.socket, original)?;",
        "super::idle_open(&self.channel.socket)?;",
        "rustix::event::poll(&mut fds, None)?;",
        "self.channel.receive_issuer(original)?;",
        "self.channel.send(packet, original)?;",
        "let _fresh = NativeAcquisition::begin(5)?;",
    ] {
        let changed = checked.replacen(
            &fragment("original.remaining()?;"),
            &fragment(&format!("{extra} original.remaining()?;")),
            1,
        );
        assert_ne!(changed, checked);
        assert!(!completed_channel_contract(&changed));
    }
    let ctor = selected_method(socket, "Channel", "complete_backup_observation");
    assert!(ctor.contains(&fragment("mut self, original: &mut NativeAcquisition")));
    assert!(ctor.contains(&fragment(
        "let mut guard = BackupSubmitOriginal::capture(original)?;"
    )));
    assert!(ctor.contains(&fragment(
        "require_completed_backup_observation_data(Self::observation(original))?;"
    )));
    assert!(ctor.contains(&fragment(
        "CompletedBackupObservationChannel { channel: self, original: guard }"
    )));
    assert!(!ctor.contains(&fragment("NativeAcquisition::begin")));
}

fn issuer_client_contract(client: &str, check: &str, sender: &str) -> bool {
    let mut next = 0;
    for required in [
        "self.check(original)?;",
        "let mut same = stage.capture_same_owner()?;",
        "same.meet_current_read_view(stage, original)?;",
        "let identity = stage.storage()?.backup_observer_identity_data(original)?;",
        "let intent = self.intent_data(original)?;",
        "protocol::nonce(\"scheduled-backup-observe-request\")?",
        "Channel::connect(original)?",
        "Packet::BackupObserveHello",
        "let (packet, mut nonce_peer) = channel.receive_issuer(original)?;",
        "nonce_peer.bind(&identity.certificate, &identity.policy, original)?;",
        "same.meet_current_read_view(stage, original)?;",
        "self.check(original)?;",
        "stage.storage()?.sign_backup_observer_bind(&identity, &intent, (&request, &challenge), original)?;",
        "channel.send_backup_observe_bind(&mut self, &Packet::BackupObserveBind { request: request.clone(), challenge: challenge.clone(), signature }, original)?;",
        "let (packet, mut grant_peer) = channel.receive_issuer(original)?;",
        "grant_peer.bind(&identity.certificate, &identity.policy, original)?;",
        "observation.data.request == request && observation.data.challenge == challenge",
        "let channel = channel.complete_backup_observation(original)?;",
        "observed.check(stage, original)?;",
        "stage.check_serving_acquisition(original)",
        "stage.refuse_serving(); original.refuse();",
    ] {
        let required = fragment(required);
        let Some(at) = client[next..].find(&required) else {
            return false;
        };
        next += at + required.len();
    }
    ["self.same.meet_current_read_view(stage, original)?;", "self.submit.check(original)?;", "let identity = stage.storage()?.backup_observer_identity_data(original)?;", "identity == self.identity", "self.nonce_peer.bind(&identity.certificate, &identity.policy, original)?;", "self.grant_peer.bind(&identity.certificate, &identity.policy, original)?;", "self.nonce_peer.check_live(original)?;", "self.grant_peer.check_live(original)?;", "self.observation.verify_data(&identity.policy, &identity.certificate, (&identity.controller, &identity.public_key), &intent, (&self.request, &self.challenge), original.sample()?.elapsed)?;", "self.submit.require_job_data(&self.observation.data.job, original)?;", "self.channel.check(original)?;", "stage.check_serving_acquisition(original)", "self.refuse(); stage.refuse_serving(); original.refuse();"]
        .iter().all(|required| check.contains(&fragment(required)))
        && ["self.check(original)?;", "Packet::BackupObserveBind { .. }", "bytes.len() <= MAX_PACKET", "let rights = [self.process.pidfd.as_fd(), self.socket.as_fd()];", "rustix::cmsg_space!(ScmRights(2))", "SendAncillaryMessage::ScmRights(&rights)", "count == bytes.len()", "let checked = self.check(original);"]
            .iter().all(|required| sender.contains(&fragment(required)))
        && client.matches(&fragment("channel.receive_issuer(original)?")).count() == 2
        && !["NativeAcquisition::begin", "sign_storage", "backup_source", "finish_known"].iter().any(|forbidden| client.contains(&fragment(forbidden)))
}

#[test]
fn actual_issuer_client_retains_submit_receipts_and_purpose_closed_rights() {
    let source = include_str!("channel/scheduled_backup.rs");
    let client = selected_method(source, "CapturedScheduledBackupSubmit", "observe_issuer");
    let check = selected_method(source, "ObservedScheduledBackupSubmit", "check");
    let sender = selected_method(
        include_str!("process/backup_anchor.rs"),
        "ScheduledJobSender",
        "send_observation_bind",
    );
    assert!(issuer_client_contract(&client, &check, &sender));
    for boundary in [
        "same.meet_current_read_view(stage, original)?;",
        "nonce_peer.bind(&identity.certificate, &identity.policy, original)?;",
        "grant_peer.bind(&identity.certificate, &identity.policy, original)?;",
        "observed.check(stage, original)?;",
    ] {
        let changed = client.replacen(&fragment(boundary), &fragment("unrelated()?;"), 1);
        assert_ne!(changed, client);
        assert!(!issuer_client_contract(&changed, &check, &sender));
    }
    for boundary in [
        "self.nonce_peer.check_live(original)?;",
        "self.grant_peer.check_live(original)?;",
        "identity == self.identity",
        "self.submit.require_job_data(&self.observation.data.job, original)?;",
        "self.channel.check(original)?;",
    ] {
        let changed = check.replacen(&fragment(boundary), &fragment("unrelated()?;"), 1);
        assert_ne!(changed, check);
        assert!(!issuer_client_contract(&client, &changed, &sender));
    }
    for (from, to) in [
        (
            "[self.process.pidfd.as_fd(), self.socket.as_fd()]",
            "[self.socket.as_fd(), self.process.pidfd.as_fd()]",
        ),
        ("ScmRights(2)", "ScmRights(1)"),
        (
            "[self.process.pidfd.as_fd(), self.socket.as_fd()]",
            "[self.process.pidfd.as_fd(), self.socket.as_fd(), issuer.as_fd()]",
        ),
        ("count == bytes.len()", "true"),
    ] {
        let changed = sender.replacen(&fragment(from), &fragment(to), 1);
        assert_ne!(changed, sender);
        assert!(!issuer_client_contract(&client, &check, &changed));
    }
}

fn fixed_observer_data_contract(identity: &str, signer: &str) -> bool {
    ["self.check_storage_acquisition(original)?;", "self.scheduled_backup_root_selection()?;", "self.stage.owner.current.try_borrow()", "BackupObserverIdentityData { policy: self.stage.owner.policy.clone(), certificate: self.stage.owner.certificate.clone(), controller, public_key: self.stage.owner.key.public() }", "self.stage.refuse_serving(); original.refuse();"]
        .iter().all(|required| identity.contains(&fragment(required)))
        && identity.matches(&fragment("self.check_storage_acquisition(original)")).count() == 2
        && ["let current = self.backup_observer_identity_data(original)?;", "current == *expected", "crate::security_epoch::scheduled_backup::requester::intent_digest_data(intent)?", "self.stage.owner.key.sign(\"scheduled-backup-observe-bind\", &(&current.policy.digest()?, &current.public_key, nonces.0, nonces.1, &intent))", "self.check_storage_acquisition(original)", "self.stage.refuse_serving(); original.refuse();"]
            .iter().all(|required| signer.contains(&fragment(required)))
        && !identity.contains(&fragment("NativeAcquisition::begin")) && !signer.contains(&fragment("NativeAcquisition::begin"))
}

#[test]
fn actual_observer_projection_and_signer_use_only_this_checked_controller_and_fixed_body() {
    let source = include_str!("owner/storage.rs");
    let owner = syn::parse_str::<syn::Type>("EnrolledStorageStage<'_, '_>")
        .unwrap()
        .to_token_stream()
        .to_string();
    let identity = selected_method(source, &owner, "backup_observer_identity_data");
    let signer = selected_method(source, &owner, "sign_backup_observer_bind");
    assert!(fixed_observer_data_contract(&identity, &signer));
    for (from, to) in [
        ("self.scheduled_backup_root_selection()?;", "unrelated()?;"),
        (
            "self.check_storage_acquisition(original)?;",
            "unrelated()?;",
        ),
        ("self.stage.owner.key.public()", "caller_key()"),
    ] {
        let changed = identity.replacen(&fragment(from), &fragment(to), 1);
        assert_ne!(changed, identity);
        assert!(!fixed_observer_data_contract(&changed, &signer));
    }
    for (from, to) in [
        ("current == *expected", "true"),
        ("intent_digest_data(intent)?", "unbounded_digest(intent)?"),
        ("\"scheduled-backup-observe-bind\"", "caller_purpose"),
        ("&current.public_key", "&expected.public_key"),
        ("self.check_storage_acquisition(original)", "unrelated()"),
    ] {
        let changed = signer.replacen(&fragment(from), &fragment(to), 1);
        assert_ne!(changed, signer);
        assert!(!fixed_observer_data_contract(&identity, &changed));
    }
}

fn outer_selected_method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
    let file = syn::parse_file(source).unwrap();
    let selected = file
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
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    selected.into_iter().next().unwrap()
}

fn outer_selected_function(source: &str, name: &str) -> syn::ItemFn {
    let file = syn::parse_file(source).unwrap();
    let selected = file
        .items
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    selected.into_iter().next().unwrap()
}

fn outer_mutate_method(source: &str, owner: &str, name: &str, from: &str, to: &str) -> String {
    let mut file = syn::parse_file(source).unwrap();
    let mut count = 0;
    for item in &mut file.items {
        if let syn::Item::Impl(item) = item
            && item.self_ty.to_token_stream().to_string() == owner
        {
            for item in &mut item.items {
                if let syn::ImplItem::Fn(method) = item
                    && method.sig.ident == name
                {
                    let from: proc_macro2::TokenStream = from.parse().unwrap();
                    let to: proc_macro2::TokenStream = to.parse().unwrap();
                    let mut targets = 0;
                    let changed =
                        outer_replace_tokens(method.to_token_stream(), &from, &to, &mut targets);
                    assert_eq!(targets, 1, "{owner}::{name}: {from}");
                    *method = syn::parse2(changed).unwrap();
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 1);
    file.to_token_stream().to_string()
}

// syn reconstructs operator spacing while macro bodies retain source spacing.
// Compare actual lexical tokens, retaining every delimiter/comma/literal, and
// ignore only Punct::spacing. Never remove commas and reparse the result.
fn outer_replace_tokens(
    source: proc_macro2::TokenStream,
    from: &proc_macro2::TokenStream,
    to: &proc_macro2::TokenStream,
    targets: &mut usize,
) -> proc_macro2::TokenStream {
    use proc_macro2::{Group, TokenTree};
    fn equal(left: &TokenTree, right: &TokenTree) -> bool {
        match (left, right) {
            (TokenTree::Group(a), TokenTree::Group(b)) => {
                let a_tokens = a.stream().into_iter().collect::<Vec<_>>();
                let b_tokens = b.stream().into_iter().collect::<Vec<_>>();
                a.delimiter() == b.delimiter()
                    && a_tokens.len() == b_tokens.len()
                    && a_tokens.iter().zip(&b_tokens).all(|(a, b)| equal(a, b))
            }
            (TokenTree::Punct(a), TokenTree::Punct(b)) => a.as_char() == b.as_char(),
            (TokenTree::Ident(a), TokenTree::Ident(b)) => a == b,
            (TokenTree::Literal(a), TokenTree::Literal(b)) => a.to_string() == b.to_string(),
            _ => false,
        }
    }
    let source = source.into_iter().collect::<Vec<_>>();
    let pattern = from.clone().into_iter().collect::<Vec<_>>();
    assert!(!pattern.is_empty());
    let mut result = proc_macro2::TokenStream::new();
    let mut index = 0;
    while index < source.len() {
        if source[index..].len() >= pattern.len()
            && source[index..index + pattern.len()]
                .iter()
                .zip(&pattern)
                .all(|(a, b)| equal(a, b))
        {
            result.extend(to.clone());
            *targets += 1;
            index += pattern.len();
            continue;
        }
        let token = match &source[index] {
            TokenTree::Group(group) => {
                let mut replacement = Group::new(
                    group.delimiter(),
                    outer_replace_tokens(group.stream(), from, to, targets),
                );
                replacement.set_span(group.span());
                TokenTree::Group(replacement)
            }
            token => token.clone(),
        };
        result.extend([token]);
        index += 1;
    }
    result
}

fn outer_caught_expression<'a>(statement: &'a syn::Stmt, name: &str) -> Option<&'a syn::Expr> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return None;
    };
    if binding.ident != name {
        return None;
    }
    let syn::Expr::Call(caught) = &*local.init.as_ref()?.expr else {
        return None;
    };
    if caught.func.to_token_stream().to_string() != "std :: panic :: catch_unwind"
        || caught.args.len() != 1
    {
        return None;
    }
    let syn::Expr::Call(safe) = caught.args.first()? else {
        return None;
    };
    if safe.func.to_token_stream().to_string() != "std :: panic :: AssertUnwindSafe"
        || safe.args.len() != 1
    {
        return None;
    }
    let syn::Expr::Closure(closure) = safe.args.first()? else {
        return None;
    };
    if !closure.inputs.is_empty() || closure.asyncness.is_some() {
        return None;
    }
    Some(&closure.body)
}

fn outer_post_contract(source: &str, owner: &str, name: &str, post: &str, unit: bool) -> bool {
    let method = outer_selected_method(source, owner, name);
    let Some(primary) = method
        .block
        .stmts
        .first()
        .and_then(|s| outer_caught_expression(s, "requested"))
    else {
        return false;
    };
    if !matches!(primary, syn::Expr::Block(_)) {
        return false;
    }
    let Some(observed) = method
        .block
        .stmts
        .get(1)
        .and_then(|s| outer_caught_expression(s, "checked"))
    else {
        return false;
    };
    if canonical(observed.to_token_stream()).to_string() != fragment(post) {
        return false;
    }
    let expected = if unit {
        "if !matches!(&requested,Ok(Ok(()))) || !matches!(&checked,Ok(Ok(()))) {self.refuse();}"
    } else {
        "if !matches!(&requested,Ok(Ok(_))) || !matches!(&checked,Ok(Ok(()))) {self.refuse();}"
    };
    method
        .block
        .stmts
        .get(2)
        .is_some_and(|s| canonical(s.to_token_stream()).to_string() == fragment(expected))
}

fn outer_retained_contract(source: &str) -> bool {
    let owner = "RetainedScheduledBackupAction < '_ >";
    if !outer_post_contract(source, owner, "check", "self.parent.check_native()", true) {
        return false;
    }
    let method = outer_selected_method(source, owner, "check");
    let primary = outer_caught_expression(&method.block.stmts[0], "requested").unwrap();
    canonical(primary.to_token_stream()).to_string()
        == fragment(
            "{self.parent.check()?;let mut stage=self.parent.controller.borrow_current_request(&mut self.parent.request)?;self.requester.check(&mut stage,&mut self.parent.original)}",
        )
        && canonical(method.block.stmts.last().unwrap().to_token_stream()).to_string()
            == fragment("settle(requested,checked)")
}

fn outer_bypass_primary_catch(source: &str, owner: &str, name: &str) -> String {
    let mut file = syn::parse_file(source).unwrap();
    let mut count = 0;
    for item in &mut file.items {
        if let syn::Item::Impl(item) = item
            && item.self_ty.to_token_stream().to_string() == owner
        {
            for item in &mut item.items {
                if let syn::ImplItem::Fn(method) = item
                    && method.sig.ident == name
                {
                    let body = outer_caught_expression(&method.block.stmts[0], "requested")
                        .unwrap()
                        .clone();
                    let syn::Stmt::Local(local) = &mut method.block.stmts[0] else {
                        unreachable!();
                    };
                    local.init.as_mut().unwrap().expr =
                        Box::new(syn::parse_quote!(Ok((||#body)())));
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 1);
    file.to_token_stream().to_string()
}

fn retained_action_contract(source: &str) -> bool {
    if !outer_post_contract(
        source,
        "PendingScheduledBackupAction < 'controller >",
        "receive",
        "self.check_native()",
        false,
    ) {
        return false;
    }
    let file = syn::parse_file(source).unwrap();
    let fields = |name: &str| {
        file.items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == name => Some(
                    item.fields
                        .iter()
                        .map(|field| {
                            (
                                field.ident.as_ref().unwrap().to_string(),
                                field.ty.to_token_stream().to_string(),
                                matches!(field.vis, syn::Visibility::Inherited),
                            )
                        })
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .unwrap()
    };
    if fields("PendingScheduledBackupAction")
        != [
            (
                "controller".into(),
                "& 'controller mut EnrolledProcessRoleOwner".into(),
                true,
            ),
            ("request".into(), "EnrolledCurrentRequest".into(), true),
            ("original".into(), "NativeAcquisition".into(), true),
            ("scope".into(), "AuthorityScope".into(), true),
            ("refused".into(), "bool".into(), true),
        ]
        || fields("RetainedScheduledBackupAction")
            != [
                (
                    "parent".into(),
                    "PendingScheduledBackupAction < 'controller >".into(),
                    true,
                ),
                (
                    "requester".into(),
                    "AdmittedScheduledBackupRequest".into(),
                    true,
                ),
            ]
    {
        return false;
    }
    let capture_method = outer_selected_function(source, "capture_scheduled_backup_action");
    if canonical(capture_method.block.stmts[0].to_token_stream()).to_string()
        != fragment("let mut request=controller.begin_current_request()?;")
    {
        return false;
    }
    let capture = canonical(capture_method.block.to_token_stream()).to_string();
    let receive = canonical(
        outer_selected_method(
            source,
            "PendingScheduledBackupAction < 'controller >",
            "receive",
        )
        .block
        .to_token_stream(),
    )
    .to_string();
    let ordered = |body: &str, fragments: &[&str]| {
        let mut offset = 0;
        for statement in fragments {
            let selected = fragment(statement);
            let Some(index) = body[offset..].find(&selected) else {
                return false;
            };
            offset += index + selected.len();
        }
        true
    };
    ordered(
        &capture,
        &[
            "let mut request = controller.begin_current_request()?;",
            "let mut stage = controller.borrow_current_request(&mut request)?;",
            "let scope=stage.storage()?.scheduled_backup_root_selection()?.scope;",
            "stage.check_for(&scope,NativeRole::EpochController)?;",
            "let original=stage.narrow_io_acquisition(5)?;",
            "let mut pending=PendingScheduledBackupAction { controller,request,original,scope,refused:false };",
            "pending.check()?;",
            "Ok(pending)",
        ],
    ) && capture.matches("begin_current_request").count() == 1
        && capture.matches("narrow_io_acquisition").count() == 1
        && ordered(
            &receive,
            &[
                "self.check()?;",
                "self.controller.borrow_current_request(&mut self.request)?;",
                "listener.accept(&mut stage,&mut self.original)?;",
                "connection.receive_submit(&mut stage,&mut self.original)?;",
                "submitted.observe_issuer(&mut stage,&mut self.original)?;",
                "observed.try_admit_request(&mut stage,&mut self.original)",
                "let checked=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||self.check_native()));",
                "if !matches!(&requested,Ok(Ok(_))) || !matches!(&checked,Ok(Ok(()))) {self.refuse();}",
                "settle(requested,checked)?;",
                "parent:self",
                "retained.check()?;",
                "Ok(retained)",
            ],
        )
        && receive.matches(&fragment("self.check()")).count() == 1
        && receive.matches(&fragment("self.check_native()")).count() == 1
        && receive.matches("borrow_current_request").count() == 1
        && ![
            "begin_current",
            "NativeAcquisition ::",
            "finish",
            "Known",
            "source",
            "upload",
        ]
        .iter()
        .any(|name| receive.contains(name))
}

#[test]
fn actual_outer_backup_action_retains_the_saved_request_before_accept_and_never_renews_it() {
    let source = include_str!("channel/scheduled_backup/outer_request.rs");
    assert!(retained_action_contract(source));
    for (from, to) in [
        (
            "request: EnrolledCurrentRequest,",
            "request: NativeOriginalRefusal,",
        ),
        (
            "let mut request = controller.begin_current_request()?;",
            "let mut request = controller.begin_current_stage()?;",
        ),
        (
            "stage.narrow_io_acquisition(5)?",
            "stage.narrow_io_acquisition(10)?",
        ),
        (
            "listener.accept(&mut stage, &mut self.original)?",
            "listener.accept(&mut stage, &mut NativeAcquisition::capture()?)?",
        ),
        (
            "observed.try_admit_request(&mut stage, &mut self.original)",
            "observed.copy_receipt_data()",
        ),
        (
            "let requester = settle(requested, checked)?;",
            "let requester = unguarded(requested)?;",
        ),
    ] {
        assert_eq!(source.matches(from).count(), 1, "mutation target {from}");
        assert!(
            !retained_action_contract(&source.replacen(from, to, 1)),
            "accepted {from}"
        );
    }
    let replaced = outer_mutate_method(
        source,
        "PendingScheduledBackupAction < 'controller >",
        "receive",
        "self.controller.borrow_current_request(&mut self.request)?",
        "self.controller.borrow_current_request(&mut self.controller.begin_current_request()?)?",
    );
    assert!(!retained_action_contract(&replaced));
    let post = outer_mutate_method(
        source,
        "PendingScheduledBackupAction < 'controller >",
        "receive",
        "|| !matches!(&checked, Ok(Ok(())))",
        "|| false",
    );
    assert!(!retained_action_contract(&post));
    let injected = source.replacen(
        "let connection = listener.accept",
        "self.request = self.controller.begin_current_request()?; let connection = listener.accept",
        1,
    );
    assert_ne!(injected, source);
    assert!(!retained_action_contract(&injected));
}

#[test]
fn actual_outer_backup_action_drop_refuses_real_shared_inputs_and_exposes_no_finish_or_getter() {
    let source = include_str!("channel/scheduled_backup/outer_request.rs");
    let pending = selected_method(
        source,
        "PendingScheduledBackupAction < 'controller >",
        "refuse",
    );
    assert!(pending.contains(&fragment(
        "self.refused=true; self.original.refuse(); self.request.refuse();"
    )));
    let retained = selected_method(source, "RetainedScheduledBackupAction < '_ >", "refuse");
    assert!(retained.contains(&fragment("self.requester.refuse(); self.parent.refuse();")));
    for owner in [
        "PendingScheduledBackupAction < '_ >",
        "RetainedScheduledBackupAction < '_ >",
    ] {
        let function = outer_selected_method(source, owner, "drop");
        assert_eq!(
            canonical(function.block.to_token_stream()).to_string(),
            fragment("{self.refuse();}")
        );
    }
    let post = outer_selected_method(
        source,
        "PendingScheduledBackupAction < 'controller >",
        "check_native",
    );
    assert_eq!(
        canonical(post.block.to_token_stream()).to_string(),
        fragment(
            "{let mut stage=self.controller.borrow_current_request(&mut self.request)?;stage.check_for(&self.scope,NativeRole::EpochController)?;stage.check_serving_acquisition(&mut self.original)}"
        )
    );
    let retained_check = canonical(
        outer_selected_method(source, "RetainedScheduledBackupAction < '_ >", "check")
            .block
            .to_token_stream(),
    )
    .to_string();
    assert!(retained_check.contains(&fragment("let checked=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||self.parent.check_native()));")));
    let file = syn::parse_file(source).unwrap();
    let mut public = Vec::new();
    for item in &file.items {
        if let syn::Item::Impl(item) = item {
            for item in &item.items {
                if let syn::ImplItem::Fn(method) = item
                    && !matches!(method.vis, syn::Visibility::Inherited)
                {
                    public.push(method.sig.ident.to_string());
                }
            }
        }
    }
    assert_eq!(public, ["receive", "check"]);
    let public_functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if !matches!(function.vis, syn::Visibility::Inherited) => {
                Some(function.sig.ident.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(public_functions, ["capture_scheduled_backup_action"]);
    assert!(!source.contains("unsafe"));
    assert!(!source.contains(".finish("));
}

#[test]
fn actual_outer_backup_primary_panic_cannot_skip_either_independent_native_post() {
    let source = include_str!("channel/scheduled_backup/outer_request.rs");
    for (owner, name, post, unit) in [
        (
            "PendingScheduledBackupAction < 'controller >",
            "receive",
            "self.check_native()",
            false,
        ),
        (
            "RetainedScheduledBackupAction < '_ >",
            "check",
            "self.parent.check_native()",
            true,
        ),
    ] {
        assert!(outer_post_contract(source, owner, name, post, unit));
        assert!(!outer_post_contract(
            &outer_bypass_primary_catch(source, owner, name),
            owner,
            name,
            post,
            unit
        ));
        let removed = outer_mutate_method(source, owner, name, post, "Ok(())");
        assert!(!outer_post_contract(&removed, owner, name, post, unit));
        let guard = outer_mutate_method(
            source,
            owner,
            name,
            "|| !matches!(&checked, Ok(Ok(())))",
            "|| false",
        );
        assert!(!outer_post_contract(&guard, owner, name, post, unit));
    }
    assert!(outer_retained_contract(source));
    let retained = outer_selected_method(source, "RetainedScheduledBackupAction < '_ >", "check");
    let body = outer_caught_expression(&retained.block.stmts[0], "requested").unwrap();
    assert_eq!(
        canonical(body.to_token_stream()).to_string(),
        fragment(
            "{self.parent.check()?;let mut stage=self.parent.controller.borrow_current_request(&mut self.parent.request)?;self.requester.check(&mut stage,&mut self.parent.original)}"
        )
    );
    assert_eq!(
        canonical(retained.block.stmts.last().unwrap().to_token_stream()).to_string(),
        fragment("settle(requested,checked)")
    );
    let removed = outer_mutate_method(
        source,
        "RetainedScheduledBackupAction < '_ >",
        "check",
        "self.requester.check(&mut stage,&mut self.parent.original)",
        "Ok(())",
    );
    assert!(!outer_retained_contract(&removed));
    let settlement = outer_mutate_method(
        source,
        "RetainedScheduledBackupAction < '_ >",
        "check",
        "settle(requested,checked)",
        "Ok(())",
    );
    assert!(!outer_retained_contract(&settlement));
    let actual = outer_selected_method(&removed, "RetainedScheduledBackupAction < '_ >", "check");
    assert_ne!(
        canonical(
            outer_caught_expression(&actual.block.stmts[0], "requested")
                .unwrap()
                .to_token_stream()
        )
        .to_string(),
        canonical(body.to_token_stream()).to_string()
    );
}

#[test]
fn actual_backup_listener_captures_the_saved_action_before_accept_and_forwards_same_resource() {
    let source = include_str!("channel/scheduled_backup.rs");
    let method = outer_selected_method(source, "ScheduledBackupSocketListener", "admit_action");
    let expected = fragment(
        "{let pending=outer_request::capture_scheduled_backup_action(controller)?;pending.receive(self)}",
    );
    assert_eq!(
        canonical(method.block.to_token_stream()).to_string(),
        expected
    );
    let changed = outer_mutate_method(
        source,
        "ScheduledBackupSocketListener",
        "admit_action",
        "pending.receive(self)",
        "pending.receive(foreign)",
    );
    assert_ne!(
        canonical(
            outer_selected_method(&changed, "ScheduledBackupSocketListener", "admit_action")
                .block
                .to_token_stream()
        )
        .to_string(),
        expected
    );
}
