//! Correlation DATA and actual-source controls, not native owner constructors.
use super::*;

#[test]
fn foreign_locator_and_busy_input_preserve_the_actual_pending_slot() -> Result<()> {
    let mut slot = Slot::new();
    let grant = Digest::new(b"actual grant DATA");
    let id = Digest::new(b"actual command DATA");
    slot.claim(&grant)?;
    slot.insert(id.clone(), 73u8)?;
    assert!(slot.take(&Digest::new(b"foreign locator")).is_err());
    assert_eq!(*slot.selected(&id)?, 73);
    assert!(slot.claim(&Digest::new(b"other grant")).is_err());
    assert_eq!(slot.seen.len(), 1);
    assert_eq!(slot.take(&id)?, 73);
    assert!(slot.claim(&grant).is_err());
    assert!(slot.selected(&id).is_err());
    Ok(())
}

#[test]
fn discard_and_process_local_capacity_cannot_regrant_an_old_attempt() -> Result<()> {
    let mut slot = Slot::new();
    for index in 0..MAX_ATTEMPTS {
        let id = Digest::of(&("command DATA", index))?;
        slot.claim(&id)?;
        slot.insert(id.clone(), index)?;
        assert_eq!(slot.take(&id)?, index);
        assert!(slot.claim(&id).is_err());
    }
    assert!(slot.claim(&Digest::new(b"beyond finite capacity")).is_err());
    assert_eq!(slot.seen.len(), MAX_ATTEMPTS);
    assert!(slot.current.is_none());
    Ok(())
}

#[test]
fn restart_loses_pending_data_and_never_reconstructs_an_owner_from_a_locator() -> Result<()> {
    let grant = Digest::new(b"grant DATA");
    let id = Digest::new(b"command DATA");
    let mut old = Slot::new();
    old.claim(&grant)?;
    old.insert(id.clone(), 41u8)?;
    drop(old);
    let mut restarted: Slot<u8> = Slot::new();
    assert!(restarted.take(&id).is_err());
    // This cache is deliberately process-local DATA, not the durable grant
    // authority. Claiming DATA again supplies no pending value or permission;
    // the genuine producer/journal must still admit every real new attempt.
    restarted.claim(&grant)?;
    assert!(restarted.selected(&id).is_err());
    Ok(())
}

fn input_data() -> Result<(EpochStore, Input)> {
    let (selected, record) = crate::security_epoch::restore_approval::fixture_publication_data()?;
    let approval = record.statement.request.intent();
    let restore = Intent {
        operation: Digest::new(b"independent operation DATA"),
        archive: crate::security_epoch::kernel::restore::Backup {
            scope: selected.scope.clone(),
            authority: selected.authority_key()?,
            source_incarnation: Digest::new(b"source DATA"),
            security_epoch: 1,
            full_archive_digest: approval.full_archive_digest.clone(),
            image: Digest::new(b"image DATA"),
            schema: approval.target.schema.clone(),
            artifact: approval.target.artifact.clone(),
            key_set: selected.key_set.clone(),
            required_keys: vec![crate::security_epoch::kernel::restore::ExactKey {
                binding: approval.custody.clone(),
                version: "1".into(),
                purpose: crate::security_epoch::kernel::restore::KeyPurpose::CustodyEncryption,
            }],
        },
        target_incarnation: approval.target.incarnation.clone(),
    };
    Ok((
        selected,
        Input {
            format: Format::V1,
            approval,
            restore,
            archive_directory: "/selected/archive".into(),
            // The user explicitly permits the same admin to approve and execute.
            approver: record.statement.request.executor.email,
            approver_credential: vec![1, 2, 3],
            executor_credential: vec![1, 2, 3],
        },
    ))
}

#[test]
fn complete_input_joins_both_distinct_intents_to_the_current_selection() -> Result<()> {
    let (selected, input) = input_data()?;
    input.require_selected(&selected)?;
    for field in [
        "full_archive_digest",
        "incarnation",
        "security_epoch",
        "artifact",
        "schema",
        "selection",
        "authority",
    ] {
        let mut changed = input.clone();
        match field {
            "full_archive_digest" => changed.approval.full_archive_digest = Digest::new(b"other"),
            "incarnation" => changed.approval.target.incarnation = Digest::new(b"other"),
            "security_epoch" => changed.approval.target.security_epoch += 1,
            "artifact" => changed.approval.target.artifact = Digest::new(b"other"),
            "schema" => changed.approval.target.schema = Digest::new(b"other"),
            "selection" => changed.approval.target.selection = Digest::new(b"other"),
            "authority" => changed.approval.target.authority = Digest::new(b"other"),
            _ => unreachable!(),
        }
        assert!(changed.require_selected(&selected).is_err(), "{field}");
    }
    let mut changed = input.clone();
    changed.restore.archive.required_keys.clear();
    assert!(changed.require_selected(&selected).is_err());
    let mut changed = input;
    changed.restore.target_incarnation = changed.restore.archive.source_incarnation.clone();
    assert!(changed.require_selected(&selected).is_err());
    Ok(())
}

#[test]
fn strict_input_is_complete_data_not_a_boolean_or_signed_record_authorizer() -> Result<()> {
    let (_, input) = input_data()?;
    let value = serde_json::to_value(&input)?;
    Input::decode(&serde_json::to_vec(&value)?)?;
    for field in [
        "approved",
        "verified",
        "signed_approval",
        "native_owner",
        "current",
        "resume",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!(true);
        assert!(
            Input::decode(&serde_json::to_vec(&changed)?).is_err(),
            "{field}"
        );
    }
    let mut changed = value.clone();
    changed["approver_credential"] = serde_json::json!(vec![1u8; MAX_CREDENTIAL_ID_BYTES + 1]);
    assert!(Input::decode(&serde_json::to_vec(&changed)?).is_err());
    for path in ["relative/archive", "/", "/selected/../archive"] {
        let mut changed = value.clone();
        changed["archive_directory"] = serde_json::json!(path);
        assert!(Input::decode(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut missing = value;
    missing
        .as_object_mut()
        .unwrap()
        .remove("executor_credential");
    assert!(Input::decode(&serde_json::to_vec(&missing)?).is_err());
    Ok(())
}

#[test]
fn input_envelope_and_version_have_only_the_reviewed_object_and_string_shapes() -> Result<()> {
    let (_, input) = input_data()?;
    let value = serde_json::to_value(&input)?;
    Input::decode(&serde_json::to_vec(&value)?)?;
    let positional = serde_json::json!([
        value["format"],
        value["approval"],
        value["restore"],
        value["archive_directory"],
        value["approver"],
        value["approver_credential"],
        value["executor_credential"],
    ]);
    assert!(Input::decode(&serde_json::to_vec(&positional)?).is_err());
    let mut alternate_version = value;
    alternate_version["format"] = serde_json::json!({ "day2_protected_restore_v1": null });
    assert!(Input::decode(&serde_json::to_vec(&alternate_version)?).is_err());
    Ok(())
}

#[test]
fn actual_executor_entry_uses_the_real_pre_reader_original_then_the_captured_archive() {
    use quote::ToTokens;
    let file = syn::parse_file(include_str!("../protected_operator.rs")).unwrap();
    let actual = file.items.iter().find_map(|item| {
        let syn::Item::Impl(item) = item else { return None; };
        if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("ProtectedRestoreCommands")) { return None; }
        item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "authenticate_archive" => Some(item),
            _ => None,
        })
    }).unwrap();
    // Pin the actual straight-line ownership join, including propagated
    // errors and exact arguments. A call counter would also admit discarded
    // results, conditional authentication, or a substituted reader/intent.
    // Parse both sides with the same runtime lexer. parse_quote! embeds rustc's
    // incidental macro-token spacing; ignoring jointness would weaken the
    // oracle. This keeps the complete AST and punctuation jointness intact.
    let expected: syn::Block = syn::parse_str(
        r#"{
        ensure!(
            matches!(&self.slot.selected(id)?.pending, Pending::Execution { .. }),
            "protected_restore_step_changed"
        );
        let Command {
            input,
            pending: Pending::Execution { pending, record },
        } = self.slot.take(id)?
        else {
            unreachable!("checked actual pending variant")
        };
        let assertion = Assertion::decode(bytes)?;
        input.require_selected(&active.store)?;
        let reader = active
            .begin_restore_execution_reader(
                metadata,
                stage,
                &record,
                &input.restore.operation,
                trace,
            )?
            .context("protected_restore_current_admin_required")?;
        let executor = (*pending)
            .authenticate(reader, &assertion)?
            .context("protected_restore_executor_refused")?;
        PreparedNativeRestoreArchive::capture(executor, &input.archive_directory, &input.restore)
    }"#,
    )
    .unwrap();
    let exact = |left: &syn::Block, right: &syn::Block| {
        left.to_token_stream().to_string() == right.to_token_stream().to_string()
    };
    let joined: syn::Block = syn::parse_str(r#"{ ensure!(true&&true, "profile"); }"#).unwrap();
    let split: syn::Block = syn::parse_str(r#"{ ensure!(true & &true, "profile"); }"#).unwrap();
    assert!(
        !exact(&joined, &split),
        "compound punctuation must stay distinct"
    );
    let guarded = |body: &syn::Block| exact(body, &expected);
    assert!(guarded(&actual.block));
    for index in 0..actual.block.stmts.len() {
        let mut bypass = actual.block.clone();
        bypass.stmts.remove(index);
        assert!(!guarded(&bypass), "removed statement {index}");
    }
    for (index, replacement) in [
        (
            1,
            syn::parse_quote!(let Command { input, pending: Pending::Execution { pending, record } } = self.slot.take(&foreign)? else { unreachable!("checked actual pending variant") };),
        ),
        (
            2,
            syn::parse_quote!(let assertion = Assertion::decode(other)?;),
        ),
        (
            4,
            syn::parse_quote!(let reader = active.begin_accepting_admin_reader(metadata, stage, &record, &input.restore.operation, trace)?.context("protected_restore_current_admin_required")?;),
        ),
        (
            5,
            syn::parse_quote!(let executor = (*pending).authenticate(other, &assertion)?.context("protected_restore_executor_refused")?;),
        ),
        (
            6,
            syn::Stmt::Expr(
                syn::parse_quote!(PreparedNativeRestoreArchive::capture(
                    executor,
                    &input.archive_directory,
                    &foreign
                )),
                None,
            ),
        ),
    ] {
        let mut mutant = actual.block.clone();
        mutant.stmts[index] = replacement;
        assert!(!guarded(&mutant), "replaced statement {index}");
    }
}

#[test]
fn browser_projection_uses_the_complete_selected_input_without_reconstructing_authority()
-> Result<()> {
    let (selected, input) = input_data()?;
    let raw = serde_json::to_vec(&input)?;
    let data = protected_restore_command_data(&raw, &selected)?;
    assert_eq!(data.id, input.id()?);
    assert_eq!(data.intent, input.approval);
    assert_eq!(data.operation, input.restore.operation);
    assert_ne!(data.operation, input.restore.commitment(&selected)?);
    assert_eq!(data.approver_email, input.approver);
    assert_eq!(data.approver_credential, input.approver_credential);
    assert_eq!(data.executor_credential, input.executor_credential);
    let mut foreign = selected.clone();
    foreign.scope.app =
        day2_capabilities::Name::try_from(format!("{}-foreign", foreign.scope.app.as_str()))?;
    assert!(protected_restore_command_data(&raw, &foreign).is_err());
    let mut changed = input;
    changed.approval.target.security_epoch += 1;
    assert!(protected_restore_command_data(&serde_json::to_vec(&changed)?, &selected).is_err());
    assert!(protected_restore_command_data(b"{\"approved\":true}", &selected).is_err());
    Ok(())
}

#[test]
fn nested_operator_intent_and_identity_sequence_aliases_do_not_normalize() -> Result<()> {
    let (_, input) = input_data()?;
    let value = serde_json::to_value(&input)?;
    for path in ["/approval", "/approval/executor"] {
        let mut changed = value.clone();
        let current = changed.pointer(path).unwrap();
        let alias = if path == "/approval" {
            serde_json::json!([
                current["grant_id"],
                current["full_archive_digest"],
                current["target"],
                current["executor"],
                current["custody"]
            ])
        } else {
            serde_json::json!([current["email"], current["subject"]])
        };
        *changed.pointer_mut(path).unwrap() = alias;
        // Prove the nested derive would accept/normalize this representation.
        let normalized: Input = serde_json::from_value(changed.clone())?;
        assert_ne!(serde_json::to_value(normalized)?, changed);
        assert!(
            Input::decode(&serde_json::to_vec(&changed)?).is_err(),
            "{path}"
        );
    }
    Input::decode(&serde_json::to_vec(&value)?)?;
    Ok(())
}
