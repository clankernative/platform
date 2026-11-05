//! Portable model/file controls. They supply no real native stage, current
//! approval, maintenance owner or accepting source from test scalar values.
use super::*;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

fn configuration() -> Instance {
    let public = day2_capabilities::restore_passkeys::PublicCoseKey::try_from(
        [
            vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20],
            vec![1; 32],
            vec![0x22, 0x58, 0x20],
            vec![2; 32],
        ]
        .concat(),
    )
    .unwrap();
    Instance::from_bytes(&serde_json::to_vec(&serde_json::json!({
        "installation":"company","environment":"canary",
        "identity":{"scheme":"google_iap","hosted_domain":"example.test"},
        "security_shell":{"origin":"https://restore.example.test","iap_audience":"/projects/1/global/backendServices/2"},
        "control":{"version":1,"state_directory":"/control","operators":["operator@example.test"],
            "sources":{"repo":{"kind":"local_git","repository":"/repo"}},"apps":{"app":{"source":"repo"}},
            "restore_passkeys":{"version":1,"keys":{"primary":{
                "email":"álîce@example.test","subject":"opaque-主体","credential_id":[1,2,3],"user_handle":[4,5],
                "cose_key":public,"backup_eligible":true,"rp_id":"restore.example.test","origin":"https://restore.example.test"
            }}}},
        "apps":{"app":{"artifact":"/artifact","readers":[],"writers":[],"edge":{"origin":"https://app.example.test","iap_audience":"/projects/1/global/backendServices/3"}}}
    })).unwrap()).unwrap()
}
fn admins() -> Admins {
    Admins {
        enabled: true,
        artifact: "artifact".into(),
        stamp: crate::authority_state::AuthorityStamp {
            epoch: Digest::new(b"active epoch").as_str().into(),
            revision: 7,
        },
        members: BTreeSet::from(["álîce@example.test".into()]),
    }
}
fn select(instance: &Instance, current: &Admins, file: Digest) -> Result<KeyRecord> {
    record(
        instance,
        "company/canary/app",
        "app",
        "artifact",
        file,
        current,
        &[1, 2, 3],
    )
}
fn config_path(root: &Path) -> PathBuf {
    let directory = root.join("config");
    fs::create_dir(&directory).unwrap();
    directory.join("instance.json")
}

#[test]
fn actual_current_admin_and_complete_selection_are_required_not_desired_policy_or_cached_record() {
    let instance = configuration();
    let current = admins();
    let file = Digest::new(b"actual held file DATA");
    let baseline = select(&instance, &current, file.clone()).unwrap();
    assert_eq!(baseline.user_handle, [4, 5]);
    assert!(baseline.backup_eligible);
    let mut changed = admins();
    changed.members.clear();
    assert!(select(&instance, &changed, file.clone()).is_err());
    changed = admins();
    changed.enabled = false;
    assert!(select(&instance, &changed, file.clone()).is_err());
    changed = admins();
    changed.artifact = "foreign".into();
    assert!(select(&instance, &changed, file.clone()).is_err());
    let mut missing = instance.clone();
    missing.control.as_mut().unwrap().restore_passkeys = None;
    assert!(select(&missing, &current, file.clone()).is_err());
    let mut removed = instance.clone();
    removed
        .control
        .as_mut()
        .unwrap()
        .restore_passkeys
        .as_mut()
        .unwrap()
        .keys
        .clear();
    assert!(select(&removed, &current, file.clone()).is_err());
    assert!(
        record(
            &instance,
            "foreign/canary/app",
            "app",
            "artifact",
            file.clone(),
            &current,
            &[1, 2, 3]
        )
        .is_err()
    );
    assert!(
        record(
            &instance,
            "company/canary/app",
            "app",
            "artifact",
            file.clone(),
            &current,
            &[9]
        )
        .is_err()
    );
    let mut wrong_origin = instance.clone();
    wrong_origin
        .control
        .as_mut()
        .unwrap()
        .restore_passkeys
        .as_mut()
        .unwrap()
        .keys
        .values_mut()
        .next()
        .unwrap()
        .origin = "https://other.example.test".into();
    assert!(select(&wrong_origin, &current, file.clone()).is_err());
    changed = admins();
    changed.stamp.revision += 1;
    assert_ne!(
        select(&instance, &changed, file.clone())
            .unwrap()
            .binding_data()
            .unwrap(),
        baseline.binding_data().unwrap()
    );
    assert_ne!(
        select(&instance, &current, Digest::new(b"different actual file"))
            .unwrap()
            .binding_data()
            .unwrap(),
        baseline.binding_data().unwrap()
    );
    for field in 0..3 {
        let mut changed = instance.clone();
        let key = changed
            .control
            .as_mut()
            .unwrap()
            .restore_passkeys
            .as_mut()
            .unwrap()
            .keys
            .values_mut()
            .next()
            .unwrap();
        match field {
            0 => key.subject = "different subject".into(),
            1 => key.user_handle.push(6),
            _ => key.backup_eligible = false,
        }
        assert_ne!(
            select(&changed, &current, file.clone())
                .unwrap()
                .binding_data()
                .unwrap(),
            baseline.binding_data().unwrap()
        );
    }
}

#[test]
fn real_held_file_reads_refuse_same_content_replacement_removal_and_in_place_change() -> Result<()>
{
    for kind in ["replace", "remove", "write", "permissions", "link"] {
        let root = tempfile::tempdir()?;
        let path = config_path(&root.path().canonicalize()?);
        let original = serde_json::to_vec(&configuration())?;
        fs::write(&path, &original)?;
        let held = file::Held::open(&path)?;
        assert_eq!(held.read()?, original);
        match kind {
            "replace" => {
                let replacement = root.path().join("new.json");
                fs::write(&replacement, &original)?;
                fs::rename(replacement, &path)?;
            }
            "remove" => {
                fs::remove_file(&path)?;
                fs::write(&path, &original)?;
            }
            "write" => {
                let mut changed = original.clone();
                changed[0] = b' ';
                fs::write(&path, changed)?;
                fs::write(&path, &original)?;
            }
            "permissions" => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o620))?;
            }
            _ => {
                fs::hard_link(&path, root.path().join("alias.json"))?;
            }
        }
        assert!(held.check_local().is_err());
        assert!(held.read().is_err());
    }
    Ok(())
}

#[test]
fn real_file_open_rejects_symlink_ancestors_hardlinks_nonregular_and_oversized_inputs() -> Result<()>
{
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let path = config_path(&root);
    fs::write(&path, b"{}")?;
    symlink(&path, root.join("symlink"))?;
    assert!(file::Held::open(&root.join("symlink")).is_err());
    symlink(path.parent().unwrap(), root.join("alias"))?;
    assert!(file::Held::open(&root.join("alias/instance.json")).is_err());
    assert!(file::Held::open(path.parent().unwrap()).is_err());
    fs::hard_link(&path, root.join("hardlink"))?;
    assert!(file::Held::open(&path).is_err());
    fs::remove_file(root.join("hardlink"))?;
    fs::File::create(&path)?.set_len(1_048_577)?;
    assert!(file::Held::open(&path).is_err());
    assert!(file::Held::open(Path::new("relative.json")).is_err());
    Ok(())
}

#[test]
fn ceremony_data_is_once_only_and_refusal_cannot_be_repaired_or_rebuilt_from_record() -> Result<()>
{
    for refused in [false, true] {
        let root = tempfile::tempdir()?;
        let path = config_path(&root.path().canonicalize()?);
        let instance = configuration();
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let held = file::Held::open(&path)?;
        let record = select(&instance, &admins(), held.binding()?)?;
        let ceremony = RegistryCeremony {
            held,
            record,
            request: Digest::new(b"complete request"),
            nonce: [9; 32],
            attempted: Cell::new(false),
            refused: Cell::new(false),
            local: PhantomData,
        };
        let encoded = ceremony.encoded_challenge()?;
        assert!(!encoded.is_empty());
        if refused {
            ceremony.refused.set(true);
            assert!(ceremony.begin_attempt().is_err());
        } else {
            ceremony.begin_attempt()?;
            assert!(ceremony.begin_attempt().is_err());
        }
        assert!(ceremony.encoded_challenge().is_err());
        // No record/config/digest constructor exists; a fresh capture requires
        // a genuine new owner and real entropy, never the stored nonce above.
    }
    Ok(())
}

fn method<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ImplItemFn> {
    let methods=file.items.iter().filter_map(|item| match item {
        syn::Item::Impl(block) if matches!(&*block.self_ty,syn::Type::Path(path) if path.path.is_ident("RegistryCeremony"))=>Some(block), _=>None,
    }).flat_map(|block|&block.items).filter_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method),_=>None}).collect::<Vec<_>>();
    ensure!(methods.len() == 1, "actual registry method selector");
    Ok(methods[0])
}
fn method_mut<'a>(file: &'a mut syn::File, name: &str) -> Result<&'a mut syn::ImplItemFn> {
    let methods=file.items.iter_mut().filter_map(|item| match item {
        syn::Item::Impl(block) if matches!(&*block.self_ty,syn::Type::Path(path) if path.path.is_ident("RegistryCeremony"))=>Some(block), _=>None,
    }).flat_map(|block|&mut block.items).filter_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method),_=>None}).collect::<Vec<_>>();
    ensure!(methods.len() == 1, "actual registry method selector");
    Ok(methods.into_iter().next().unwrap())
}
fn calls(block: &syn::Block) -> Vec<String> {
    use syn::visit::Visit;
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.0.push(node.method.to_string());
            syn::visit::visit_expr_method_call(self, node);
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*node.func {
                self.0
                    .push(p.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut collector = Calls(Vec::new());
    collector.visit_block(block);
    collector.0
}
fn validate_current_wiring(file: &syn::File) -> Result<()> {
    let capture = calls(&method(file, "capture")?.block);
    ensure!(
        capture.first().map(String::as_str) == Some("require_native_registry_read"),
        "native owner before capture work"
    );
    ensure!(
        capture
            .iter()
            .position(|x| x == "require_native_registry_read")
            < capture.iter().position(|x| x == "open"),
        "native owner before path I/O"
    );
    let verify = calls(&method(file, "verify_current")?.block);
    ensure!(
        verify.first().map(String::as_str) == Some("begin_attempt"),
        "one attempt before verification work"
    );
    let positions = verify
        .iter()
        .enumerate()
        .filter(|(_, x)| x.as_str() == "observe")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    ensure!(positions.len() == 2, "both fresh current observations");
    let signatures = verify
        .iter()
        .enumerate()
        .filter(|(_, x)| x.as_str() == "verify")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    ensure!(
        signatures.len() == 1 && positions[0] < signatures[0] && signatures[0] < positions[1],
        "actual signature bracketed by current observations"
    );
    let mut actual = method(file, "verify_current")?.clone();
    let actual = body(&mut actual)?;
    ensure!(actual.stmts.len() >= 4, "verification result tail");
    let requested=actual.stmts.iter().filter_map(|statement|match statement {
        syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="requested")=>Some(local),_=>None,
    }).collect::<Vec<_>>();
    ensure!(
        requested.len() == 1,
        "actual requested signature result selector"
    );
    let syn::Expr::Block(signature) = &*requested[0].init.as_ref().unwrap().expr else {
        anyhow::bail!("scoped key signature block")
    };
    ensure!(
        matches!(signature.block.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Call(call),None)) if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.len()==2 && path.path.segments[0].ident=="super" && path.path.segments[1].ident=="verify") && call.args.len()==5),
        "actual signature result must remain the requested result"
    );
    let tail = &actual.stmts[actual.stmts.len() - 4..];
    ensure!(
        matches!(&tail[0],syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="checked") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::MethodCall(call) if call.method=="observe"))),
        "postcheck evaluated before selecting primary error"
    );
    ensure!(
        matches!(&tail[1],syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="value") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::Try(expr) if matches!(&*expr.expr,syn::Expr::Path(path) if path.path.is_ident("requested"))))),
        "requested error stays primary"
    );
    ensure!(
        matches!(&tail[2],syn::Stmt::Expr(syn::Expr::Try(expr),Some(_)) if matches!(&*expr.expr,syn::Expr::Path(path) if path.path.is_ident("checked"))),
        "postcheck result enforced before facts return"
    );
    Ok(())
}
fn body(method: &mut syn::ImplItemFn) -> Result<&mut syn::Block> {
    let syn::Stmt::Local(local) = &mut method.block.stmts[0] else {
        anyhow::bail!("result local selector")
    };
    let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
        anyhow::bail!("actual result closure call")
    };
    let syn::Expr::Paren(paren) = &mut *call.func else {
        anyhow::bail!("actual closure parentheses")
    };
    let syn::Expr::Closure(closure) = &mut *paren.expr else {
        anyhow::bail!("actual result closure")
    };
    let syn::Expr::Block(block) = &mut *closure.body else {
        anyhow::bail!("actual result closure body")
    };
    Ok(&mut block.block)
}
#[test]
fn production_capture_and_verification_cannot_lose_native_origin_or_final_current_observation()
-> Result<()> {
    let source = syn::parse_file(include_str!("../registry.rs"))?;
    validate_current_wiring(&source)?;
    for mode in 0..5 {
        let mut changed = source.clone();
        if mode == 0 {
            let block = body(method_mut(&mut changed, "capture")?)?;
            ensure!(
                calls(&syn::Block {
                    brace_token: block.brace_token,
                    stmts: vec![block.stmts[0].clone()]
                }) == ["require_native_registry_read"],
                "actual first native guard selector"
            );
            block.stmts.remove(0);
        } else {
            let block = body(method_mut(&mut changed, "verify_current")?)?;
            if mode == 1 {
                block.stmts.remove(0);
            } else if mode == 3 {
                let length = block.stmts.len();
                block.stmts.swap(length - 4, length - 3);
            } else if mode == 4 {
                let local=block.stmts.iter_mut().find_map(|statement|match statement {
                    syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="requested")=>Some(local),_=>None,
                }).unwrap();
                let syn::Expr::Block(signature) = &mut *local.init.as_mut().unwrap().expr else {
                    unreachable!()
                };
                let syn::Stmt::Expr(_, semicolon) = signature.block.stmts.last_mut().unwrap()
                else {
                    unreachable!()
                };
                *semicolon = Some(syn::token::Semi::default());
                let forged: syn::Expr = syn::parse_quote!(Ok(forged_facts));
                signature.block.stmts.push(syn::Stmt::Expr(forged, None));
            } else {
                let targets=block.stmts.iter_mut().filter_map(|statement|match statement {
                    syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="checked")=>Some(local),_=>None,
                }).collect::<Vec<_>>();
                ensure!(targets.len() == 1, "actual checked local selector");
                targets
                    .into_iter()
                    .next()
                    .unwrap()
                    .init
                    .as_mut()
                    .unwrap()
                    .expr = Box::new(syn::parse_quote!(Ok(())));
            }
        }
        assert!(validate_current_wiring(&changed).is_err());
    }
    Ok(())
}

#[test]
fn actual_native_sql_origin_cannot_drop_runtime_identity_native_kind_phase_or_current_check()
-> Result<()> {
    let mut source = syn::parse_file(include_str!("../../../oauth/native_management.rs"))?;
    let selected=source.items.iter_mut().filter_map(|item|match item {
        syn::Item::Impl(block) if matches!(&*block.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment|segment.ident=="SqlOwner"))=>Some(block),_=>None,
    }).flat_map(|block|&mut block.items).filter_map(|item|match item {
        syn::ImplItem::Fn(method) if method.sig.ident=="require_native_registry_read"=>Some(method),_=>None,
    }).collect::<Vec<_>>();
    ensure!(selected.len() == 1, "actual SQL origin method selector");
    let block = &selected[0].block;
    fn path(expr: &syn::Expr, name: &str) -> bool {
        matches!(expr,syn::Expr::Path(path) if path.path.is_ident(name))
    }
    fn call(expr: &syn::Expr, name: &str, arguments: &[&str]) -> bool {
        matches!(expr,syn::Expr::MethodCall(call) if call.method==name && path(&call.receiver,"owner") && call.args.len()==arguments.len() && call.args.iter().zip(arguments).all(|(expr,name)|path(expr,name)))
    }
    let expected: syn::Stmt = syn::parse_quote!(ensure!(matches!(&owner.source,RuntimeSource::Native{..}) && matches!(owner.phase,Some(RuntimePhase::SqlRead|RuntimePhase::SqlWrite)),"restore_registry_native_runtime_required"););
    let syn::Stmt::Macro(expected) = expected else {
        anyhow::bail!("actual ensure statement fixture")
    };
    let validate = |actual: &syn::Block| -> Result<()> {
        ensure!(actual.stmts.len() == 4, "all actual origin decisions");
        let syn::Stmt::Local(local) = &actual.stmts[0] else {
            anyhow::bail!("native owner source selector")
        };
        let syn::Pat::TupleStruct(pattern) = &local.pat else {
            anyhow::bail!("native owner source pattern")
        };
        ensure!(
            pattern.path.segments.len() == 2
                && pattern.path.segments[0].ident == "SqlOwnerSource"
                && pattern.path.segments[1].ident == "Runtime"
                && pattern.elems.len() == 1
                && matches!(&pattern.elems[0],syn::Pat::Ident(id) if id.ident=="owner"),
            "actual runtime owner retained"
        );
        let init = local
            .init
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native owner source missing"))?;
        ensure!(
            matches!(&*init.expr,syn::Expr::Reference(reference) if reference.mutability.is_some() && matches!(&*reference.expr,syn::Expr::Field(field) if path(&field.base,"self") && matches!(&field.member,syn::Member::Named(member) if member=="source"))),
            "actual owning source borrowed"
        );
        let (_, otherwise) = init
            .diverge
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("other sources must refuse"))?;
        let syn::Expr::Block(otherwise) = &**otherwise else {
            anyhow::bail!("closed refusal block")
        };
        ensure!(
            otherwise.block.stmts.len() == 1
                && matches!(&otherwise.block.stmts[0],syn::Stmt::Expr(syn::Expr::Macro(expr),None) if expr.mac.path.segments.len()==2 && expr.mac.path.segments[0].ident=="anyhow" && expr.mac.path.segments[1].ident=="bail" && expr.mac.tokens.to_string()=="\"restore_registry_native_runtime_required\""),
            "other owner source refuses"
        );
        ensure!(
            matches!(&actual.stmts[1],syn::Stmt::Expr(syn::Expr::Try(expr),Some(_)) if call(&expr.expr,"require_runtime",&["runtime"])),
            "exact runtime checked before admission"
        );
        ensure!(
            matches!(&actual.stmts[2],syn::Stmt::Macro(statement) if statement.mac.path.is_ident("ensure") && statement.mac.tokens.to_string()==expected.mac.tokens.to_string()),
            "native source and SQL phase required"
        );
        ensure!(
            matches!(&actual.stmts[3],syn::Stmt::Expr(expr,None) if call(expr,"check",&[])),
            "actual current owner checked last"
        );
        Ok(())
    };
    validate(block)?;
    ensure!(block.stmts.len() == 4, "all actual origin decisions");
    for index in 0..4 {
        let mut changed = block.clone();
        changed.stmts.remove(index);
        assert!(validate(&changed).is_err());
    }
    for rewritten in [
        "ensure!(true,\"restore_registry_native_runtime_required\");",
        "ensure!(matches!(owner.phase,Some(RuntimePhase::SqlRead|RuntimePhase::SqlWrite)),\"restore_registry_native_runtime_required\");",
        "ensure!(matches!(&owner.source,RuntimeSource::Native{..}),\"restore_registry_native_runtime_required\");",
    ] {
        let mut changed = block.clone();
        changed.stmts[2] = syn::parse_str(rewritten)?;
        assert!(validate(&changed).is_err());
    }
    Ok(())
}

#[test]
fn retained_config_path_cannot_be_substituted_by_identical_configuration() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let first = config_path(&root);
    let bytes = serde_json::to_vec(&configuration())?;
    fs::write(&first, &bytes)?;
    let second = root.join("different-instance.json");
    fs::write(&second, &bytes)?;
    let held = file::Held::open(&first)?;
    held.require_path(&first)?;
    assert!(held.require_path(&second).is_err());
    assert_eq!(held.read()?, bytes); // A handle check is DATA, not an owner grant.
    Ok(())
}
#[test]
fn current_selection_checks_actual_runtime_path_before_reading_retained_bytes() -> Result<()> {
    fn validate(block: &syn::Block) -> Result<()> {
        fn path(expr: &syn::Expr, name: &str) -> bool {
            matches!(expr,syn::Expr::Path(path) if path.path.is_ident(name))
        }
        let [first, second, third, ..] = block.stmts.as_slice() else {
            anyhow::bail!("selected prefix")
        };
        ensure!(
            matches!(first,syn::Stmt::Expr(syn::Expr::Try(expr),Some(_)) if matches!(&*expr.expr,syn::Expr::MethodCall(call) if path(&call.receiver,"sql") && call.method=="require_native_registry_read" && call.args.len()==1 && path(&call.args[0],"runtime"))),
            "native owner before config selection"
        );
        ensure!(
            matches!(second,syn::Stmt::Expr(syn::Expr::Try(expr),Some(_)) if matches!(&*expr.expr,syn::Expr::MethodCall(call) if path(&call.receiver,"held") && call.method=="require_path" && call.args.len()==1 && matches!(&call.args[0],syn::Expr::Try(selected) if matches!(&*selected.expr,syn::Expr::MethodCall(inner) if path(&inner.receiver,"runtime") && inner.method=="restore_registry_path" && inner.args.is_empty())))),
            "actual runtime instance path before retained read"
        );
        ensure!(
            matches!(third,syn::Stmt::Local(local) if local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::Try(expr) if matches!(&*expr.expr,syn::Expr::MethodCall(call) if path(&call.receiver,"held") && call.method=="read" && call.args.is_empty())))),
            "actual retained read follows both guards"
        );
        Ok(())
    }
    let source = syn::parse_file(include_str!("../registry.rs"))?;
    let selected = source
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "selected" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(selected.len() == 1, "actual current selector");
    let block = &selected[0].block;
    validate(block)?;
    for index in 0..3 {
        let mut changed = block.clone();
        if index == 0 {
            changed.stmts.remove(1);
        } else if index == 1 {
            changed.stmts.swap(1, 2);
        } else {
            changed.stmts[1] =
                syn::parse_quote!(held.require_path(other.restore_registry_path()?)?;);
        }
        assert!(validate(&changed).is_err());
    }
    Ok(())
}

#[test]
fn published_selector_symlink_must_not_be_replaced_by_its_startup_canonical_target() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let old_directory = root.join("versions/old");
    let new_directory = root.join("versions/new");
    fs::create_dir_all(&old_directory)?;
    fs::create_dir_all(&new_directory)?;
    let old = old_directory.join("instance.json");
    let new = new_directory.join("instance.json");
    let published = root.join("published");
    let selector = published.join("instance.json");
    fs::write(&old, serde_json::to_vec(&configuration())?)?;
    let mut removed = configuration();
    removed.control.as_mut().unwrap().restore_passkeys = None;
    fs::write(&new, serde_json::to_vec(&removed)?)?;
    symlink(&old_directory, &published)?;
    assert!(fs::symlink_metadata(&selector)?.is_file());
    let startup_resolved = selector.canonicalize()?;
    assert!(file::Held::open(&selector).is_err());
    // Concrete negative control: resolving first admits the stale target. The
    // actual source must retain the published selector and reject this layout.
    let stale = file::Held::open(&startup_resolved)?;
    fs::remove_file(&published)?;
    symlink(&new_directory, &published)?;
    assert!(fs::symlink_metadata(&selector)?.is_file());
    assert!(file::Held::open(&selector).is_err());
    let unchanged_old = file::Held::open(&startup_resolved)?;
    assert!(
        Instance::from_bytes(&unchanged_old.read()?)?
            .control
            .unwrap()
            .restore_passkeys
            .is_some()
    );
    stale.check_local()?; // Old version directory and handles still look valid.
    Ok(())
}
#[test]
fn native_input_retains_published_selector_before_canonicalization_and_actual_runtime_carries_it()
-> Result<()> {
    fn select(file: &syn::File) -> Result<&syn::ImplItemFn> {
        let methods=file.items.iter().filter_map(|item|match item {
            syn::Item::Impl(block) if matches!(&*block.self_ty,syn::Type::Path(path) if path.path.is_ident("InitialStoreMetadata"))=>Some(block),_=>None,
        }).flat_map(|block|&block.items).filter_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident=="load"=>Some(method),_=>None}).collect::<Vec<_>>();
        ensure!(methods.len() == 1, "actual native input load selector");
        Ok(methods[0])
    }
    fn retains_first(block: &syn::Block) -> Result<()> {
        ensure!(
            matches!(block.stmts.first(),Some(syn::Stmt::Local(local)) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="instance_selector") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::MethodCall(call) if call.method=="to_path_buf" && call.args.is_empty() && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("instance_path"))))),
            "original published selector captured before path canonicalization"
        );
        ensure!(
            calls(block)
                .iter()
                .filter(|call| call.as_str() == "canonicalize")
                .count()
                == 1,
            "one existing native input canonicalization"
        );
        ensure!(
            matches!(block.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Call(call),None)) if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.len()==2 && path.path.segments[0].ident=="Self" && path.path.segments[1].ident=="admit") && call.args.len()==5 && matches!(&call.args[1],syn::Expr::Path(path) if path.path.is_ident("instance_selector"))),
            "captured original reaches actual metadata constructor"
        );
        Ok(())
    }
    let file = syn::parse_file(include_str!("../../../store.rs"))?;
    let load = select(&file)?;
    retains_first(&load.block)?;
    let mut removed = load.block.clone();
    removed.stmts.remove(0);
    assert!(retains_first(&removed).is_err());
    let mut late = load.block.clone();
    late.stmts.swap(0, 1);
    assert!(retains_first(&late).is_err());
    let mut resolved = load.block.clone();
    let syn::Stmt::Expr(syn::Expr::Call(call), None) = resolved.stmts.last_mut().unwrap() else {
        unreachable!()
    };
    call.args[1] = syn::parse_quote!(instance_path.clone());
    assert!(retains_first(&resolved).is_err());
    let constructors=file.items.iter().filter_map(|item|match item {
        syn::Item::Impl(block) if matches!(&*block.self_ty,syn::Type::Path(path) if path.path.is_ident("InitialStoreMetadata"))=>Some(block),_=>None,
    }).flat_map(|block|&block.items).filter_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident=="admit"=>Some(method),_=>None}).collect::<Vec<_>>();
    ensure!(constructors.len() == 1, "actual metadata constructor");
    // The actual native Runtime initializer must carry this original DATA,
    // while all ordinary Runtime constructors leave it absent.
    use syn::visit::Visit;
    struct Fields(Vec<syn::Expr>);
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            for field in &node.fields {
                if matches!(&field.member,syn::Member::Named(name) if name=="restore_registry_selector")
                {
                    self.0.push(field.expr.clone());
                }
            }
            syn::visit::visit_expr_struct(self, node);
        }
    }
    struct SelectorFields(Vec<syn::Expr>);
    impl<'ast> Visit<'ast> for SelectorFields {
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            for field in &node.fields {
                if matches!(&field.member,syn::Member::Named(name) if name=="instance_selector") {
                    self.0.push(field.expr.clone());
                }
            }
            syn::visit::visit_expr_struct(self, node);
        }
    }
    let validates_constructor = |block: &syn::Block| -> Result<()> {
        let mut selected = SelectorFields(Vec::new());
        selected.visit_block(block);
        ensure!(
            selected.0.len() == 1
                && matches!(&selected.0[0],syn::Expr::Path(path) if path.path.is_ident("instance_selector")),
            "metadata stores actual selector argument"
        );
        Ok(())
    };
    validates_constructor(&constructors[0].block)?;
    let mut changed = constructors[0].block.clone();
    let syn::Stmt::Expr(syn::Expr::Call(ok), None) = changed.stmts.last_mut().unwrap() else {
        unreachable!()
    };
    let syn::Expr::Struct(actual) = &mut ok.args[0] else {
        unreachable!()
    };
    let fields = actual
        .fields
        .iter_mut()
        .filter(
            |field| matches!(&field.member,syn::Member::Named(name) if name=="instance_selector"),
        )
        .collect::<Vec<_>>();
    ensure!(fields.len() == 1, "actual selector field mutation target");
    fields.into_iter().next().unwrap().expr = syn::parse_quote!(instance_path.clone());
    assert!(validates_constructor(&changed).is_err());
    let native = syn::parse_file(include_str!("../../../store/native_storage.rs"))?;
    let mut fields = Fields(Vec::new());
    fields.visit_file(&native);
    ensure!(
        fields.0.len() == 1
            && matches!(&fields.0[0],syn::Expr::Call(call) if matches!(&*call.func,syn::Expr::Path(path) if path.path.is_ident("Some")) && call.args.len()==1 && matches!(&call.args[0],syn::Expr::Field(field) if matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("metadata")) && matches!(&field.member,syn::Member::Named(name) if name=="instance_selector"))),
        "native runtime retains actual selector DATA"
    );
    Ok(())
}

#[test]
fn native_serving_forwards_the_published_input_not_the_layout_resolved_path() -> Result<()> {
    fn path(expr: &syn::Expr, name: &str) -> bool {
        matches!(expr,syn::Expr::Path(path) if path.path.is_ident(name))
    }
    fn validate(block: &syn::Block) -> Result<()> {
        ensure!(
            matches!(block.stmts.first(),Some(syn::Stmt::Local(local)) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="published_instance_path") && local.init.as_ref().is_some_and(|init|path(&init.expr,"instance_path"))),
            "published selector retained before layout"
        );
        let selected=block.stmts.iter().filter_map(|statement|match statement {
            syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="runtime") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::If(branch) if path(&branch.cond,"initial_storage")))=>Some(local),_=>None,
        }).collect::<Vec<_>>();
        ensure!(selected.len() == 1, "actual startup runtime selector");
        let syn::Expr::If(branch) = &*selected[0].init.as_ref().unwrap().expr else {
            anyhow::bail!("actual initial branch")
        };
        ensure!(
            path(&branch.cond, "initial_storage") && branch.then_branch.stmts.len() == 3,
            "closed native input branch"
        );
        let syn::Stmt::Local(local) = &branch.then_branch.stmts[0] else {
            anyhow::bail!("metadata before bind")
        };
        ensure!(matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="metadata") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::Try(expr) if matches!(&*expr.expr,syn::Expr::Call(call) if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.iter().map(|part|part.ident.to_string()).collect::<Vec<_>>()==["crate","store","InitialStoreMetadata","load"]) && call.args.len()==2 && path(&call.args[0],"published_instance_path") && path(&call.args[1],"app")))),"actual published selector reaches native input");
        ensure!(
            matches!(&branch.then_branch.stmts[1],syn::Stmt::Expr(syn::Expr::Try(expr),Some(_)) if matches!(&*expr.expr,syn::Expr::MethodCall(call) if path(&call.receiver,"metadata") && call.method=="require_input_path" && call.args.len()==1 && matches!(&call.args[0],syn::Expr::Reference(reference) if reference.mutability.is_none() && path(&reference.expr,"instance_path")))),
            "selected canonical layout must still match"
        );
        Ok(())
    }
    let file = syn::parse_file(include_str!("../../../deployment.rs"))?;
    let selected = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "serve_configured" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(selected.len() == 1, "actual serving selector");
    let block = &selected[0].block;
    validate(block)?;
    let mut late = block.clone();
    let original = late.stmts.remove(0);
    late.stmts.push(original);
    assert!(validate(&late).is_err());
    for mode in 0..2 {
        let mut changed = block.clone();
        let local=changed.stmts.iter_mut().find_map(|statement|match statement {syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="runtime") && local.init.as_ref().is_some_and(|init|matches!(&*init.expr,syn::Expr::If(branch) if path(&branch.cond,"initial_storage")))=>Some(local),_=>None}).unwrap();
        let syn::Expr::If(branch) = &mut *local.init.as_mut().unwrap().expr else {
            unreachable!()
        };
        if mode == 0 {
            branch.then_branch.stmts[0] = syn::parse_quote!(let metadata=crate::store::InitialStoreMetadata::load(&instance_path,app)?;);
        } else {
            branch.then_branch.stmts.remove(1);
        }
        assert!(validate(&changed).is_err());
    }
    Ok(())
}
