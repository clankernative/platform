//! Portable source and mutation controls for the Linux issuer service.
//! These inspect the real source; they do not create native owners or kernel fixtures.

use quote::ToTokens;

fn tokens(source: &str) -> String {
    fn strip(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        stream
            .into_iter()
            .filter_map(|token| match token {
                proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                    Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                        '?',
                        proc_macro2::Spacing::Alone,
                    )))
                }
                proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                    proc_macro2::Group::new(group.delimiter(), strip(group.stream())),
                )),
                other => Some(other),
            })
            .collect()
    }
    strip(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
}

fn implementation(owner_name: &str, name: &str) -> String {
    let file = syn::parse_file(include_str!("service.rs")).unwrap();
    let mut found = file.items.into_iter().filter_map(|item| {
        let syn::Item::Impl(owner) = item else {
            return None;
        };
        if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident(owner_name)) {
            return None;
        }
        owner.items.into_iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == name => {
                Some(tokens(&method.into_token_stream().to_string()))
            }
            _ => None,
        })
    });
    let body = found.next().unwrap();
    assert!(found.next().is_none());
    body
}

#[test]
fn source_controls_align_question_semicolon_spacing_without_changing_the_actor() {
    assert_eq!(tokens("app.check(costs)?;"), tokens("app.check(costs) ? ;"));
    assert_ne!(tokens("app.check(costs)?;"), tokens("other.check(costs)?;"));
}

#[test]
fn source_controls_preserve_comparison_and_closure_punctuation_boundaries() {
    for source in [
        "admission.statement.process == *peer.data()",
        "self.admission.statement.process == *self.hello.data()",
        "self.restore.as_mut().map(|restore| &mut restore.app)",
    ] {
        let expression: syn::Expr = syn::parse_str(source).unwrap();
        assert_eq!(
            tokens(&expression.into_token_stream().to_string()),
            tokens(source)
        );
    }
    for (separated, joint) in [
        (
            "admission.statement.process == *peer.data()",
            "admission.statement.process==*peer.data()",
        ),
        (
            "self.restore.as_mut().map(|restore| &mut restore.app)",
            "self.restore.as_mut().map(|restore|&mut restore.app)",
        ),
        ("a & &b", "a && b"),
    ] {
        assert_ne!(tokens(separated), tokens(joint));
    }
}

fn handler(name: &str) -> String {
    let file = syn::parse_file(include_str!("service.rs")).unwrap();
    file.items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => {
                Some(tokens(&function.into_token_stream().to_string()))
            }
            _ => None,
        })
        .unwrap()
}

fn app_request() -> String {
    handler("restore_app")
}

fn ordered(body: &str, parts: &[&str]) -> bool {
    let mut rest = body;
    for part in parts {
        let part = tokens(part);
        let Some(at) = rest.find(&part) else {
            return false;
        };
        rest = &rest[at + part.len()..];
    }
    true
}

fn app_is_retained_before_send(body: &str) -> bool {
    ordered(
        body,
        &[
            "authorized.app.begin()?;",
            "restore_publish_check",
            "MessageProcess::check_same_actor",
            "let signed=protocol::SignedRestoreAdmission",
            "signed.verify_data",
            "AuthorizedRestoreApp::capture(issuer,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
            "authorized.app.retain(app)?;",
            "let sent=channel.send",
            "Packet::RestoreAppGrant",
            "let post=restore_publish_check",
            "let peer_post=MessageProcess::check_same_actor",
            "sent?;post?;peer_post?;",
            "let checked=restore_publish_check",
            "cohort.original.refuse();",
            "requested?;checked",
        ],
    )
}

fn capture_is_actual(body: &str) -> bool {
    ordered(
        body,
        &[
            "frozen.remaining()?;acquisition.remaining()?;",
            "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
            "admission.verify_data",
            "admission.statement.process== *peer.data()",
            "peer.data()==bound.data()",
            "frozen.interval_data()",
            "acquisition.interval_data()",
            "effective_deadline_ns",
            "let mut original=frozen.narrow(5,ceiling)?;",
            "peer.retain_message_anchor(&mut original,&costs.hashes(Subject::Requester))?;",
            "bound.retain_message_anchor(&mut original,&costs.hashes(Subject::Requester))?;",
            "MessageProcess::check_same_actor",
            "original.sample()",
            "original.remaining()?;acquisition.remaining()?;",
            "policy:issuer.policy.clone()",
            "admission,hello,bound:answer,original,confirmation_attempted:false,confirmation:None",
            "let checked=frozen.remaining();",
            "frozen.refuse();acquisition.refuse();",
            "let app=requested?;checked?;Ok(app)",
        ],
    ) && !body.contains(&tokens("NativeAcquisition::begin"))
}

fn retained_check_is_actual(body: &str) -> bool {
    ordered(
        body,
        &[
            "let requested:Result<()>",
            "self.admission.verify_data(&self.policy,&self.certificate,&self.authorization,self.original.sample()?.elapsed)?;",
            "self.admission.statement.process== *self.hello.data()",
            "self.hello.data()==self.bound.data()",
            "MessageProcess::check_same_actor(&mut [&mut self.hello,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
            "self.original.remaining().map(|_|())",
            "let checked=self.original.remaining();",
            "if requested.is_err() || checked.is_err() {self.original.refuse();}",
            "requested?;checked.map(|_|())",
        ],
    ) && body
        .matches(&tokens("let checked=self.original.remaining();"))
        .count()
        == 1
        && body.matches(&tokens("requested?")).count() == 1
        && !body.contains(&tokens("NativeAcquisition::begin"))
}

fn frozen_check_joins_independent_app(body: &str) -> bool {
    ordered(
        body,
        &[
            "let requested:Result<()>",
            "MessageProcess::check_same_actor(&mut [&mut self.controller,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
            "self.original.remaining().map(|_|())",
            "let app=match self.restore.as_mut().map(|restore| &mut restore.app)",
            "Some(RestoreAppAdmission::Retained(app))=>app.check(costs)",
            "let confirmation=self.check_prepared_confirmation(costs);",
            "let checked=self.original.remaining();",
            "if requested.is_err() || app.is_err() || confirmation.is_err() || checked.is_err() {self.original.refuse();}",
            "requested?;app?;confirmation?;checked.map(|_|())",
        ],
    ) && body.matches(&tokens("requested?")).count() == 1
        && body.matches(&tokens("app.check(costs)")).count() == 1
        && !body.contains(&tokens("NativeAcquisition::begin"))
}

fn finish_is_closed(body: &str) -> bool {
    ordered(
        body,
        &[
            "!cohort.finish_attempted && cohort.completion.is_none()",
            "cohort.finish_attempted=true;",
            "finish_publish_check",
            "peer.data()==cohort.controller.data()",
            "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
            "RestoreAppAdmission::Retained(app)",
            "app.statement_data(costs)?",
            "completion.validate_data",
            "completion.frozen==day2_capabilities::Digest::of",
            "Packet::RestoreFinishNonce",
            "let checked=finish_publish_check",
            "sent?;checked?;",
            "let received=channel.receive",
            "let checked=finish_publish_check",
            "let (packet,mut bound)=received?;checked?;",
            "Packet::RestoreFinishBind",
            "*selected==completion && echoed==request && answered==challenge",
            "protocol::verify",
            "\"restore-issuer-finish-bind-v1\"",
            "MessageProcess::check_same_actor(&mut [&mut cohort.controller,&mut cohort.bound,peer,&mut bound],acquisition,&costs.hashes(Subject::Requester))?;",
            "finish_publish_check",
            "cohort.original.interval_data()",
            "acquisition.interval_data()",
            "app.original.deadline_ns",
            ".min(frozen_ceiling).min(request_ceiling)",
            "issuer.key.sign(\"restore-issuer-completed-v1\",&statement)",
            "let checked=finish_publish_check",
            "let signature=signed?;checked?;",
            "signed.verify_data",
            "cohort.completion=Some(signed.clone());",
            "Packet::RestoreFinishGrant",
            "let checked=finish_publish_check",
            "let peer_post=MessageProcess::check_same_actor",
            "sent?;checked?;peer_post?;",
            "let checked=finish_publish_check",
            "cohort.original.refuse();acquisition.refuse();",
            "requested?;checked",
        ],
    ) && !body.contains(&tokens("NativeAcquisition::begin"))
        && !body.contains(&tokens("Issuance::Open"))
}

fn finish_post_is_independent(body: &str) -> bool {
    ordered(
        body,
        &[
            "let requested=restore_publish_check",
            "let checked=MessageProcess::check_same_actor",
            "let original_post=cohort.original.remaining();",
            "if requested.is_err() || checked.is_err() || original_post.is_err() {cohort.original.refuse();acquisition.refuse();}",
            "requested?;checked?;original_post.map",
        ],
    ) && body.matches(&tokens("requested?")).count() == 1
        && !body.contains(&tokens("NativeAcquisition::begin"))
}

#[test]
fn actual_handler_retains_kernel_app_anchors_before_even_an_ambiguous_grant_send() {
    let actual = app_request();
    assert!(app_is_retained_before_send(&actual));
    for (before, after) in [
        ("authorized.app.begin()?;", "let _reusable=();"),
        (
            "AuthorizedRestoreApp::capture(issuer,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
            "AuthorizedRestoreApp::capture(other,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
        ),
        ("authorized.app.retain(app)?;", "drop(app);"),
        (
            "let post=restore_publish_check",
            "let post=skip_publish_check",
        ),
        ("sent?;post?;peer_post?;", "post?;sent?;peer_post?;"),
    ] {
        let before = tokens(before);
        let after = tokens(after);
        assert!(actual.contains(&before));
        assert!(!app_is_retained_before_send(
            &actual.replacen(&before, &after, 1)
        ));
    }
}

#[test]
fn actual_retained_capture_uses_existing_real_handles_and_same_frozen_original() {
    let actual = implementation("AuthorizedRestoreApp", "capture");
    assert!(capture_is_actual(&actual));
    for (before, after) in [
        (
            "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
            "let _unchecked=();",
        ),
        (
            "frozen.narrow(5,ceiling)",
            "NativeAcquisition::begin(std::time::Duration::from_secs(5))",
        ),
        ("admission.statement.process== *peer.data()", "true"),
        ("peer.retain_message_anchor", "other.retain_message_anchor"),
        (
            "let checked=frozen.remaining();",
            "let checked=Ok(std::time::Duration::ZERO);",
        ),
        (
            "let app=requested?;checked?;Ok(app)",
            "checked?;let app=requested?;Ok(app)",
        ),
    ] {
        let before = tokens(before);
        assert!(actual.contains(&before));
        assert!(!capture_is_actual(&actual.replacen(
            &before,
            &tokens(after),
            1
        )));
    }
}

#[test]
fn actual_retained_app_rechecks_signed_actor_kernel_handles_and_original_on_error() {
    let actual = implementation("AuthorizedRestoreApp", "check");
    assert!(retained_check_is_actual(&actual));
    assert!(!retained_check_is_actual(&tokens(
        "fn check(&mut self,costs:&Costs)->Result<()> {Ok(())}"
    )));
    for (before, after) in [
        (
            "self.admission.verify_data(&self.policy,&self.certificate,&self.authorization,self.original.sample()?.elapsed)?;",
            "let _unchecked=();",
        ),
        (
            "self.admission.statement.process== *self.hello.data()",
            "true",
        ),
        ("self.hello.data()==self.bound.data()", "true"),
        (
            "MessageProcess::check_same_actor(&mut [&mut self.hello,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
            "let _unchecked=();",
        ),
        (
            "&mut self.hello,&mut self.bound",
            "&mut self.hello,&mut self.hello",
        ),
        (
            "let checked=self.original.remaining();",
            "let checked=Ok(std::time::Duration::ZERO);",
        ),
        (
            "let checked=self.original.remaining();",
            "requested?;let checked=self.original.remaining();",
        ),
        ("requested.is_err() || checked.is_err()", "checked.is_err()"),
        ("self.original.refuse();", "let _reusable=();"),
        ("requested?;checked.map(|_|())", "checked?;requested"),
    ] {
        let before = tokens(before);
        assert_eq!(actual.matches(&before).count(), 1, "{before}");
        assert!(
            !retained_check_is_actual(&actual.replacen(&before, &tokens(after), 1)),
            "{before}"
        );
    }
}

#[test]
fn actual_frozen_check_observes_app_even_after_controller_failure_and_preserves_primary() {
    let actual = implementation("FrozenCohort", "check");
    assert!(frozen_check_joins_independent_app(&actual));
    for (before, after) in [
        ("let app=match", "requested?;let app=match"),
        (
            "let confirmation=self.check_prepared_confirmation(costs);",
            "let confirmation:Result<()>=Ok(());",
        ),
        (
            "Some(RestoreAppAdmission::Retained(app))=>app.check(costs)",
            "Some(RestoreAppAdmission::Retained(app))=>Ok(())",
        ),
        (
            "let checked=self.original.remaining();",
            "let checked=Ok(std::time::Duration::ZERO);",
        ),
        (
            "requested.is_err() || app.is_err() || confirmation.is_err() || checked.is_err()",
            "requested.is_err() || checked.is_err()",
        ),
        ("self.original.refuse();", "let _reusable=();"),
        (
            "requested?;app?;confirmation?;checked.map(|_|())",
            "app?;requested?;confirmation?;checked.map(|_|())",
        ),
    ] {
        let before = tokens(before);
        assert_eq!(actual.matches(&before).count(), 1, "{before}");
        assert!(
            !frozen_check_joins_independent_app(&actual.replacen(&before, &tokens(after), 1)),
            "{before}"
        );
    }
}

#[test]
fn actual_finish_retains_generation_actual_app_and_one_attempt_before_any_reply() {
    let actual = handler("restore_finish");
    assert!(finish_is_closed(&actual));
    for (before, after) in [
        ("cohort.finish_attempted=true;", "let _reusable=();"),
        ("app.statement_data(costs)?", "caller_app()"),
        ("completion.validate_data", "skip_completion_check"),
        (
            "*selected==completion && echoed==request && answered==challenge",
            "true",
        ),
        ("\"restore-issuer-finish-bind-v1\"", "\"role-bind\""),
        (
            ".min(frozen_ceiling).min(request_ceiling)",
            ".max(frozen_ceiling).max(request_ceiling)",
        ),
        (
            "let signature=signed?;checked?;",
            "checked?;let signature=signed?;",
        ),
        (
            "cohort.completion=Some(signed.clone());",
            "let _unretained=();",
        ),
        (
            "cohort.original.refuse();acquisition.refuse();",
            "cohort.original.refuse();",
        ),
    ] {
        let before = tokens(before);
        assert_eq!(actual.matches(&before).count(), 1, "{before}");
        assert!(
            !finish_is_closed(&actual.replacen(&before, &tokens(after), 1)),
            "{before}"
        );
    }
    let post = handler("finish_publish_check");
    assert!(finish_post_is_independent(&post));
    assert!(!finish_post_is_independent(&tokens(
        "fn finish_publish_check()->Result<()> {Ok(())}"
    )));
    for (before, after) in [
        (
            "let requested=restore_publish_check",
            "let requested=skip_publish_check",
        ),
        (
            "let checked=MessageProcess::check_same_actor",
            "requested?;let checked=MessageProcess::check_same_actor",
        ),
        (
            "let original_post=cohort.original.remaining();",
            "let original_post=Ok(std::time::Duration::ZERO);",
        ),
        (
            "requested.is_err() || checked.is_err() || original_post.is_err()",
            "false",
        ),
        (
            "cohort.original.refuse();acquisition.refuse();",
            "cohort.original.refuse();",
        ),
        (
            "requested?;checked?;original_post.map",
            "checked?;requested?;original_post.map",
        ),
    ] {
        let before = tokens(before);
        assert_eq!(post.matches(&before).count(), 1, "{before}");
        assert!(
            !finish_post_is_independent(&post.replacen(&before, &tokens(after), 1)),
            "{before}"
        );
    }
}
