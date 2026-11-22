//! Portable mutation checks of the actual fixed Linux service. No native owner
//! is fabricated here; real kernel/resource conformance is Linux-only.
use quote::ToTokens;

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
    !actual.contains("NativeAcquisition :: begin") && !actual.contains("SignedStage")
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
    assert!(!body.contains("NativeAcquisition :: begin"));
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
    assert!(ordinary.contains("net :: recv_pidfd_packet"));
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
