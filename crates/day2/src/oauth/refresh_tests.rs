//! Real admitted Calendar worker -> Runtime -> private refresh -> encrypted
//! settlement -> bounded read. Only native readiness/clock/HTTP use test ports.
use super::*;
use crate::{artifact::LoadedArtifact, oauth::{account, effects, exchange, outbound, profiles, refresh}};
use std::{collections::BTreeSet, fs, path::PathBuf, sync::{Arc, atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst}}, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case { Complete, LostReply, WrongScope, WrongAccount, ChangedRefresh, RevokedAfterToken,
    RevokedAfterAccount, PolicyChanged, EpochChanged, ReadinessRewind, PublicationRewind,
    PublicationExpired, CustodyFailure }

struct Port {
    case: Case,
    db: PathBuf,
    local_runtime: Runtime,
    scopes: String,
    now: AtomicI64,
    entropy: AtomicU64,
    posts: AtomicUsize,
    accounts: AtomicUsize,
    reads: AtomicUsize,
}

fn response(body: Value) -> Result<effects::Response> {
    Ok(effects::Response::Simulated { status: reqwest::StatusCode::OK,
        headers: reqwest::header::HeaderMap::from_iter([(reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"))]),
        body: std::io::Cursor::new(serde_json::to_vec(&body)?), peer: None })
}

impl Port {
    fn revoke(&self) -> Result<()> {
        let mut db = store::open(&self.db)?;
        let slot: String = db.query_row("SELECT slot FROM oauth_connection_slots", [], |r| r.get(0))?;
        assert!(super::super::store::disable_slot(&mut db, &slot, 1)?);
        Ok(())
    }
}

impl effects::Hooks for Port {
    fn domain(&self) -> u64 { 0x6381 }
    fn wall_time(&self) -> Result<i64> { Ok(self.now.load(SeqCst)) }
    fn monotonic(&self) -> Duration { Duration::ZERO }
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        let value = self.entropy.fetch_add(1, SeqCst).to_le_bytes();
        for (i, byte) in bytes.iter_mut().enumerate() { *byte = value[i % value.len()].wrapping_add(i as u8); }
        Ok(())
    }
    fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
        // A real competing writer succeeds at every provider boundary.
        let mut db = store::open(&self.db)?;
        crate::write_queue::immediate(&mut db)?.commit()?;
        match request.url().as_str() {
            super::super::google::TOKEN => {
                assert_eq!(request.method(), reqwest::Method::POST);
                let fields = url::form_urlencoded::parse(request.body().context("refresh form")?.as_bytes().context("refresh body")?)
                    .into_owned().collect::<std::collections::BTreeMap<_,_>>();
                assert_eq!(fields.len(), 4);
                assert_eq!(fields["grant_type"], "refresh_token");
                assert_eq!(fields["refresh_token"], "private_runtime_refresh");
                assert_eq!(fields["client_id"], "123-refresh.apps.googleusercontent.com");
                assert_eq!(fields["client_secret"], "private_refresh_client_credential");
                let ordinal = self.posts.fetch_add(1, SeqCst) + 2;
                if self.case == Case::LostReply { anyhow::bail!("simulated response lost after possible dispatch"); }
                if self.case == Case::RevokedAfterToken { self.revoke()?; }
                if self.case == Case::EpochChanged { db.execute("UPDATE oauth_connection_slots SET security_epoch=security_epoch+1", [])?; }
                if self.case == Case::PolicyChanged {
                    let current = authority_state::current(&db)?;
                    let mut document = current.document;
                    document.policy.as_mut().context("policy")?.operations.get_mut("list_events").context("list policy")?.observations.clear();
                    authority_state::apply(&self.local_runtime,
                        &authority_state::LocalOperator::assert_local("admin")?,
                        &authority_state::ApplyAuthority { request_id: "narrow_during_refresh".into(), expected: Some(current.stamp), document })?;
                }
                if self.case == Case::ReadinessRewind { self.now.store(260, SeqCst); }
                let mut body = json!({"access_token":format!("private_refresh_access_{ordinal}"),"token_type":"Bearer","expires_in":90,"scope":self.scopes});
                if self.case == Case::WrongScope { body["scope"] = "openid".into(); }
                if self.case == Case::ChangedRefresh { body["refresh_token"] = "unreviewed_rotated_token".into(); }
                response(body)
            }
            super::super::google::USERINFO => {
                self.accounts.fetch_add(1, SeqCst);
                assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
                let version = self.posts.load(SeqCst) + 1;
                assert_eq!(request.headers()[reqwest::header::AUTHORIZATION].to_str()?, format!("Bearer private_refresh_access_{version}"));
                if self.case == Case::RevokedAfterAccount { self.revoke()?; }
                if self.case == Case::PublicationRewind { self.now.store(270, SeqCst); }
                if self.case == Case::CustodyFailure { db.execute_batch("CREATE TRIGGER refuse_refresh_material BEFORE UPDATE ON oauth_private_tokens BEGIN SELECT RAISE(ABORT,'injected custody publication failure'); END")?; }
                response(json!({"sub":if self.case == Case::WrongAccount {"google-bob"} else {"google-alice"},
                    "hd":"example.com","email_verified":true,"email":"presentation-only@example.com"}))
            }
            _ => {
                assert_eq!(request.url().host_str(), Some("www.googleapis.com"));
                assert_eq!(request.url().path(), "/calendar/v3/calendars/primary/events");
                self.reads.fetch_add(1, SeqCst);
                let version: i64 = db.query_row("SELECT token_version FROM oauth_connection_slots", [], |row| row.get(0))?;
                assert!(version > 1);
                assert_eq!(request.headers()[reqwest::header::AUTHORIZATION].to_str()?, format!("Bearer private_refresh_access_{version}"));
                response(json!({"kind":"calendar#events","items":[]}))
            }
        }
    }
}

struct NativeAuthority { selection: Selection, port: Arc<Port>, commits: AtomicUsize }

impl Authority for NativeAuthority {
    fn current(&self, _: &str, _: &str, _: &str, _: i64) -> Result<Option<Selection>> {
        if self.port.case == Case::ReadinessRewind && self.port.posts.load(SeqCst) > 0 {
            self.port.now.store(255, SeqCst);
        }
        Ok(Some(self.selection.clone()))
    }
    fn custody(&self, _: &str, _: &str, _: &str, expected: &Digest, _: i64) -> Result<Option<KeyLease>> {
        assert_eq!(&self.selection.identity()?, expected);
        Ok(Some(profiles::tests::exchange_key()))
    }
    fn refresh_client(&self, _: &str, _: &str, _: &str, expected: &Digest, _: i64) -> Result<Option<refresh::ClientCredential>> {
        assert_eq!(&self.selection.identity()?, expected);
        Ok(Some(refresh::ClientCredential::new("123-refresh.apps.googleusercontent.com".into(),
            "private_refresh_client_credential".into(), self.selection.instance.registration.client_credential.clone())?))
    }
    fn with_current(&self, _: &str, _: &str, _: &str, _: i64,
        commit: &mut dyn FnMut(&Selection) -> Result<bool>) -> Result<bool> {
        let call = self.commits.fetch_add(1, SeqCst);
        if call == 1 {
            if self.port.case == Case::PublicationRewind { self.port.now.store(265, SeqCst); }
            if self.port.case == Case::PublicationExpired { self.port.now.store(340, SeqCst); }
        }
        commit(&self.selection)
    }
}

fn activate(runtime: &Runtime, fixture: &profiles::tests::QualificationFixture) -> Result<()> {
    let mut db = store::open(runtime.db())?;
    let key = profiles::tests::exchange_key();
    let prepared = exchange::prepare_authorization(fixture.input(), &key,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")?;
    let code_ref = prepared.code_ref().to_owned();
    assert!(prepared.begin(&mut db, 1)?);
    let raw = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", "0123456789abcdefghijklmnopqrstuvwxyzABCDEF").append_pair("code", "private_original_code")
        .append_pair("iss", &fixture.reviewed.issuer_url).finish();
    assert!(matches!(exchange::handle_qualified_callback(&mut db, fixture.input(), outbound::CallbackIngress {
        attempt: &fixture.intent.attempt, raw_query: raw.as_bytes(), route: &fixture.instance.registration.callback,
        session: fixture.binding.session(), issuer_binding: &fixture.reviewed.issuer, code_ref: &code_ref, now: 2 }, &key)?,
        outbound::CallbackOutcome::CodeAccepted { .. }));
    let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)?.context("original permit")?;
    let scopes = fixture.permission.action_scopes.values().flatten().cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(" ");
    let exchange::ExchangeObservation::Response(response) = permit.send(|_| Ok(exchange::TokenHttpResponse {
        status:200, content_type:"application/json".into(), body:serde_json::to_vec(&json!({"access_token":"private_original_access",
        "refresh_token":"private_runtime_refresh","token_type":"Bearer","expires_in":300,"scope":scopes}))? })) else { anyhow::bail!("original response"); };
    let profiles::AccountBindingEvidence::MappedHuman { mapping, .. } = &fixture.instance.account else { anyhow::bail!("mapped fixture"); };
    let mapped = account::MappedHumanEvidence { human:fixture.intent.owner.clone(), issuer:fixture.reviewed.issuer_url.clone(),
        provider_subject:"google-alice".into(), tenant:"example.com".into(), mapping_revision:mapping.revision.clone() };
    let observed = account::ProviderAccount { issuer:mapped.issuer.clone(), subject:mapped.provider_subject.clone(),
        tenant:mapped.tenant.clone(), display_email:"alice@example.com".into() };
    let prepared = response.validate_mapped(fixture.input(), &mapped, &observed)?.prepare_tokens(&key)?;
    assert!(exchange::settle_mapped(&mut db, prepared, fixture.input(), &mapped.mapping_revision, 4)?);
    Ok(())
}

#[test]
fn compiled_calendar_refresh_publishes_versions_and_fences_failure_recovery() -> Result<()> {
    let artifact = std::env::var("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT").context("compiled Calendar artifact required")?;
    for case in [Case::Complete, Case::LostReply, Case::WrongScope, Case::WrongAccount, Case::ChangedRefresh,
        Case::RevokedAfterToken, Case::RevokedAfterAccount, Case::PolicyChanged, Case::EpochChanged,
        Case::ReadinessRewind, Case::PublicationRewind, Case::PublicationExpired, Case::CustodyFailure] {
        let directory = tempfile::tempdir()?;
        let instance_path = directory.path().join("instance.json");
        fs::write(&instance_path, serde_json::to_vec(&crate::development::verification_instance_data(std::path::Path::new(&artifact), None, "alice@example.com")?)?)?;
        let mut runtime = Runtime::from_artifact_for_tests(instance_path, "app".into(), directory.path().join("app.sqlite"), LoadedArtifact::load(std::path::Path::new(&artifact))?)?;
        runtime.initialize()?;
        let (selection, fixture) = super::tests::product_selection(&runtime)?;
        let scopes = fixture.permission.action_scopes.values().flatten().cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(" ");
        let port = Arc::new(Port { case, db:runtime.db().to_owned(), local_runtime:runtime.clone(), scopes,
            now:AtomicI64::new(250), entropy:AtomicU64::new(1), posts:AtomicUsize::new(0), accounts:AtomicUsize::new(0), reads:AtomicUsize::new(0) });
        effects::scope(port.clone(), || -> Result<()> {
            activate(&runtime, &fixture)?;
            runtime.connections = Some(Arc::new(NativeAuthority { selection, port:port.clone(), commits:AtomicUsize::new(0) }));
            let db = store::open(runtime.db())?;
            let original: Vec<u8> = db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| r.get(0))?;
            let human = crate::iap::Verified { email:"alice@example.com".into(), subject:"accounts.google.com:google-alice".into() };
            crate::iap::bind_subject(&db, &human, 250)?;
            let input = json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"});
            let invoke = |id: &str| runtime.invoke_verified("oauthcalendar.list_events", store::RequestIdentity { actor:&human.email, origin:Some(&human) }, id, &input, port.now.load(SeqCst), store::Fault::None);
            let first = invoke("refresh_v2");
            if case == Case::Complete {
                let outcome = first.with_context(|| format!("{case:?} v2"))?;
                assert_eq!(outcome.status, "success"); assert_eq!(outcome.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 1); assert_eq!(port.accounts.load(SeqCst), 1); assert_eq!(port.reads.load(SeqCst), 1);
                let binding = exchange::load_binding(&db, &fixture.intent.attempt)?.context("activation binding")?;
                let account: String = db.query_row("SELECT account FROM oauth_connection_slots", [], |r| r.get(0))?;
                let key = profiles::tests::exchange_key();
                let token = super::super::custody::load_access(&db, &key, &fixture.intent, &binding, &account, 2, 250)?.context("v2 material")?;
                assert_eq!(token.expires_at, 340);
                assert!(super::super::custody::load_access(&db, &key, &fixture.intent, &binding, &account, 1, 250).is_err());
                let reference: String = db.query_row("SELECT reference FROM oauth_use_handles WHERE invocation='refresh_v2'", [], |r| r.get(0))?;
                // Drop the returned outcome and reopen the store as a caller
                // recovering a lost acknowledgement. The committed receipt
                // permits observation, never another refresh of base version 1.
                drop(outcome);
                let reopened = store::open(runtime.db())?;
                assert_eq!(reopened.query_row("SELECT count(*) FROM oauth_refresh_attempts WHERE state='replacement_committed' AND base_version=1 AND next_version=2 AND length(receipt)>0", [], |r| r.get::<_,i64>(0))?, 1);
                assert_eq!(invoke("after_lost_ack")?.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 1);
                port.now.store(280, SeqCst);
                assert_eq!(invoke("refresh_v3")?.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 2);
                assert_eq!(db.query_row("SELECT token_version FROM oauth_connection_slots", [], |r| r.get::<_,i64>(0))?, 3);
                assert!(super::super::custody::load_access(&db, &key, &fixture.intent, &binding, &account, 2, 280).is_err());
                assert!(super::super::custody::load_access(&db, &key, &fixture.intent, &binding, &account, 3, 280)?.is_some());
                let old = Request { operation:"oauthcalendar.list_events".into(), input:input.to_string(),
                    context:store::invocation_context(&db, "refresh_v2")?, observations:vec![] };
                assert_eq!(load(&db, &runtime, &old, "calendar", &reference, 280).err().context("stale Use survived publication")?.to_string(),
                    "connection use generation or account changed", "Use must fail on its material pin while its 60-second lifetime remains valid");
            } else {
                assert!(!first.as_ref().is_ok_and(|o| o.status == "success" && o.result["status"] == "ok"), "{case:?}: failed refresh completed a Calendar read");
                assert_eq!(port.posts.load(SeqCst), 1, "{case:?}"); assert_eq!(port.reads.load(SeqCst), 0, "{case:?}");
                assert_eq!(db.query_row("SELECT token_version FROM oauth_connection_slots", [], |r| r.get::<_,i64>(0))?, 1, "{case:?}");
                assert_eq!(db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| r.get::<_,Vec<u8>>(0))?, original, "{case:?}: partial material publication");
                let before = port.posts.load(SeqCst);
                port.now.store(250, SeqCst);
                let _ = invoke("recovery_no_resend");
                assert_eq!(port.posts.load(SeqCst), before, "{case:?}: recovery resent an unresolved base");
                if matches!(case, Case::ReadinessRewind | Case::PublicationRewind | Case::PublicationExpired) {
                    assert_eq!(db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r.get::<_,String>(0))?, "reauth_required");
                }
            }
            assert_eq!(db.query_row("SELECT count(*) FROM day2_entries", [], |r| r.get::<_,i64>(0))?, 0);
            Ok(())
        }).with_context(|| format!("compiled refresh case {case:?}"))?;
    }
    Ok(())
}
