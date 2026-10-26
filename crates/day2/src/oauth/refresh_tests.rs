//! Real admitted Calendar worker -> Runtime -> private refresh -> encrypted
//! settlement -> bounded read. Only native readiness/clock/HTTP use test ports.
use super::*;
use crate::{
    artifact::LoadedArtifact,
    authority_state,
    oauth::{account, effects, exchange, outbound, profiles, refresh},
};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Complete,
    LostReply,
    WrongScope,
    WrongAccount,
    ChangedRefresh,
    RevokedAfterToken,
    RevokedAfterAccount,
    PolicyChanged,
    EpochChanged,
    ReadinessRewind,
    PublicationRewind,
    PublicationExpired,
    CustodyFailure,
    CredentialRewind,
    ReturnRewind,
    MaterialSubstitution,
    SuccessorReturnRewind,
    AbsentReturnRewind,
    ClientReturnRewind,
    DispatchReturnRewind,
    DispatchErrorRecovery,
    PublicationErrorRecovery,
    PublicationClockUnavailable,
    PublicationFallbackRewind,
}

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
    crash: Option<effects::RefreshBoundary>,
    transport: Option<PathBuf>,
    activate_on_fill: AtomicBool,
    fail_clock: AtomicBool,
    publication_clock_reads: AtomicUsize,
}

fn response(body: Value) -> Result<effects::Response> {
    Ok(effects::Response::Simulated {
        status: reqwest::StatusCode::OK,
        headers: reqwest::header::HeaderMap::from_iter([(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        )]),
        body: std::io::Cursor::new(serde_json::to_vec(&body)?),
        peer: None,
    })
}

fn fixture_result(run: impl FnOnce() -> Result<()>) -> Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
        anyhow::bail!("conformance assertion panicked; see the original test output")
    })
}

fn fixture_scope(port: Arc<Port>, run: impl FnOnce() -> Result<()>) -> Result<()> {
    fixture_result(|| effects::scope(port, run))
}

impl Port {
    fn narrow_policy(&self) -> Result<()> {
        let db = store::open(&self.db)?;
        let current = authority_state::current(&db)?;
        let mut document = current.document;
        document
            .policy
            .as_mut()
            .context("policy")?
            .operations
            .get_mut("oauthcalendar.list_events")
            .context("list policy")?
            .observations
            .clear();
        document
            .resources
            .operations
            .remove("oauthcalendar.list_events");
        let previous = current.stamp.revision;
        let receipt = authority_state::apply(
            &self.local_runtime,
            &authority_state::LocalOperator::assert_local("admin")?,
            &authority_state::ApplyAuthority {
                request_id: "narrow_during_refresh".into(),
                expected: Some(current.stamp),
                document,
            },
        )?;
        let applied = authority_state::current(&db)?;
        assert_eq!(applied.stamp, receipt.stamp);
        assert_eq!(applied.stamp.revision, previous + 1);
        assert!(
            applied
                .document
                .policy
                .as_ref()
                .context("applied policy")?
                .operations["oauthcalendar.list_events"]
                .observations
                .is_empty()
        );
        assert!(
            !applied
                .document
                .resources
                .operations
                .contains_key("oauthcalendar.list_events")
        );
        Ok(())
    }

    fn record(&self, phase: &str) -> Result<()> {
        if let Some(path) = &self.transport {
            let log = Connection::open(path)?;
            log.execute("INSERT INTO sends(phase) VALUES(?1)", [phase])?;
        }
        Ok(())
    }

    fn revoke(&self) -> Result<()> {
        let mut db = store::open(&self.db)?;
        let slot: String =
            db.query_row("SELECT slot FROM oauth_connection_slots", [], |r| r.get(0))?;
        assert!(super::super::store::disable_slot(&mut db, &slot, 1)?);
        Ok(())
    }
}

impl effects::Hooks for Port {
    fn provider_observation(
        &self,
        _: crate::oauth::shell_oidc::ProviderObservationData,
    ) -> Result<()> {
        anyhow::bail!("unscripted provider observation")
    }

    fn refresh_boundary(&self, boundary: effects::RefreshBoundary) {
        if self.crash == Some(boundary) {
            self.record(&format!("boundary:{boundary:?}"))
                .expect("durable child boundary log");
            std::process::exit(86);
        }
    }
    fn domain(&self) -> u64 {
        0x6381
    }
    fn wall_time(&self) -> Result<i64> {
        ensure!(
            !self.fail_clock.load(SeqCst),
            "injected unavailable native clock"
        );
        let now = self.now.load(SeqCst);
        if self.case == Case::PublicationFallbackRewind && now == 270 {
            self.publication_clock_reads.fetch_add(1, SeqCst);
        }
        Ok(now)
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        if self.activate_on_fill.swap(false, SeqCst) {
            let (_, fixture) = super::tests::product_selection(&self.local_runtime)?;
            activate(&self.local_runtime, &fixture)?;
            self.now.store(245, SeqCst);
        }
        let value = self.entropy.fetch_add(1, SeqCst).to_le_bytes();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = value[i % value.len()].wrapping_add(i as u8);
        }
        Ok(())
    }
    fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
        // A real competing writer succeeds at every provider boundary.
        let mut db = store::open(&self.db)?;
        crate::write_queue::immediate(&mut db)?.commit()?;
        match request.url().as_str() {
            super::super::google::TOKEN => {
                assert_eq!(request.method(), reqwest::Method::POST);
                let fields = url::form_urlencoded::parse(
                    request
                        .body()
                        .context("refresh form")?
                        .as_bytes()
                        .context("refresh body")?,
                )
                .into_owned()
                .collect::<std::collections::BTreeMap<_, _>>();
                assert_eq!(fields.len(), 4);
                assert_eq!(fields["grant_type"], "refresh_token");
                assert_eq!(fields["refresh_token"], "private_runtime_refresh");
                assert_eq!(
                    fields["client_id"],
                    "123-refresh.apps.googleusercontent.com"
                );
                assert_eq!(fields["client_secret"], "private_refresh_client_credential");
                self.record("token_post")?;
                let ordinal = self.posts.fetch_add(1, SeqCst) + 2;
                if self.case == Case::LostReply {
                    anyhow::bail!("simulated response lost after possible dispatch");
                }
                if self.case == Case::RevokedAfterToken {
                    self.revoke()?;
                }
                if self.case == Case::EpochChanged {
                    db.execute(
                        "UPDATE oauth_connection_slots SET security_epoch=security_epoch+1",
                        [],
                    )?;
                }
                if self.case == Case::PolicyChanged {
                    self.narrow_policy()?;
                }
                if self.case == Case::ReadinessRewind {
                    self.now.store(260, SeqCst);
                }
                let mut body = json!({"access_token":format!("private_refresh_access_{ordinal}"),"token_type":"Bearer","expires_in":90,"scope":self.scopes});
                if self.case == Case::WrongScope {
                    body["scope"] = "openid".into();
                }
                if self.case == Case::ChangedRefresh {
                    body["refresh_token"] = "unreviewed_rotated_token".into();
                }
                response(body)
            }
            super::super::google::USERINFO => {
                assert_eq!(request.method(), reqwest::Method::GET);
                self.record("account_get")?;
                self.accounts.fetch_add(1, SeqCst);
                assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
                let version = self.posts.load(SeqCst) + 1;
                assert_eq!(
                    request.headers()[reqwest::header::AUTHORIZATION].to_str()?,
                    format!("Bearer private_refresh_access_{version}")
                );
                if self.case == Case::RevokedAfterAccount {
                    self.revoke()?;
                }
                if matches!(
                    self.case,
                    Case::PublicationRewind
                        | Case::PublicationErrorRecovery
                        | Case::PublicationClockUnavailable
                ) {
                    self.now.store(270, SeqCst);
                }
                if self.case == Case::CustodyFailure {
                    db.execute_batch("CREATE TRIGGER refuse_refresh_material BEFORE UPDATE ON oauth_private_tokens BEGIN SELECT RAISE(ABORT,'injected custody publication failure'); END")?;
                }
                response(
                    json!({"sub":if self.case == Case::WrongAccount {"google-bob"} else {"google-alice"},
                    "hd":"example.com","email_verified":true,"email":"presentation-only@example.com"}),
                )
            }
            _ => {
                assert_eq!(request.method(), reqwest::Method::GET);
                self.record("calendar_get")?;
                assert_eq!(request.url().host_str(), Some("www.googleapis.com"));
                assert_eq!(
                    request.url().path(),
                    "/calendar/v3/calendars/primary/events"
                );
                self.reads.fetch_add(1, SeqCst);
                let version: i64 = db.query_row(
                    "SELECT token_version FROM oauth_connection_slots",
                    [],
                    |row| row.get(0),
                )?;
                assert!(version > 1);
                assert_eq!(
                    request.headers()[reqwest::header::AUTHORIZATION].to_str()?,
                    format!("Bearer private_refresh_access_{version}")
                );
                response(json!({"kind":"calendar#events","items":[]}))
            }
        }
    }
}

struct NativeAuthority {
    selection: Selection,
    port: Arc<Port>,
    commits: AtomicUsize,
}

impl Authority for NativeAuthority {
    fn current(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        _: &mut super::super::admission::SubjectReader<'_, '_, '_, '_>,
    ) -> Result<Option<Selection>> {
        if self.port.case == Case::AbsentReturnRewind {
            let db = store::open(&self.port.db)?;
            let missing: bool = db.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM oauth_connection_slots)",
                [],
                |r| r.get(0),
            )?;
            if missing {
                self.port.activate_on_fill.store(true, SeqCst);
            }
        }
        if self.port.case == Case::ReadinessRewind && self.port.posts.load(SeqCst) > 0 {
            self.port.now.store(255, SeqCst);
        }
        Ok(Some(self.selection.clone()))
    }
    fn custody(
        &self,
        _: &str,
        _: &str,
        _: &str,
        expected: &Digest,
        _: i64,
        _: &mut super::super::admission::SubjectReader<'_, '_, '_, '_>,
    ) -> Result<Option<KeyLease>> {
        assert_eq!(&self.selection.identity()?, expected);
        Ok(Some(profiles::tests::exchange_key()))
    }
    fn refresh_client(
        &self,
        _: &str,
        _: &str,
        _: &str,
        expected: &Digest,
        _: i64,
        _: &mut super::super::admission::SubjectReader<'_, '_, '_, '_>,
    ) -> Result<Option<refresh::ClientCredential>> {
        assert_eq!(&self.selection.identity()?, expected);
        if self.port.case == Case::CredentialRewind {
            self.port.now.store(245, SeqCst);
            return Err(refresh::ClockRefusal.into());
        }
        let checked_at = if self.port.case == Case::ClientReturnRewind {
            270
        } else {
            self.port.now.load(SeqCst)
        };
        if self.port.case == Case::ClientReturnRewind {
            self.port.now.store(265, SeqCst);
        }
        Ok(Some(refresh::ClientCredential::new(
            "123-refresh.apps.googleusercontent.com".into(),
            "private_refresh_client_credential".into(),
            self.selection
                .instance
                .registration
                .client_credential
                .clone(),
            checked_at,
        )?))
    }
    fn with_current<'owner, 'stage, 'role, 'original>(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        subjects: &mut super::super::admission::SubjectReader<'owner, 'stage, 'role, 'original>,
        commit: &mut dyn FnMut(
            &Selection,
            &mut super::super::admission::SubjectReader<'owner, 'stage, 'role, 'original>,
        ) -> Result<bool>,
    ) -> Result<bool> {
        let call = self.commits.fetch_add(1, SeqCst);
        if call == 0 && self.port.case == Case::DispatchReturnRewind {
            self.port.now.store(270, SeqCst);
        }
        if call == 0 && self.port.case == Case::DispatchErrorRecovery {
            self.port.now.store(245, SeqCst);
        }
        if call == 1 {
            if matches!(
                self.port.case,
                Case::PublicationRewind
                    | Case::PublicationErrorRecovery
                    | Case::PublicationClockUnavailable
            ) {
                self.port.now.store(265, SeqCst);
            }
            if self.port.case == Case::PublicationExpired {
                self.port.now.store(340, SeqCst);
            }
            if matches!(
                self.port.case,
                Case::ReturnRewind | Case::SuccessorReturnRewind
            ) {
                self.port.now.store(270, SeqCst);
            }
            if self.port.case == Case::PublicationFallbackRewind {
                self.port.now.store(270, SeqCst);
                self.port.narrow_policy()?;
                self.port.publication_clock_reads.store(0, SeqCst);
            }
        }
        let result = commit(&self.selection, subjects);
        if call == 0 && self.port.case == Case::DispatchErrorRecovery {
            self.port.now.store(250, SeqCst);
        }
        if call == 1 && self.port.case == Case::PublicationErrorRecovery {
            self.port.now.store(270, SeqCst);
        }
        if call == 1 && self.port.case == Case::PublicationClockUnavailable {
            self.port.fail_clock.store(true, SeqCst);
        }
        if call == 1 && self.port.case == Case::PublicationFallbackRewind {
            assert_eq!(
                self.port.publication_clock_reads.load(SeqCst),
                1,
                "the actual publication validator must sample 270 before its authority error"
            );
            assert!(
                result.is_err(),
                "the narrowed authority must reject publication"
            );
            self.port.now.store(265, SeqCst);
        }
        if call == 0
            && result.as_ref().is_ok_and(|value| *value)
            && self.port.case == Case::DispatchReturnRewind
        {
            self.port.now.store(265, SeqCst);
        }
        if call == 1
            && result.as_ref().is_ok_and(|value| *value)
            && matches!(
                self.port.case,
                Case::ReturnRewind | Case::SuccessorReturnRewind
            )
        {
            if self.port.case == Case::SuccessorReturnRewind {
                let mut successor = self.port.local_runtime.clone();
                successor.connections = Some(Arc::new(NativeAuthority {
                    selection: self.selection.clone(),
                    port: self.port.clone(),
                    commits: AtomicUsize::new(2),
                }));
                self.port.now.store(280, SeqCst);
                let human = crate::iap::Verified {
                    email: "alice@example.com".into(),
                    subject: "accounts.google.com:google-alice".into(),
                };
                let input = json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"});
                let outcome = successor.invoke_verified(
                    "oauthcalendar.list_events",
                    store::RequestIdentity {
                        actor: &human.email,
                        origin: Some(&human),
                    },
                    "concurrent_successor_v3",
                    &input,
                    280,
                    store::Fault::None,
                )?;
                assert_eq!(
                    outcome.result["status"], "ok",
                    "concurrent successor must use real sealed publication"
                );
            }
            self.port.now.store(265, SeqCst);
        }
        result
    }
}

fn activate(runtime: &Runtime, fixture: &profiles::tests::QualificationFixture) -> Result<()> {
    let mut db = store::open(runtime.db())?;
    let key = profiles::tests::exchange_key();
    let prepared = exchange::prepare_authorization(
        fixture.input(),
        &key,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
    )?;
    let code_ref = prepared.code_ref().to_owned();
    assert!(prepared.begin(&mut db, 1)?);
    let raw = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", "0123456789abcdefghijklmnopqrstuvwxyzABCDEF")
        .append_pair("code", "private_original_code")
        .append_pair("iss", &fixture.reviewed.issuer_url)
        .finish();
    assert!(matches!(
        exchange::handle_qualified_callback(
            &mut db,
            fixture.input(),
            outbound::CallbackIngress {
                attempt: &fixture.intent.attempt,
                raw_query: raw.as_bytes(),
                route: &fixture.instance.registration.callback,
                session: fixture.binding.session(),
                issuer_binding: &fixture.reviewed.issuer,
                code_ref: &code_ref,
                now: 2
            },
            &key,
        )?,
        outbound::CallbackOutcome::CodeAccepted { .. }
    ));
    let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)?
        .context("original permit")?;
    let scopes = fixture
        .permission
        .action_scopes
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ");
    let exchange::ExchangeObservation::Response(response) = permit.send(|_| Ok(exchange::TokenHttpResponse {
        status:200, content_type:"application/json".into(), body:serde_json::to_vec(&json!({"access_token":"private_original_access",
        "refresh_token":"private_runtime_refresh","token_type":"Bearer","expires_in":300,"scope":scopes}))? })) else { anyhow::bail!("original response"); };
    let profiles::AccountBindingEvidence::MappedHuman { mapping, .. } = &fixture.instance.account
    else {
        anyhow::bail!("mapped fixture");
    };
    let mapped = account::MappedHumanEvidence {
        human: fixture.intent.owner.clone(),
        issuer: fixture.reviewed.issuer_url.clone(),
        provider_subject: "google-alice".into(),
        tenant: "example.com".into(),
        mapping_revision: mapping.revision.clone(),
    };
    let observed = account::ProviderAccount {
        issuer: mapped.issuer.clone(),
        subject: mapped.provider_subject.clone(),
        tenant: mapped.tenant.clone(),
        display_email: "alice@example.com".into(),
    };
    let prepared = response
        .validate_mapped(fixture.input(), &mapped, &observed)?
        .prepare_tokens(&key)?;
    assert!(exchange::settle_mapped(
        &mut db,
        prepared,
        fixture.input(),
        &mapped.mapping_revision,
        4
    )?);
    Ok(())
}

#[test]
fn compiled_calendar_refresh_publishes_versions_and_fences_failure_recovery() -> Result<()> {
    let artifact = std::env::var("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
        .context("compiled Calendar artifact required")?;
    for case in [
        Case::Complete,
        Case::LostReply,
        Case::WrongScope,
        Case::WrongAccount,
        Case::ChangedRefresh,
        Case::RevokedAfterToken,
        Case::RevokedAfterAccount,
        Case::PolicyChanged,
        Case::EpochChanged,
        Case::ReadinessRewind,
        Case::PublicationRewind,
        Case::PublicationExpired,
        Case::CustodyFailure,
        Case::CredentialRewind,
        Case::ReturnRewind,
        Case::MaterialSubstitution,
        Case::SuccessorReturnRewind,
        Case::AbsentReturnRewind,
        Case::ClientReturnRewind,
        Case::DispatchReturnRewind,
        Case::DispatchErrorRecovery,
        Case::PublicationErrorRecovery,
        Case::PublicationClockUnavailable,
        Case::PublicationFallbackRewind,
    ] {
        let directory = tempfile::tempdir()?;
        let instance_path = directory.path().join("instance.json");
        fs::write(
            &instance_path,
            serde_json::to_vec(&crate::development::verification_instance_data(
                std::path::Path::new(&artifact),
                None,
                "alice@example.com",
            )?)?,
        )?;
        let mut runtime = Runtime::from_artifact_for_tests(
            instance_path,
            "app".into(),
            directory.path().join("app.sqlite"),
            LoadedArtifact::load(std::path::Path::new(&artifact))?,
        )?;
        runtime.initialize()?;
        let (selection, fixture) = super::tests::product_selection(&runtime)?;
        let scopes = fixture
            .permission
            .action_scopes
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(" ");
        let port = Arc::new(Port {
            case,
            db: runtime.db().to_owned(),
            local_runtime: runtime.clone(),
            scopes,
            now: AtomicI64::new(250),
            entropy: AtomicU64::new(1),
            posts: AtomicUsize::new(0),
            accounts: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            crash: None,
            transport: None,
            activate_on_fill: AtomicBool::new(false),
            fail_clock: AtomicBool::new(false),
            publication_clock_reads: AtomicUsize::new(0),
        });
        let result = fixture_scope(port.clone(), || -> Result<()> {
            if case != Case::AbsentReturnRewind {
                activate(&runtime, &fixture)?;
            }
            runtime.connections = Some(Arc::new(NativeAuthority {
                selection,
                port: port.clone(),
                commits: AtomicUsize::new(0),
            }));
            let db = store::open(runtime.db())?;
            if case == Case::MaterialSubstitution {
                db.execute(
                    "UPDATE oauth_private_tokens SET reference='substituted_material_reference'",
                    [],
                )?;
            }
            let original: Option<Vec<u8>> = db
                .query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| {
                    r.get(0)
                })
                .optional()?;
            let human = crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "accounts.google.com:google-alice".into(),
            };
            crate::iap::bind_subject(&db, &human, 250)?;
            let input = json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"});
            let invoke = |id: &str| {
                runtime.invoke_verified(
                    "oauthcalendar.list_events",
                    store::RequestIdentity {
                        actor: &human.email,
                        origin: Some(&human),
                    },
                    id,
                    &input,
                    port.now.load(SeqCst),
                    store::Fault::None,
                )
            };
            let first = invoke("refresh_v2");
            if case == Case::Complete {
                let outcome = first.with_context(|| format!("{case:?} v2"))?;
                assert_eq!(outcome.status, "success");
                assert_eq!(outcome.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 1);
                assert_eq!(port.accounts.load(SeqCst), 1);
                assert_eq!(port.reads.load(SeqCst), 1);
                let binding = exchange::load_binding(&db, &fixture.intent.attempt)?
                    .context("activation binding")?;
                let account: String =
                    db.query_row("SELECT account FROM oauth_connection_slots", [], |r| {
                        r.get(0)
                    })?;
                let key = profiles::tests::exchange_key();
                let token = super::super::custody::load_access(
                    &db,
                    &key,
                    &fixture.intent,
                    &binding,
                    &account,
                    2,
                    250,
                )?
                .context("v2 material")?;
                assert_eq!(token.expires_at, 340);
                assert!(
                    super::super::custody::load_access(
                        &db,
                        &key,
                        &fixture.intent,
                        &binding,
                        &account,
                        1,
                        250
                    )
                    .is_err()
                );
                // Drop the returned outcome and reopen the store as a caller
                // recovering a lost acknowledgement. The committed receipt
                // permits observation, never another refresh of base version 1.
                drop(outcome);
                let reopened = store::open(runtime.db())?;
                assert_eq!(reopened.query_row("SELECT count(*) FROM oauth_refresh_attempts WHERE state='replacement_committed' AND base_version=1 AND next_version=2 AND length(receipt)>0", [], |r| r.get::<_,i64>(0))?, 1);
                assert_eq!(invoke("after_lost_ack")?.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 1);
                // Stop a real compiled query after its preparation. Its genuine
                // Use remains pending while another
                // invocation publishes v3; ordinary cleanup must retain it.
                let interrupted = runtime
                    .invoke_verified(
                        "oauthcalendar.list_events",
                        store::RequestIdentity {
                            actor: &human.email,
                            origin: Some(&human),
                        },
                        "pending_v2",
                        &input,
                        250,
                        store::Fault::AfterPrepare,
                    )
                    .expect_err("expected the actual preparation boundary interruption");
                assert!(store::Fault::AfterPrepare.caused(&interrupted));
                assert_eq!(
                    db.query_row(
                        "SELECT status FROM day2_invocations WHERE id='pending_v2'",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    "pending"
                );
                let reference: String = db.query_row(
                    "SELECT reference FROM oauth_use_handles WHERE invocation='pending_v2'",
                    [],
                    |r| r.get(0),
                )?;
                port.now.store(280, SeqCst);
                assert_eq!(invoke("refresh_v3")?.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 2);
                assert_eq!(
                    db.query_row(
                        "SELECT token_version FROM oauth_connection_slots",
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    3
                );
                assert!(
                    super::super::custody::load_access(
                        &db,
                        &key,
                        &fixture.intent,
                        &binding,
                        &account,
                        2,
                        280
                    )
                    .is_err()
                );
                assert!(
                    super::super::custody::load_access(
                        &db,
                        &key,
                        &fixture.intent,
                        &binding,
                        &account,
                        3,
                        280
                    )?
                    .is_some()
                );
                let old = Request {
                    operation: "oauthcalendar.list_events".into(),
                    input: input.to_string(),
                    context: store::invocation_context(&db, "pending_v2")?,
                    observations: vec![],
                };
                let snapshot = db.unchecked_transaction()?;
                assert_eq!(snapshot.query_row("SELECT count(*) FROM oauth_use_handles WHERE reference=?1 AND invocation='pending_v2'", [&reference], |r| r.get::<_,i64>(0))?, 1, "the genuine pending Use must survive ordinary cleanup");
                let stale = load(&snapshot, &runtime, &old, "calendar", &reference, 280);
                snapshot.commit()?;
                assert_eq!(
                    stale
                        .err()
                        .context("stale Use survived publication")?
                        .to_string(),
                    "connection use generation or account changed",
                    "Use must fail on its material pin while its 60-second lifetime remains valid"
                );
                let reads = port.reads.load(SeqCst);
                // Query observations are not journaled: resuming prepares a
                // fresh authenticated v3 read rather than reusing the old Use.
                let resumed = runtime.execute("pending_v2", store::Fault::None)?;
                assert_eq!(resumed.status, "success");
                assert_eq!(resumed.result["status"], "ok");
                assert_eq!(port.posts.load(SeqCst), 2);
                assert_eq!(
                    port.reads.load(SeqCst),
                    reads + 1,
                    "resuming the query must prepare a fresh current-version read"
                );
            } else {
                assert!(
                    !first
                        .as_ref()
                        .is_ok_and(|o| o.status == "success" && o.result["status"] == "ok"),
                    "{case:?}: failed refresh completed a Calendar read"
                );
                let posts = match case {
                    Case::CredentialRewind
                    | Case::MaterialSubstitution
                    | Case::AbsentReturnRewind
                    | Case::ClientReturnRewind
                    | Case::DispatchReturnRewind => 0,
                    Case::DispatchErrorRecovery => 0,
                    Case::SuccessorReturnRewind => 2,
                    _ => 1,
                };
                assert_eq!(port.posts.load(SeqCst), posts, "{case:?}");
                assert_eq!(
                    port.reads.load(SeqCst),
                    usize::from(case == Case::SuccessorReturnRewind),
                    "{case:?}"
                );
                let version = match case {
                    Case::ReturnRewind => 2,
                    Case::SuccessorReturnRewind => 3,
                    _ => 1,
                };
                assert_eq!(
                    db.query_row(
                        "SELECT token_version FROM oauth_connection_slots",
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    version,
                    "{case:?}"
                );
                if case == Case::AbsentReturnRewind {
                    assert!(original.is_none());
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r
                            .get::<_, String>(0))?,
                        "active",
                        "uncaptured activation must not be retired"
                    );
                    assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM oauth_use_handles WHERE invocation='refresh_v2'",
                            [],
                            |r| r.get::<_, i64>(0)
                        )?,
                        0,
                        "absent-material clock floor failed to stop Use minting"
                    );
                } else if version == 1 {
                    assert_eq!(
                        db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| r
                            .get::<_, Vec<u8>>(0))?,
                        original.as_ref().context("original material")?.clone(),
                        "{case:?}: partial material publication"
                    );
                } else {
                    assert_ne!(
                        db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| r
                            .get::<_, Vec<u8>>(0))?,
                        original.as_ref().context("original material")?.clone(),
                        "{case:?}: committed successor missing"
                    );
                }
                if case == Case::ReadinessRewind {
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r
                            .get::<_, String>(0))?,
                        "reauth_required",
                        "the observed readiness clock refusal must persist before recovery"
                    );
                    assert_eq!(port.accounts.load(SeqCst), 0);
                    assert_eq!(
                        db.query_row("SELECT count(*) FROM oauth_refresh_attempts WHERE state='may_have_been_sent' AND base_version=1", [], |r| r.get::<_, i64>(0))?,
                        1,
                        "clock refusal cannot clear the durable no-resend barrier"
                    );
                }
                let before = port.posts.load(SeqCst);
                port.fail_clock.store(false, SeqCst);
                port.now.store(
                    if case == Case::SuccessorReturnRewind {
                        280
                    } else {
                        250
                    },
                    SeqCst,
                );
                let recovery = invoke("recovery_no_resend");
                if matches!(case, Case::SuccessorReturnRewind | Case::AbsentReturnRewind) {
                    assert_eq!(recovery?.result["status"], "ok");
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r
                            .get::<_, String>(0))?,
                        "active",
                        "late refusal must not disable v3"
                    );
                }
                assert_eq!(
                    port.posts.load(SeqCst),
                    before + usize::from(case == Case::AbsentReturnRewind),
                    "{case:?}: recovery resent an unresolved base"
                );
                if matches!(
                    case,
                    Case::ReadinessRewind
                        | Case::PublicationRewind
                        | Case::PublicationExpired
                        | Case::CredentialRewind
                        | Case::ReturnRewind
                        | Case::MaterialSubstitution
                        | Case::ClientReturnRewind
                        | Case::DispatchReturnRewind
                        | Case::DispatchErrorRecovery
                        | Case::PublicationErrorRecovery
                        | Case::PublicationClockUnavailable
                        | Case::PublicationFallbackRewind
                ) {
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r
                            .get::<_, String>(0))?,
                        "reauth_required",
                        "{case:?}: observed clock or material refusal must persist"
                    );
                }
                if matches!(case, Case::PolicyChanged | Case::CustodyFailure) {
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |r| r
                            .get::<_, String>(0))?,
                        "active",
                        "generic authority/DB errors must not fabricate clock refusal"
                    );
                }
            }
            assert_eq!(
                db.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))?,
                0
            );
            Ok(())
        });
        if let Err(error) = result {
            let retained = directory.keep();
            anyhow::bail!(
                "compiled refresh case {case:?} failed; protected fixture retained at {}: {error:#}",
                retained.display()
            );
        }
    }
    Ok(())
}

fn crash_runtime(
    directory: &std::path::Path,
    artifact: &std::path::Path,
    create: bool,
) -> Result<Runtime> {
    let instance_path = directory.join("instance.json");
    if create {
        fs::write(
            &instance_path,
            serde_json::to_vec(&crate::development::verification_instance_data(
                artifact,
                None,
                "alice@example.com",
            )?)?,
        )?;
    }
    let runtime = Runtime::from_artifact_for_tests(
        instance_path,
        "app".into(),
        directory.join("app.sqlite"),
        LoadedArtifact::load(artifact)?,
    )?;
    runtime.initialize()?;
    Ok(runtime)
}

fn crash_authority(
    runtime: &mut Runtime,
    directory: &std::path::Path,
    point: Option<effects::RefreshBoundary>,
) -> Result<(Arc<Port>, profiles::tests::QualificationFixture)> {
    let (selection, fixture) = super::tests::product_selection(runtime)?;
    let scopes = fixture
        .permission
        .action_scopes
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ");
    let port = Arc::new(Port {
        case: Case::Complete,
        db: runtime.db().to_owned(),
        local_runtime: runtime.clone(),
        scopes,
        now: AtomicI64::new(250),
        entropy: AtomicU64::new(500),
        posts: AtomicUsize::new(0),
        accounts: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        crash: point,
        transport: Some(directory.join("transport.sqlite")),
        activate_on_fill: AtomicBool::new(false),
        fail_clock: AtomicBool::new(false),
        publication_clock_reads: AtomicUsize::new(0),
    });
    runtime.connections = Some(Arc::new(NativeAuthority {
        selection,
        port: port.clone(),
        commits: AtomicUsize::new(0),
    }));
    Ok((port, fixture))
}

#[test]
fn compiled_refresh_crash_recovery_uses_sealed_dispatch_and_publication() -> Result<()> {
    const CHILD_DIRECTORY: &str = "DAY2_REFRESH_CRASH_DIRECTORY";
    const CHILD_POINT: &str = "DAY2_REFRESH_CRASH_POINT";
    let artifact = PathBuf::from(
        std::env::var("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
            .context("compiled Calendar artifact required")?,
    );
    let human = crate::iap::Verified {
        email: "alice@example.com".into(),
        subject: "accounts.google.com:google-alice".into(),
    };
    let input = json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"});
    let points = [
        effects::RefreshBoundary::DispatchCommitted,
        effects::RefreshBoundary::MaterialWritten,
        effects::RefreshBoundary::PublicationCommitted,
    ];
    if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
        let directory = PathBuf::from(directory);
        let selected = std::env::var(CHILD_POINT)?;
        let point = points
            .into_iter()
            .find(|point| format!("{point:?}") == selected)
            .context("unknown child boundary")?;
        let mut runtime = crash_runtime(&directory, &artifact, false)?;
        let (port, _) = crash_authority(&mut runtime, &directory, Some(point))?;
        effects::scope(port, || {
            runtime.invoke_verified(
                "oauthcalendar.list_events",
                store::RequestIdentity {
                    actor: &human.email,
                    origin: Some(&human),
                },
                "crashed_refresh",
                &input,
                250,
                store::Fault::None,
            )
        })?;
        anyhow::bail!("child missed its real production boundary");
    }
    for point in points {
        let directory = tempfile::tempdir()?;
        let result = fixture_result(|| -> Result<()> {
            let transport = Connection::open(directory.path().join("transport.sqlite"))?;
            transport.execute_batch(
                "CREATE TABLE sends(seq INTEGER PRIMARY KEY, phase TEXT NOT NULL)",
            )?;
            let mut runtime = crash_runtime(directory.path(), &artifact, true)?;
            fs::write(
                directory.path().join("campaign.json"),
                serde_json::to_vec_pretty(&json!({
                    "test":"compiled_refresh_crash_recovery_uses_sealed_dispatch_and_publication",
                    "boundary":format!("{point:?}"), "artifact":runtime.artifact().id(),
                    "test_executable":std::env::current_exe()?, "scope":"native simulated provider, real admitted worker, real private custody/dispatch/publication and process exit; no live qualification"
                }))?,
            )?;
            let (port, fixture) = crash_authority(&mut runtime, directory.path(), None)?;
            effects::scope(port, || -> Result<()> {
                activate(&runtime, &fixture)?;
                crate::iap::bind_subject(&store::open(runtime.db())?, &human, 250)?;
                Ok(())
            })?;
            let db = store::open(runtime.db())?;
            let original: Vec<u8> =
                db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| {
                    r.get(0)
                })?;
            drop(db);
            drop(runtime);
            let stdout = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.path().join("child.stdout"))?;
            let stderr = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.path().join("child.stderr"))?;
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "oauth::usage::refresh_tests::compiled_refresh_crash_recovery_uses_sealed_dispatch_and_publication", "--nocapture"])
                .env(CHILD_DIRECTORY, directory.path()).env(CHILD_POINT, format!("{point:?}"))
                .stdout(std::process::Stdio::from(stdout)).stderr(std::process::Stdio::from(stderr)).spawn()?;
            let started = std::time::Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    child.kill()?;
                    let _ = child.wait()?;
                    anyhow::bail!("child exceeded bounded crash campaign deadline");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            ensure!(
                status.code() == Some(86),
                "wrong child exit at {point:?}: {status}"
            );
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase=?1",
                    [format!("boundary:{point:?}")],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            let child_posts = i64::from(point != effects::RefreshBoundary::DispatchCommitted);
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase='token_post'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                child_posts
            );
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase='account_get'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                child_posts
            );
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase='calendar_get'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            let mut recovered = crash_runtime(directory.path(), &artifact, false)?;
            let (port, fixture) = crash_authority(&mut recovered, directory.path(), None)?;
            effects::scope(port.clone(), || -> Result<()> {
                let db = store::open(recovered.db())?;
                let committed = point == effects::RefreshBoundary::PublicationCommitted;
                let (version, state, next, receipt): (i64,String,Option<i64>,Option<String>) = db.query_row(
                    "SELECT s.token_version,r.state,r.next_version,r.receipt FROM oauth_connection_slots s JOIN oauth_refresh_attempts r ON r.slot=s.slot",
                    [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
                let ciphertext: Vec<u8> =
                    db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| {
                        r.get(0)
                    })?;
                if committed {
                    assert_eq!(
                        (version, state, next),
                        (2, "replacement_committed".into(), Some(2))
                    );
                    assert!(receipt.as_ref().is_some_and(|s| !s.is_empty()));
                    assert_ne!(ciphertext, original);
                    let binding = exchange::load_binding(&db, &fixture.intent.attempt)?
                        .context("original binding")?;
                    let account: String =
                        db.query_row("SELECT account FROM oauth_connection_slots", [], |r| {
                            r.get(0)
                        })?;
                    assert!(
                        super::super::custody::load_access(
                            &db,
                            &profiles::tests::exchange_key(),
                            &fixture.intent,
                            &binding,
                            &account,
                            2,
                            250
                        )?
                        .is_some()
                    );
                } else {
                    assert_eq!(
                        (version, state, next, receipt),
                        (1, "may_have_been_sent".into(), None, None)
                    );
                    assert_eq!(
                        ciphertext, original,
                        "partial publication survived process exit"
                    );
                }
                // Resume the same accepted product invocation. It must observe
                // committed v2 or refuse unresolved dispatch, never refresh again.
                let outcome = recovered.execute("crashed_refresh", store::Fault::None);
                if committed {
                    let outcome = outcome?;
                    assert_eq!(outcome.status, "success");
                    assert_eq!(outcome.result["status"], "ok");
                    assert_eq!(port.reads.load(SeqCst), 1);
                    assert_eq!(
                        recovered
                            .execute("crashed_refresh", store::Fault::None)?
                            .result["status"],
                        "ok"
                    );
                    assert_eq!(
                        port.reads.load(SeqCst),
                        1,
                        "settled replay repeated provider read"
                    );
                } else {
                    assert!(
                        !outcome
                            .as_ref()
                            .is_ok_and(|o| o.status == "success" && o.result["status"] == "ok")
                    );
                    assert_eq!(port.reads.load(SeqCst), 0);
                }
                assert_eq!(port.posts.load(SeqCst), 0);
                assert_eq!(
                    db.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))?,
                    0
                );
                Ok(())
            })?;
            // This durable oracle includes both processes, unlike per-process
            // Atomic counters. Recovery cannot erase or hide a second send.
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase='token_post'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                child_posts
            );
            assert_eq!(
                transport.query_row(
                    "SELECT count(*) FROM sends WHERE phase='account_get'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                child_posts
            );
            Ok(())
        });
        if let Err(error) = result {
            let retained = directory.keep();
            anyhow::bail!(
                "{point:?} sealed refresh crash failed; protected fixture and child output retained at {}: {error:#}",
                retained.display()
            );
        }
    }
    Ok(())
}
