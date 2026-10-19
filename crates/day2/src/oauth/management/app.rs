//! The owning app's closed management protocol. Browser/session assertions are
//! verified by the private receiver before reaching this module.
use super::{Action, Attestation, SlotFence, View};
use crate::{
    authority_state, iap,
    oauth::{admission, effects, usage},
    store::{self, Runtime},
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{Digest, oauth::AccountBindingPolicy};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use usage::Authority as _;

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Call {
    Capture {
        registration: String,
        operation: Action,
    },
    Pending {
        id: String,
    },
    Confirm {
        id: String,
        proof: Attestation,
    },
    Callback {
        id: String,
        query: String,
        session: Digest,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Reply {
    Pending { view: Box<View> },
    Redirect { location: String },
    Completed { status: String },
}

pub(in crate::oauth) fn install(db: &Connection) -> Result<()> {
    crate::oauth::schema::install_current(db, "oauth_management_schema_version", 1,
        "CREATE TABLE IF NOT EXISTS oauth_management_schema_version(version INTEGER PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS oauth_management_intents(
             id TEXT PRIMARY KEY,
             view TEXT NOT NULL CHECK(length(view) <= 16384 AND json_valid(view) AND json_type(view)='object'),
             expires_at INTEGER NOT NULL,
             state TEXT NOT NULL CHECK(state IN ('pending','authorized','completed','intervention_required')),
             session TEXT,
             CHECK(json_extract(view,'$.id')=id AND json_extract(view,'$.expires_at')=expires_at),
             CHECK((state='pending')=(session IS NULL))
         );
         CREATE TABLE IF NOT EXISTS oauth_management_dispatch_slots(
             slot TEXT PRIMARY KEY,
             attempt TEXT NOT NULL UNIQUE REFERENCES oauth_management_intents(id)
         );",
        &[crate::oauth::schema::Invariant { table: "oauth_management_intents", predicate:
            "length(id) BETWEEN 20 AND 128 AND length(view) BETWEEN 1 AND 16384 AND json_valid(view)
             AND json_type(view)='object' AND expires_at>0
             AND state IN ('pending','authorized','completed','intervention_required')
             AND (state='pending')=(session IS NULL)
             AND json_extract(view,'$.id')=id AND json_extract(view,'$.expires_at')=expires_at
             AND (session IS NULL OR length(session)=71)" },
          crate::oauth::schema::Invariant { table: "oauth_management_dispatch_slots", predicate:
            "length(slot)=71 AND length(attempt) BETWEEN 20 AND 128
             AND EXISTS(SELECT 1 FROM oauth_management_intents i WHERE i.id=attempt
                 AND i.state IN ('authorized','completed','intervention_required')
                 AND json_extract(i.view,'$.slot')=slot)" }])
}

pub(crate) struct Manager {
    runtime: Runtime,
    authority: Arc<admission::ArtifactApprovalAuthority>,
}

impl Manager {
    pub(in crate::oauth) fn native_scopes(
        &self,
    ) -> Result<Vec<day2_capabilities::security_epoch::AuthorityScope>> {
        let instance = crate::artifact::Instance::load(self.runtime.instance_path())?;
        ensure!(
            instance.scope(self.runtime.app())? == self.runtime.scope(),
            "native App scope changed"
        );
        crate::oauth::native_management::selected_scopes(&instance, Some(self.runtime.app()))
    }

    pub(in crate::oauth) fn app(&self) -> &str {
        self.runtime.app()
    }

    pub(in crate::oauth) fn new(
        runtime: Runtime,
        authority: Arc<admission::ArtifactApprovalAuthority>,
    ) -> Self {
        Self { runtime, authority }
    }

    pub(in crate::oauth) fn dispatch(
        &self,
        call: Call,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Reply> {
        match call {
            Call::Capture {
                registration,
                operation,
            } => Ok(Reply::Pending {
                view: Box::new(self.capture(&registration, operation, identity, now)?),
            }),
            Call::Pending { id } => Ok(Reply::Pending {
                view: Box::new(self.pending(&id, identity, now)?),
            }),
            Call::Confirm { id, proof } => {
                let view = self.pending(&id, identity, now)?;
                match view.action {
                    Action::Connect => Ok(Reply::Redirect {
                        location: self.authorize_connect(&id, &proof, identity, now)?,
                    }),
                    Action::Disconnect => self.disconnect(&view, &proof, identity, now),
                }
            }
            Call::Callback { id, query, session } => {
                self.callback(&id, &query, &session, identity, now)
            }
        }
    }

    fn authority_in(
        &self,
        db: &Connection,
        identity: &iap::Verified,
    ) -> Result<authority_state::AuthorityStamp> {
        self.runtime.check_binding(db)?;
        let active = authority_state::current(db)?;
        ensure!(
            active.document.enabled
                && active.artifact_id == self.runtime.artifact().id()
                && std::path::Path::new(&active.artifact_path)
                    == self.runtime.artifact().directory()
                && active.document.hosted_domain.as_deref() == self.runtime.hosted_domain()
                && (crate::authority::admits(&active.document.readers, &identity.email)
                    || crate::authority::admits(&active.document.writers, &identity.email)),
            "OAuth management current authority refused"
        );
        active.document.validate(self.runtime.artifact())?;
        let subject: Option<String> = db
            .query_row(
                "SELECT subject FROM day2_principals WHERE email=?1",
                [&identity.email],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            subject.as_deref() == Some(identity.subject.as_str()),
            "OAuth management subject changed"
        );
        Ok(active.stamp)
    }

    fn selection(
        &self,
        registration: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<usage::Selection> {
        use crate::oauth::approval_registry::ApprovalAuthority as _;
        self.authority
            .observe_identity(self.runtime.app(), identity, now)?;
        let selection = usage::Authority::current(
            self.authority.as_ref(),
            self.runtime.app(),
            registration,
            &identity.email,
            now,
        )?
        .context("OAuth registration not ready")?;
        ensure!(
            selection.requirement.account_policy == AccountBindingPolicy::MappedHuman
                && selection.reviewed.issuer_url == crate::oauth::google::ISSUER
                && selection.reviewed.token_endpoint == crate::oauth::google::TOKEN,
            "OAuth product management profile unavailable"
        );
        Ok(selection)
    }

    fn fence(db: &Connection, slot: &Digest) -> Result<Option<SlotFence>> {
        Ok(db
            .query_row(
                "SELECT generation,security_epoch,token_version,account,affinity,profile,status
             FROM oauth_connection_slots WHERE slot=?1",
                [slot.as_str()],
                |row| {
                    Ok(SlotFence {
                        generation: row.get(0)?,
                        epoch: row.get(1)?,
                        token_version: row.get(2)?,
                        account: row.get(3)?,
                        affinity: row.get(4)?,
                        profile: row.get(5)?,
                        status: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    fn load(
        &self,
        db: &Connection,
        id: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<(View, String, Option<String>)> {
        crate::oauth::connect::identifier(id)?;
        let (json, state, session): (String, String, Option<String>) = db.query_row(
            "SELECT view,state,session FROM oauth_management_intents WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let view: View = crate::json::decode(json.as_bytes())?;
        view.validate(identity, now)?;
        ensure!(
            view.id == id
                && view.app == self.runtime.app()
                && view.scope == self.runtime.scope()
                && view.artifact == self.runtime.artifact().id(),
            "OAuth management owner changed"
        );
        Ok((view, state, session))
    }

    fn check_in(&self, db: &Connection, view: &View, identity: &iap::Verified) -> Result<()> {
        ensure!(
            self.authority_in(db, identity)? == view.authority
                && Self::fence(db, &view.slot)? == view.fence,
            "OAuth management authority or slot changed"
        );
        if view.action == Action::Connect {
            Self::unclaimed(db, &view.slot, Some(&view.id))?;
        }
        Ok(())
    }

    fn unclaimed(db: &Connection, slot: &Digest, own: Option<&str>) -> Result<()> {
        let available: bool = db.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM oauth_management_dispatch_slots
            WHERE slot=?1 AND (?2 IS NULL OR attempt<>?2))",
            params![slot.as_str(), own],
            |row| row.get(0),
        )?;
        ensure!(
            available,
            "OAuth slot has a dispatched connection; disposable reset or operator cleanup required"
        );
        Ok(())
    }

    pub(super) fn capture(
        &self,
        registration: &str,
        action: Action,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<View> {
        let original = crate::oauth::native_management::capture_app(self.runtime.app())?;
        crate::oauth::connect::identifier(registration)?;
        let mut db = store::open(self.runtime.db())?;
        iap::bind_subject(&db, identity, now)?;
        self.authority_in(&db, identity)?;
        let selection = self.selection(registration, identity, now)?;
        let suffix = effects::random()?;
        let challenge = Digest::new(effects::random()?.as_bytes());
        let captured_at = effects::wall_time()?;
        ensure!(captured_at >= now, "OAuth management clock moved backwards");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if action == Action::Connect {
            Self::unclaimed(&tx, &selection.slot, None)?;
        }
        tx.execute(
            "DELETE FROM oauth_management_intents WHERE state='pending' AND expires_at<=?1",
            [captured_at],
        )?;
        let count: i64 =
            tx.query_row("SELECT count(*) FROM oauth_management_intents", [], |row| {
                row.get(0)
            })?;
        ensure!(count < 1024, "OAuth management capacity reached");
        let route = crate::oauth::shell_transport::route_prefix(
            selection.binding.namespace.installation.as_str(),
            selection.binding.namespace.environment.as_str(),
            self.runtime.app(),
        )?;
        let view = View {
            id: format!("{route}{suffix}"),
            app: self.runtime.app().into(),
            scope: self.runtime.scope().into(),
            artifact: self.runtime.artifact().id().into(),
            authority: self.authority_in(&tx, identity)?,
            registration: registration.into(),
            logical_id: selection.requirement.logical_id.clone(),
            action,
            human: identity.email.clone(),
            subject: identity.subject.clone(),
            selection: selection.identity()?,
            slot: selection.slot.clone(),
            fence: Self::fence(&tx, &selection.slot)?,
            binding_namespace: admission::binding_namespace(&selection.binding)?,
            usage: selection.requirement.usage.clone(),
            scopes: selection
                .permission
                .action_scopes
                .values()
                .flatten()
                .cloned()
                .collect(),
            app_origin: selection.instance.app_origin_url.clone(),
            shell_origin: selection.instance.shell.origin_url.clone(),
            callback_url: selection.instance.registration.callback_url.clone(),
            challenge,
            created_at: captured_at,
            expires_at: captured_at
                .checked_add(super::SECONDS)
                .context("OAuth management deadline overflow")?,
        };
        view.validate(identity, captured_at)?;
        let json = serde_json::to_string(&view)?;
        ensure!(json.len() <= 16384, "OAuth management context budget");
        tx.execute("INSERT INTO oauth_management_intents(id,view,expires_at,state) VALUES(?1,?2,?3,'pending')",
            params![view.id, json, view.expires_at])?;
        tx.commit()?;
        original.bind(
            &crate::oauth::fresh_auth::FreshIntent::management(&view, identity)?,
            captured_at,
        )?;
        Ok(view)
    }

    pub(super) fn pending(&self, id: &str, identity: &iap::Verified, now: i64) -> Result<View> {
        let db = store::open(self.runtime.db())?;
        let (view, state, _) = self.load(&db, id, identity, now)?;
        crate::oauth::native_management::check(
            &crate::oauth::fresh_auth::FreshIntent::management(&view, identity)?,
            crate::oauth::native_management::Phase::Pending,
            now,
        )?;
        ensure!(
            state == "pending",
            "OAuth management intent already consumed"
        );
        self.check_in(&db, &view, identity)?;
        drop(db);
        let selection = self.selection(&view.registration, identity, now)?;
        ensure!(
            selection.identity()? == view.selection,
            "OAuth management selection changed"
        );
        view.validate(identity, effects::wall_time()?)?;
        Ok(view)
    }

    pub(in crate::oauth) fn fresh_owner(
        &self,
        call: &crate::oauth::fresh_owner::CallData,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<crate::oauth::fresh_owner::ReplyData> {
        use crate::oauth::{fresh_auth::FreshIntent, fresh_owner::PurposeData};
        if call.purpose == PurposeData::CredentialIntent {
            return crate::managed_credentials::browser::fresh_owner(
                &self.runtime,
                call,
                identity,
                now,
            );
        }
        ensure!(
            matches!(
                call.purpose,
                PurposeData::OAuthConnect | PurposeData::OAuthDisconnect
            ),
            "OAuth management fresh purpose refused"
        );
        // Current selected registration/key acquisition happens before taking
        // the app writer; no SQLite transaction spans the private RPC.
        let expected = self.pending(&call.attempt, identity, now)?;
        let at = effects::wall_time()?;
        ensure!(at >= now, "OAuth management clock moved backwards");
        let mut db = store::open(self.runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let (view, state, _) = self.load(&tx, &call.attempt, identity, at)?;
        ensure!(
            state == "pending" && view == expected,
            "OAuth management pending changed"
        );
        self.check_in(&tx, &view, identity)?;
        let intent = FreshIntent::management(&view, identity)?;
        let reply =
            crate::oauth::fresh_owner::apply_in_current_app_transaction(&tx, &intent, call, at)?;
        tx.commit()?;
        Ok(reply)
    }

    pub(super) fn authorize_connect(
        &self,
        id: &str,
        proof: &Attestation,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<String> {
        let view = self.pending(id, identity, now)?;
        ensure!(
            view.action == Action::Connect,
            "OAuth management purpose changed"
        );
        self.authority
            .verify_management(&view, proof, identity, now)?;
        let selection = self.selection(&view.registration, identity, now)?;
        ensure!(
            selection.identity()? == view.selection,
            "OAuth management selection changed"
        );
        let key = self
            .authority
            .custody(
                self.runtime.app(),
                &view.registration,
                &identity.email,
                &view.selection,
                now,
            )?
            .context("OAuth custody unavailable")?;
        let verifier = effects::random()?;
        let state = format!("product.{}.{}", view.id, effects::random()?);
        let at = effects::wall_time()?;
        ensure!(at >= now, "OAuth management clock moved backwards");
        view.validate(identity, at)?;
        let callback = crate::oauth::connect::CallbackBinding::from_secret_state(
            state.as_bytes(),
            crate::oauth::connect::CallbackBindingSpec {
                issuer: selection.reviewed.issuer.clone(),
                issuer_url: selection.reviewed.issuer_url.clone(),
                security_origin: selection.instance.shell.origin.clone(),
                profile: selection.permission.profile.clone(),
                callback: selection.instance.registration.callback.clone(),
                binding_namespace: view.binding_namespace.clone(),
                session: proof.session.clone(),
                product_return: selection.binding.product_return.clone(),
            },
        )?;
        let intent = crate::oauth::connect::ConnectIntent {
            attempt: view.id.clone(),
            slot: view.slot.as_str().into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: view.human.clone(),
            profile: selection.permission.profile.id.as_str().into(),
            registration: Digest::of(&selection.instance.registration.registration)?
                .as_str()
                .into(),
            callback: Digest::of(&selection.instance.registration.callback)?
                .as_str()
                .into(),
            consent: selection
                .permission
                .consent_digest(&selection.requirement)?
                .as_str()
                .into(),
            expires_at: view.expires_at,
        };
        let prepared = crate::oauth::exchange::prepare_authorization(
            crate::oauth::profiles::OutboundQualification {
                intent: &intent,
                binding: &callback,
                requirement: &selection.requirement,
                permission: &selection.permission,
                reviewed: &selection.reviewed,
                instance: &selection.instance,
            },
            &key,
            &verifier,
        )?;
        let client = self.authority.management_client(&view)?;
        let mut location = url::Url::parse(&selection.reviewed.authorization_endpoint)?;
        ensure!(
            location.as_str() == crate::oauth::google::AUTHORIZATION,
            "OAuth authorization endpoint changed"
        );
        location.query_pairs_mut().extend_pairs([
            ("client_id", client.as_str()),
            (
                "redirect_uri",
                selection.instance.registration.callback_url.as_str(),
            ),
            ("response_type", "code"),
            (
                "scope",
                view.scopes
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .as_str(),
            ),
            ("state", state.as_str()),
            ("code_challenge", prepared.code_challenge()),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "false"),
            ("login_hint", identity.email.as_str()),
        ]);
        let mut db = store::open(self.runtime.db())?;
        let guard = StartGuard {
            manager: self,
            view: &view,
            identity,
            session: &proof.session,
        };
        let mut prepared = Some(prepared);
        let checking = effects::wall_time()?;
        ensure!(checking >= at, "OAuth connect clock moved backwards");
        view.validate(identity, checking)?;
        let started = usage::Authority::with_current(
            self.authority.as_ref(),
            self.runtime.app(),
            &view.registration,
            &identity.email,
            checking,
            &mut |current| {
                ensure!(
                    current.identity()? == view.selection,
                    "OAuth connect readiness changed"
                );
                let finished = effects::wall_time()?;
                ensure!(finished >= checking, "OAuth connect clock moved backwards");
                view.validate(identity, finished)?;
                crate::oauth::connect::begin_managed(
                    &mut db,
                    prepared.take().context("OAuth connect permit consumed")?,
                    finished,
                    &guard,
                )
            },
        )?;
        ensure!(started, "OAuth connect intent already consumed");
        Ok(location.into())
    }

    fn context(
        &self,
        db: &Connection,
        id: &str,
    ) -> Result<(
        crate::oauth::connect::ConnectIntent,
        crate::oauth::connect::CallbackBinding,
    )> {
        let (intent, callback): (_, String) = db.query_row(
            "SELECT a.slot,a.expected_generation,a.expected_epoch,a.proposed_generation,a.owner,a.profile,
             a.registration,a.callback,a.consent,a.expires_at,b.binding FROM oauth_connect_attempts a
             JOIN oauth_callback_bindings b ON b.attempt=a.attempt WHERE a.attempt=?1", [id], |row| {
                Ok((crate::oauth::connect::ConnectIntent { attempt: id.into(), slot: row.get(0)?, expected_generation: row.get(1)?,
                    expected_epoch: row.get(2)?, proposed_generation: row.get(3)?, owner: row.get(4)?, profile: row.get(5)?,
                    registration: row.get(6)?, callback: row.get(7)?, consent: row.get(8)?, expires_at: row.get(9)? }, row.get(10)?))
            })?;
        Ok((intent, crate::json::decode(callback.as_bytes())?))
    }

    fn callback(
        &self,
        id: &str,
        query: &str,
        session: &Digest,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Reply> {
        ensure!(query.len() <= 8192, "OAuth callback budget");
        let mut db = store::open(self.runtime.db())?;
        let (view, state, stored_session) = self.load(&db, id, identity, now)?;
        crate::oauth::native_management::check(
            &crate::oauth::fresh_auth::FreshIntent::management(&view, identity)?,
            crate::oauth::native_management::Phase::Callback,
            now,
        )?;
        ensure!(
            view.action == Action::Connect
                && state == "authorized"
                && stored_session.as_deref() == Some(session.as_str()),
            "OAuth callback confirmation missing or consumed"
        );
        self.check_in(&db, &view, identity)?;
        let selection = self.selection(&view.registration, identity, now)?;
        ensure!(
            selection.identity()? == view.selection,
            "OAuth callback selection changed"
        );
        let key = self
            .authority
            .custody(
                self.runtime.app(),
                &view.registration,
                &identity.email,
                &view.selection,
                now,
            )?
            .context("OAuth custody unavailable")?;
        let client = self
            .authority
            .refresh_client(
                self.runtime.app(),
                &view.registration,
                &identity.email,
                &view.selection,
                now,
            )?
            .context("OAuth client unavailable")?;
        let (intent, binding) = self.context(&db, id)?;
        let input = || crate::oauth::profiles::OutboundQualification {
            intent: &intent,
            binding: &binding,
            requirement: &selection.requirement,
            permission: &selection.permission,
            reviewed: &selection.reviewed,
            instance: &selection.instance,
        };
        let private =
            crate::oauth::exchange::load_binding(&db, id)?.context("OAuth exchange missing")?;
        let at = effects::wall_time()?;
        ensure!(at >= now, "OAuth callback clock moved backwards");
        view.validate(identity, at)?;
        let outcome = crate::oauth::exchange::handle_qualified_callback(
            &mut db,
            input(),
            crate::oauth::outbound::CallbackIngress {
                attempt: id,
                raw_query: query.as_bytes(),
                route: binding.callback(),
                session,
                issuer_binding: binding.issuer(),
                code_ref: &private.code_ref,
                now: at,
            },
            &key,
        )?;
        match outcome {
            crate::oauth::outbound::CallbackOutcome::Denied { .. } => {
                db.execute("UPDATE oauth_management_intents SET state='completed' WHERE id=?1 AND state='authorized'", [id])?;
                return Ok(Reply::Completed {
                    status: "Provider authorization declined.".into(),
                });
            }
            crate::oauth::outbound::CallbackOutcome::CodeAccepted { .. } => {}
            crate::oauth::outbound::CallbackOutcome::Rejected => {
                anyhow::bail!("OAuth callback refused")
            }
        }
        let guard = FinishGuard {
            manager: self,
            view: &view,
            identity,
            session,
        };
        let mut permit = None;
        let dispatched = usage::Authority::with_current(
            self.authority.as_ref(),
            self.runtime.app(),
            &view.registration,
            &identity.email,
            at,
            &mut |current| {
                ensure!(
                    current.identity()? == view.selection,
                    "OAuth exchange readiness changed"
                );
                let checked = effects::wall_time()?;
                ensure!(checked >= at, "OAuth exchange clock moved backwards");
                permit = crate::oauth::exchange::authorize_managed_exchange(
                    &mut db,
                    input(),
                    checked,
                    &guard,
                )?;
                Ok(permit.is_some())
            },
        )?;
        ensure!(dispatched, "OAuth exchange permit unavailable");
        let sent_at = effects::wall_time()?;
        ensure!(sent_at >= at, "OAuth exchange clock moved backwards");
        view.validate(identity, sent_at)?;
        let (outcome, account) = client.initial_exchange(
            permit.context("OAuth exchange permit absent")?,
            crate::oauth::refresh::InitialExchange {
                db: &db,
                key: &key,
                selection: &selection,
                subject: &identity.subject,
                now: sent_at,
                guard: &guard,
            },
        )?;
        let response = match outcome {
            crate::oauth::exchange::ExchangeObservation::Uncertain(uncertain) => {
                uncertain.record(&db)?;
                return Ok(Reply::Completed { status: "Connection outcome unknown. No connection was published; operator cleanup is required before another attempt.".into() });
            }
            crate::oauth::exchange::ExchangeObservation::Response(response) => response,
        };
        let crate::oauth::profiles::AccountBindingEvidence::MappedHuman { mapping, owner, .. } =
            &selection.instance.account
        else {
            anyhow::bail!("OAuth mapped account required");
        };
        ensure!(owner == &identity.email, "OAuth account owner changed");
        let subject = identity
            .subject
            .strip_prefix("accounts.google.com:")
            .context("OAuth Google subject unavailable")?;
        let mapped = crate::oauth::account::MappedHumanEvidence {
            human: identity.email.clone(),
            issuer: crate::oauth::google::ISSUER.into(),
            provider_subject: subject.into(),
            tenant: self
                .runtime
                .hosted_domain()
                .context("OAuth hosted domain unavailable")?
                .into(),
            mapping_revision: mapping.revision.clone(),
        };
        let prepared = response
            .validate_mapped(
                input(),
                &mapped,
                &account.context("OAuth provider account unavailable")?,
            )?
            .prepare_tokens(&key)?;
        let mut prepared = Some(prepared);
        let checking = effects::wall_time()?;
        ensure!(
            checking >= sent_at,
            "OAuth settlement clock moved backwards"
        );
        view.validate(identity, checking)?;
        let settled = usage::Authority::with_current(
            self.authority.as_ref(),
            self.runtime.app(),
            &view.registration,
            &identity.email,
            checking,
            &mut |current| {
                ensure!(
                    current.identity()? == view.selection,
                    "OAuth settlement readiness changed"
                );
                let finished = effects::wall_time()?;
                ensure!(
                    finished >= checking,
                    "OAuth settlement clock moved backwards"
                );
                crate::oauth::exchange::settle_managed(
                    &mut db,
                    prepared.take().context("OAuth settlement consumed")?,
                    input(),
                    &mapping.revision,
                    finished,
                    &guard,
                )
            },
        )?;
        ensure!(settled, "OAuth connection publication refused");
        Ok(Reply::Completed {
            status: "Connection active.".into(),
        })
    }

    fn disconnect(
        &self,
        view: &View,
        proof: &Attestation,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Reply> {
        crate::oauth::native_management::check(
            &crate::oauth::fresh_auth::FreshIntent::management(view, identity)?,
            crate::oauth::native_management::Phase::DisconnectCommit,
            now,
        )?;
        self.authority
            .verify_management(view, proof, identity, now)?;
        let fence = view
            .fence
            .as_ref()
            .context("OAuth disconnect slot absent")?;
        let mut db = store::open(self.runtime.db())?;
        let checking = effects::wall_time()?;
        ensure!(checking >= now, "OAuth disconnect clock moved backwards");
        view.validate(identity, checking)?;
        let fenced = usage::Authority::with_current(
            self.authority.as_ref(),
            self.runtime.app(),
            &view.registration,
            &identity.email,
            checking,
            &mut |current| {
                ensure!(
                    current.identity()? == view.selection,
                    "OAuth disconnect readiness changed"
                );
                let finished = effects::wall_time()?;
                ensure!(
                    finished >= checking,
                    "OAuth disconnect clock moved backwards"
                );
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let (stored, state, _) = self.load(&tx, &view.id, identity, finished)?;
                ensure!(
                    state == "pending" && stored == *view,
                    "OAuth disconnect pending changed"
                );
                self.check_in(&tx, view, identity)?;
                let changed = tx.execute("UPDATE oauth_connection_slots SET status='disabled',security_epoch=security_epoch+1
                WHERE slot=?1 AND generation=?2 AND token_version=?3 AND security_epoch=?4 AND status='active'",
                params![view.slot.as_str(), fence.generation, fence.token_version, fence.epoch])?;
                ensure!(changed == 1, "OAuth disconnect fence lost");
                tx.execute(
                    "UPDATE oauth_refresh_attempts SET state='publication_rejected' WHERE slot=?1
                AND state IN ('ready','may_have_been_sent','uncertain')",
                    [view.slot.as_str()],
                )?;
                tx.execute("UPDATE oauth_connect_attempts SET state='cancelled',code_ref=NULL,account=NULL,scope_evidence=NULL WHERE slot=?1
                AND state IN ('awaiting_provider_authorization','exchange_ready','exchange_may_have_been_sent','exchange_uncertain','awaiting_account_approval')", [view.slot.as_str()])?;
                tx.execute("DELETE FROM oauth_private_codes WHERE attempt IN(SELECT attempt FROM oauth_connect_attempts WHERE slot=?1 AND state='cancelled')", [view.slot.as_str()])?;
                tx.execute("DELETE FROM oauth_private_verifiers WHERE attempt IN(SELECT attempt FROM oauth_connect_attempts WHERE slot=?1 AND state='cancelled')", [view.slot.as_str()])?;
                tx.execute("DELETE FROM oauth_external_quarantine WHERE attempt IN(SELECT attempt FROM oauth_connect_attempts WHERE slot=?1 AND state='cancelled')", [view.slot.as_str()])?;
                tx.execute(
                    "DELETE FROM oauth_private_tokens WHERE slot=?1",
                    [view.slot.as_str()],
                )?;
                tx.execute("UPDATE oauth_management_intents SET state='intervention_required',session=?2 WHERE id=?1 AND state='pending'",
                params![view.id, proof.session.as_str()])?;
                tx.commit()?;
                Ok(true)
            },
        )?;
        ensure!(fenced, "OAuth disconnect not admitted");
        // Google revokes the account's grants for every client in the project.
        // This app cannot prove
        // the cross-app/installation holder inventory, so no automatic send is
        // safe. Local use is fenced; an operator must resolve provider cleanup.
        Ok(Reply::Completed { status: "Disconnected locally. Google grant revocation requires operator cleanup; no revocation request was sent.".into() })
    }
}

/// A transaction borrow of the actual manager and immutable original context.
/// It is constructed only after current shell signature/readiness checks.
pub(in crate::oauth) struct StartGuard<'a> {
    manager: &'a Manager,
    view: &'a View,
    identity: &'a iap::Verified,
    session: &'a Digest,
}

impl StartGuard<'_> {
    pub(in crate::oauth) fn check(&self, db: &Connection, now: i64) -> Result<()> {
        let (stored, state, _) = self.manager.load(db, &self.view.id, self.identity, now)?;
        ensure!(
            state == "pending" && stored == *self.view && self.view.action == Action::Connect,
            "OAuth connect pending context changed"
        );
        self.manager.check_in(db, self.view, self.identity)
    }

    pub(in crate::oauth) fn commit(&self, db: &Connection) -> Result<()> {
        let changed = db.execute(
            "UPDATE oauth_management_intents SET state='authorized',session=?2 WHERE id=?1 AND state='pending'",
            params![self.view.id, self.session.as_str()],
        )?;
        ensure!(changed == 1, "OAuth connect confirmation already consumed");
        Ok(())
    }
}

pub(in crate::oauth) struct FinishGuard<'a> {
    manager: &'a Manager,
    view: &'a View,
    identity: &'a iap::Verified,
    session: &'a Digest,
}

impl FinishGuard<'_> {
    pub(in crate::oauth) fn require_send(&self, entry: i64) -> Result<()> {
        let now = effects::wall_time()?;
        ensure!(now >= entry, "OAuth initial dispatch clock moved backwards");
        self.view.validate(self.identity, now)?;
        let selection = self
            .manager
            .selection(&self.view.registration, self.identity, now)?;
        ensure!(
            selection.identity()? == self.view.selection,
            "OAuth initial dispatch selection changed"
        );
        let finished = effects::wall_time()?;
        ensure!(
            finished >= now,
            "OAuth initial dispatch clock moved backwards"
        );
        let db = store::open(self.manager.runtime.db())?;
        self.check(&db, finished)?;
        self.require_dispatched(&db)
    }

    pub(in crate::oauth) fn commit_dispatch(&self, db: &Connection) -> Result<()> {
        db.execute(
            "INSERT INTO oauth_management_dispatch_slots(slot,attempt) VALUES(?1,?2)",
            params![self.view.slot.as_str(), self.view.id],
        )?;
        Ok(())
    }

    fn require_dispatched(&self, db: &Connection) -> Result<()> {
        ensure!(db.query_row("SELECT EXISTS(SELECT 1 FROM oauth_management_dispatch_slots WHERE slot=?1 AND attempt=?2)",
            params![self.view.slot.as_str(), self.view.id], |row| row.get::<_, bool>(0))?, "OAuth dispatch barrier absent");
        Ok(())
    }
    pub(in crate::oauth) fn check(&self, db: &Connection, now: i64) -> Result<()> {
        let (stored, state, session) = self.manager.load(db, &self.view.id, self.identity, now)?;
        ensure!(
            stored == *self.view
                && state == "authorized"
                && session.as_deref() == Some(self.session.as_str()),
            "OAuth callback original confirmation changed"
        );
        self.manager.check_in(db, self.view, self.identity)
    }

    pub(in crate::oauth) fn complete(&self, db: &Connection) -> Result<()> {
        self.require_dispatched(db)?;
        ensure!(db.execute("UPDATE oauth_management_intents SET state='completed' WHERE id=?1 AND state='authorized'",
            [&self.view.id])? == 1, "OAuth callback already completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{
        effects,
        fresh_auth::{FreshIntent, VerifiedAuthTime},
        shell_oidc,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst},
        time::Duration,
    };

    struct Port {
        now: AtomicI64,
        entropy: AtomicU64,
        posts: AtomicUsize,
        accounts: AtomicUsize,
        revokes: AtomicUsize,
        revoke_authority: Option<PathBuf>,
        expire_after_account: bool,
        lose_token_reply: AtomicBool,
        scope: String,
    }

    impl effects::Hooks for Port {
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("unscripted provider observation")
        }

        fn domain(&self) -> u64 {
            97831
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(self.now.load(SeqCst))
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(self.now.load(SeqCst) as u64)
        }
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let n = self.entropy.fetch_add(1, SeqCst);
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = n.wrapping_add(i as u64) as u8;
            }
            Ok(())
        }
        fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
            let value = match (request.method().as_str(), request.url().as_str()) {
                (
                    "GET",
                    "https://secretmanager.googleapis.com/v1/projects/12345/secrets/google_client_secret/versions/7:access",
                ) => {
                    let secret = "fixture-client-secret";
                    json!({"name":"projects/12345/secrets/google_client_secret/versions/7","payload":{
                        "data":STANDARD.encode(secret),"dataCrc32c":crc32c::crc32c(secret.as_bytes()).to_string()}})
                }
                ("POST", crate::oauth::google::TOKEN) => {
                    self.posts.fetch_add(1, SeqCst);
                    if self.lose_token_reply.load(SeqCst) {
                        anyhow::bail!("fixture token reply lost after dispatch");
                    }
                    assert_eq!(request.timeout(), Some(&Duration::from_secs(10)));
                    let fields = crate::web_security::fields(
                        request
                            .body()
                            .and_then(|b| b.as_bytes())
                            .context("token form missing")?,
                    )?;
                    assert_eq!(fields["code"], "private-provider-code");
                    assert_eq!(fields["client_secret"], "fixture-client-secret");
                    assert_eq!(fields["grant_type"], "authorization_code");
                    assert_eq!(fields["code_verifier"].len(), 43);
                    if let Some(path) = &self.revoke_authority {
                        store::open(path)?
                            .execute("UPDATE day2_authority SET revision=revision+1", [])?;
                    }
                    json!({"access_token":"private-access-token","refresh_token":"private-refresh-token",
                        "token_type":"Bearer","expires_in":3600,"scope":self.scope})
                }
                ("GET", crate::oauth::google::USERINFO) => {
                    self.accounts.fetch_add(1, SeqCst);
                    assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
                    assert_eq!(
                        request.headers()[reqwest::header::AUTHORIZATION],
                        "Bearer private-access-token"
                    );
                    if self.expire_after_account {
                        self.now.store(400, SeqCst);
                    }
                    json!({"sub":"alice","email":"alice@example.com","email_verified":true,"hd":"example.com"})
                }
                ("POST", "https://oauth2.googleapis.com/revoke") => {
                    self.revokes.fetch_add(1, SeqCst);
                    let fields = crate::web_security::fields(
                        request
                            .body()
                            .and_then(|b| b.as_bytes())
                            .context("revocation form missing")?,
                    )?;
                    assert_eq!(fields.len(), 1);
                    assert_eq!(fields["token"], "private-refresh-token");
                    json!({})
                }
                _ => anyhow::bail!("unexpected OAuth management transport"),
            };
            Ok(effects::Response::Simulated {
                status: reqwest::StatusCode::OK,
                headers: reqwest::header::HeaderMap::from_iter([(
                    reqwest::header::CONTENT_TYPE,
                    reqwest::header::HeaderValue::from_static("application/json"),
                )]),
                body: std::io::Cursor::new(serde_json::to_vec(&value)?),
                peer: None,
            })
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        manager: Manager,
        signer: Arc<admission::ArtifactShellSigner>,
        identity: iap::Verified,
        port: Arc<Port>,
    }

    impl Fixture {
        fn new(revoke_authority: bool) -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let (runtime, authority, signer) =
                admission::tests::management_fixture(directory.path())?;
            let port = Arc::new(Port {
                now: AtomicI64::new(100),
                entropy: AtomicU64::new(1),
                posts: AtomicUsize::new(0),
                accounts: AtomicUsize::new(0),
                revokes: AtomicUsize::new(0),
                revoke_authority: revoke_authority.then(|| runtime.db().to_path_buf()),
                expire_after_account: false,
                lose_token_reply: AtomicBool::new(false),
                scope: "openid email https://www.googleapis.com/auth/calendar.events.readonly"
                    .into(),
            });
            Ok(Self {
                _directory: directory,
                manager: Manager::new(runtime, authority),
                signer,
                identity: iap::Verified {
                    email: "alice@example.com".into(),
                    subject: "accounts.google.com:alice".into(),
                },
                port,
            })
        }

        fn proof(&self, view: &View, session: Digest) -> Result<Attestation> {
            self.port.now.store(view.created_at + 2, SeqCst);
            crate::oauth::native_management::reserve_shell(
                &FreshIntent::management(view, &self.identity)?,
                view.created_at + 2,
            )?;
            let proof = VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
                FreshIntent::management(view, &self.identity)?,
                self.identity.email.clone(),
                self.identity.subject.clone(),
                view.created_at + 1,
            ));
            self.signer.attest_management(
                view,
                &proof,
                &self.identity,
                session,
                view.created_at + 2,
            )
        }

        fn connect(&self) -> Result<(View, Digest, String)> {
            let at = self.port.now.load(SeqCst);
            let view = self
                .manager
                .capture("calendar", Action::Connect, &self.identity, at)?;
            let session = Digest::new(b"browser-session");
            let proof = self.proof(&view, session.clone())?;
            let url = self.manager.authorize_connect(
                &view.id,
                &proof,
                &self.identity,
                self.port.now.load(SeqCst),
            )?;
            let state = url::Url::parse(&url)?
                .query_pairs()
                .find(|(k, _)| k == "state")
                .context("state missing")?
                .1
                .into_owned();
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query
                .append_pair("state", &state)
                .append_pair("code", "private-provider-code")
                .append_pair("iss", crate::oauth::google::ISSUER);
            Ok((view, session, query.finish()))
        }
    }

    #[test]
    fn original_binding_covers_the_complete_committed_management_context() -> Result<()> {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            type Mutate = fn(&mut View, &mut iap::Verified);
            let mutations: &[Mutate] = &[
                |v, i| {
                    v.human = "bob@example.com".into();
                    i.email = v.human.clone();
                },
                |v, i| {
                    v.subject = "accounts.google.com:another".into();
                    i.subject = v.subject.clone();
                },
                |v, _| v.app = "anotherapp".into(),
                |v, _| v.scope = "another_scope".into(),
                |v, _| v.artifact = "another_artifact".into(),
                |v, _| v.authority.revision += 1,
                |v, _| v.registration = "another_registration".into(),
                |v, _| v.logical_id = "another_logical".into(),
                |v, _| v.selection = Digest::new(b"another selection"),
                |v, _| v.slot = Digest::new(b"another slot"),
                |v, _| v.challenge = Digest::new(b"another challenge"),
                |v, _| v.usage = "another use".into(),
                |v, _| {
                    v.action = Action::Disconnect;
                    v.fence = Some(SlotFence {
                        generation: 1,
                        epoch: 1,
                        token_version: 1,
                        account: "account".into(),
                        affinity: "affinity".into(),
                        profile: "profile".into(),
                        status: "active".into(),
                    });
                },
            ];
            for mutate in mutations {
                let view =
                    fixture
                        .manager
                        .capture("calendar", Action::Connect, &fixture.identity, 100)?;
                let mut changed = view.clone();
                let mut identity = fixture.identity.clone();
                mutate(&mut changed, &mut identity);
                let intent = FreshIntent::management(&changed, &identity)?;
                assert!(
                    crate::oauth::native_management::check(
                        &intent,
                        crate::oauth::native_management::Phase::Pending,
                        100
                    )
                    .is_err()
                );
            }
            Ok(())
        })
    }

    #[test]
    fn persisted_pending_cannot_restore_original_on_restart_or_another_thread() -> Result<()> {
        let fixture = Fixture::new(false)?;
        let view = effects::scope(fixture.port.clone(), || -> Result<View> {
            let view =
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, 100)?;
            fixture.manager.pending(&view.id, &fixture.identity, 100)?;
            std::thread::scope(|scope| -> Result<()> {
                scope
                    .spawn(|| {
                        effects::scope(fixture.port.clone(), || {
                            assert!(
                                fixture
                                    .manager
                                    .pending(&view.id, &fixture.identity, 100)
                                    .is_err()
                            );
                        })
                    })
                    .join()
                    .unwrap();
                Ok(())
            })?;
            fixture.manager.pending(&view.id, &fixture.identity, 100)?;
            Ok(view)
        })?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            assert!(
                fixture
                    .manager
                    .pending(&view.id, &fixture.identity, 100)
                    .is_err()
            );
            let db = store::open(fixture.manager.runtime.db())?;
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM oauth_management_intents WHERE id=?1 AND state='pending'",
                    [&view.id],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            Ok(())
        })
    }

    #[test]
    fn product_connect_callback_disconnect_uses_real_transactions_and_private_adapter() -> Result<()>
    {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let (view, session, query) = fixture.connect()?;
            let reply =
                fixture
                    .manager
                    .callback(&view.id, &query, &session, &fixture.identity, 102)?;
            assert!(matches!(reply, Reply::Completed { status } if status == "Connection active."));
            assert!(
                fixture
                    .manager
                    .callback(&view.id, &query, &session, &fixture.identity, 102)
                    .is_err()
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            assert_eq!(fixture.port.accounts.load(SeqCst), 1);
            let db = store::open(fixture.manager.runtime.db())?;
            assert_eq!(
                Manager::fence(&db, &view.slot)?
                    .context("slot missing")?
                    .status,
                "active"
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |r| r
                    .get::<_, i64>(0))?,
                1
            );
            db.execute("INSERT INTO oauth_connection_slots VALUES('independent_slot',1,1,1,'other_profile','other_account','other_affinity','active')", [])?;
            // Plain material is absent from the actual encrypted database rows.
            let private: Vec<u8> =
                db.query_row("SELECT ciphertext FROM oauth_private_tokens", [], |r| {
                    r.get(0)
                })?;
            assert!(
                !private
                    .windows(b"private-access-token".len())
                    .any(|v| v == b"private-access-token")
            );
            drop(db);
            fixture.port.now.store(103, SeqCst);
            let disconnect =
                fixture
                    .manager
                    .capture("calendar", Action::Disconnect, &fixture.identity, 103)?;
            let proof = fixture.proof(&disconnect, Digest::new(b"disconnect-browser"))?;
            let reply = fixture
                .manager
                .disconnect(&disconnect, &proof, &fixture.identity, 105)?;
            assert!(
                matches!(reply, Reply::Completed { status } if status.contains("operator cleanup"))
            );
            assert!(
                fixture
                    .manager
                    .disconnect(&disconnect, &proof, &fixture.identity, 105)
                    .is_err()
            );
            assert_eq!(fixture.port.revokes.load(SeqCst), 0);
            let db = store::open(fixture.manager.runtime.db())?;
            let disabled = Manager::fence(&db, &view.slot)?.context("slot missing")?;
            assert_eq!(disabled.status, "disabled");
            assert_eq!(disabled.epoch, 2);
            assert_eq!(
                db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT status FROM oauth_connection_slots WHERE slot='independent_slot'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "active"
            );
            assert!(
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, 105)
                    .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn product_callback_rejects_other_browser_duplicate_state_and_wrong_issuer_before_send()
    -> Result<()> {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let (view, session, query) = fixture.connect()?;
            let with_issuer = |issuer: Option<&str>, denied: bool| {
                let mut changed = url::form_urlencoded::Serializer::new(String::new());
                for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                    if key == "iss" {
                        continue;
                    }
                    if denied && key == "code" {
                        changed.append_pair("error", "access_denied");
                    } else {
                        changed.append_pair(&key, &value);
                    }
                }
                if let Some(issuer) = issuer {
                    changed.append_pair("iss", issuer);
                }
                changed.finish()
            };
            let before =
                crate::oauth::simulation::snapshot(&store::open(fixture.manager.runtime.db())?)?;
            for (query, browser) in [
                (query.clone(), Digest::new(b"other-browser")),
                (format!("{query}&state=duplicate"), session.clone()),
            ] {
                assert!(
                    fixture
                        .manager
                        .callback(&view.id, &query, &browser, &fixture.identity, 102)
                        .is_err()
                );
                assert_eq!(
                    crate::oauth::simulation::snapshot(&store::open(
                        fixture.manager.runtime.db()
                    )?)?,
                    before
                );
            }
            for denied in [false, true] {
                let valid = with_issuer(Some(crate::oauth::google::ISSUER), denied);
                for invalid in [
                    with_issuer(None, denied),
                    with_issuer(Some(""), denied),
                    with_issuer(Some("https://attacker.example"), denied),
                    format!("{valid}&iss={}", crate::oauth::google::ISSUER),
                ] {
                    assert!(
                        fixture
                            .manager
                            .callback(&view.id, &invalid, &session, &fixture.identity, 102)
                            .is_err()
                    );
                    assert_eq!(
                        crate::oauth::simulation::snapshot(&store::open(
                            fixture.manager.runtime.db()
                        )?)?,
                        before
                    );
                    assert_eq!(fixture.port.posts.load(SeqCst), 0);
                }
            }
            assert_eq!(fixture.port.posts.load(SeqCst), 0);
            fixture
                .manager
                .callback(&view.id, &query, &session, &fixture.identity, 102)?;
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            Ok(())
        })
    }

    #[test]
    fn product_pending_rejects_changed_purpose_owner_expiry_and_confirm_replay() -> Result<()> {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let view =
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, 100)?;
            let proof = fixture.proof(&view, Digest::new(b"browser"))?;
            let mut changed = view.clone();
            changed.action = Action::Disconnect;
            assert!(
                fixture
                    .manager
                    .authority
                    .verify_management(&changed, &proof, &fixture.identity, 102)
                    .is_err()
            );
            let bob = iap::Verified {
                email: "bob@example.com".into(),
                subject: "accounts.google.com:bob".into(),
            };
            assert!(fixture.manager.pending(&view.id, &bob, 102).is_err());
            fixture
                .manager
                .authorize_connect(&view.id, &proof, &fixture.identity, 102)?;
            assert!(
                fixture
                    .manager
                    .authorize_connect(&view.id, &proof, &fixture.identity, 102)
                    .is_err()
            );
            fixture.port.now.store(400, SeqCst);
            assert!(
                fixture
                    .manager
                    .pending(&view.id, &fixture.identity, 400)
                    .is_err()
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 0);
            Ok(())
        })
    }

    #[test]
    fn business_authority_changed_during_exchange_prevents_token_publication() -> Result<()> {
        let fixture = Fixture::new(true)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let (view, session, query) = fixture.connect()?;
            assert!(
                matches!(fixture.manager.callback(&view.id, &query, &session, &fixture.identity, 102)?,
                Reply::Completed { status } if status.contains("outcome unknown"))
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            assert_eq!(fixture.port.accounts.load(SeqCst), 0);
            let db = store::open(fixture.manager.runtime.db())?;
            assert_eq!(
                db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert!(Manager::fence(&db, &view.slot)?.is_none());
            Ok(())
        })
    }

    #[test]
    fn pending_expiry_during_provider_io_prevents_activation() -> Result<()> {
        let mut fixture = Fixture::new(false)?;
        Arc::get_mut(&mut fixture.port)
            .context("test port shared")?
            .expire_after_account = true;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let (view, session, query) = fixture.connect()?;
            assert!(
                fixture
                    .manager
                    .callback(&view.id, &query, &session, &fixture.identity, 102)
                    .is_err()
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            assert_eq!(fixture.port.accounts.load(SeqCst), 1);
            let db = store::open(fixture.manager.runtime.db())?;
            assert_eq!(
                db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert!(Manager::fence(&db, &view.slot)?.is_none());
            Ok(())
        })
    }

    #[test]
    fn lost_exchange_fences_new_and_already_authorized_connects_across_expiry_and_reopen()
    -> Result<()> {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<()> {
            let (a, session_a, query_a) = fixture.connect()?;
            let (b, session_b, query_b) = fixture.connect()?;
            fixture.port.lose_token_reply.store(true, SeqCst);
            let now = fixture.port.now.load(SeqCst);
            assert!(
                matches!(fixture.manager.callback(&a.id, &query_a, &session_a, &fixture.identity, now)?,
                Reply::Completed { status } if status.contains("outcome unknown"))
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            assert!(
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, now)
                    .is_err()
            );
            assert!(
                fixture
                    .manager
                    .callback(&b.id, &query_b, &session_b, &fixture.identity, now)
                    .is_err()
            );
            let mut reopened = store::open(fixture.manager.runtime.db())?;
            assert_eq!(
                reopened.query_row(
                    "SELECT attempt FROM oauth_management_dispatch_slots WHERE slot=?1",
                    [a.slot.as_str()],
                    |row| row.get::<_, String>(0)
                )?,
                a.id
            );
            fixture.port.now.store(a.expires_at, SeqCst);
            assert!(crate::oauth::connect::expire(
                &mut reopened,
                &a.id,
                a.expires_at,
                |_| Ok(())
            )?);
            drop(reopened);
            assert!(
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, a.expires_at)
                    .is_err()
            );
            assert!(
                fixture
                    .manager
                    .callback(&b.id, &query_b, &session_b, &fixture.identity, a.expires_at)
                    .is_err()
            );
            assert_eq!(fixture.port.posts.load(SeqCst), 1);
            assert_eq!(fixture.port.accounts.load(SeqCst), 0);
            Ok(())
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    enum Model {
        Pending,
        Authorized,
        Active,
        Disabled,
    }

    fn replay(seed: u64) -> Result<serde_json::Value> {
        let fixture = Fixture::new(false)?;
        effects::scope(fixture.port.clone(), || -> Result<serde_json::Value> {
            let view =
                fixture
                    .manager
                    .capture("calendar", Action::Connect, &fixture.identity, 100)?;
            let session = Digest::new(b"replay-browser");
            let proof = fixture.proof(&view, session.clone())?;
            let mut model = Model::Pending;
            let mut query = String::new();
            let mut history = Vec::new();
            let mut random = seed;
            let mut posts = 0;
            for index in 0..40 {
                random = random
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let operation = if index < 3 && seed.is_multiple_of(4) {
                    index
                } else {
                    ((random >> 32) % 6) as usize
                };
                let now = fixture.port.now.load(SeqCst);
                let (accepted, expected) = match operation {
                    0 => {
                        let expected = model == Model::Pending && now < view.expires_at;
                        let result = fixture.manager.authorize_connect(
                            &view.id,
                            &proof,
                            &fixture.identity,
                            now,
                        );
                        if let Ok(location) = &result {
                            let state = url::Url::parse(location)?
                                .query_pairs()
                                .find(|(k, _)| k == "state")
                                .context("state absent")?
                                .1
                                .into_owned();
                            query = url::form_urlencoded::Serializer::new(String::new())
                                .append_pair("state", &state)
                                .append_pair("code", "private-provider-code")
                                .append_pair("iss", crate::oauth::google::ISSUER)
                                .finish();
                        }
                        if expected {
                            model = Model::Authorized;
                        }
                        (result.is_ok(), expected)
                    }
                    1 => {
                        let expected = model == Model::Authorized && now < view.expires_at;
                        let result = fixture.manager.callback(
                            &view.id,
                            &query,
                            &session,
                            &fixture.identity,
                            now,
                        );
                        if expected {
                            model = Model::Active;
                            posts += 1;
                        }
                        (result.is_ok(), expected)
                    }
                    2 => {
                        let expected = model == Model::Active;
                        let result = (|| -> Result<()> {
                            let disconnect = fixture.manager.capture(
                                "calendar",
                                Action::Disconnect,
                                &fixture.identity,
                                now,
                            )?;
                            let proof =
                                fixture.proof(&disconnect, Digest::new(b"replay-disconnect"))?;
                            fixture.manager.disconnect(
                                &disconnect,
                                &proof,
                                &fixture.identity,
                                fixture.port.now.load(SeqCst),
                            )?;
                            Ok(())
                        })();
                        if expected {
                            model = Model::Disabled;
                        }
                        (result.is_ok(), expected)
                    }
                    3 => (
                        fixture
                            .manager
                            .callback(
                                &view.id,
                                &query,
                                &Digest::new(b"other-browser"),
                                &fixture.identity,
                                now,
                            )
                            .is_ok(),
                        false,
                    ),
                    4 => {
                        fixture
                            .port
                            .now
                            .store(now + 1 + ((random >> 16) % 100) as i64, SeqCst);
                        (true, true)
                    }
                    5 => {
                        drop(store::open(fixture.manager.runtime.db())?);
                        (true, true)
                    }
                    _ => unreachable!(),
                };
                ensure!(
                    accepted == expected,
                    "management schedule diverged seed={seed} step={index} operation={operation} state={model:?}"
                );
                let db = store::open(fixture.manager.runtime.db())?;
                let slot = Manager::fence(&db, &view.slot)?;
                ensure!(
                    match model {
                        Model::Pending | Model::Authorized => slot.is_none(),
                        Model::Active => slot
                            .as_ref()
                            .is_some_and(|s| s.status == "active" && s.epoch == 1),
                        Model::Disabled => slot
                            .as_ref()
                            .is_some_and(|s| s.status == "disabled" && s.epoch == 2),
                    },
                    "management slot oracle diverged seed={seed} step={index}"
                );
                ensure!(
                    fixture.port.posts.load(SeqCst) == posts
                        && fixture.port.revokes.load(SeqCst) == 0,
                    "management send oracle diverged"
                );
                history.push(json!({"operation":operation,"accepted":accepted,"model":model,
                    "now":fixture.port.now.load(SeqCst),"snapshot":crate::oauth::simulation::snapshot(&db)?}));
            }
            Ok(json!({"version":1,"seed":seed,"history":history}))
        })
    }

    #[test]
    fn management_seeded_histories_replay_complete_private_state_without_network() -> Result<()> {
        for seed in 0..16 {
            let first = replay(seed)?;
            let second = replay(seed)?;
            assert_eq!(first, second, "management replay seed={seed}");
            let exported = serde_json::to_string(&first)?;
            for secret in [
                "private-provider-code",
                "private-access-token",
                "private-refresh-token",
                "fixture-client-secret",
            ] {
                ensure!(
                    !exported.contains(secret),
                    "management private material entered replay evidence"
                );
            }
        }
        Ok(())
    }
}
