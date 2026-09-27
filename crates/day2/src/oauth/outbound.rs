//! Private outbound callback continuation. The security shell supplies the
//! route and session references; the provider supplies only bounded query data.

use super::connect::{self, CallbackBinding};
use super::protocol::{self, CallbackParameters, ParsedCallback, ProviderDenial};
use anyhow::Result;
use day2_capabilities::Digest;
use day2_capabilities::oauth::{ProductReturnRef, ProviderCallbackRef, ProviderIssuerRef};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::BTreeSet;

pub struct CallbackIngress<'a> {
    pub attempt: &'a str,
    pub raw_query: &'a [u8],
    pub route: &'a ProviderCallbackRef,
    pub session: &'a Digest,
    pub issuer_binding: &'a ProviderIssuerRef,
    pub code_ref: &'a str,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackOutcome {
    CodeAccepted {
        product_return: ProductReturnRef,
    },
    Denied {
        reason: ProviderDenial,
        product_return: ProductReturnRef,
    },
    Rejected,
}

/// No raw callback parameter or provider error description reaches the result.
/// A custody failure rolls back both private code storage and the attempt CAS.
pub fn handle_callback(
    db: &mut Connection,
    ingress: CallbackIngress<'_>,
    custody_write: impl FnOnce(&Transaction<'_>, &str) -> Result<()>,
) -> Result<CallbackOutcome> {
    connect::identifier(ingress.attempt)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, i64, String, String)> = tx
        .query_row(
            "SELECT a.state, a.expires_at, a.callback, b.binding
             FROM oauth_connect_attempts a
             JOIN oauth_callback_bindings b ON b.attempt = a.attempt
             WHERE a.attempt = ?1",
            [ingress.attempt],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((state, expiry, callback, encoded)) = row else {
        return Ok(CallbackOutcome::Rejected);
    };
    if state != "awaiting_provider_authorization" || ingress.now >= expiry {
        return Ok(CallbackOutcome::Rejected);
    }
    let binding: CallbackBinding = serde_json::from_str(&encoded)?;
    if binding.callback() != ingress.route
        || binding.session() != ingress.session
        || binding.issuer() != ingress.issuer_binding
        || Digest::of(binding.callback())?.as_str() != callback
    {
        return Ok(CallbackOutcome::Rejected);
    }
    let parsed = protocol::parse_callback(
        ingress.raw_query,
        &CallbackParameters {
            require_issuer: true,
            allowed_extras: BTreeSet::new(),
        },
    )?;
    let (state, issuer) = match &parsed {
        ParsedCallback::Code { state, issuer, .. }
        | ParsedCallback::Denied { state, issuer, .. } => (state, issuer),
    };
    if connect::callback_state_hash(state.as_str().as_bytes())? != *binding.state_hash()
        || issuer.as_deref() != Some(binding.issuer_url())
    {
        return Ok(CallbackOutcome::Rejected);
    }
    let outcome = match parsed {
        ParsedCallback::Code { code, .. } => {
            connect::identifier(ingress.code_ref)?;
            custody_write(&tx, code.as_str())?;
            tx.execute(
                "UPDATE oauth_connect_attempts SET state = 'exchange_ready', code_ref = ?2
                 WHERE attempt = ?1 AND state = 'awaiting_provider_authorization'",
                params![ingress.attempt, ingress.code_ref],
            )?;
            CallbackOutcome::CodeAccepted {
                product_return: binding.product_return().clone(),
            }
        }
        ParsedCallback::Denied { reason, .. } => {
            tx.execute(
                "UPDATE oauth_connect_attempts SET state = 'denied'
                 WHERE attempt = ?1 AND state = 'awaiting_provider_authorization'",
                [ingress.attempt],
            )?;
            CallbackOutcome::Denied {
                reason,
                product_return: binding.product_return().clone(),
            }
        }
    };
    tx.commit()?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::connect::{CallbackBindingSpec, ConnectIntent, ConnectState};
    use day2_capabilities::oauth::SecurityOriginRef;
    use day2_capabilities::{BindingRef, Name};
    use std::cell::Cell;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    const STATE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF";

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    struct Fixture {
        intent: ConnectIntent,
        binding: CallbackBinding,
        route: ProviderCallbackRef,
        issuer: ProviderIssuerRef,
        session: Digest,
    }

    fn fixture(attempt: &str) -> Fixture {
        let profile = pin("google-calendar-v1");
        let security_origin = SecurityOriginRef(pin("security-origin"));
        let route = ProviderCallbackRef::derive(
            &security_origin,
            &profile,
            "installation.production.workspace.calendar.human_1",
        )
        .unwrap();
        let issuer = ProviderIssuerRef(pin("provider-issuer"));
        let session = Digest::of(&("security-session-v1", "session_1")).unwrap();
        let intent = ConnectIntent {
            attempt: attempt.into(),
            slot: "installation.production.workspace.calendar.human_1".into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "human_1".into(),
            profile: profile.id.as_str().into(),
            registration: "registration_v1".into(),
            callback: Digest::of(&route).unwrap().as_str().into(),
            consent: "consent_v1".into(),
            expires_at: 100,
        };
        let binding = CallbackBinding::from_secret_state(
            STATE,
            CallbackBindingSpec {
                issuer: issuer.clone(),
                issuer_url: "https://provider.example/".into(),
                security_origin,
                profile,
                callback: route.clone(),
                binding_namespace: intent.slot.clone(),
                session: session.clone(),
                product_return: ProductReturnRef(pin("workspace-calendar-return")),
            },
        )
        .unwrap();
        Fixture {
            intent,
            binding,
            route,
            issuer,
            session,
        }
    }

    fn prepared(fixture: &Fixture) -> Connection {
        let mut db = Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        assert!(connect::begin_bound(&mut db, &fixture.intent, &fixture.binding, 1).unwrap());
        db
    }

    fn ingress<'a>(
        fixture: &'a Fixture,
        raw_query: &'a [u8],
        route: &'a ProviderCallbackRef,
        session: &'a Digest,
        issuer: &'a ProviderIssuerRef,
    ) -> CallbackIngress<'a> {
        CallbackIngress {
            attempt: &fixture.intent.attempt,
            raw_query,
            route,
            session,
            issuer_binding: issuer,
            code_ref: "private_code_1",
            now: 2,
        }
    }

    #[test]
    fn exact_callback_claims_once_and_custody_commits_with_state() {
        let fixture = fixture("attempt_1");
        let mut db = prepared(&fixture);
        let raw = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fprovider.example%2F";
        let input = ingress(
            &fixture,
            raw,
            &fixture.route,
            &fixture.session,
            &fixture.issuer,
        );
        let accepted = handle_callback(&mut db, input, |tx, code| {
            assert_eq!(code, "secret_code");
            tx.execute_batch("CREATE TABLE private_codes (id TEXT PRIMARY KEY, encrypted BLOB)")?;
            tx.execute(
                "INSERT INTO private_codes VALUES ('private_code_1', ?1)",
                [b"encrypted-fixture".as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(accepted, CallbackOutcome::CodeAccepted { .. }));
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::ExchangeReady)
        );
        assert_eq!(
            handle_callback(
                &mut db,
                ingress(
                    &fixture,
                    raw,
                    &fixture.route,
                    &fixture.session,
                    &fixture.issuer
                ),
                |_, _| panic!("duplicate callback reached custody"),
            )
            .unwrap(),
            CallbackOutcome::Rejected
        );
    }

    #[test]
    fn wrong_state_issuer_route_or_session_never_reaches_custody() {
        let fixture = fixture("attempt_1");
        let mut db = prepared(&fixture);
        let valid = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fprovider.example%2F";
        let wrong_state = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEG&code=secret_code&iss=https%3A%2F%2Fprovider.example%2F";
        let wrong_issuer = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fevil.example%2F";
        let other_route = ProviderCallbackRef::derive(
            &SecurityOriginRef(pin("security-origin")),
            &pin("google-calendar-v1"),
            "other_namespace",
        )
        .unwrap();
        let other_session = Digest::of(&"another-session").unwrap();
        let other_issuer = ProviderIssuerRef(pin("another-issuer"));
        for input in [
            ingress(
                &fixture,
                wrong_state,
                &fixture.route,
                &fixture.session,
                &fixture.issuer,
            ),
            ingress(
                &fixture,
                wrong_issuer,
                &fixture.route,
                &fixture.session,
                &fixture.issuer,
            ),
            ingress(
                &fixture,
                valid,
                &other_route,
                &fixture.session,
                &fixture.issuer,
            ),
            ingress(
                &fixture,
                valid,
                &fixture.route,
                &other_session,
                &fixture.issuer,
            ),
            ingress(
                &fixture,
                valid,
                &fixture.route,
                &fixture.session,
                &other_issuer,
            ),
        ] {
            assert_eq!(
                handle_callback(&mut db, input, |_, _| panic!(
                    "bad callback reached custody"
                ))
                .unwrap(),
                CallbackOutcome::Rejected
            );
        }
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::AwaitingProviderAuthorization)
        );
    }

    #[test]
    fn denial_is_redacted_and_custody_failure_rolls_back_code_claim() {
        let fixture = fixture("attempt_1");
        let mut db = prepared(&fixture);
        let raw = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fprovider.example%2F";
        assert!(
            handle_callback(
                &mut db,
                ingress(
                    &fixture,
                    raw,
                    &fixture.route,
                    &fixture.session,
                    &fixture.issuer
                ),
                |_, _| anyhow::bail!("custody unavailable"),
            )
            .is_err()
        );
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::AwaitingProviderAuthorization)
        );
        let denied = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&error=access_denied&error_description=SECRET_CANARY&iss=https%3A%2F%2Fprovider.example%2F";
        let called = Cell::new(false);
        let outcome = handle_callback(
            &mut db,
            ingress(
                &fixture,
                denied,
                &fixture.route,
                &fixture.session,
                &fixture.issuer,
            ),
            |_, _| {
                called.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(!called.get());
        assert!(matches!(
            outcome,
            CallbackOutcome::Denied {
                reason: ProviderDenial::AccessDenied,
                ..
            }
        ));
        assert!(!format!("{outcome:?}").contains("SECRET_CANARY"));
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::Denied)
        );
    }

    #[test]
    fn unbound_attempt_and_unknown_callback_schema_fail_closed() {
        let fixture = fixture("attempt_1");
        let mut db = Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        assert!(connect::begin(&mut db, &fixture.intent, 1).unwrap());
        assert_eq!(
            handle_callback(
                &mut db,
                ingress(
                    &fixture,
                    b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=x&iss=https%3A%2F%2Fprovider.example%2F",
                    &fixture.route,
                    &fixture.session,
                    &fixture.issuer,
                ),
                |_, _| panic!("unbound attempt reached custody"),
            )
            .unwrap(),
            CallbackOutcome::Rejected
        );
        db.execute("UPDATE oauth_callback_schema_version SET version = 2", [])
            .unwrap();
        assert!(connect::install_schema(&db).is_err());
    }

    #[test]
    fn two_hosts_cannot_claim_the_same_bound_callback() {
        let fixture = fixture("attempt_1");
        let dir = tempdir().unwrap();
        let path = dir.path().join("bound-callback.sqlite");
        let mut setup = Connection::open(&path).unwrap();
        connect::install_schema(&setup).unwrap();
        assert!(connect::begin_bound(&mut setup, &fixture.intent, &fixture.binding, 1).unwrap());
        drop(setup);
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let jobs = (0..2)
                .map(|_| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    let fixture = &fixture;
                    scope.spawn(move || {
                        let mut db = Connection::open(path).unwrap();
                        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                        barrier.wait();
                        handle_callback(
                            &mut db,
                            ingress(
                                fixture,
                                b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fprovider.example%2F",
                                &fixture.route,
                                &fixture.session,
                                &fixture.issuer,
                            ),
                            |_, _| Ok(()),
                        )
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .into_iter()
                .filter(|outcome| matches!(outcome, CallbackOutcome::CodeAccepted { .. }))
                .count(),
            1
        );
    }
}
