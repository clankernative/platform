//! Current exact-row encryption maintenance from an explicit trusted source.
//! No native original, operator route, key supplier or retirement is supplied.

use super::{Authority, Selection, Target};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, ManifestFamily},
};
use std::sync::Mutex;

/// Independent maintenance policy DATA, never human issuance/reveal permission
/// or permission inferred from ciphertext, token possession or stored key names.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub binding: CredentialFamilyBinding,
    pub family: ManifestFamily,
    pub version: String,
    pub target: Digest,
    pub selection: Selection,
}

pub(crate) struct Observation {
    pub checked_at: i64,
    pub grant: Option<Grant>,
}

/// Local, nonblocking current observation on EVERY call, including inside SQL.
/// A genuine supplier must independently enforce maintenance permission, exact
/// current row, policy revision, epoch, previous/replacement custody keys and
/// its original fixed deadline. Copying a Grant is not such an implementation.
pub(crate) trait Source {
    fn observe(&self, target: &Target, now: i64) -> Result<Observation>;
}

/// One attempt's exact selection and observed-refusal memory. Construction
/// loads no keys, samples no clock and cannot create or renew an original.
pub(crate) struct CurrentAuthority<'source> {
    source: &'source dyn Source,
    state: Mutex<State>,
}

struct State {
    first: Option<Grant>,
    last_checked_at: Option<i64>,
    refused: bool,
}

impl<'source> CurrentAuthority<'source> {
    pub(crate) fn new(source: &'source dyn Source) -> Self {
        Self {
            source,
            state: Mutex::new(State {
                first: None,
                last_checked_at: None,
                refused: false,
            }),
        }
    }
}

impl Authority for CurrentAuthority<'_> {
    fn authorize(&self, target: &Target, now: i64) -> Result<Selection> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("credential custody source lock poisoned"))?;
        ensure!(!state.refused, "credential custody attempt refused");
        // A Result error keeps refusal set; an unwind poisons the same state.
        state.refused = true;
        ensure!(
            now >= 0 && state.last_checked_at.is_none_or(|previous| now >= previous),
            "credential custody source clock rewound"
        );
        let observed = self.source.observe(target, now)?;
        ensure!(
            observed.checked_at == now,
            "credential custody source is stale"
        );
        let grant = observed
            .grant
            .context("credential custody maintenance denied")?;
        ensure!(
            grant.binding == target.binding
                && grant.family == target.family
                && grant.version == target.identity.version
                && grant.target == target.fingerprint,
            "credential custody maintenance target changed"
        );
        super::validate_selection(&grant.selection, target, now)?;
        ensure!(
            state.first.as_ref().is_none_or(|first| first == &grant),
            "credential custody original selection changed"
        );
        let result = grant.selection.clone();
        if state.first.is_none() {
            state.first = Some(grant);
        }
        state.last_checked_at = Some(now);
        state.refused = false;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Request, current, prepare, stage};
    use super::*;
    use crate::managed_credentials::store::{self, tests as fixture};
    use crate::managed_credentials::{crypto, effects, simulation::World};
    use crate::oauth::approval_registry::{
        ApprovalKeyMaterial, ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef,
    };
    use day2_capabilities::{
        BindingRef, Name,
        credentials::{DeliveryProfile, RotationProfile},
        oauth::{ResourceAudienceRef, SecurityOriginRef},
    };
    use rusqlite::{Connection, TransactionBehavior, types::Value};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Copy, Debug)]
    enum Fault {
        None,
        Deny,
        Error,
        Panic,
        Binding,
        Family,
        Version,
        Target,
        Epoch,
        Previous,
        Replacement,
        Policy,
        Renew,
        Stale,
    }

    // Symbolic policy model: a grant is unchanged until one scripted boundary;
    // no actual adapter result or production validator predicts its answer.
    struct Model {
        calls: usize,
        at: usize,
        fault: Fault,
    }

    impl Model {
        fn refuses(&self) -> bool {
            !matches!(self.fault, Fault::None)
        }

        fn key_bound(&self) -> usize {
            self.at.saturating_sub(1).min(2)
        }
    }

    struct Controlled {
        original: Grant,
        model: Mutex<Model>,
    }

    impl Source for Controlled {
        fn observe(&self, _: &Target, now: i64) -> Result<Observation> {
            let mut model = self.model.lock().unwrap();
            model.calls += 1;
            let mut grant = self.original.clone();
            let mut checked_at = now;
            if model.calls == model.at {
                match model.fault {
                    Fault::None => {}
                    Fault::Deny => {
                        return Ok(Observation {
                            checked_at,
                            grant: None,
                        });
                    }
                    Fault::Error => anyhow::bail!("controlled custody source unavailable"),
                    Fault::Panic => panic!("controlled custody source unwind"),
                    Fault::Binding => grant.binding.namespace.binding_generation += 1,
                    Fault::Family => grant.family.contract = Digest::new(b"foreign family"),
                    Fault::Version => grant.version = "foreign-version".into(),
                    Fault::Target => grant.target = Digest::new(b"foreign actual row"),
                    Fault::Epoch => grant.selection.security_epoch += 1,
                    Fault::Previous => grant.selection.previous.version = "foreign-key".into(),
                    Fault::Replacement => grant.selection.replacement.version = "encrypt-v3".into(),
                    Fault::Policy => {
                        grant.selection.authority_revision = Digest::new(b"new policy")
                    }
                    Fault::Renew => {
                        grant.selection.observed_at += 1;
                        grant.selection.ready_until += 1;
                    }
                    Fault::Stale => checked_at -= 1,
                }
            }
            Ok(Observation {
                checked_at,
                grant: Some(grant),
            })
        }
    }

    #[derive(Debug)]
    struct KeyFailure;

    impl std::fmt::Display for KeyFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("controlled custody key unavailable")
        }
    }

    impl std::error::Error for KeyFailure {}

    struct Keys {
        calls: AtomicUsize,
        fail_at: usize,
        clock: Arc<World>,
        move_clock: bool,
    }

    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            assert_eq!(purpose, ApprovalKeyPurpose::CustodyEncryption);
            if self.move_clock {
                self.clock.set_wall(if call == 1 { 1100 } else { 1099 });
            }
            if call == self.fail_at {
                return Err(KeyFailure.into());
            }
            let bytes = match reference.version.as_str() {
                "encrypt-v1" => [4; 32],
                "encrypt-v2" => [8; 32],
                _ => anyhow::bail!("unexpected custody key"),
            };
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: reference.version.clone(),
                purpose,
                bytes,
            })
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        db: Connection,
        binding: CredentialFamilyBinding,
        family: ManifestFamily,
        version: String,
        source: Controlled,
        keys: Keys,
    }

    impl Fixture {
        fn new(clock: Arc<World>, at: usize, fault: Fault) -> Result<Self> {
            let (directory, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let pin = |value: &str| {
                BindingRef::pin(Name::try_from(value.to_owned()).unwrap(), &value).unwrap()
            };
            let family = fixture::family();
            let binding = CredentialFamilyBinding {
                namespace: fixture::namespace(),
                family: family.id.clone(),
                approved_authority: pin("authority"),
                management: pin("management"),
                rotation: RotationProfile::AtomicReplace,
                delivery: DeliveryProfile::AuthenticatedCreatorReveal,
                verifier: pin("verifier"),
                custody: pin("custody"),
                security_shell: SecurityOriginRef(pin("security")),
                audience: ResourceAudienceRef(pin("audience")),
                epoch_store: pin("epoch"),
                max_lifetime_seconds: 2000,
                reveal_window_seconds: 300,
                quota: pin("quota"),
            };
            let version = receipt.version.context("issued version")?;
            let (target, _) = current(
                &db,
                &Request {
                    binding: &binding,
                    family: &family,
                    version: &version,
                },
                1000,
            )?;
            let grant = Grant {
                binding: binding.clone(),
                family: family.clone(),
                version: version.clone(),
                target: target.fingerprint,
                selection: Selection {
                    previous: ApprovalKeyRef {
                        binding: binding.custody.clone(),
                        version: "encrypt-v1".into(),
                    },
                    replacement: ApprovalKeyRef {
                        binding: binding.custody.clone(),
                        version: "encrypt-v2".into(),
                    },
                    security_epoch: 7,
                    authority_revision: Digest::new(b"custody maintenance policy"),
                    observed_at: 900,
                    ready_until: 1200,
                },
            };
            Ok(Self {
                _directory: directory,
                db,
                binding,
                family,
                version,
                source: Controlled {
                    original: grant,
                    model: Mutex::new(Model {
                        calls: 0,
                        at,
                        fault,
                    }),
                },
                keys: Keys {
                    calls: AtomicUsize::new(0),
                    fail_at: 0,
                    clock,
                    move_clock: false,
                },
            })
        }

        fn request(&self) -> Request<'_> {
            Request {
                binding: &self.binding,
                family: &self.family,
                version: &self.version,
            }
        }
    }

    fn image(db: &Connection) -> Result<Vec<(String, Vec<Vec<Value>>)>> {
        let names = db
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        names
            .into_iter()
            .map(|name| {
                let mut query = db.prepare(&format!(
                    "SELECT * FROM \"{}\" ORDER BY rowid",
                    name.replace('"', "\"\"")
                ))?;
                let width = query.column_count();
                let rows = query
                    .query_map([], |r| {
                        (0..width)
                            .map(|i| r.get(i))
                            .collect::<rusqlite::Result<Vec<Value>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((name, rows))
            })
            .collect()
    }

    #[test]
    fn actual_custody_adapter_changes_only_envelope_and_preserves_the_token() -> Result<()> {
        let clock = World::new(980);
        effects::scope(clock.clone(), || {
            let mut f = Fixture::new(clock, 0, Fault::None)?;
            let before = image(&f.db)?;
            let (_, old) = current(&f.db, &f.request(), 1000)?;
            let identity = crate::json::decode(old.identity_json.as_bytes())?;
            let token = crypto::decrypt_for_human(
                &fixture::lease(),
                &identity,
                &identity,
                1,
                "encrypt-v1",
                old.nonce.as_slice().try_into()?,
                &old.ciphertext,
            )?;
            let authority = CurrentAuthority::new(&f.source);
            let prepared = prepare(&f.db, &authority, &f.keys, f.request())?;
            let tx =
                f.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            stage(&tx, &authority, prepared)?;
            tx.commit()?;
            let (_, after) = current(&f.db, &f.request(), 1000)?;
            let next =
                crypto::KeyLease::new(&[3; 32], &[8; 32], "verify-v1".into(), "encrypt-v2".into())?;
            ensure!(
                crypto::decrypt_for_human(
                    &next,
                    &identity,
                    &identity,
                    2,
                    "encrypt-v2",
                    after.nonce.as_slice().try_into()?,
                    &after.ciphertext
                )? == token,
                "custody changed canonical token"
            );
            assert_eq!(f.source.model.lock().unwrap().calls, 5);
            assert_eq!(f.keys.calls.load(Ordering::SeqCst), 2);
            let mut observed = image(&f.db)?;
            let before_material = &before
                .iter()
                .find(|x| x.0 == "day2_credential_material")
                .unwrap()
                .1;
            let after_material = &mut observed
                .iter_mut()
                .find(|x| x.0 == "day2_credential_material")
                .unwrap()
                .1;
            // Column order is the actual schema's version, identity, material
            // revision, envelope revision, key, nonce, ciphertext.
            assert_eq!(after_material.len(), 1);
            ensure!(
                after_material[0][..3] == before_material[0][..3],
                "custody changed material identity"
            );
            assert_eq!(after_material[0][3], Value::Integer(2));
            after_material[0][3..].clone_from_slice(&before_material[0][3..]);
            ensure!(observed == before, "custody changed non-envelope rows");
            Ok(())
        })
    }

    #[test]
    fn independent_cuts_refuse_at_each_actual_boundary_and_cannot_be_repaired() -> Result<()> {
        for repeat in 0..2 {
            for at in 1..=5 {
                for fault in [
                    Fault::Deny,
                    Fault::Error,
                    Fault::Binding,
                    Fault::Family,
                    Fault::Version,
                    Fault::Target,
                    Fault::Epoch,
                    Fault::Previous,
                    Fault::Stale,
                ] {
                    let clock = World::new(981 + repeat);
                    effects::scope(clock.clone(), || -> Result<()> {
                        let mut f = Fixture::new(clock, at, fault)?;
                        let before = image(&f.db)?;
                        let expected_keys = f.source.model.lock().unwrap().key_bound();
                        assert!(f.source.model.lock().unwrap().refuses());
                        let authority = CurrentAuthority::new(&f.source);
                        let ready = prepare(&f.db, &authority, &f.keys, f.request());
                        if at < 5 {
                            assert!(ready.is_err(), "accepted boundary {at}/{fault:?}");
                        } else {
                            let tx = f.db.transaction()?;
                            assert!(stage(&tx, &authority, ready?).is_err());
                            tx.rollback()?;
                        }
                        assert_eq!(f.keys.calls.load(Ordering::SeqCst), expected_keys);
                        ensure!(
                            image(&f.db)? == before,
                            "refused custody operation changed rows"
                        );
                        f.source.model.lock().unwrap().fault = Fault::None;
                        let (target, _) = current(&f.db, &f.request(), 1000)?;
                        assert!(authority.authorize(&target, 1000).is_err());
                        assert_eq!(
                            f.source.model.lock().unwrap().calls,
                            at,
                            "refused source was reused"
                        );
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn policy_key_or_expiry_renewal_cannot_replace_the_first_grant() -> Result<()> {
        for at in 2..=5 {
            for fault in [Fault::Policy, Fault::Replacement, Fault::Renew] {
                let clock = World::new(984);
                effects::scope(clock.clone(), || -> Result<()> {
                    let mut f = Fixture::new(clock, at, fault)?;
                    let before = image(&f.db)?;
                    let authority = CurrentAuthority::new(&f.source);
                    let ready = prepare(&f.db, &authority, &f.keys, f.request());
                    if at < 5 {
                        assert!(ready.is_err());
                    } else {
                        let tx = f.db.transaction()?;
                        assert!(stage(&tx, &authority, ready?).is_err());
                        tx.rollback()?;
                    }
                    ensure!(
                        image(&f.db)? == before,
                        "refused custody operation changed rows"
                    );
                    f.source.model.lock().unwrap().fault = Fault::None;
                    let (target, _) = current(&f.db, &f.request(), 1000)?;
                    assert!(authority.authorize(&target, 1000).is_err());
                    assert_eq!(f.source.model.lock().unwrap().calls, at);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    #[test]
    fn provider_error_stays_primary_while_the_actual_source_postcheck_runs() -> Result<()> {
        for failed_key in 1..=2 {
            let clock = World::new(985);
            effects::scope(clock.clone(), || -> Result<()> {
                let mut f = Fixture::new(clock, failed_key + 1, Fault::Deny)?;
                f.keys.fail_at = failed_key;
                let before = image(&f.db)?;
                let authority = CurrentAuthority::new(&f.source);
                let error = prepare(&f.db, &authority, &f.keys, f.request())
                    .err()
                    .context("provider error was accepted")?;
                assert!(error.downcast_ref::<KeyFailure>().is_some());
                assert_eq!(f.keys.calls.load(Ordering::SeqCst), failed_key);
                assert_eq!(f.source.model.lock().unwrap().calls, failed_key + 1);
                ensure!(
                    image(&f.db)? == before,
                    "refused custody operation changed rows"
                );
                f.source.model.lock().unwrap().fault = Fault::None;
                let (target, _) = current(&f.db, &f.request(), 1000)?;
                assert!(authority.authorize(&target, 1000).is_err());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn provider_clock_rewind_is_compared_to_the_latest_checked_time() -> Result<()> {
        let clock = World::new(986);
        effects::scope(clock.clone(), || {
            let mut f = Fixture::new(clock, 0, Fault::None)?;
            f.keys.move_clock = true;
            let before = image(&f.db)?;
            let authority = CurrentAuthority::new(&f.source);
            assert!(prepare(&f.db, &authority, &f.keys, f.request()).is_err());
            assert_eq!(f.keys.calls.load(Ordering::SeqCst), 2);
            ensure!(
                image(&f.db)? == before,
                "refused custody operation changed rows"
            );
            // The source sees the rewind too; repairing the clock cannot
            // recover this same authority attempt.
            f.keys.clock.set_wall(1100);
            let (target, _) = current(&f.db, &f.request(), 1100)?;
            assert!(authority.authorize(&target, 1100).is_err());
            Ok(())
        })
    }

    #[test]
    fn actual_competing_rewrap_or_revoke_defeats_the_old_adapter_preparation() -> Result<()> {
        for revoke in [false, true] {
            let clock = World::new(988);
            effects::scope(clock.clone(), || -> Result<()> {
                let mut f = Fixture::new(clock, 0, Fault::None)?;
                let authority = CurrentAuthority::new(&f.source);
                let loser = prepare(&f.db, &authority, &f.keys, f.request())?;
                if revoke {
                    let lineage: String = f.db.query_row(
                        "SELECT lineage FROM day2_credential_versions WHERE id=?1",
                        [&f.version],
                        |r| r.get(0),
                    )?;
                    let tx = f.db.transaction()?;
                    assert!(store::stage_revoke(&tx, &f.binding.namespace, &lineage)?);
                    tx.commit()?;
                } else {
                    let other = CurrentAuthority::new(&f.source);
                    let winner = prepare(&f.db, &other, &f.keys, f.request())?;
                    let tx = f.db.transaction()?;
                    stage(&tx, &other, winner)?;
                    tx.commit()?;
                }
                let committed = image(&f.db)?;
                let tx = f.db.transaction()?;
                assert!(stage(&tx, &authority, loser).is_err());
                tx.rollback()?;
                ensure!(
                    image(&f.db)? == committed,
                    "stale custody changed winning state"
                );
                let envelope: i64 = f.db.query_row(
                    "SELECT envelope_revision FROM day2_credential_material",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(envelope, if revoke { 1 } else { 2 });
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn pending_custody_stage_does_not_turn_rollback_into_publication() -> Result<()> {
        let clock = World::new(989);
        effects::scope(clock.clone(), || -> Result<()> {
            let mut f = Fixture::new(clock, 0, Fault::None)?;
            let before = image(&f.db)?;
            let authority = CurrentAuthority::new(&f.source);
            let ready = prepare(&f.db, &authority, &f.keys, f.request())?;
            let tx = f.db.transaction()?;
            let _pending = stage(&tx, &authority, ready)?;
            tx.rollback()?;
            ensure!(image(&f.db)? == before, "rolled-back custody was published");
            Ok(())
        })
    }

    #[test]
    fn equality_expiry_and_source_unwind_remain_refused() -> Result<()> {
        let clock = World::new(987);
        effects::scope(clock.clone(), || -> Result<()> {
            let f = Fixture::new(clock.clone(), 0, Fault::None)?;
            let authority = CurrentAuthority::new(&f.source);
            let (target, _) = current(&f.db, &f.request(), 1000)?;
            authority.authorize(&target, 1000)?;
            assert!(authority.authorize(&target, 1200).is_err());
            assert!(authority.authorize(&target, 1000).is_err());
            let f = Fixture::new(clock, 2, Fault::Panic)?;
            let before = image(&f.db)?;
            let authority = CurrentAuthority::new(&f.source);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(
                    &f.db,
                    &authority,
                    &f.keys,
                    f.request()
                )))
                .is_err()
            );
            let (target, _) = current(&f.db, &f.request(), 1000)?;
            assert!(authority.authorize(&target, 1000).is_err());
            ensure!(
                image(&f.db)? == before,
                "refused custody operation changed rows"
            );
            Ok(())
        })
    }
}
