//! Conditional, single-row encryption maintenance. No operator/native entry is
//! enabled here. A future caller needs genuine maintenance and SQL owners.
//! The controlled authorizer is separate from human issuance/reveal authority.

use super::{namespace_key, validate_id};
use crate::{
    managed_credentials::{
        crypto::{self, MaterialIdentity, RewrapKey, RewrapSource},
        effects,
    },
    oauth::approval_registry::{ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, ManagedProfile, ManifestFamily},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use zeroize::Zeroize;

/// Requested DATA, never a permit. The current row and authorizer select what
/// may actually be prepared; creator/reveal permission is not consulted.
pub(crate) struct Request<'a> {
    pub binding: &'a CredentialFamilyBinding,
    pub family: &'a ManifestFamily,
    pub version: &'a str,
}

/// Current target DATA from an actual joined SQLite row. No constructor from a
/// caller-supplied snapshot or envelope exists.
pub(crate) struct Target {
    identity: MaterialIdentity,
    fingerprint: Digest,
    binding: CredentialFamilyBinding,
    family: ManifestFamily,
    envelope_revision: u64,
    encryption_version: String,
    expires_at: i64,
}

impl Target {
    pub(crate) fn identity(&self) -> &MaterialIdentity {
        &self.identity
    }
    pub(crate) fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }
    pub(crate) fn binding(&self) -> &CredentialFamilyBinding {
        &self.binding
    }
    pub(crate) fn encryption_version(&self) -> &str {
        &self.encryption_version
    }
    pub(crate) fn envelope_revision(&self) -> u64 {
        self.envelope_revision
    }
    pub(crate) fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Authorizer output DATA is insufficient on its own: every core transition
/// calls the actual authorizer with its freshly selected target.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Selection {
    pub previous: ApprovalKeyRef,
    pub replacement: ApprovalKeyRef,
    pub security_epoch: u64,
    pub authority_revision: Digest,
    pub observed_at: i64,
    pub ready_until: i64,
}

/// Trusted local current evidence only. Must check independent maintenance
/// permission, exact namespace/family/version, epoch and key selection. This
/// method may not perform provider I/O (it is also called inside caller TX).
/// There is deliberately no production adapter or native purpose factory.
pub(crate) trait Authority {
    fn authorize(&self, target: &Target, now: i64) -> Result<Selection>;
}

#[derive(PartialEq, Eq, serde::Serialize)]
struct Row {
    namespace_json: String,
    family_contract: String,
    lineage: String,
    lineage_revision: i64,
    recipient: String,
    session: String,
    grant: String,
    grant_digest: String,
    grant_until: i64,
    epoch: i64,
    version: String,
    selector: String,
    verifier: Vec<u8>,
    verifier_version: String,
    issued_at: i64,
    expires_at: i64,
    identity_json: String,
    material_revision: i64,
    envelope_revision: i64,
    encryption_version: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    principal: String,
    creator: String,
    label: String,
    predecessor: Option<String>,
}

fn current(db: &Connection, request: &Request<'_>, now: i64) -> Result<(Target, Row)> {
    request.binding.namespace.validate()?;
    request.family.verify()?;
    validate_id(request.version)?;
    ensure!(
        request.binding.family == request.family.id
            && matches!(
                request.family.profile,
                ManagedProfile::Client | ManagedProfile::Personal
            ),
        "unsupported credential rewrap family"
    );
    let row = db.query_row(
        "SELECT l.namespace_json,l.family_contract,l.id,l.revision,l.recipient,l.session,
            l.grant_json,l.grant_digest,l.grant_valid_until,l.security_epoch,
            v.id,v.selector,v.verifier,v.verifier_key_version,v.issued_at,v.expires_at,
            m.identity_json,m.material_revision,m.envelope_revision,m.encryption_key_version,m.nonce,m.ciphertext,
            l.principal,l.creator,l.label,v.predecessor
         FROM day2_credential_material m
         JOIN day2_credential_versions v ON v.id=m.version
         JOIN day2_credential_lineages l ON l.id=v.lineage
         WHERE v.id=?1 AND l.namespace=?2 AND l.family=?3 AND l.family_contract=?4
           AND l.state='active' AND l.head=v.id AND v.state='active'
           AND v.security_epoch=l.security_epoch AND v.grant_digest=l.grant_digest",
        params![request.version, namespace_key(&request.binding.namespace)?, request.family.id.as_str(), request.family.contract.as_str()],
        |r| Ok(Row {
            namespace_json:r.get(0)?,family_contract:r.get(1)?,lineage:r.get(2)?,lineage_revision:r.get(3)?,
            recipient:r.get(4)?,session:r.get(5)?,grant:r.get(6)?,grant_digest:r.get(7)?,grant_until:r.get(8)?,epoch:r.get(9)?,
            version:r.get(10)?,selector:r.get(11)?,verifier:r.get(12)?,verifier_version:r.get(13)?,issued_at:r.get(14)?,expires_at:r.get(15)?,
            identity_json:r.get(16)?,material_revision:r.get(17)?,envelope_revision:r.get(18)?,encryption_version:r.get(19)?,nonce:r.get(20)?,ciphertext:r.get(21)?,
            principal:r.get(22)?,creator:r.get(23)?,label:r.get(24)?,predecessor:r.get(25)?,
        }),
    ).optional()?.context("credential rewrap target unavailable")?;
    ensure!(
        now >= row.issued_at && now < row.expires_at && now < row.grant_until,
        "credential rewrap target expired or clock rewound"
    );
    let namespace = crate::json::decode(row.namespace_json.as_bytes())?;
    ensure!(
        request.binding.namespace == namespace,
        "credential rewrap namespace changed"
    );
    let identity = MaterialIdentity {
        namespace,
        family: request.family.id.as_str().to_owned(),
        lineage: row.lineage.clone(),
        version: row.version.clone(),
        recipient: row.recipient.clone(),
        security_epoch: row.epoch.try_into()?,
        material_revision: row.material_revision.try_into()?,
    };
    let stored: MaterialIdentity = crate::json::decode(row.identity_json.as_bytes())?;
    ensure!(
        stored == identity && identity.security_epoch > 0 && identity.material_revision > 0,
        "credential rewrap stored identity changed"
    );
    let target = Target {
        identity,
        fingerprint: Digest::of(&("day2-managed-rewrap-target-v1", &row))?,
        binding: request.binding.clone(),
        family: request.family.clone(),
        envelope_revision: row.envelope_revision.try_into()?,
        encryption_version: row.encryption_version.clone(),
        expires_at: row.expires_at,
    };
    Ok((target, row))
}

fn authorize(authority: &dyn Authority, target: &Target, now: i64) -> Result<Selection> {
    let selected = authority.authorize(target, now)?;
    ensure!(
        selected.security_epoch == target.identity.security_epoch
            && selected.previous.binding == target.binding.custody
            && selected.replacement.binding == target.binding.custody
            && selected.previous.version == target.encryption_version
            && selected.previous.version != selected.replacement.version
            && selected.observed_at >= 0
            && selected.observed_at <= now
            && now < selected.ready_until
            && selected
                .ready_until
                .checked_sub(selected.observed_at)
                .is_some_and(|n| n <= 300),
        "credential rewrap maintenance selection unavailable or changed"
    );
    Ok(selected)
}

fn key(provider: &dyn ApprovalKeyProvider, reference: &ApprovalKeyRef) -> Result<RewrapKey> {
    let mut material = provider.load(reference, ApprovalKeyPurpose::CustodyEncryption)?;
    let result = (|| {
        ensure!(
            material.binding == reference.binding
                && material.version == reference.version
                && material.purpose == ApprovalKeyPurpose::CustodyEncryption,
            "credential rewrap key lease identity changed"
        );
        RewrapKey::new(&material.bytes, reference.version.clone())
    })();
    material.bytes.zeroize();
    result
}

/// Opaque, one-use ciphertext staging. It cannot reveal or publish a token.
pub(crate) struct Prepared {
    target: Target,
    original: Row,
    selection: Selection,
    last_observed_at: i64,
    envelope: crypto::RewrappedEnvelope,
}

/// No write transaction may span key-provider/entropy work. A genuine native
/// maintenance entry is intentionally absent; callers must not raw-open a
/// native Runtime to reach this controlled core.
pub(crate) fn prepare(
    db: &Connection,
    authority: &dyn Authority,
    provider: &dyn ApprovalKeyProvider,
    request: Request<'_>,
) -> Result<Prepared> {
    ensure!(
        db.is_autocommit(),
        "credential rewrap preparation requires no transaction"
    );
    let started = effects::wall_time()?;
    let (target, original) = current(db, &request, started)?;
    let selected = authorize(authority, &target, started)?;
    let old = key(provider, &selected.previous)?;
    let replacement = key(provider, &selected.replacement)?;
    // Re-select after provider I/O. No changed current row is decrypted merely
    // because its earlier metadata was self-consistent.
    let now = effects::wall_time()?;
    let (target, observed) = current(db, &request, now)?;
    ensure!(
        observed == original && now >= started && authorize(authority, &target, now)? == selected,
        "credential rewrap preparation became stale"
    );
    let envelope = crypto::prepare_rewrap(
        &old,
        &replacement,
        &target.identity,
        RewrapSource {
            identity: &target.identity,
            selector: &original.selector,
            envelope_revision: target.envelope_revision,
            encryption_version: &target.encryption_version,
            nonce: original
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid credential rewrap nonce"))?,
            ciphertext: &original.ciphertext,
        },
    )?;
    let finished = effects::wall_time()?;
    ensure!(
        finished >= now && authorize(authority, &target, finished)? == selected,
        "credential rewrap preparation authority changed"
    );
    Ok(Prepared {
        target,
        original,
        selection: selected,
        last_observed_at: finished,
        envelope,
    })
}

/// A staging marker only. No public receipt, plaintext, permit, serialization
/// or commit-success conversion exists. The caller owns product commit and
/// unknown-outcome handling; rollback must never be reported as maintenance.
pub(crate) struct Pending {
    _private: (),
}

pub(crate) fn stage(
    tx: &Transaction<'_>,
    authority: &dyn Authority,
    prepared: Prepared,
) -> Result<Pending> {
    let now = effects::wall_time()?;
    ensure!(
        now >= prepared.last_observed_at && now < prepared.selection.ready_until,
        "credential rewrap preparation expired or clock rewound"
    );
    let (target, row) = current(
        tx,
        &Request {
            binding: &prepared.target.binding,
            family: &prepared.target.family,
            version: &prepared.target.identity.version,
        },
        now,
    )?;
    ensure!(
        row == prepared.original,
        "credential rewrap material changed"
    );
    // Local current maintenance evidence IMMEDIATELY before the conditional
    // update, on the actual target reselected under this caller transaction.
    ensure!(
        authorize(authority, &target, now)? == prepared.selection,
        "credential rewrap maintenance authority changed"
    );
    let update_at = effects::wall_time()?;
    ensure!(
        update_at >= now
            && update_at < prepared.selection.ready_until
            && update_at < row.expires_at
            && update_at < row.grant_until,
        "credential rewrap authority expired or clock rewound before update"
    );
    let changed = tx.execute(
        "UPDATE day2_credential_material SET envelope_revision=?1,encryption_key_version=?2,nonce=?3,ciphertext=?4
         WHERE version=?5 AND identity_json=?6 AND material_revision=?7 AND envelope_revision=?8
           AND encryption_key_version=?9 AND nonce=?10 AND ciphertext=?11
           AND EXISTS(SELECT 1 FROM day2_credential_versions v JOIN day2_credential_lineages l ON l.id=v.lineage
             WHERE v.id=day2_credential_material.version AND l.namespace=?12 AND l.family_contract=?13
               AND l.state='active' AND l.head=v.id AND l.revision=?14 AND v.state='active'
               AND v.security_epoch=?15 AND l.security_epoch=?15 AND v.grant_digest=l.grant_digest
               AND l.namespace_json=?17 AND l.family=?18 AND l.id=?19
               AND l.recipient=?20 AND l.session=?21 AND l.grant_json=?22
               AND l.grant_digest=?23 AND l.grant_valid_until=?24
               AND v.lineage=?19 AND v.selector=?25 AND v.verifier=?26
               AND v.verifier_key_version=?27 AND v.issued_at=?28 AND v.expires_at=?29
               AND l.principal=?30 AND l.creator=?31 AND l.label=?32 AND v.predecessor IS ?33
               AND v.issued_at<=?16 AND ?16<v.expires_at AND ?16<l.grant_valid_until)",
        params![i64::try_from(prepared.envelope.envelope_revision)?, prepared.envelope.encryption_version,
            prepared.envelope.nonce.as_slice(),prepared.envelope.ciphertext,row.version,row.identity_json,
            row.material_revision,row.envelope_revision,row.encryption_version,row.nonce,row.ciphertext,
            namespace_key(&target.identity.namespace)?,row.family_contract,row.lineage_revision,row.epoch,update_at,
            row.namespace_json,target.identity.family,row.lineage,row.recipient,row.session,row.grant,
            row.grant_digest,row.grant_until,row.selector,row.verifier,row.verifier_version,row.issued_at,row.expires_at,
            row.principal,row.creator,row.label,row.predecessor],
    )?;
    ensure!(changed == 1, "credential rewrap conditional write lost");
    Ok(Pending { _private: () })
}

#[cfg(test)]
mod tests {
    use super::super::tests as fixture;
    use super::*;
    use crate::{
        managed_credentials::{crypto::KeyLease, simulation::World},
        oauth::approval_registry::ApprovalKeyMaterial,
    };
    use day2_capabilities::{
        BindingRef, Name,
        credentials::{DeliveryProfile, RotationProfile},
        oauth::{ResourceAudienceRef, SecurityOriginRef},
    };
    use rusqlite::{TransactionBehavior, types::Value};
    use std::{
        cell::RefCell,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    fn binding() -> CredentialFamilyBinding {
        CredentialFamilyBinding {
            namespace: fixture::namespace(),
            family: fixture::family().id,
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
        }
    }

    struct LocalAuthority {
        allowed: Arc<AtomicBool>,
        binding: CredentialFamilyBinding,
        version: String,
        selection: RefCell<Selection>,
        calls: RefCell<Vec<Digest>>,
    }

    impl Authority for LocalAuthority {
        fn authorize(&self, target: &Target, now: i64) -> Result<Selection> {
            ensure!(
                self.allowed.load(Ordering::SeqCst)
                    && target.binding() == &self.binding
                    && target.identity().version == self.version,
                "controlled maintenance denied"
            );
            self.calls.borrow_mut().push(target.fingerprint().clone());
            ensure!(now >= 1000, "controlled maintenance clock");
            Ok(self.selection.borrow().clone())
        }
    }

    struct Keys {
        binding: BindingRef,
        calls: AtomicUsize,
        revoke: Option<Arc<AtomicBool>>,
        advance: Option<Arc<World>>,
    }

    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure!(
                reference.binding == self.binding
                    && purpose == ApprovalKeyPurpose::CustodyEncryption,
                "controlled maintenance key purpose"
            );
            let bytes = match reference.version.as_str() {
                "encrypt-v1" => [4; 32],
                "encrypt-v2" => [8; 32],
                _ => anyhow::bail!("controlled key unavailable"),
            };
            if let Some(allowed) = &self.revoke {
                allowed.store(false, Ordering::SeqCst);
            }
            if let Some(world) = &self.advance {
                world.set_wall(1050);
            }
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: reference.version.clone(),
                purpose,
                bytes,
            })
        }
    }

    fn ports(version: &str) -> (LocalAuthority, Keys) {
        let binding = binding();
        let selection = Selection {
            previous: ApprovalKeyRef {
                binding: binding.custody.clone(),
                version: "encrypt-v1".into(),
            },
            replacement: ApprovalKeyRef {
                binding: binding.custody.clone(),
                version: "encrypt-v2".into(),
            },
            security_epoch: 7,
            authority_revision: Digest::new(b"maintenance-v1"),
            observed_at: 900,
            ready_until: 1200,
        };
        let keys = Keys {
            binding: binding.custody.clone(),
            calls: AtomicUsize::new(0),
            revoke: None,
            advance: None,
        };
        (
            LocalAuthority {
                allowed: Arc::new(AtomicBool::new(true)),
                binding,
                version: version.into(),
                selection: RefCell::new(selection),
                calls: RefCell::new(Vec::new()),
            },
            keys,
        )
    }

    fn prepared(db: &Connection, authority: &LocalAuthority, keys: &Keys) -> Result<Prepared> {
        prepare(
            db,
            authority,
            keys,
            Request {
                binding: &authority.binding,
                family: &fixture::family(),
                version: &authority.version,
            },
        )
    }

    fn other_rows(db: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
        [
            "day2_credential_lineages",
            "day2_credential_versions",
            "day2_credential_deliveries",
            "day2_credential_receipts",
            "day2_credential_reveals",
            "day2_credential_revocations",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
            let count = statement.column_count();
            let rows = statement
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<Value>>>()
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .collect()
    }

    #[test]
    fn one_row_rewrap_preserves_material_and_all_non_envelope_state() -> Result<()> {
        effects::scope(World::new(701), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            let request = Request {
                binding: &authority.binding,
                family: &fixture::family(),
                version: receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            };
            let (_, before) = current(&db, &request, 1000)?;
            let others = other_rows(&db)?;
            let old = crypto::decrypt_for_human(
                &fixture::lease(),
                &crate::json::decode(before.identity_json.as_bytes())?,
                &crate::json::decode(before.identity_json.as_bytes())?,
                1,
                "encrypt-v1",
                before.nonce.as_slice().try_into()?,
                &before.ciphertext,
            )?;
            let staged = prepared(&db, &authority, &keys)?;
            assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
            let calls = authority.calls.borrow().len();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending = stage(&tx, &authority, staged)?;
            assert_eq!(authority.calls.borrow().len(), calls + 1);
            tx.commit()?;
            let (_, after) = current(&db, &request, 1000)?;
            assert_eq!(after.envelope_revision, 2);
            assert_eq!(after.encryption_version, "encrypt-v2");
            let identity = crate::json::decode(after.identity_json.as_bytes())?;
            let next = KeyLease::new(&[3; 32], &[8; 32], "verify-v1".into(), "encrypt-v2".into())?;
            let token = crypto::decrypt_for_human(
                &next,
                &identity,
                &identity,
                2,
                "encrypt-v2",
                after.nonce.as_slice().try_into()?,
                &after.ciphertext,
            )?;
            assert_eq!(token, old);
            assert_eq!(other_rows(&db)?, others);
            assert_eq!(after.identity_json, before.identity_json);
            assert_eq!(after.material_revision, before.material_revision);
            super::super::install_schema(&db)?;
            Ok(())
        })
    }

    #[test]
    fn rollback_and_competing_rewrap_never_publish_a_stale_envelope() -> Result<()> {
        effects::scope(World::new(702), || {
            let (dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            let first = prepared(&db, &authority, &keys)?;
            let mut competing = Connection::open(dir.path().join("app.sqlite"))?;
            let stale = prepared(&competing, &authority, &keys)?;
            let original = first.original.ciphertext.clone();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending = stage(&tx, &authority, first)?;
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                    .get::<_, Vec<u8>>(0))?,
                original
            );
            let first = prepared(&db, &authority, &keys)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending = stage(&tx, &authority, first)?;
            tx.commit()?;
            let winner =
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| {
                    r.get::<_, Vec<u8>>(0)
                })?;
            let tx = competing.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(stage(&tx, &authority, stale).is_err());
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                    .get::<_, Vec<u8>>(0))?,
                winner
            );
            Ok(())
        })
    }

    #[test]
    fn rotation_revocation_and_new_material_defeat_old_preparation() -> Result<()> {
        effects::scope(World::new(703), || {
            for action in ["rotate", "revoke", "material"] {
                let (_dir, mut db) = fixture::database()?;
                let receipt = fixture::committed_issue(&mut db)?;
                let (authority, keys) = ports(
                    receipt
                        .version
                        .as_deref()
                        .context("issued version required")?,
                );
                let ready = prepared(&db, &authority, &keys)?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                match action {
                    "revoke" => {
                        assert!(super::super::stage_revoke(
                            &tx,
                            &fixture::namespace(),
                            &receipt.lineage
                        )?);
                    }
                    "rotate" => {
                        assert!(matches!(
                            super::super::stage_rotation(
                                &tx,
                                &fixture::lease(),
                                &fixture::snapshot(&receipt),
                                super::super::RotationIntent {
                                    invocation: "rotation-for-rewrap",
                                    instruction_slot: 0,
                                    recipient: "issuer/human-1",
                                    session: "session-1",
                                    issued_at: 1100,
                                    expires_at: 2100,
                                    reveal_until: 1400,
                                }
                            )?,
                            super::super::RotationResult::Rotated(_)
                        ));
                    }
                    _ => {
                        let mut identity: MaterialIdentity =
                            crate::json::decode(ready.original.identity_json.as_bytes())?;
                        identity.material_revision += 1;
                        tx.execute("UPDATE day2_credential_material SET material_revision=?1,identity_json=?2,ciphertext=?3",params![i64::try_from(identity.material_revision)?,serde_json::to_string(&identity)?,vec![9u8;64]])?;
                    }
                }
                tx.commit()?;
                let material = db.query_row(
                    "SELECT ciphertext FROM day2_credential_material WHERE version=?1",
                    [&receipt.version],
                    |r| r.get::<_, Vec<u8>>(0),
                )?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert!(stage(&tx, &authority, ready).is_err());
                tx.rollback()?;
                assert_eq!(
                    db.query_row(
                        "SELECT ciphertext FROM day2_credential_material WHERE version=?1",
                        [&receipt.version],
                        |r| r.get::<_, Vec<u8>>(0)
                    )?,
                    material
                );
            }
            Ok(())
        })
    }

    #[test]
    fn maintenance_is_rechecked_in_transaction_and_expires_at_equality() -> Result<()> {
        let world = World::new(704);
        effects::scope(world.clone(), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, mut keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            authority.allowed.store(false, Ordering::SeqCst);
            assert!(prepared(&db, &authority, &keys).is_err());
            assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
            authority.allowed.store(true, Ordering::SeqCst);
            keys.revoke = Some(authority.allowed.clone());
            assert!(prepared(&db, &authority, &keys).is_err());
            keys.revoke = None;
            authority.allowed.store(true, Ordering::SeqCst);
            let ready = prepared(&db, &authority, &keys)?;
            authority.allowed.store(false, Ordering::SeqCst);
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(stage(&tx, &authority, ready).is_err());
            tx.rollback()?;
            authority.allowed.store(true, Ordering::SeqCst);
            let ready = prepared(&db, &authority, &keys)?;
            world.set_wall(1200);
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(stage(&tx, &authority, ready).is_err());
            tx.rollback()?;
            assert_eq!(
                db.query_row(
                    "SELECT envelope_revision FROM day2_credential_material",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            Ok(())
        })
    }

    #[test]
    fn stage_preserves_latest_preparation_clock_and_accepts_only_nonrewinding_equality()
    -> Result<()> {
        let world = World::new(705);
        effects::scope(world.clone(), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, mut keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            keys.advance = Some(world.clone());
            let first = prepared(&db, &authority, &keys)?;
            assert_eq!(first.last_observed_at, 1050);
            let original = first.original.ciphertext.clone();
            world.set_wall(1025);
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(stage(&tx, &authority, first).is_err());
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                    .get::<_, Vec<u8>>(0))?,
                original
            );
            world.set_wall(1050);
            let ready = prepared(&db, &authority, &keys)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending = stage(&tx, &authority, ready)?;
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                    .get::<_, Vec<u8>>(0))?,
                original
            );
            Ok(())
        })
    }
    #[test]
    fn preparation_inside_transaction_never_calls_keys_and_epoch_changes_refuse_staging()
    -> Result<()> {
        effects::scope(World::new(706), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(prepared(&tx, &authority, &keys).is_err());
            assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
            tx.rollback()?;
            for change in ["epoch", "key", "authority"] {
                let ready = prepared(&db, &authority, &keys)?;
                let original = ready.original.ciphertext.clone();
                let before = authority.selection.borrow().clone();
                match change {
                    "epoch" => authority.selection.borrow_mut().security_epoch = 8,
                    "key" => {
                        authority.selection.borrow_mut().replacement.version = "encrypt-v3".into()
                    }
                    _ => {
                        authority.selection.borrow_mut().authority_revision =
                            Digest::new(b"maintenance-v2")
                    }
                }
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert!(stage(&tx, &authority, ready).is_err());
                tx.rollback()?;
                assert_eq!(
                    db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                        .get::<_, Vec<u8>>(0))?,
                    original
                );
                *authority.selection.borrow_mut() = before;
            }
            Ok(())
        })
    }

    #[test]
    fn version_expiry_is_not_extended_by_maintenance_readiness() -> Result<()> {
        let world = World::new(707);
        effects::scope(world.clone(), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            authority.selection.borrow_mut().observed_at = 1850;
            authority.selection.borrow_mut().ready_until = 2150;
            world.set_wall(1900);
            let ready = prepared(&db, &authority, &keys)?;
            let original = ready.original.ciphertext.clone();
            world.set_wall(2000);
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(stage(&tx, &authority, ready).is_err());
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                    .get::<_, Vec<u8>>(0))?,
                original
            );
            assert_eq!(
                db.query_row("SELECT expires_at FROM day2_credential_versions", [], |r| r
                    .get::<_, i64>(0))?,
                2000
            );
            Ok(())
        })
    }

    #[test]
    fn final_authorizer_cannot_cross_the_original_expiry_or_rewind_before_cas() -> Result<()> {
        struct ClockCut<'a> {
            authority: &'a LocalAuthority,
            world: Arc<World>,
            next: i64,
        }
        impl Authority for ClockCut<'_> {
            fn authorize(&self, target: &Target, now: i64) -> Result<Selection> {
                let selection = self.authority.authorize(target, now)?;
                self.world.set_wall(self.next);
                Ok(selection)
            }
        }
        let world = World::new(708);
        effects::scope(world.clone(), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            for next in [999, 1200] {
                world.set_wall(1000);
                let ready = prepared(&db, &authority, &keys)?;
                let original = ready.original.ciphertext.clone();
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert!(
                    stage(
                        &tx,
                        &ClockCut {
                            authority: &authority,
                            world: world.clone(),
                            next
                        },
                        ready
                    )
                    .is_err()
                );
                tx.rollback()?;
                assert_eq!(
                    db.query_row("SELECT ciphertext FROM day2_credential_material", [], |r| r
                        .get::<_, Vec<u8>>(0))?,
                    original
                );
            }
            Ok(())
        })
    }

    #[test]
    fn entropy_refusal_leaves_the_exact_row_and_all_product_state_unchanged() -> Result<()> {
        struct NoSecret(Arc<World>);
        impl effects::Hooks for NoSecret {
            fn domain(&self) -> u64 {
                effects::Hooks::domain(self.0.as_ref())
            }
            fn wall_time(&self) -> Result<i64> {
                effects::Hooks::wall_time(self.0.as_ref())
            }
            fn monotonic(&self) -> std::time::Duration {
                effects::Hooks::monotonic(self.0.as_ref())
            }
            fn fill_id(&self, bytes: &mut [u8]) -> Result<()> {
                effects::Hooks::fill_id(self.0.as_ref(), bytes)
            }
            fn fill_secret(&self, _: &mut [u8]) -> Result<()> {
                anyhow::bail!("controlled entropy refusal")
            }
        }
        let world = World::new(709);
        effects::scope(world.clone(), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            let request = Request {
                binding: &authority.binding,
                family: &fixture::family(),
                version: &authority.version,
            };
            let (_, before) = current(&db, &request, 1000)?;
            let others = other_rows(&db)?;
            effects::scope(Arc::new(NoSecret(world.clone())), || {
                assert!(prepared(&db, &authority, &keys).is_err());
            });
            let (_, after) = current(&db, &request, 1000)?;
            assert!(before == after);
            assert_eq!(other_rows(&db)?, others);
            Ok(())
        })
    }

    #[test]
    fn private_maintenance_values_have_no_duplicating_or_exporting_traits() {
        macro_rules! absent {
            ($type:ty, $bound:path) => {
                const _: fn() = || {
                    trait AmbiguousIfImpl<A> {
                        fn check() {}
                    }
                    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                    struct Invalid;
                    impl<T: ?Sized + $bound> AmbiguousIfImpl<Invalid> for T {}
                    let _ = <$type as AmbiguousIfImpl<_>>::check;
                };
            };
        }
        macro_rules! opaque {
            ($type:ty) => {
                absent!($type, Clone);
                absent!($type, Copy);
                absent!($type, Default);
                absent!($type, std::fmt::Debug);
                absent!($type, serde::Serialize);
                absent!($type, serde::Deserialize<'static>);
            };
        }
        opaque!(RewrapKey);
        opaque!(Prepared);
        opaque!(Pending);
    }

    #[test]
    fn key_provider_cannot_substitute_binding_version_or_purpose() -> Result<()> {
        struct Substituted<'a> {
            source: &'a Keys,
            field: u8,
        }
        impl ApprovalKeyProvider for Substituted<'_> {
            fn load(
                &self,
                reference: &ApprovalKeyRef,
                purpose: ApprovalKeyPurpose,
            ) -> Result<ApprovalKeyMaterial> {
                let mut material = self.source.load(reference, purpose)?;
                match self.field {
                    0 => material.binding = pin("foreign-custody"),
                    1 => material.version = "foreign-version".into(),
                    _ => material.purpose = ApprovalKeyPurpose::CustodyVerifier,
                }
                Ok(material)
            }
        }
        effects::scope(World::new(710), || {
            let (_dir, mut db) = fixture::database()?;
            let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = ports(
                receipt
                    .version
                    .as_deref()
                    .context("issued version required")?,
            );
            for field in 0..3 {
                let request = Request {
                    binding: &authority.binding,
                    family: &fixture::family(),
                    version: &authority.version,
                };
                let (_, before) = current(&db, &request, 1000)?;
                assert!(
                    prepare(
                        &db,
                        &authority,
                        &Substituted {
                            source: &keys,
                            field
                        },
                        request
                    )
                    .is_err()
                );
                let (_, after) = current(
                    &db,
                    &Request {
                        binding: &authority.binding,
                        family: &fixture::family(),
                        version: &authority.version,
                    },
                    1000,
                )?;
                assert!(before == after);
            }
            assert_eq!(keys.calls.load(Ordering::SeqCst), 3);
            Ok(())
        })
    }
}
