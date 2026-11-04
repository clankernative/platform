//! Conditional, single-row encryption and verifier maintenance. No operator/native entry is
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
    verifier_version: String,
    verifier_revision: u64,
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
    pub(crate) fn verifier_version(&self) -> &str {
        &self.verifier_version
    }
    pub(crate) fn verifier_revision(&self) -> u64 {
        self.verifier_revision
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
    version_grant: String,
    verifier_revision: i64,
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
            l.principal,l.creator,l.label,v.predecessor,v.grant_digest,v.verifier_revision
         FROM day2_credential_material m
         JOIN day2_credential_versions v ON v.id=m.version
         JOIN day2_credential_lineages l ON l.id=v.lineage
         WHERE v.id=?1 AND l.namespace=?2 AND l.family=?3 AND l.family_contract=?4
           AND l.state='active' AND l.head=v.id AND v.state='active'
           AND v.security_epoch=l.security_epoch",
        params![request.version, namespace_key(&request.binding.namespace)?, request.family.id.as_str(), request.family.contract.as_str()],
        |r| Ok(Row {
            namespace_json:r.get(0)?,family_contract:r.get(1)?,lineage:r.get(2)?,lineage_revision:r.get(3)?,
            recipient:r.get(4)?,session:r.get(5)?,grant:r.get(6)?,grant_digest:r.get(7)?,grant_until:r.get(8)?,epoch:r.get(9)?,
            version:r.get(10)?,selector:r.get(11)?,verifier:r.get(12)?,verifier_version:r.get(13)?,issued_at:r.get(14)?,expires_at:r.get(15)?,
            identity_json:r.get(16)?,material_revision:r.get(17)?,envelope_revision:r.get(18)?,encryption_version:r.get(19)?,nonce:r.get(20)?,ciphertext:r.get(21)?,
            principal:r.get(22)?,creator:r.get(23)?,label:r.get(24)?,predecessor:r.get(25)?,
            version_grant:r.get(26)?,
            verifier_revision:r.get(27)?,
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
    let stored: MaterialIdentity = crate::json::decode(row.identity_json.as_bytes())?;
    let ceiling: day2_capabilities::oauth::GrantCeiling =
        crate::json::decode(row.grant.as_bytes())?;
    super::require_grant_subset(&ceiling, &stored.grant)?;
    ensure!(
        ceiling.digest.as_str() == row.grant_digest
            && stored.grant.digest.as_str() == row.version_grant,
        "credential rewrap grant changed"
    );
    let identity = MaterialIdentity {
        namespace,
        family: request.family.id.as_str().to_owned(),
        lineage: row.lineage.clone(),
        version: row.version.clone(),
        recipient: row.recipient.clone(),
        security_epoch: row.epoch.try_into()?,
        material_revision: row.material_revision.try_into()?,
        grant: stored.grant.clone(),
    };
    ensure!(
        stored == identity && identity.security_epoch > 0 && identity.material_revision > 0
            && row.verifier_revision > 0,
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
        verifier_version: row.verifier_version.clone(),
        verifier_revision: row.verifier_revision.try_into()?,
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
               AND v.security_epoch=?15 AND l.security_epoch=?15 AND v.grant_digest=?34
               AND l.namespace_json=?17 AND l.family=?18 AND l.id=?19
               AND l.recipient=?20 AND l.session=?21 AND l.grant_json=?22
               AND l.grant_digest=?23 AND l.grant_valid_until=?24
               AND v.lineage=?19 AND v.selector=?25 AND v.verifier=?26
               AND v.verifier_key_version=?27 AND v.issued_at=?28 AND v.expires_at=?29
               AND l.principal=?30 AND l.creator=?31 AND l.label=?32 AND v.predecessor IS ?33
               AND v.verifier_revision=?35
               AND v.issued_at<=?16 AND ?16<v.expires_at AND ?16<l.grant_valid_until)",
        params![i64::try_from(prepared.envelope.envelope_revision)?, prepared.envelope.encryption_version,
            prepared.envelope.nonce.as_slice(),prepared.envelope.ciphertext,row.version,row.identity_json,
            row.material_revision,row.envelope_revision,row.encryption_version,row.nonce,row.ciphertext,
            namespace_key(&target.identity.namespace)?,row.family_contract,row.lineage_revision,row.epoch,update_at,
            row.namespace_json,target.identity.family,row.lineage,row.recipient,row.session,row.grant,
            row.grant_digest,row.grant_until,row.selector,row.verifier,row.verifier_version,row.issued_at,row.expires_at,
            row.principal,row.creator,row.label,row.predecessor,row.version_grant,row.verifier_revision],
    )?;
    ensure!(changed == 1, "credential rewrap conditional write lost");
    Ok(Pending { _private: () })
}

/// A distinct, current verifier-maintenance selection, never encryption or
/// human delivery permission. Accepted previous keys come from this authority,
/// not from the presented token or the stored key-version string alone.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifierSelection {
    pub previous: ApprovalKeyRef,
    pub replacement: ApprovalKeyRef,
    pub security_epoch: u64,
    pub authority_revision: Digest,
    pub observed_at: i64,
    pub ready_until: i64,
}

/// Local current evidence only, including exact binding/family/target, epoch,
/// accepted old verifier key and replacement. No provider I/O under caller TX.
/// No production adapter, maintenance purpose or operator execution is enabled.
pub(crate) trait VerifierAuthority {
    fn authorize(&self, target: &Target, now: i64) -> Result<VerifierSelection>;
}

fn authorize_verifier(authority: &dyn VerifierAuthority, target: &Target, now: i64) -> Result<VerifierSelection> {
    let selected = authority.authorize(target, now)?;
    ensure!(selected.security_epoch == target.identity.security_epoch
        && selected.previous.binding == target.binding.verifier
        && selected.replacement.binding == target.binding.verifier
        && selected.previous.version == target.verifier_version
        && selected.previous.version != selected.replacement.version
        && selected.observed_at >= 0 && selected.observed_at <= now
        && now < selected.ready_until
        && selected.ready_until.checked_sub(selected.observed_at).is_some_and(|n| n <= 300),
        "credential verifier maintenance selection unavailable or changed");
    Ok(selected)
}

fn verifier_key(provider: &dyn ApprovalKeyProvider, reference: &ApprovalKeyRef) -> Result<crypto::VerifierLease> {
    let mut material = provider.load(reference, ApprovalKeyPurpose::CustodyVerifier)?;
    let result = (|| {
        ensure!(material.binding == reference.binding && material.version == reference.version
            && material.purpose == ApprovalKeyPurpose::CustodyVerifier,
            "credential verifier key lease identity changed");
        crypto::VerifierLease::new(&material.bytes, reference.version.clone())
    })();
    material.bytes.zeroize();
    result
}

/// One-use verifier staging. Contains neither the presented token nor any
/// encryption/decryption key, permit, secret getter or current authority.
pub(crate) struct VerifierPrepared {
    target: Target,
    original: Row,
    selection: VerifierSelection,
    last_observed_at: i64,
    replacement_verifier: [u8; 32],
    replacement_revision: i64,
}

pub(crate) fn prepare_verifier(
    db: &Connection,
    authority: &dyn VerifierAuthority,
    provider: &dyn ApprovalKeyProvider,
    request: Request<'_>,
    presented_token: &str,
) -> Result<VerifierPrepared> {
    ensure!(db.is_autocommit(), "credential verifier preparation requires no transaction");
    let started = effects::wall_time()?;
    let (target, original) = current(db, &request, started)?;
    let replacement_revision = original.verifier_revision.checked_add(1)
        .context("credential verifier revision exhausted")?;
    let selected = authorize_verifier(authority, &target, started)?;
    let previous = verifier_key(provider, &selected.previous)?;
    let after_previous = effects::wall_time()?;
    let (intermediate, observed) = current(db, &request, after_previous)?;
    ensure!(after_previous >= started && observed == original
        && authorize_verifier(authority, &intermediate, after_previous)? == selected,
        "credential verifier preparation became stale after previous key");
    let replacement = verifier_key(provider, &selected.replacement)?;
    let now = effects::wall_time()?;
    let (target, observed) = current(db, &request, now)?;
    ensure!(now >= after_previous && observed == original
        && authorize_verifier(authority, &target, now)? == selected,
        "credential verifier preparation became stale");
    let replacement_verifier = crypto::prepare_verifier_replacement(
        &previous, &replacement, &target.identity, &original.selector, &original.verifier, presented_token)?;
    let finished = effects::wall_time()?;
    ensure!(finished >= now && authorize_verifier(authority, &target, finished)? == selected,
        "credential verifier preparation authority changed");
    Ok(VerifierPrepared { target, original, selection: selected, last_observed_at: finished,
        replacement_verifier, replacement_revision })
}

/// Staging only. The existing caller's SQL coordinator must settle its real
/// commit; rollback or an unknown completion cannot become maintenance success.
pub(crate) struct VerifierPending { _private: () }

pub(crate) fn stage_verifier(
    tx: &Transaction<'_>,
    authority: &dyn VerifierAuthority,
    prepared: VerifierPrepared,
) -> Result<VerifierPending> {
    let now = effects::wall_time()?;
    ensure!(now >= prepared.last_observed_at && now < prepared.selection.ready_until,
        "credential verifier preparation expired or clock rewound");
    let (target, row) = current(tx, &Request { binding: &prepared.target.binding,
        family: &prepared.target.family, version: &prepared.target.identity.version }, now)?;
    ensure!(row == prepared.original, "credential verifier material changed");
    ensure!(authorize_verifier(authority, &target, now)? == prepared.selection,
        "credential verifier maintenance authority changed");
    let update_at = effects::wall_time()?;
    ensure!(update_at >= now && update_at < prepared.selection.ready_until
        && update_at < row.expires_at && update_at < row.grant_until,
        "credential verifier authority expired or clock rewound before update");
    let changed = tx.execute(
        "UPDATE day2_credential_versions SET verifier=?1,verifier_key_version=?2,verifier_revision=?3
         WHERE id=?4 AND lineage=?5 AND predecessor IS ?6 AND selector=?7
           AND verifier=?8 AND verifier_key_version=?9 AND verifier_revision=?10
           AND issued_at=?11 AND expires_at=?12 AND security_epoch=?13 AND grant_digest=?14 AND state='active'
           AND issued_at<=?15 AND ?15<expires_at
           AND EXISTS(SELECT 1 FROM day2_credential_lineages l
             JOIN day2_credential_material m ON m.version=day2_credential_versions.id
             WHERE l.id=day2_credential_versions.lineage AND l.namespace=?16 AND l.namespace_json=?17
               AND l.family=?18 AND l.family_contract=?19 AND l.head=day2_credential_versions.id
               AND l.state='active' AND l.revision=?20 AND l.security_epoch=?13
               AND l.principal=?21 AND l.creator=?22 AND l.label=?23 AND l.recipient=?24 AND l.session=?25
               AND l.grant_json=?26 AND l.grant_digest=?27 AND l.grant_valid_until=?28 AND ?15<l.grant_valid_until
               AND m.identity_json=?29 AND m.material_revision=?30 AND m.envelope_revision=?31
               AND m.encryption_key_version=?32 AND m.nonce=?33 AND m.ciphertext=?34)",
        params![prepared.replacement_verifier.as_slice(), prepared.selection.replacement.version,
            prepared.replacement_revision, row.version, row.lineage, row.predecessor, row.selector,
            row.verifier, row.verifier_version, row.verifier_revision, row.issued_at, row.expires_at,
            row.epoch, row.version_grant, update_at, namespace_key(&target.identity.namespace)?,
            row.namespace_json, target.identity.family, row.family_contract, row.lineage_revision,
            row.principal, row.creator, row.label, row.recipient, row.session, row.grant,
            row.grant_digest, row.grant_until, row.identity_json, row.material_revision, row.envelope_revision,
            row.encryption_version, row.nonce, row.ciphertext],
    )?;
    ensure!(changed == 1, "credential verifier conditional write lost");
    Ok(VerifierPending { _private: () })
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

    struct VerifyAuthority {
        binding: CredentialFamilyBinding,
        family: ManifestFamily,
        version: String,
        allowed: Arc<AtomicBool>,
        selection: RefCell<VerifierSelection>,
    }

    impl VerifierAuthority for VerifyAuthority {
        fn authorize(&self, target: &Target, _: i64) -> Result<VerifierSelection> {
            ensure!(self.allowed.load(Ordering::SeqCst) && target.binding == self.binding
                && target.family == self.family && target.identity.version == self.version,
                "controlled verifier maintenance denied");
            Ok(self.selection.borrow().clone())
        }
    }

    struct VerifyKeys {
        binding: BindingRef,
        calls: AtomicUsize,
        revoke: Option<Arc<AtomicBool>>,
        advance: Option<(Arc<World>, i64)>,
        substitution: u8,
    }

    impl ApprovalKeyProvider for VerifyKeys {
        fn load(&self, reference: &ApprovalKeyRef, purpose: ApprovalKeyPurpose) -> Result<ApprovalKeyMaterial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure!(reference.binding == self.binding && purpose == ApprovalKeyPurpose::CustodyVerifier,
                "controlled verifier key selection refused");
            let bytes = match reference.version.as_str() {
                "verify-v1" => [3; 32], "verify-v2" => [9; 32], "verify-v3" => [13; 32],
                _ => anyhow::bail!("controlled verifier key unavailable"),
            };
            if let Some(allowed) = &self.revoke { allowed.store(false, Ordering::SeqCst); }
            if let Some((world, now)) = &self.advance { world.set_wall(*now); }
            let mut material = ApprovalKeyMaterial { binding: reference.binding.clone(), version: reference.version.clone(), purpose, bytes };
            match self.substitution {
                1 => material.binding.revision = Digest::new(b"foreign-verifier-binding"),
                2 => material.version = "foreign-version".into(),
                3 => material.purpose = ApprovalKeyPurpose::CustodyEncryption,
                4 if reference.version == "verify-v1" => material.bytes = [99; 32],
                _ => {},
            }
            Ok(material)
        }
    }

    fn verifier_ports(version: &str, family: ManifestFamily) -> (VerifyAuthority, VerifyKeys) {
        let binding = binding();
        let selected = VerifierSelection {
            previous: ApprovalKeyRef { binding: binding.verifier.clone(), version: "verify-v1".into() },
            replacement: ApprovalKeyRef { binding: binding.verifier.clone(), version: "verify-v2".into() },
            security_epoch: 7, authority_revision: Digest::new(b"verifier-policy-v1"), observed_at: 900, ready_until: 1200,
        };
        let keys = VerifyKeys { binding: binding.verifier.clone(), calls: AtomicUsize::new(0), revoke: None, advance: None, substitution: 0 };
        (VerifyAuthority { binding, family, version: version.into(), allowed: Arc::new(AtomicBool::new(true)), selection: RefCell::new(selected) }, keys)
    }

    fn verifier_prepared(db: &Connection, authority: &VerifyAuthority, keys: &VerifyKeys, token: &str) -> Result<VerifierPrepared> {
        prepare_verifier(db, authority, keys, Request { binding: &authority.binding, family: &authority.family, version: &authority.version }, token)
    }

    // Private rows and tokens deliberately have no Debug or serialization.
    #[derive(PartialEq)]
    struct VerifyImage(std::collections::BTreeMap<String, Vec<Vec<Value>>>);

    fn verifier_image(db: &Connection) -> Result<VerifyImage> {
        let mut names = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'day2_credential_*' ORDER BY name")?;
        let tables = names.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(tables.iter().map(String::as_str).collect::<std::collections::BTreeSet<_>>()
            == super::super::CREDENTIAL_TABLES.iter().copied().collect(), "verifier fixture table inventory changed");
        let mut image = std::collections::BTreeMap::new();
        for table in tables {
            let count: i64 = db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
            ensure!((0..=4).contains(&count), "verifier fixture row bound");
            let mut query = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
            let columns = query.column_count();
            ensure!(columns <= 32, "verifier fixture column bound");
            let rows = query.query_map([], |r| (0..columns).map(|i| r.get(i)).collect::<rusqlite::Result<Vec<Value>>>())?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for row in &rows { for value in row {
                ensure!(match value { Value::Text(text) => text.len() <= 65536,
                    Value::Blob(bytes) => bytes.len() <= 8192, _ => true }, "verifier fixture cell bound");
            } }
            image.insert(table, rows);
        }
        Ok(VerifyImage(image))
    }

    fn verifier_token(db: &Connection, authority: &VerifyAuthority) -> Result<String> {
        let (target, row) = current(db, &Request { binding: &authority.binding, family: &authority.family, version: &authority.version }, 1000)?;
        crypto::decrypt_for_human(&fixture::lease(), &target.identity, &target.identity,
            row.envelope_revision.try_into()?, &row.encryption_version, row.nonce.as_slice().try_into()?, &row.ciphertext)
    }

    fn only_verifier_changed(before: &VerifyImage, after: &VerifyImage) -> Result<()> {
        ensure!(before.0.keys().eq(after.0.keys()), "verifier maintenance changed tables");
        for (table, rows) in &before.0 {
            let next = &after.0[table];
            if table == "day2_credential_versions" {
                ensure!(rows.len() == 1 && next.len() == 1 && rows[0].len() == 12 && next[0].len() == 12
                    && rows[0][..4] == next[0][..4] && rows[0][6..11] == next[0][6..11],
                    "verifier maintenance changed bearer identity or authority");
            } else { ensure!(rows == next, "verifier maintenance changed other private state"); }
        }
        Ok(())
    }

    #[test]
    fn verifier_replacement_preserves_presented_token_and_all_other_private_state() -> Result<()> {
        effects::scope(World::new(721), || -> Result<()> {
            for profile in [ManagedProfile::Client, ManagedProfile::Personal] {
                let (_dir, mut db) = fixture::database()?;
                let mut family = fixture::family();
                family.profile = profile;
                family.contract = Digest::of(&("credential-family-contract-v1", &family.id, &family.profile,
                    &family.grant, &family.roots, family.lifetime_seconds))?;
                family.verify()?;
                let mut issue = fixture::issue("verifier-issue");
                issue.family_contract = family.contract.clone();
                if family.profile == ManagedProfile::Personal {
                    issue.principal = issue.recipient.clone();
                    issue.ceiling = day2_capabilities::oauth::GrantCeiling::derive(issue.ceiling.client.clone(), issue.principal.clone(),
                        issue.ceiling.audience.clone(), issue.ceiling.roots.clone())?;
                }
                let material = super::super::prepare_issue(&fixture::lease(), &family, issue)?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let receipt = super::super::stage_issue(&tx, material)?.public_identity().clone();tx.commit()?;
                let (authority, keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, family);
                let token = verifier_token(&db, &authority)?;
                let before = verifier_image(&db)?;
                let ready = verifier_prepared(&db, &authority, &keys, &token)?;
                let identity = ready.target.identity.clone();let selector = ready.original.selector.clone();
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let _pending = stage_verifier(&tx, &authority, ready)?;tx.commit()?;
                let after = verifier_image(&db)?;only_verifier_changed(&before, &after)?;
                let (hash, key, revision): (Vec<u8>,String,i64) = db.query_row("SELECT verifier,verifier_key_version,verifier_revision FROM day2_credential_versions", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
                ensure!(key == "verify-v2" && revision == 2 && verifier_token(&db, &authority)? == token, "verifier identity changed");
                ensure!(crypto::verify_managed(&crypto::VerifierLease::new(&[9;32], key.clone())?, &identity, &selector, &hash, &key, &token)?, "new exact verifier refused same token");
                ensure!(crypto::verify_managed(&fixture::lease(), &identity, &selector, &hash, &key, &token).is_err(), "old exact key accepted replacement");
                super::super::install_schema(&db)?;
            }
            Ok(())
        })
    }

    #[test]
    fn verifier_wrong_token_or_key_identity_never_creates_staging() -> Result<()> {
        effects::scope(World::new(722), || -> Result<()> {
            let (_dir, db) = fixture::database()?;
            let mut db = db; let receipt = fixture::committed_issue(&mut db)?;
            let (authority, mut keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, fixture::family());
            let token = verifier_token(&db, &authority)?;let before = verifier_image(&db)?;
            for invalid in ["bad".to_owned(), format!("{token}.extra"), token.replacen("d2c1.", "d2c2.", 1),
                format!("{}.{}", token.rsplit_once('.').unwrap().0, "A".repeat(43))] {
                ensure!(verifier_prepared(&db, &authority, &keys, &invalid).is_err(), "unverified token obtained staging");
            }
            for substitution in 1..=4 { keys.substitution = substitution;
                ensure!(verifier_prepared(&db, &authority, &keys, &token).is_err(), "substituted key obtained staging"); }
            ensure!(verifier_image(&db)? == before, "refused verification changed private state");
            Ok(())
        })
    }

    #[test]
    fn verifier_rollback_and_stale_competitor_do_not_publish() -> Result<()> {
        effects::scope(World::new(723), || -> Result<()> {
            let (_dir, mut db) = fixture::database()?;let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, fixture::family());
            let token = verifier_token(&db, &authority)?;let before = verifier_image(&db)?;
            let rollback = verifier_prepared(&db, &authority, &keys, &token)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending = stage_verifier(&tx, &authority, rollback)?;tx.rollback()?;
            ensure!(verifier_image(&db)? == before, "rolled-back verifier became durable");
            let winner = verifier_prepared(&db, &authority, &keys, &token)?;
            let stale = verifier_prepared(&db, &authority, &keys, &token)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;let _pending = stage_verifier(&tx, &authority, winner)?;tx.commit()?;
            let committed = verifier_image(&db)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;ensure!(stage_verifier(&tx, &authority, stale).is_err(), "stale verifier overwrote winner");tx.rollback()?;
            ensure!(verifier_image(&db)? == committed, "losing verifier changed durable rows");
            Ok(())
        })
    }

    #[test]
    fn verifier_revision_fences_an_exact_old_key_and_hash_aba() -> Result<()> {
        effects::scope(World::new(724), || -> Result<()> {
            let (_dir, mut db) = fixture::database()?;let receipt = fixture::committed_issue(&mut db)?;
            let (authority, keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, fixture::family());
            let token = verifier_token(&db, &authority)?;
            authority.selection.borrow_mut().replacement.version = "verify-v3".into();
            let stale = verifier_prepared(&db, &authority, &keys, &token)?;
            let original_hash = stale.original.verifier.clone();let original_selection = authority.selection.borrow().clone();
            for (previous, replacement) in [("verify-v1","verify-v2"),("verify-v2","verify-v1")] {
                authority.selection.borrow_mut().previous.version = previous.into();authority.selection.borrow_mut().replacement.version = replacement.into();
                let ready = verifier_prepared(&db, &authority, &keys, &token)?;let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let _pending = stage_verifier(&tx, &authority, ready)?;tx.commit()?;
            }
            let (hash, revision): (Vec<u8>,i64) = db.query_row("SELECT verifier,verifier_revision FROM day2_credential_versions", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
            ensure!(hash == original_hash && revision == 3, "ABA control missed exact original verifier");
            *authority.selection.borrow_mut() = original_selection;
            let before = verifier_image(&db)?;let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(stage_verifier(&tx, &authority, stale).is_err(), "ABA resurrected stale preparation");tx.rollback()?;
            ensure!(verifier_image(&db)? == before, "ABA loser changed private state");Ok(())
        })
    }

    #[test]
    fn verifier_rotation_revoke_and_rewrap_defeat_stale_preparation() -> Result<()> {
        effects::scope(World::new(725), || -> Result<()> {
            for action in ["rotate","revoke","rewrap"] {
                let (_dir, mut db) = fixture::database()?;let receipt = fixture::committed_issue(&mut db)?;
                let (authority, keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, fixture::family());
                let token = verifier_token(&db, &authority)?;let ready = verifier_prepared(&db, &authority, &keys, &token)?;
                let encrypted = if action == "rewrap" { let (auth, keys) = ports(&authority.version);Some((prepared(&db,&auth,&keys)?,auth)) } else {None};
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                match action {
                    "rotate" => { ensure!(matches!(super::super::stage_rotation(&tx, &fixture::lease(), &fixture::snapshot(&receipt), super::super::RotationIntent {
                        grant: &ready.target.identity.grant, invocation:"rotation-for-verifier", instruction_slot:0, recipient:"issuer/human-1", session:"session-1",
                        issued_at:1000,expires_at:2000,reveal_until:1300 })?, super::super::RotationResult::Rotated(_)), "rotation control refused"); },
                    "revoke" => { ensure!(super::super::stage_revoke(&tx, &fixture::namespace(), &receipt.lineage)?, "revoke control missed row"); },
                    _ => { let (ready, auth) = encrypted.context("rewrap control absent")?;let _pending = stage(&tx,&auth,ready)?; },
                }
                tx.commit()?;let before = verifier_image(&db)?;let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure!(stage_verifier(&tx, &authority, ready).is_err(), "stale verifier survived lifecycle change");tx.rollback()?;
                ensure!(verifier_image(&db)? == before, "stale verifier resurrected authority");
            }
            Ok(())
        })
    }

    #[test]
    fn verifier_change_also_defeats_stale_encryption_preparation() -> Result<()> {
        effects::scope(World::new(726), || -> Result<()> {
            let (_dir, mut db) = fixture::database()?;let receipt = fixture::committed_issue(&mut db)?;
            let version = receipt.version.as_deref().context("issued version")?;
            let (enc_authority, enc_keys) = ports(version);let stale = prepared(&db,&enc_authority,&enc_keys)?;
            let (authority, keys) = verifier_ports(version,fixture::family());let token = verifier_token(&db,&authority)?;
            let ready = verifier_prepared(&db,&authority,&keys,&token)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _pending=stage_verifier(&tx,&authority,ready)?;tx.commit()?;
            let before=verifier_image(&db)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(stage(&tx,&enc_authority,stale).is_err(),"encryption preparation overwrote newer verifier state");tx.rollback()?;
            ensure!(verifier_image(&db)?==before,"stale encryption changed verifier state");Ok(())
        })
    }

    #[test]
    fn verifier_checks_permission_before_keys_after_each_provider_and_at_stage() -> Result<()> {
        effects::scope(World::new(727), || -> Result<()> {
            let (_dir, mut db) = fixture::database()?;let receipt = fixture::committed_issue(&mut db)?;
            let (authority, mut keys) = verifier_ports(receipt.version.as_deref().context("issued version")?, fixture::family());
            let token = verifier_token(&db,&authority)?;let before=verifier_image(&db)?;
            authority.allowed.store(false,Ordering::SeqCst);
            ensure!(verifier_prepared(&db,&authority,&keys,&token).is_err() && keys.calls.load(Ordering::SeqCst)==0,"denied maintenance loaded keys");
            authority.allowed.store(true,Ordering::SeqCst);
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(verifier_prepared(&tx,&authority,&keys,&token).is_err() && keys.calls.load(Ordering::SeqCst)==0,"key work ran under transaction");tx.rollback()?;
            keys.revoke=Some(authority.allowed.clone());
            ensure!(verifier_prepared(&db,&authority,&keys,&token).is_err() && keys.calls.load(Ordering::SeqCst)==1,"revoked key read reached replacement key");
            keys.revoke=None;authority.allowed.store(true,Ordering::SeqCst);
            let ready=verifier_prepared(&db,&authority,&keys,&token)?;
            authority.selection.borrow_mut().authority_revision=Digest::new(b"new-maintenance-policy");
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(stage_verifier(&tx,&authority,ready).is_err(),"stale maintenance policy published");tx.rollback()?;
            ensure!(verifier_image(&db)?==before,"authority refusal changed private rows");Ok(())
        })
    }

    #[test]
    fn verifier_keeps_latest_clock_and_checks_final_cas_expiry_and_rewind() -> Result<()> {
        struct ClockCut<'a> { authority: &'a VerifyAuthority, world: Arc<World>, next: i64 }
        impl VerifierAuthority for ClockCut<'_> {
            fn authorize(&self,target:&Target,now:i64)->Result<VerifierSelection>{
                let selected=self.authority.authorize(target,now)?;self.world.set_wall(self.next);Ok(selected)
            }
        }
        let world=World::new(728);
        effects::scope(world.clone(),||->Result<()>{
            let (_dir,mut db)=fixture::database()?;let receipt=fixture::committed_issue(&mut db)?;
            let (authority,mut keys)=verifier_ports(receipt.version.as_deref().context("issued version")?,fixture::family());
            let token=verifier_token(&db,&authority)?;let before=verifier_image(&db)?;
            for now in [999,1200] {
                world.set_wall(1000);keys.advance=Some((world.clone(),now));
                ensure!(verifier_prepared(&db,&authority,&keys,&token).is_err(),"provider renewed or rewound original window");
            }
            keys.advance=Some((world.clone(),1001));world.set_wall(1000);
            let ready=verifier_prepared(&db,&authority,&keys,&token)?;world.set_wall(1000);
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(stage_verifier(&tx,&authority,ready).is_err(),"latest provider clock was forgotten");tx.rollback()?;
            keys.advance=None;
            for now in [999,1200] {
                world.set_wall(1000);let ready=verifier_prepared(&db,&authority,&keys,&token)?;
                let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure!(stage_verifier(&tx,&ClockCut{authority:&authority,world:world.clone(),next:now},ready).is_err(),"final CAS crossed expiry or rewind");tx.rollback()?;
            }
            world.set_wall(1000);let ready=verifier_prepared(&db,&authority,&keys,&token)?;
            // Equality with the last observation is valid; equality with expiry is not.
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;let _pending=stage_verifier(&tx,&authority,ready)?;tx.rollback()?;
            ensure!(verifier_image(&db)?==before,"clock control changed durable state");Ok(())
        })
    }

    #[test]
    fn verifier_revision_exhaustion_and_old_schema_refuse_without_upgrade() -> Result<()> {
        effects::scope(World::new(729),||->Result<()>{
            let (_dir,mut db)=fixture::database()?;let receipt=fixture::committed_issue(&mut db)?;
            let (authority,keys)=verifier_ports(receipt.version.as_deref().context("issued version")?,fixture::family());
            let token=verifier_token(&db,&authority)?;
            db.execute("UPDATE day2_credential_versions SET verifier_revision=?1",[i64::MAX])?;
            let before=verifier_image(&db)?;
            ensure!(verifier_prepared(&db,&authority,&keys,&token).is_err() && keys.calls.load(Ordering::SeqCst)==0,"exhausted verifier revision wrapped or fetched keys");
            ensure!(verifier_image(&db)?==before,"exhausted verifier revision changed rows");
            let old=super::super::CREDENTIAL_DDL.replace(",\n            verifier_revision INTEGER NOT NULL CHECK(verifier_revision > 0)","");
            ensure!(old!=super::super::CREDENTIAL_DDL,"old schema control did not remove revision");
            let old_db=Connection::open_in_memory()?;old_db.execute_batch(&old)?;
            old_db.execute("INSERT INTO day2_credential_schema_version VALUES(2)",[])?;
            let schema:String=old_db.query_row("SELECT group_concat(sql,';') FROM (SELECT sql FROM sqlite_schema ORDER BY name)",[],|r|r.get(0))?;
            ensure!(super::super::install_schema(&old_db).is_err(),"old verifier layout silently upgraded");
            let after:String=old_db.query_row("SELECT group_concat(sql,';') FROM (SELECT sql FROM sqlite_schema ORDER BY name)",[],|r|r.get(0))?;
            ensure!(schema==after,"refused old layout was mutated");Ok(())
        })
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
    fn narrowed_version_rewrap_preserves_both_grants_and_rejects_each_changed_snapshot()
    -> Result<()> {
        use day2_capabilities::credentials::{GrantSelection, RotationGrant};
        let world = World::new(707);
        effects::scope(world.clone(), || {
            for change in [
                "none",
                "ceiling_json",
                "ceiling_digest",
                "version_json",
                "version_digest",
                "ceiling_pair",
                "version_pair",
            ] {
                world.set_wall(1100);
                let (_directory, mut db) = fixture::database()?;
                let (family, ceiling) = fixture::selectable_fixture()?;
                let mut issue = fixture::issue("rewrap-selected-issue");
                issue.family_contract = family.contract.clone();
                issue.ceiling = ceiling.clone();
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let first = super::super::stage_issue(
                    &tx,
                    super::super::prepare_issue(&fixture::lease(), &family, issue)?,
                )?
                .public_identity()
                .clone();
                tx.commit()?;
                let selection = GrantSelection::new(&family, vec!["ReadTranscription".into()])?;
                let grant = family.rotation_ceiling(&ceiling, RotationGrant::Narrow(&selection))?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let successor = match super::super::stage_rotation(
                    &tx,
                    &fixture::lease(),
                    &fixture::snapshot(&first),
                    super::super::RotationIntent {
                        grant: &grant,
                        invocation: "rewrap-selected-narrow",
                        instruction_slot: 0,
                        recipient: "issuer/human-1",
                        session: "session-1",
                        issued_at: 1100,
                        expires_at: 2000,
                        reveal_until: 1300,
                    },
                )? {
                    super::super::RotationResult::Rotated(pending) => {
                        pending.public_identity().clone()
                    }
                    super::super::RotationResult::Conflict => {
                        anyhow::bail!("fresh rotation conflicted")
                    }
                };
                tx.commit()?;
                let version = successor.version.as_deref().context("narrowed successor")?;
                let (authority, keys) = ports(version);
                let request = Request {
                    binding: &authority.binding,
                    family: &family,
                    version,
                };
                let (_, before) = current(&db, &request, 1100)?;
                let ready = prepare(
                    &db,
                    &authority,
                    &keys,
                    Request {
                        binding: &authority.binding,
                        family: &family,
                        version,
                    },
                )?;
                assert_eq!(ready.target.identity.grant, grant);
                match change {
                    "ceiling_json" => {
                        db.execute(
                            "UPDATE day2_credential_lineages SET grant_json=?1",
                            [serde_json::to_string(&grant)?],
                        )?;
                    }
                    "ceiling_digest" => {
                        db.execute(
                            "UPDATE day2_credential_lineages SET grant_digest=?1",
                            [grant.digest.as_str()],
                        )?;
                    }
                    "version_json" => {
                        let mut identity: MaterialIdentity =
                            crate::json::decode(before.identity_json.as_bytes())?;
                        identity.grant = ceiling.clone();
                        db.execute(
                            "UPDATE day2_credential_material SET identity_json=?1 WHERE version=?2",
                            params![serde_json::to_string(&identity)?, version],
                        )?;
                    }
                    "version_digest" => {
                        db.execute(
                            "UPDATE day2_credential_versions SET grant_digest=?1 WHERE id=?2",
                            params![ceiling.digest.as_str(), version],
                        )?;
                    }
                    "ceiling_pair" => {
                        db.execute(
                            "UPDATE day2_credential_lineages SET grant_json=?1,grant_digest=?2",
                            params![serde_json::to_string(&grant)?, grant.digest.as_str()],
                        )?;
                    }
                    "version_pair" => {
                        let mut identity: MaterialIdentity =
                            crate::json::decode(before.identity_json.as_bytes())?;
                        identity.grant = ceiling.clone();
                        db.execute(
                            "UPDATE day2_credential_material SET identity_json=?1 WHERE version=?2",
                            params![serde_json::to_string(&identity)?, version],
                        )?;
                        db.execute(
                            "UPDATE day2_credential_versions SET grant_digest=?1 WHERE id=?2",
                            params![ceiling.digest.as_str(), version],
                        )?;
                    }
                    _ => {}
                }
                if matches!(change, "ceiling_pair" | "version_pair") {
                    // Each replacement is internally consistent, so this must
                    // reach the stale-target comparison rather than fail only
                    // at the grant JSON/digest consistency checks.
                    let (changed, _) = current(&db, &request, 1100)?;
                    assert_ne!(changed.fingerprint(), ready.target.fingerprint());
                }
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if change != "none" {
                    assert!(
                        stage(&tx, &authority, ready).is_err(),
                        "accepted changed {change}"
                    );
                    tx.rollback()?;
                    let (ciphertext,revision):(Vec<u8>,i64)=db.query_row("SELECT ciphertext,envelope_revision FROM day2_credential_material WHERE version=?1",[version],|r|Ok((r.get(0)?,r.get(1)?)))?;
                    assert_eq!(ciphertext, before.ciphertext);
                    assert_eq!(revision, 1);
                    continue;
                }
                let _pending = stage(&tx, &authority, ready)?;
                tx.commit()?;
                let (_, after) = current(&db, &request, 1100)?;
                assert_eq!(after.identity_json, before.identity_json);
                assert_eq!(after.grant, before.grant);
                assert_eq!(after.grant_digest, before.grant_digest);
                assert_eq!(after.version_grant, grant.digest.as_str());
                let identity: MaterialIdentity =
                    crate::json::decode(after.identity_json.as_bytes())?;
                let old = crypto::decrypt_for_human(
                    &fixture::lease(),
                    &identity,
                    &identity,
                    1,
                    "encrypt-v1",
                    before.nonce.as_slice().try_into()?,
                    &before.ciphertext,
                )?;
                let replacement =
                    KeyLease::new(&[3; 32], &[8; 32], "verify-v1".into(), "encrypt-v2".into())?;
                let new = crypto::decrypt_for_human(
                    &replacement,
                    &identity,
                    &identity,
                    2,
                    "encrypt-v2",
                    after.nonce.as_slice().try_into()?,
                    &after.ciphertext,
                )?;
                assert_eq!(old, new);
                super::super::install_schema(&db)?;
            }
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
                                    grant: &ready.target.identity.grant,
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
        opaque!(VerifierPrepared);
        opaque!(VerifierPending);
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
