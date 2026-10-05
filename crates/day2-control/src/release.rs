//! Atomic release authority and readiness guards, not a deployment workflow.
//!
//! Git approvals, authority updates and secret observations enter through trusted
//! host adapters. Their receipt digests are identities, not authentication or
//! cryptographic proof of a live forge/provider. This module performs no cloud
//! mutation and never stores secret values. The simulation exercises these same
//! SQLite guards; real adapters still require independent qualification.

use crate::provider_evidence::{RevisionRelation, StateEvidence};
use crate::{BindingRef, BuildPlan, Digest, GitOid, Name, journal::OperatorActor};
use crate::{journal::Journal, kernel::State};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTarget {
    pub company: Name,
    pub environment: Name,
    pub app: Name,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAuthority {
    pub source: BindingRef,
    pub policy: Digest,
    /// Operator who recorded this binding, not an allowlist of Git reviewers.
    pub actor: OperatorActor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitApproval {
    pub source: BindingRef,
    pub commit: GitOid,
    pub policy: Digest,
    pub receipt: Digest,
    pub actor: OperatorActor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableSecretRef {
    pub binding: BindingRef,
    pub secret: Name,
    pub version: NonZeroU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretObservation {
    pub reference: ImmutableSecretRef,
    /// Weak metadata remains evidence; only a scoped qualified read grants readiness.
    pub provider_state: StateEvidence,
    pub evidence: Digest,
    pub enabled: bool,
    pub access_granted: bool,
    pub projection_ready: bool,
}
impl SecretObservation {
    pub(crate) fn same_state(&self, other: &Self) -> bool {
        self.reference == other.reference
            && self.enabled == other.enabled
            && self.access_granted == other.access_granted
            && self.projection_ready == other.projection_ready
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseApproval {
    pub target: ReleaseTarget,
    pub request: Name,
    pub expected_generation: u64,
    pub build_execution: Digest,
    pub artifact: Digest,
    pub evidence: Digest,
    pub git: GitApproval,
    pub secret: ImmutableSecretRef,
}

/// Identity of a persisted approval, issued or recovered by the release journal.
/// Recovery does not restore current authority. Preparation and new activation
/// recheck desired generation, authority, build and secret reservation. Stops
/// check release status and preserve the recorded operator attribution.
///
/// Callers cannot construct an approval handle:
/// ```compile_fail,E0451
/// use day2_control::{Digest, release::ApprovedRelease};
/// let _ = ApprovedRelease { id: Digest::new(b"invented approval") };
/// ```
///
/// Untrusted serialized input cannot become an approval handle:
/// ```compile_fail,E0277
/// use day2_control::release::ApprovedRelease;
/// fn accepts_wire_input<T: serde::de::DeserializeOwned>() {}
/// accepts_wire_input::<ApprovedRelease>();
/// ```
#[derive(Clone, Debug)]
pub struct ApprovedRelease {
    id: Digest,
}
impl ApprovedRelease {
    pub fn id(&self) -> &Digest {
        &self.id
    }
}

/// Identity of persisted readiness for one approved release generation.
/// Recovering this handle verifies the stored proof's identity and generation;
/// new activation still checks current authority and exact secret readiness.
///
/// Callers cannot pair invented readiness with a release:
/// ```compile_fail,E0451
/// use day2_control::{Digest, release::ReadyRelease};
/// let _ = ReadyRelease {
///     id: Digest::new(b"invented readiness"),
///     release: Digest::new(b"invented release"),
/// };
/// ```
///
/// Untrusted serialized input cannot become a readiness handle:
/// ```compile_fail,E0277
/// use day2_control::release::ReadyRelease;
/// fn accepts_wire_input<T: serde::de::DeserializeOwned>() {}
/// accepts_wire_input::<ReadyRelease>();
/// ```
///
/// Approval identity cannot be used as readiness:
/// ```compile_fail,E0308
/// use day2_control::{journal::Journal, release::ApprovedRelease};
/// fn activate_too_early(journal: &mut Journal, approved: &ApprovedRelease) {
///     let _ = journal.activate_release(approved);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ReadyRelease {
    id: Digest,
    release: Digest,
}
impl ReadyRelease {
    pub fn id(&self) -> &Digest {
        &self.id
    }
}

// Always compiled, including production cfg(not(test)) implementations elsewhere
// in this crate. Historical handles may clone, but cannot be created by decoding
// untrusted wire input or by taking a default value.
const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $trait:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::check;
        }};
    }
    assert_not_impl!(ApprovedRelease, Default);
    assert_not_impl!(ReadyRelease, Default);
    assert_not_impl!(ApprovedRelease, serde::Deserialize<'static>);
    assert_not_impl!(ReadyRelease, serde::Deserialize<'static>);
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReceipt {
    pub id: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceipt {
    pub id: Digest,
    pub target: ReleaseTarget,
    pub release: Digest,
    pub generation: u64,
    pub artifact: Digest,
    pub secret: ImmutableSecretRef,
    pub readiness: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseState {
    pub generation: u64,
    pub desired: Option<Digest>,
    pub active: Option<ActivationReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseNotReady {
    AwaitingSecretMetadata,
    SecretDisabled,
    SecretAccessDenied,
    SecretProjectionUnavailable,
}
impl std::fmt::Display for ReleaseNotReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AwaitingSecretMetadata => "awaiting secret metadata",
            Self::SecretDisabled => "awaiting enabled secret version",
            Self::SecretAccessDenied => "awaiting secret access",
            Self::SecretProjectionUnavailable => "awaiting secret projection",
        })
    }
}
impl std::error::Error for ReleaseNotReady {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredApproval {
    pub(crate) approval: ReleaseApproval,
    pub(crate) generation: u64,
    pub(crate) authority_revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReady {
    pub(crate) release: Digest,
    pub(crate) generation: u64,
    pub(crate) secret_revision: u64,
    pub(crate) secret_evidence: Digest,
}

impl Journal {
    pub(crate) fn initialize_release_schema(&mut self) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS release_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);
            INSERT OR IGNORE INTO release_meta VALUES(1,2);",
        )?;
        let version: i64 = tx.query_row(
            "SELECT version FROM release_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == 1 {
            for table in [
                "release_slots",
                "release_observed",
                "release_observation_receipts",
                "release_approvals",
                "release_status",
                "release_stops",
                "release_readiness",
                "release_activations",
                "release_events",
            ] {
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )?;
                if exists {
                    let occupied: bool = tx.query_row(
                        &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                        [],
                        |row| row.get(0),
                    )?;
                    ensure!(
                        !occupied,
                        "legacy release evidence requires explicit reviewed migration"
                    );
                }
            }
            tx.execute("UPDATE release_meta SET version=2 WHERE singleton=1", [])?;
        } else {
            ensure!(version == 2, "unsupported release journal version");
        }
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS release_slots (
                target TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>=0),
                desired TEXT, active TEXT);
            CREATE TABLE IF NOT EXISTS release_observed (
                target TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision>0), body TEXT NOT NULL,
                PRIMARY KEY(target,kind,key));
            CREATE TABLE IF NOT EXISTS release_observation_receipts (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision>0));
            CREATE TABLE IF NOT EXISTS release_secret_uncertainty (
                target TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                incomparable INTEGER NOT NULL CHECK(incomparable IN (0,1)),
                PRIMARY KEY(target,key));
            CREATE TABLE IF NOT EXISTS release_approvals (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, fingerprint TEXT NOT NULL,
                body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS release_status (
                id TEXT PRIMARY KEY REFERENCES release_approvals(id),
                status TEXT NOT NULL CHECK(status IN ('approved','cancelled','revoked','active')));
            CREATE TABLE IF NOT EXISTS release_stops (
                release TEXT PRIMARY KEY REFERENCES release_approvals(id), body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS release_readiness (
                id TEXT PRIMARY KEY, release TEXT NOT NULL REFERENCES release_approvals(id),
                body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS release_activations (
                release TEXT PRIMARY KEY REFERENCES release_approvals(id), body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS release_catalog_scopes (
                scope TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS release_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
                kind TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS release_events_no_update BEFORE UPDATE ON release_events
                BEGIN SELECT RAISE(ABORT,'release audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS release_events_no_delete BEFORE DELETE ON release_events
                BEGIN SELECT RAISE(ABORT,'release audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS release_events_no_replace BEFORE INSERT ON release_events
                WHEN EXISTS(SELECT 1 FROM release_events WHERE sequence=NEW.sequence)
                BEGIN SELECT RAISE(ABORT,'release audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS release_approvals_no_update BEFORE UPDATE ON release_approvals
                BEGIN SELECT RAISE(ABORT,'release approvals are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS release_approvals_no_delete BEFORE DELETE ON release_approvals
                BEGIN SELECT RAISE(ABORT,'release approvals are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS release_activations_no_update BEFORE UPDATE ON release_activations
                BEGIN SELECT RAISE(ABORT,'release receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS release_activations_no_delete BEFORE DELETE ON release_activations
                BEGIN SELECT RAISE(ABORT,'release receipts are immutable'); END;",
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Trusted installation-policy adapter observation, never an app capability.
    pub fn observe_release_authority(
        &mut self,
        target: &ReleaseTarget,
        request: &Name,
        expected_revision: u64,
        authority: &ReleaseAuthority,
    ) -> Result<u64> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let receipt = observe(
            &tx,
            target,
            "authority",
            "current",
            request,
            expected_revision,
            authority,
        )?;
        tx.commit()?;
        Ok(receipt.revision)
    }

    /// Records metadata only. A revoked value/access observation invalidates all
    /// prior ready handles even if an equivalent ready observation arrives later.
    pub fn observe_release_secret(
        &mut self,
        target: &ReleaseTarget,
        request: &Name,
        expected_revision: u64,
        observation: &SecretObservation,
    ) -> Result<SecretReceipt> {
        observation.provider_state.require(
            &observation.reference.binding,
            &Digest::of(&observation.reference)?,
            None,
        )?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let key = secret_key(&observation.reference)?;
        let id = observation_id(target, "secret", &key, request)?;
        let duplicate =
            observation_receipt(&tx, &id, &Digest::of(&(expected_revision, observation))?)?;
        let receipt = if let Some(receipt) = duplicate {
            receipt
        } else {
            if let Some((_, current)) =
                read_observation::<SecretObservation>(&tx, target, "secret", &key)?
            {
                let relation = observation
                    .provider_state
                    .revision()
                    .relation(current.provider_state.revision());
                if relation == RevisionRelation::Incomparable
                    || (relation == RevisionRelation::Same && !observation.same_state(&current))
                {
                    mark_secret_uncertain(
                        &tx,
                        target,
                        &key,
                        observation,
                        relation == RevisionRelation::Incomparable,
                    )?;
                    tx.commit()?;
                    anyhow::bail!(
                        "conflicting qualified secret observation; readiness invalidated"
                    );
                }
                ensure!(
                    relation == RevisionRelation::Newer,
                    "stale provider secret observation"
                );
            }
            let receipt = observe(
                &tx,
                target,
                "secret",
                &key,
                request,
                expected_revision,
                observation,
            )?;
            clear_secret_uncertainty(&tx, target, &key, observation)?;
            receipt
        };
        tx.commit()?;
        Ok(receipt)
    }

    pub fn approve_release(&mut self, approval: &ReleaseApproval) -> Result<ApprovedRelease> {
        let id = Digest::of(&("day2-release-v1", &approval.target, &approval.request))?;
        let fingerprint = Digest::of(approval)?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        if let Some(prior) = tx
            .query_row(
                "SELECT fingerprint FROM release_approvals WHERE id=?1",
                [id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            ensure!(
                prior == fingerprint.as_str(),
                "release request reused with different inputs"
            );
            // Historical redelivery returns the original receipt, never restores desired state.
            let approved = Self::recover_approved_release_in(&tx, &id)?;
            tx.commit()?;
            return Ok(approved);
        }
        let state = read_state(&tx, &approval.target)?;
        ensure!(
            state.generation == approval.expected_generation,
            "stale desired generation"
        );
        let (authority_revision, authority) =
            read_observation::<ReleaseAuthority>(&tx, &approval.target, "authority", "current")?
                .ok_or_else(|| anyhow::anyhow!("release authority is not configured"))?;
        validate_authority(approval, &authority)?;
        validate_build(&tx, approval)?;
        crate::runtime_secret::reserve_release_in(&tx, &id, approval)?;
        let generation = successor(state.generation)?;
        let stored = StoredApproval {
            approval: approval.clone(),
            generation,
            authority_revision,
        };
        let target = target_key(&approval.target)?;
        tx.execute(
            "INSERT INTO release_approvals VALUES(?1,?2,?3,?4)",
            params![
                id.as_str(),
                target,
                fingerprint.as_str(),
                serde_json::to_string(&stored)?
            ],
        )?;
        tx.execute(
            "INSERT INTO release_status VALUES(?1,'approved')",
            [id.as_str()],
        )?;
        tx.execute("INSERT INTO release_slots(target,generation,desired,active) VALUES(?1,?2,?3,NULL)
            ON CONFLICT(target) DO UPDATE SET generation=excluded.generation,desired=excluded.desired",
            params![target, i64::try_from(generation)?, id.as_str()])?;
        release_event(&tx, &approval.target, "approved", &stored)?;
        tx.commit()?;
        Ok(ApprovedRelease { id })
    }

    pub fn prepare_release(&mut self, approved: &ApprovedRelease) -> Result<ReadyRelease> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let ready = Self::prepare_release_in(&tx, approved)?;
        tx.commit()?;
        Ok(ready)
    }

    pub(crate) fn prepare_release_in(
        tx: &Transaction<'_>,
        approved: &ApprovedRelease,
    ) -> Result<ReadyRelease> {
        let stored = current_approval(tx, &approved.id)?;
        let (secret_revision, observation) = ready_secret(tx, &stored.approval)?;
        let ready = StoredReady {
            release: approved.id.clone(),
            generation: stored.generation,
            secret_revision,
            secret_evidence: Digest::of(&observation)?,
        };
        let id = Digest::of(&("day2-release-readiness-v1", &ready))?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO release_readiness VALUES(?1,?2,?3)",
            params![
                id.as_str(),
                approved.id.as_str(),
                serde_json::to_string(&ready)?
            ],
        )?;
        if changed == 1 {
            release_event(tx, &stored.approval.target, "ready", &ready)?;
        }
        Self::recover_ready_release_in(tx, &id, &approved.id)
    }

    /// Restores verified persisted identity after a host restart. A cancelled,
    /// superseded or already activated approval can be recovered; recovery grants
    /// no current mutation authority. Preparation and new activation require
    /// current authority; stops retain their status and attribution guards.
    ///
    /// Handles are obtained through checked journal APIs:
    /// ```no_run
    /// use day2_control::{Digest, journal::Journal};
    /// # fn example() -> anyhow::Result<()> {
    /// let mut journal = Journal::open(std::path::Path::new("release.sqlite"))?;
    /// let approved = journal.load_approved_release(&Digest::new(b"persisted approval"))?;
    /// let ready = journal.prepare_release(&approved)?;
    /// let receipt = journal.activate_release(&ready)?;
    /// assert_eq!(&receipt.readiness, ready.id());
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_approved_release(&self, id: &Digest) -> Result<ApprovedRelease> {
        let tx = self.connection.unchecked_transaction()?;
        let approved = Self::recover_approved_release_in(&tx, id)?;
        tx.commit()?;
        Ok(approved)
    }

    /// Recover historical identity inside the caller's transaction. Current
    /// authority remains the responsibility of the protected release operation.
    pub(crate) fn recover_approved_release_in(
        tx: &Transaction<'_>,
        id: &Digest,
    ) -> Result<ApprovedRelease> {
        read_approval(tx, id)?;
        Ok(ApprovedRelease { id: id.clone() })
    }

    /// Recover only a persisted readiness proof for this release generation.
    /// This does not grant current authority or attest to current provider facts.
    pub(crate) fn recover_ready_release_in(
        tx: &Transaction<'_>,
        id: &Digest,
        release: &Digest,
    ) -> Result<ReadyRelease> {
        read_readiness(tx, id, release)?;
        Ok(ReadyRelease {
            id: id.clone(),
            release: release.clone(),
        })
    }

    /// This commits the authority pointer, not an atomic mutation of cloud state.
    /// A future deployment adapter must supply separately qualified readback and
    /// transition guards before this bounded secret-readiness proof is sufficient.
    pub fn activate_release(&mut self, ready: &ReadyRelease) -> Result<ActivationReceipt> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let enrolled: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM release_workflows
            WHERE json_extract(body,'$.snapshot.plan.release')=?1)",
            [ready.release.as_str()],
            |r| r.get(0),
        )?;
        ensure!(
            !enrolled,
            "enrolled release requires guarded deployment workflow activation"
        );
        let receipt = Self::activate_release_in_checked(&tx, ready, None)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub(crate) fn activate_release_in_checked(
        tx: &Transaction<'_>,
        ready: &ReadyRelease,
        catalog: Option<&crate::release_catalog::ReleaseCatalogCandidate>,
    ) -> Result<ActivationReceipt> {
        if let Some(body) = tx
            .query_row(
                "SELECT body FROM release_activations WHERE release=?1",
                [ready.release.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let receipt: ActivationReceipt = serde_json::from_str(&body)?;
            ensure!(
                receipt.readiness == ready.id,
                "release already activated with different readiness"
            );
            return Ok(receipt);
        }
        let proof = read_readiness(tx, &ready.id, &ready.release)?;
        let stored = current_approval(tx, &ready.release)?;
        crate::release_catalog::check_activation_candidate(
            tx,
            &ready.release,
            &stored.approval,
            catalog,
        )?;
        let (revision, observation) = ready_secret(tx, &stored.approval)?;
        ensure!(
            revision == proof.secret_revision && Digest::of(&observation)? == proof.secret_evidence,
            "stale secret readiness"
        );
        let receipt = ActivationReceipt {
            id: Digest::of(&("day2-release-activation-v1", &ready.release, &ready.id))?,
            target: stored.approval.target.clone(),
            release: ready.release.clone(),
            generation: stored.generation,
            artifact: stored.approval.artifact,
            secret: stored.approval.secret,
            readiness: ready.id.clone(),
        };
        let target = target_key(&receipt.target)?;
        crate::runtime_secret::activate_release_in(tx, &receipt)?;
        let changed = tx.execute(
            "UPDATE release_slots SET active=?1 WHERE target=?2
            AND generation=?3 AND desired=?4",
            params![
                serde_json::to_string(&receipt)?,
                target,
                i64::try_from(receipt.generation)?,
                ready.release.as_str()
            ],
        )?;
        ensure!(changed == 1, "release activation lost desired authority");
        tx.execute(
            "INSERT INTO release_activations VALUES(?1,?2)",
            params![ready.release.as_str(), serde_json::to_string(&receipt)?],
        )?;
        tx.execute(
            "UPDATE release_status SET status='active' WHERE id=?1",
            [ready.release.as_str()],
        )?;
        release_event(tx, &receipt.target, "activated", &receipt)?;
        Ok(receipt)
    }

    /// Actor assertions originate in a trusted host adapter, not an app request.
    pub fn cancel_release(
        &mut self,
        release: &ApprovedRelease,
        actor: &OperatorActor,
    ) -> Result<()> {
        self.stop_release(release, actor, "cancelled")
    }

    pub fn revoke_release(
        &mut self,
        release: &ApprovedRelease,
        actor: &OperatorActor,
    ) -> Result<()> {
        self.stop_release(release, actor, "revoked")
    }

    fn stop_release(
        &mut self,
        release: &ApprovedRelease,
        actor: &OperatorActor,
        status: &str,
    ) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let stored = read_approval(&tx, &release.id)?;
        let current: String = tx.query_row(
            "SELECT status FROM release_status WHERE id=?1",
            [release.id.as_str()],
            |row| row.get(0),
        )?;
        if current != status {
            ensure!(current == "approved", "release is no longer pending");
            tx.execute(
                "UPDATE release_status SET status=?1 WHERE id=?2",
                params![status, release.id.as_str()],
            )?;
            tx.execute(
                "INSERT INTO release_stops VALUES(?1,?2)",
                params![
                    release.id.as_str(),
                    serde_json::to_string(&(status, actor))?
                ],
            )?;
            release_event(&tx, &stored.approval.target, status, &(&release.id, actor))?;
        } else {
            let body: String = tx.query_row(
                "SELECT body FROM release_stops WHERE release=?1",
                [release.id.as_str()],
                |row| row.get(0),
            )?;
            let (stored_status, stored_actor): (String, OperatorActor) =
                serde_json::from_str(&body)?;
            ensure!(
                stored_status == status && stored_actor == *actor,
                "release stop redelivered with different attribution"
            );
        }
        tx.commit()?;
        Ok(())
    }

    pub fn release_state(&self, target: &ReleaseTarget) -> Result<ReleaseState> {
        read_state(&self.connection, target)
    }

    pub fn release_secret_metadata(
        &self,
        target: &ReleaseTarget,
        reference: &ImmutableSecretRef,
    ) -> Result<Option<(u64, SecretObservation)>> {
        read_observation(&self.connection, target, "secret", &secret_key(reference)?)
    }

    pub fn release_event_count(&self, target: &ReleaseTarget) -> Result<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM release_events WHERE target=?1",
            [target_key(target)?],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count)?)
    }
}

fn target_key(target: &ReleaseTarget) -> Result<String> {
    Ok(serde_json::to_string(target)?)
}

pub(crate) fn secret_key(reference: &ImmutableSecretRef) -> Result<String> {
    Ok(Digest::of(reference)?.as_str().to_owned())
}

fn successor(revision: u64) -> Result<u64> {
    ensure!(revision < i64::MAX as u64, "release revision exhausted");
    Ok(revision + 1)
}

pub(crate) fn read_state(connection: &Connection, target: &ReleaseTarget) -> Result<ReleaseState> {
    let row: Option<(i64, Option<String>, Option<String>)> = connection
        .query_row(
            "SELECT generation,desired,active FROM release_slots WHERE target=?1",
            [target_key(target)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match row {
        None => Ok(ReleaseState {
            generation: 0,
            desired: None,
            active: None,
        }),
        Some((generation, desired, active)) => Ok(ReleaseState {
            generation: u64::try_from(generation)?,
            desired: desired.map(Digest::try_from).transpose()?,
            active: active.map(|body| serde_json::from_str(&body)).transpose()?,
        }),
    }
}

fn observation_id(target: &ReleaseTarget, kind: &str, key: &str, request: &Name) -> Result<Digest> {
    Digest::of(&("day2-release-observation-v1", target, kind, key, request))
}

fn observation_receipt(
    connection: &Connection,
    id: &Digest,
    fingerprint: &Digest,
) -> Result<Option<SecretReceipt>> {
    let prior: Option<(String, i64)> = connection
        .query_row(
            "SELECT fingerprint,revision FROM release_observation_receipts WHERE id=?1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    prior
        .map(|(prior, revision)| {
            ensure!(
                prior == fingerprint.as_str(),
                "observation request reused with different inputs"
            );
            Ok(SecretReceipt {
                id: id.clone(),
                revision: u64::try_from(revision)?,
            })
        })
        .transpose()
}

pub(crate) fn read_observation<T: for<'de> Deserialize<'de>>(
    connection: &Connection,
    target: &ReleaseTarget,
    kind: &str,
    key: &str,
) -> Result<Option<(u64, T)>> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT revision,body FROM release_observed WHERE target=?1 AND kind=?2 AND key=?3",
            params![target_key(target)?, kind, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(revision, body)| Ok((u64::try_from(revision)?, serde_json::from_str(&body)?)))
        .transpose()
}

pub(crate) fn observe<T: Serialize>(
    connection: &Connection,
    target: &ReleaseTarget,
    kind: &str,
    key: &str,
    request: &Name,
    expected_revision: u64,
    body: &T,
) -> Result<SecretReceipt> {
    let id = observation_id(target, kind, key, request)?;
    let fingerprint = Digest::of(&(expected_revision, body))?;
    if let Some(receipt) = observation_receipt(connection, &id, &fingerprint)? {
        return Ok(receipt);
    }
    let current: Option<i64> = connection
        .query_row(
            "SELECT revision FROM release_observed WHERE target=?1 AND kind=?2 AND key=?3",
            params![target_key(target)?, kind, key],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        u64::try_from(current.unwrap_or(0))? == expected_revision,
        "stale observation revision"
    );
    let revision = successor(expected_revision)?;
    connection.execute(
        "INSERT INTO release_observed VALUES(?1,?2,?3,?4,?5)
        ON CONFLICT(target,kind,key) DO UPDATE SET revision=excluded.revision,body=excluded.body",
        params![
            target_key(target)?,
            kind,
            key,
            i64::try_from(revision)?,
            serde_json::to_string(body)?
        ],
    )?;
    connection.execute(
        "INSERT INTO release_observation_receipts VALUES(?1,?2,?3)",
        params![id.as_str(), fingerprint.as_str(), i64::try_from(revision)?],
    )?;
    release_event(connection, target, kind, &(&id, revision, body))?;
    Ok(SecretReceipt { id, revision })
}

pub(crate) fn read_approval(connection: &Connection, id: &Digest) -> Result<StoredApproval> {
    let (target, fingerprint, body): (String, String, String) = connection.query_row(
        "SELECT target,fingerprint,body FROM release_approvals WHERE id=?1",
        [id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let stored: StoredApproval = serde_json::from_str(&body)?;
    ensure!(
        Digest::of(&stored.approval)?.as_str() == fingerprint,
        "release approval integrity mismatch"
    );
    ensure!(
        Digest::of(&(
            "day2-release-v1",
            &stored.approval.target,
            &stored.approval.request
        ))? == *id,
        "release approval identity mismatch"
    );
    ensure!(
        target == target_key(&stored.approval.target)?
            && stored.generation == successor(stored.approval.expected_generation)?
            && stored.authority_revision > 0,
        "release approval generation or authority identity mismatch"
    );
    Ok(stored)
}

/// Validates historical proof identity; current authority and provider readiness
/// are checked by the operation that uses the proof.
pub(crate) fn read_readiness(
    connection: &Connection,
    id: &Digest,
    release: &Digest,
) -> Result<StoredReady> {
    let body: String = connection.query_row(
        "SELECT body FROM release_readiness WHERE id=?1 AND release=?2",
        params![id.as_str(), release.as_str()],
        |row| row.get(0),
    )?;
    let proof: StoredReady = serde_json::from_str(&body)?;
    ensure!(
        Digest::of(&("day2-release-readiness-v1", &proof))? == *id,
        "readiness receipt integrity mismatch"
    );
    let approval = read_approval(connection, release)?;
    ensure!(
        proof.release == *release && proof.generation == approval.generation,
        "readiness belongs to another release generation"
    );
    ensure!(
        proof.secret_revision > 0,
        "invalid secret readiness revision"
    );
    Ok(proof)
}

fn validate_authority(approval: &ReleaseApproval, authority: &ReleaseAuthority) -> Result<()> {
    ensure!(
        approval.git.source == authority.source && approval.git.policy == authority.policy,
        "Git approval does not match current installation authority"
    );
    Ok(())
}

fn validate_build(connection: &Connection, approval: &ReleaseApproval) -> Result<()> {
    let (fingerprint, plan, state, cancelled): (String, String, String, bool) = connection
        .query_row(
            "SELECT fingerprint,plan,state,cancel_requested FROM executions WHERE id=?1",
            [approval.build_execution.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let plan: BuildPlan = serde_json::from_str(&plan)?;
    plan.validate()?;
    ensure!(
        plan.fingerprint()?.as_str() == fingerprint
            && plan.execution_id()? == approval.build_execution,
        "build execution identity mismatch"
    );
    ensure!(
        plan.company == approval.target.company && plan.app == approval.target.app,
        "build belongs to another release target"
    );
    ensure!(
        plan.profile.source == approval.git.source && plan.commit == approval.git.commit,
        "Git approval does not match exact build source"
    );
    ensure!(!cancelled, "build cancellation invalidates release");
    let state: State = serde_json::from_str(&state)?;
    ensure!(
        matches!(state, State::Succeeded { artifact, evidence, .. }
        if artifact == approval.artifact && evidence == approval.evidence),
        "release requires exact succeeded build artifact and evidence"
    );
    Ok(())
}

pub(crate) fn current_approval(connection: &Connection, id: &Digest) -> Result<StoredApproval> {
    let stored = read_approval(connection, id)?;
    let status: String = connection.query_row(
        "SELECT status FROM release_status WHERE id=?1",
        [id.as_str()],
        |row| row.get(0),
    )?;
    ensure!(status == "approved", "release is not approved and pending");
    let state = read_state(connection, &stored.approval.target)?;
    ensure!(
        state.desired.as_ref() == Some(id) && state.generation == stored.generation,
        "release has been superseded"
    );
    let (revision, authority) = read_observation::<ReleaseAuthority>(
        connection,
        &stored.approval.target,
        "authority",
        "current",
    )?
    .ok_or_else(|| anyhow::anyhow!("release authority is not configured"))?;
    ensure!(
        revision == stored.authority_revision,
        "release approval authority is stale"
    );
    validate_authority(&stored.approval, &authority)?;
    validate_build(connection, &stored.approval)?;
    crate::runtime_secret::require_release_in(connection, id, &stored.approval)?;
    Ok(stored)
}

pub(crate) fn ready_secret(
    connection: &Connection,
    approval: &ReleaseApproval,
) -> Result<(u64, SecretObservation)> {
    let uncertain: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM release_secret_uncertainty WHERE target=?1 AND key=?2)",
        params![target_key(&approval.target)?, secret_key(&approval.secret)?],
        |row| row.get(0),
    )?;
    if uncertain {
        return Err(ReleaseNotReady::AwaitingSecretMetadata.into());
    }
    let (revision, observation) = read_observation::<SecretObservation>(
        connection,
        &approval.target,
        "secret",
        &secret_key(&approval.secret)?,
    )?
    .ok_or(ReleaseNotReady::AwaitingSecretMetadata)?;
    ensure!(
        observation.reference == approval.secret,
        "secret metadata identity mismatch"
    );
    observation.provider_state.require(
        &approval.secret.binding,
        &Digest::of(&approval.secret)?,
        None,
    )?;
    if !observation.enabled {
        return Err(ReleaseNotReady::SecretDisabled.into());
    }
    if !observation.access_granted {
        return Err(ReleaseNotReady::SecretAccessDenied.into());
    }
    if !observation.projection_ready {
        return Err(ReleaseNotReady::SecretProjectionUnavailable.into());
    }
    Ok((revision, observation))
}

pub(crate) fn mark_secret_uncertain(
    connection: &Connection,
    target: &ReleaseTarget,
    key: &str,
    observation: &SecretObservation,
    incomparable: bool,
) -> Result<()> {
    connection.execute(
        "INSERT INTO release_secret_uncertainty VALUES(?1,?2,?3,?4) ON CONFLICT(target,key) DO UPDATE SET body=excluded.body,incomparable=release_secret_uncertainty.incomparable OR excluded.incomparable",
        params![target_key(target)?, key, serde_json::to_string(observation)?, incomparable],
    )?;
    release_event(
        connection,
        target,
        "secret_observation_conflict",
        observation,
    )
}

pub(crate) fn clear_secret_uncertainty(
    connection: &Connection,
    target: &ReleaseTarget,
    key: &str,
    observation: &SecretObservation,
) -> Result<()> {
    let conflict: Option<(String, bool)> = connection
        .query_row(
            "SELECT body,incomparable FROM release_secret_uncertainty WHERE target=?1 AND key=?2",
            params![target_key(target)?, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((conflict, incomparable)) = conflict {
        if incomparable {
            return Ok(());
        }
        let conflict: SecretObservation = serde_json::from_str(&conflict)?;
        if observation
            .provider_state
            .revision()
            .relation(conflict.provider_state.revision())
            != RevisionRelation::Newer
        {
            return Ok(());
        }
    }
    connection.execute(
        "DELETE FROM release_secret_uncertainty WHERE target=?1 AND key=?2",
        params![target_key(target)?, key],
    )?;
    Ok(())
}

pub(crate) fn release_event<T: Serialize>(
    connection: &Connection,
    target: &ReleaseTarget,
    kind: &str,
    body: &T,
) -> Result<()> {
    connection.execute(
        "INSERT INTO release_events(target,kind,body) VALUES(?1,?2,?3)",
        params![target_key(target)?, kind, serde_json::to_string(body)?],
    )?;
    Ok(())
}

#[cfg(test)]
mod proof_recovery_tests {
    use super::*;

    fn name(value: &str) -> Name {
        value.to_owned().try_into().unwrap()
    }

    /// Recovery validates historical evidence without inventing current facts.
    /// These records deliberately have no current desired slot or successful build.
    fn fixture() -> (tempfile::TempDir, Journal, Digest, Digest) {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&directory.path().join("release.sqlite")).unwrap();
        let source = BindingRef::pin(name("forge"), &"repository").unwrap();
        let approval = ReleaseApproval {
            target: ReleaseTarget {
                company: name("company"),
                environment: name("staging"),
                app: name("reports"),
            },
            request: name("release-1"),
            expected_generation: 7,
            build_execution: Digest::new(b"historical build"),
            artifact: Digest::new(b"artifact"),
            evidence: Digest::new(b"evidence"),
            git: GitApproval {
                source,
                commit: GitOid::try_from(format!("{:040x}", 1)).unwrap(),
                policy: Digest::new(b"policy"),
                receipt: Digest::new(b"approval receipt"),
                actor: "reviewer".to_owned().try_into().unwrap(),
            },
            secret: ImmutableSecretRef {
                binding: BindingRef::pin(name("secrets"), &"project").unwrap(),
                secret: name("credential"),
                version: NonZeroU64::new(1).unwrap(),
            },
        };
        let id = Digest::of(&("day2-release-v1", &approval.target, &approval.request)).unwrap();
        let stored = StoredApproval {
            approval,
            generation: 8,
            authority_revision: 2,
        };
        let ready = StoredReady {
            release: id.clone(),
            generation: stored.generation,
            secret_revision: 3,
            secret_evidence: Digest::new(b"historical secret observation"),
        };
        let readiness = Digest::of(&("day2-release-readiness-v1", &ready)).unwrap();
        journal
            .register_runtime_secret(
                &stored.approval.target,
                &stored.approval.secret,
                &crate::runtime_secret::ProviderResource {
                    provider: name("test"),
                    account: name("company"),
                    secret: name("credential"),
                },
                &stored.approval.git.actor,
            )
            .unwrap();
        let tx = journal.connection.transaction().unwrap();
        crate::runtime_secret::reserve_release_in(&tx, &id, &stored.approval).unwrap();
        tx.execute(
            "INSERT INTO release_approvals VALUES(?1,?2,?3,?4)",
            params![
                id.as_str(),
                target_key(&stored.approval.target).unwrap(),
                Digest::of(&stored.approval).unwrap().as_str(),
                serde_json::to_string(&stored).unwrap(),
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO release_status VALUES(?1,'revoked')",
            [id.as_str()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO release_readiness VALUES(?1,?2,?3)",
            params![
                readiness.as_str(),
                id.as_str(),
                serde_json::to_string(&ready).unwrap(),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        (directory, journal, id, readiness)
    }

    #[test]
    fn recover_historical_proofs_after_reopen_without_granting_current_authority() {
        let (directory, journal, id, readiness) = fixture();
        drop(journal);
        let mut journal = Journal::open(&directory.path().join("release.sqlite")).unwrap();
        let tx = journal.connection.transaction().unwrap();
        let approved = Journal::recover_approved_release_in(&tx, &id).unwrap();
        let ready = Journal::recover_ready_release_in(&tx, &readiness, &id).unwrap();
        assert_eq!(approved.id(), &id);
        assert_eq!(ready.id(), &readiness);
        assert_eq!(
            Journal::prepare_release_in(&tx, &approved)
                .unwrap_err()
                .to_string(),
            "release is not approved and pending"
        );
        assert_eq!(
            Journal::activate_release_in_checked(&tx, &ready, None)
                .unwrap_err()
                .to_string(),
            "release is not approved and pending"
        );
        let events: i64 = tx
            .query_row("SELECT count(*) FROM release_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events, 0, "identity recovery must not mutate release state");
        tx.commit().unwrap();
    }

    #[test]
    fn approval_recovery_rejects_unknown_identity_and_damaged_persisted_records() {
        for damage in 0..5 {
            let (_directory, mut journal, id, _readiness) = fixture();
            let tx = journal.connection.transaction().unwrap();
            assert!(
                Journal::recover_approved_release_in(&tx, &Digest::new(b"unknown approval"))
                    .is_err()
            );
            tx.execute_batch("DROP TRIGGER release_approvals_no_update")
                .unwrap();
            let mut stored = read_approval(&tx, &id).unwrap();
            let mut target = target_key(&stored.approval.target).unwrap();
            let mut fingerprint = Digest::of(&stored.approval).unwrap();
            match damage {
                0 => stored.approval.artifact = Digest::new(b"forged artifact"),
                1 => {
                    stored.approval.request = name("forged-request");
                    fingerprint = Digest::of(&stored.approval).unwrap();
                }
                2 => stored.generation += 1,
                3 => stored.authority_revision = 0,
                4 => target = "another target".to_owned(),
                _ => unreachable!(),
            }
            tx.execute(
                "UPDATE release_approvals SET target=?1,fingerprint=?2,body=?3 WHERE id=?4",
                params![
                    target,
                    fingerprint.as_str(),
                    serde_json::to_string(&stored).unwrap(),
                    id.as_str(),
                ],
            )
            .unwrap();
            let error = Journal::recover_approved_release_in(&tx, &id).unwrap_err();
            assert_eq!(
                error.to_string(),
                match damage {
                    0 => "release approval integrity mismatch",
                    1 => "release approval identity mismatch",
                    2..=4 => "release approval generation or authority identity mismatch",
                    _ => unreachable!(),
                }
            );
            tx.rollback().unwrap();
        }
    }

    #[test]
    fn readiness_recovery_rejects_unknown_alias_and_damaged_persisted_proofs() {
        for damage in 0..6 {
            let (_directory, mut journal, release, id) = fixture();
            let tx = journal.connection.transaction().unwrap();
            assert!(
                Journal::recover_ready_release_in(
                    &tx,
                    &Digest::new(b"unknown readiness"),
                    &release
                )
                .is_err()
            );
            let mut proof = read_readiness(&tx, &id, &release).unwrap();
            let mut row_release = release.clone();
            let mut row_id = id.clone();
            match damage {
                0 => proof.secret_evidence = Digest::new(b"forged observation"),
                1 => row_id = Digest::new(b"forged readiness alias"),
                2 => {
                    proof.release = Digest::new(b"another release");
                    row_id = Digest::of(&("day2-release-readiness-v1", &proof)).unwrap();
                }
                3 => {
                    proof.generation += 1;
                    row_id = Digest::of(&("day2-release-readiness-v1", &proof)).unwrap();
                }
                4 => {
                    proof.secret_revision = 0;
                    row_id = Digest::of(&("day2-release-readiness-v1", &proof)).unwrap();
                }
                5 => {
                    let mut other = read_approval(&tx, &release).unwrap();
                    other.approval.request = name("another-release");
                    row_release = Digest::of(&(
                        "day2-release-v1",
                        &other.approval.target,
                        &other.approval.request,
                    ))
                    .unwrap();
                    tx.execute(
                        "INSERT INTO release_approvals VALUES(?1,?2,?3,?4)",
                        params![
                            row_release.as_str(),
                            target_key(&other.approval.target).unwrap(),
                            Digest::of(&other.approval).unwrap().as_str(),
                            serde_json::to_string(&other).unwrap(),
                        ],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            tx.execute(
                "UPDATE release_readiness SET id=?1,release=?2,body=?3 WHERE id=?4",
                params![
                    row_id.as_str(),
                    row_release.as_str(),
                    serde_json::to_string(&proof).unwrap(),
                    id.as_str(),
                ],
            )
            .unwrap();
            let error = Journal::recover_ready_release_in(&tx, &row_id, &release).unwrap_err();
            match damage {
                0 | 1 => assert_eq!(error.to_string(), "readiness receipt integrity mismatch"),
                2 | 3 => {
                    assert_eq!(
                        error.to_string(),
                        "readiness belongs to another release generation"
                    )
                }
                4 => assert_eq!(error.to_string(), "invalid secret readiness revision"),
                5 => assert!(matches!(
                    error.downcast_ref::<rusqlite::Error>(),
                    Some(rusqlite::Error::QueryReturnedNoRows)
                )),
                _ => unreachable!(),
            }
            if damage == 5 {
                assert_eq!(
                    Journal::recover_ready_release_in(&tx, &row_id, &row_release)
                        .unwrap_err()
                        .to_string(),
                    "readiness belongs to another release generation"
                );
            }
            tx.rollback().unwrap();
        }
    }
}
