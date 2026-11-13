//! Closed restore-exchange DATA. No message, projection, digest or phase can
//! construct an enrolled role, consumed approval, creator, holder or writer.
use super::{
    NativeRole,
    policy::EnrollmentPolicy,
    protocol::{IssuerCertificate, StagePurpose},
    storage_peer_wire::StageStatement,
};
use crate::security_epoch::{
    kernel::UpdateTime, kernel::restore::completion::TargetReport, restore_approval::TargetBinding,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};

mod app;
pub(in crate::security_epoch::native_enrollment) use app::RestoreAppStatement;
#[cfg(any(target_os = "linux", test))]
pub(in crate::security_epoch::native_enrollment) use app::RestoreOriginal;

fn map_only<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct MapOnly<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOnly<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a closed restore object")
        }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> std::result::Result<T, M::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(MapOnly(std::marker::PhantomData))
}

macro_rules! map_record {
    ($name:ident { $($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, PartialEq, Eq, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(in crate::security_epoch) struct $name { $(pub $field: $ty),* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self,D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Wire { $($(#[$attribute])* $field: $ty),* }
                let Wire { $($field),* } = map_only(deserializer)?;
                Ok(Self { $($field),* })
            }
        }
    };
}

map_record! { Selection {
    operation: Digest, approval_request: Digest, intent: Digest, full_archive: Digest,
    #[serde(deserialize_with = "target_only")]
    target: TargetBinding,
} }
// The target and its nested scope are both records, not JSON sequences. Keep
// original MapAccess throughout so duplicate fields are rejected by serde.
fn target_only<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<TargetBinding, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Target {
        #[serde(deserialize_with = "map_only")]
        scope: day2_capabilities::security_epoch::AuthorityScope,
        binding_generation: u64,
        authority: Digest,
        selection: Digest,
        incarnation: Digest,
        security_epoch: u64,
        artifact: Digest,
        schema: Digest,
    }
    let Target {
        scope,
        binding_generation,
        authority,
        selection,
        incarnation,
        security_epoch,
        artifact,
        schema,
    } = map_only(deserializer)?;
    Ok(TargetBinding {
        scope,
        binding_generation,
        authority,
        selection,
        incarnation,
        security_epoch,
        artifact,
        schema,
    })
}

// Authenticated stop projection DATA only. It is produced only after the
// actual retained peer has checked the signed frozen issuer statement.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::security_epoch) struct AuthorityStopData {
    pub admin_binding: Digest,
    pub selection: crate::security_epoch::kernel::restore::StopSelection,
    pub stopped: Digest,
}

pub(in crate::security_epoch) enum AdminPeerResult {
    Known,
    Stop(AuthorityStopData),
}

map_record! { Creator { device_major: u32, device_minor: u32, inode: u64, length: u64, user: u32, group: u32 } }
// Historical document selectors only, not initial-file/holder authority.
// grant is the original GRANT-ID; the fixed codec derives its consumed-use
// key, never accepts a caller path. These IDs grant no provider read port.
map_record! { LedgerKeys { initial_create: Digest, initial_activation: Digest, advance: Digest, grant: Digest } }
map_record! { Projection {
    selection: Selection, creator: Creator,
    #[serde(deserialize_with = "map_only")]
    report: TargetReport,
    consumed_use: Digest, captured_records: Digest, ledger: LedgerKeys,
} }

impl Projection {
    pub(in crate::security_epoch) fn validate(&self, expected: &Selection) -> Result<()> {
        ensure!(
            &self.selection == expected
                && self.selection.target.binding_generation > 0
                && self.selection.target.security_epoch > 0
                && self.creator.inode > 0
                && (100..=16 * 1024 * 1024).contains(&self.creator.length)
                && self.report.intent == self.selection.intent
                && self.report.target_incarnation == self.selection.target.incarnation
                && self.report.target_epoch == self.selection.target.security_epoch
                && self.report.artifact == self.selection.target.artifact
                && self.report.schema == self.selection.target.schema,
            "restore_peer_projection_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-restored-file-projection-v1", self))
    }
}

map_record! { Exchange { app_stage: Digest, controller_stage: Digest, app_nonce: Digest,
controller_nonce: Digest, projection: Digest } }

impl Exchange {
    pub(in crate::security_epoch::native_enrollment) fn require_selected(
        &self,
        app: &RestoreAppStatement,
        controller: &StageStatement,
        app_nonce: &Digest,
        controller_nonce: &Digest,
        projection: &Projection,
    ) -> Result<()> {
        ensure!(
            self.app_stage == app.digest()?
                && self.controller_stage == controller.digest()?
                && &self.app_nonce == app_nonce
                && &self.controller_nonce == controller_nonce
                && self.projection == projection.digest()?,
            "restore_peer_exchange_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-restored-holder-exchange-v1", self))
    }
}

map_record! { Activation { receipt: Digest, root: Digest, sentinel: Digest,
root_version: UpdateTime, sentinel_version: UpdateTime, receipt_version: UpdateTime,
expectation: crate::security_epoch::firestore::RestoreWriterReadExpectation } }

macro_rules! restore_body {
    ($($variant:ident { $($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)? }),* $(,)?) => {
        #[derive(Clone, PartialEq, Eq, Serialize)]
        #[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
        pub(in crate::security_epoch::native_enrollment) enum RestoreBody {
            $($variant { $($field: $ty),* }),*
        }

        impl<'de> Deserialize<'de> for RestoreBody {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
                enum Wire { $($variant { $($(#[$attribute])* $field: $ty),* }),* }
                struct MapOnly;
                impl<'de> Visitor<'de> for MapOnly {
                    type Value = RestoreBody;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("a closed restore peer phase object") }
                    fn visit_map<M: MapAccess<'de>>(self, map: M) -> std::result::Result<Self::Value, M::Error> {
                        Ok(match Wire::deserialize(MapAccessDeserializer::new(map))? {
                            $(Wire::$variant { $($field),* } => RestoreBody::$variant { $($field),* }),*
                        })
                    }
                }
                deserializer.deserialize_map(MapOnly)
            }
        }
    };
}

restore_body! {
    Ready { #[serde(deserialize_with = "map_only")] controller: Box<StageStatement>, nonce: Digest, selection: Selection },
    Hello { #[serde(deserialize_with = "map_only")] app: Box<RestoreAppStatement>, nonce: Digest, controller_nonce: Digest, selection: Selection },
    Offer { #[serde(deserialize_with = "map_only")] controller: Box<StageStatement>, exchange: Exchange, projection: Box<Projection> },
    Confirm { exchange: Digest, projection: Digest },
    Durable { exchange: Digest, projection: Digest },
    Accepted { exchange: Digest, projection: Digest },
    Activated { exchange: Digest, activation: Box<Activation> },
    ActivatedAck { exchange: Digest, activation: Digest,
        #[serde(deserialize_with = "map_only")] cohort: super::storage_peer_wire::SqliteCohort },
    Released { exchange: Digest, activation: Digest },
    RoleReady { exchange: Digest,
        #[serde(deserialize_with = "map_only")] completion: Box<super::protocol::SignedRestoreIssuerCompletion> },
    RoleDecision { exchange: Digest,
        #[serde(deserialize_with = "map_only")] decision: Box<super::protocol::SignedRestoreRoleActivation> },
    AppPrepared { exchange: Digest,
        #[serde(deserialize_with = "map_only")] confirmation: Box<super::protocol::SignedRestorePreparedConfirmation>,
        #[serde(deserialize_with = "map_only")] cohort: super::storage_peer_wire::SqliteCohort },
    PreparedAccepted { exchange: Digest, confirmation: Digest, cohort: Digest, effective_deadline_ns: u64 },
    AppInstalled { exchange: Digest, prepared: Digest,
        #[serde(deserialize_with = "map_only")] cohort: super::storage_peer_wire::SqliteCohort,
        #[serde(deserialize_with = "map_only")] app: Box<StageStatement> },
    InstalledAccepted { exchange: Digest, installed: Digest, cohort: Digest, effective_deadline_ns: u64 },
}

impl RestoreBody {
    /// Cryptographic comparison DATA only. A native receiver must additionally
    /// retain the actual new SCM sender, same first keeper, original and parent.
    pub(in crate::security_epoch::native_enrollment) fn installed_confirmation_data(
        &self,
        expected_exchange: &Digest,
        chain: (
            &super::protocol::SignedRestorePreparedConfirmation,
            &super::protocol::SignedRestoreRoleActivation,
            &super::protocol::SignedRestoreIssuerCompletion,
        ),
        policy: &EnrollmentPolicy,
        restore_app: &RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<&StageStatement> {
        let Self::AppInstalled {
            exchange,
            prepared,
            cohort,
            app,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_installed_confirmation");
        };
        let (confirmation, decision, completion) = chain;
        confirmation.verify_data(
            policy,
            &restore_app.certificate,
            (decision, completion),
            restore_app,
            (
                &confirmation.statement.request,
                &confirmation.statement.challenge,
            ),
            now,
        )?;
        cohort.validate()?;
        ensure!(
            exchange == expected_exchange
                && prepared == &confirmation.digest_data()?
                && cohort == &completion.statement.data.cohort
                && app.certificate == restore_app.certificate
                && app.stage == decision.statement.stage
                && app.original.purpose == StagePurpose::CurrentRole
                && app.original.domain == restore_app.original.domain
                && app.original.origin_ns == restore_app.original.origin_ns
                && app.original.origin_ns < app.original.deadline_ns
                && app.original.deadline_ns <= confirmation.statement.effective_deadline_ns
                && u128::from(app.original.origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(app.original.deadline_ns),
            "restore_peer_installed_confirmation_changed"
        );
        Ok(app)
    }

    /// Commitment to the complete installed ACK DATA, not native delivery or
    /// permission. There is no receipt/owner constructor from this digest.
    pub(in crate::security_epoch::native_enrollment) fn installed_digest_data(
        &self,
    ) -> Result<Digest> {
        ensure!(
            matches!(self, Self::AppInstalled { .. }),
            "restore_peer_expected_installed_confirmation"
        );
        Digest::of(&("day2-restored-app-installed-data-v1", self))
    }

    /// Identity DATA for the later ordinary connection, from the exact two
    /// installed packets. It deliberately samples no old clock and validates
    /// no future request: only the genuine retained native owners may transfer
    /// their completed cursor and authenticate a fresh Current exchange.
    pub(in crate::security_epoch::native_enrollment) fn current_connection_binding_data(
        &self,
        acceptance: &Self,
    ) -> Result<Digest> {
        let Self::AppInstalled {
            exchange,
            cohort,
            app,
            ..
        } = self
        else {
            anyhow::bail!("restore_current_installed_packet_required");
        };
        let Self::InstalledAccepted {
            exchange: accepted_exchange,
            installed,
            cohort: accepted_cohort,
            effective_deadline_ns,
        } = acceptance
        else {
            anyhow::bail!("restore_current_acceptance_packet_required");
        };
        cohort.validate()?;
        ensure!(
            accepted_exchange == exchange
                && installed == &self.installed_digest_data()?
                && accepted_cohort == &Digest::of(cohort)?
                && app.original.purpose == StagePurpose::CurrentRole
                && app.stage.data.role == super::NativeRole::AppHost
                && app.original.origin_ns < *effective_deadline_ns
                && *effective_deadline_ns <= app.original.deadline_ns,
            "restore_current_connection_binding_changed"
        );
        Digest::of(&("day2-restored-current-connection-data-v1", self, acceptance))
    }

    pub(in crate::security_epoch::native_enrollment) fn installed_acceptance_deadline_data(
        &self,
        expected_exchange: &Digest,
        installed: &Self,
        now: std::time::Duration,
    ) -> Result<std::time::Duration> {
        let Self::AppInstalled {
            exchange: installed_exchange,
            cohort: expected_cohort,
            app,
            ..
        } = installed
        else {
            anyhow::bail!("restore_peer_expected_installed_confirmation");
        };
        let Self::InstalledAccepted {
            exchange,
            installed: commitment,
            cohort,
            effective_deadline_ns,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_installed_acceptance");
        };
        ensure!(
            exchange == expected_exchange
                && installed_exchange == expected_exchange
                && commitment == &installed.installed_digest_data()?
                && cohort == &Digest::of(expected_cohort)?
                && *effective_deadline_ns <= app.original.deadline_ns
                && app.original.origin_ns < *effective_deadline_ns
                && u128::from(app.original.origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(*effective_deadline_ns),
            "restore_peer_installed_acceptance_changed"
        );
        Ok(std::time::Duration::from_nanos(*effective_deadline_ns))
    }

    /// Comparison DATA only. The native receiver must additionally retain the
    /// actual SCM sender, same App key, original, first keeper and full parent.
    pub(in crate::security_epoch::native_enrollment) fn prepared_confirmation_data(
        &self,
        expected_exchange: &Digest,
        chain: (
            &super::protocol::SignedRestoreRoleActivation,
            &super::protocol::SignedRestoreIssuerCompletion,
        ),
        policy: &EnrollmentPolicy,
        app: &RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<&super::protocol::SignedRestorePreparedConfirmation> {
        let Self::AppPrepared {
            exchange,
            confirmation,
            cohort,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_prepared_confirmation")
        };
        ensure!(
            exchange == expected_exchange && cohort == &chain.1.statement.data.cohort,
            "restore_peer_prepared_exchange_or_cohort_changed"
        );
        confirmation.verify_data(
            policy,
            &app.certificate,
            chain,
            app,
            (
                &confirmation.statement.request,
                &confirmation.statement.challenge,
            ),
            now,
        )?;
        Ok(confirmation)
    }

    /// A signed Controller echo of the exact prepared record/cohort. This is
    /// not an installed acknowledgement or permission to publish a Runtime.
    pub(in crate::security_epoch::native_enrollment) fn prepared_acceptance_deadline_data(
        &self,
        expected_exchange: &Digest,
        expected: &super::protocol::SignedRestorePreparedConfirmation,
        expected_cohort: &super::storage_peer_wire::SqliteCohort,
        now: std::time::Duration,
    ) -> Result<std::time::Duration> {
        let Self::PreparedAccepted {
            exchange,
            confirmation,
            cohort,
            effective_deadline_ns,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_prepared_acceptance")
        };
        ensure!(
            exchange == expected_exchange
                && confirmation == &expected.digest_data()?
                && cohort == &Digest::of(expected_cohort)?
                && *effective_deadline_ns <= expected.statement.effective_deadline_ns
                && now.as_nanos() < u128::from(*effective_deadline_ns),
            "restore_peer_prepared_acceptance_changed"
        );
        Ok(std::time::Duration::from_nanos(*effective_deadline_ns))
    }

    /// Selection DATA after actual message authentication. This only names
    /// the App's required independent ledger read, never keeper permission.
    pub(in crate::security_epoch::native_enrollment) fn writer_activation_data(
        &self,
        expected_exchange: &Digest,
    ) -> Result<&Activation> {
        let Self::Activated {
            exchange,
            activation,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_writer_activation");
        };
        ensure!(
            exchange == expected_exchange,
            "restore_peer_writer_activation_exchange_changed"
        );
        Ok(activation)
    }

    /// Cohort comparison DATA from the actual App keeper ACK. A native caller
    /// must retain and authenticate the sender and all same-original postchecks
    /// before using it to join its own auxiliary SQLite handles.
    pub(in crate::security_epoch::native_enrollment) fn activation_ack(
        &self,
        expected_exchange: &Digest,
        expected_activation: &Digest,
    ) -> Result<&super::storage_peer_wire::SqliteCohort> {
        let Self::ActivatedAck {
            exchange,
            activation,
            cohort,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_keeper_ack");
        };
        ensure!(
            exchange == expected_exchange && activation == expected_activation,
            "restore_peer_keeper_ack_changed"
        );
        cohort.validate()?;
        Ok(cohort)
    }

    /// Signed completion comparison DATA only. The App receiver must still
    /// authenticate the actual retained Controller, fresh own writer records,
    /// original and same first keeper before any ordinary-role transition.
    pub(in crate::security_epoch::native_enrollment) fn role_ready_data(
        &self,
        expected_exchange: &Digest,
        expected: &super::protocol::RestoreIssuerCompletionData,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        app: &RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<&super::protocol::SignedRestoreIssuerCompletion> {
        let Self::RoleReady {
            exchange,
            completion,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_role_handoff");
        };
        ensure!(
            exchange == expected_exchange,
            "restore_peer_role_exchange_changed"
        );
        completion.verify_data(policy, certificate, expected, app, now)?;
        Ok(completion)
    }

    /// Signed comparison DATA only. The issuer nonce belongs to the actual
    /// Controller exchange, not an App challenge; this App instead binds its
    /// exact retained completion, original channel and genuine signed sender.
    pub(in crate::security_epoch::native_enrollment) fn role_decision_data(
        &self,
        expected_exchange: &Digest,
        completion: &super::protocol::SignedRestoreIssuerCompletion,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        app: &RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<&super::protocol::SignedRestoreRoleActivation> {
        let Self::RoleDecision { exchange, decision } = self else {
            anyhow::bail!("restore_peer_expected_role_decision")
        };
        ensure!(
            exchange == expected_exchange,
            "restore_peer_role_decision_exchange_changed"
        );
        decision.verify_data(
            policy,
            certificate,
            completion,
            app,
            (&decision.statement.request, &decision.statement.challenge),
            now,
        )?;
        Ok(decision)
    }

    pub(in crate::security_epoch::native_enrollment) fn ready(
        &self,
        expected: &Selection,
    ) -> Result<(&StageStatement, &Digest)> {
        let Self::Ready {
            controller,
            nonce,
            selection,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_ready");
        };
        self.require_stage_purpose(StagePurpose::CurrentRole)?;
        ensure!(selection == expected, "restore_peer_selection_changed");
        Ok((controller, nonce))
    }

    pub(in crate::security_epoch::native_enrollment) fn hello(
        &self,
        expected: &Selection,
        ready_nonce: &Digest,
    ) -> Result<(&RestoreAppStatement, &Digest)> {
        let Self::Hello {
            app,
            nonce,
            controller_nonce,
            selection,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_hello");
        };
        self.require_stage_purpose(StagePurpose::CurrentRole)?;
        ensure!(
            selection == expected && controller_nonce == ready_nonce,
            "restore_peer_hello_changed"
        );
        app.require_selection(selection)?;
        Ok((app, nonce))
    }

    pub(in crate::security_epoch::native_enrollment) fn offer(
        &self,
        expected: &Selection,
        app: &RestoreAppStatement,
        ready: &StageStatement,
        app_nonce: &Digest,
        ready_nonce: &Digest,
    ) -> Result<(&Exchange, &Projection)> {
        let Self::Offer {
            controller,
            exchange,
            projection,
        } = self
        else {
            anyhow::bail!("restore_peer_expected_offer");
        };
        self.require_stage_purpose(StagePurpose::CurrentRole)?;
        ensure!(&**controller == ready, "restore_peer_ready_replaced");
        app.require_controller(ready)?;
        projection.validate(expected)?;
        exchange.require_selected(app, ready, app_nonce, ready_nonce, projection)?;
        Ok((exchange, projection))
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(in crate::security_epoch::native_enrollment) fn require_file_echo(
        &self,
        step: super::handshake::Step,
        expected_exchange: &Digest,
        expected_projection: &Digest,
    ) -> Result<()> {
        use super::handshake::Step;
        let (actual, exchange, projection) = match self {
            Self::Confirm {
                exchange,
                projection,
            } => (Step::Confirm, exchange, projection),
            Self::Durable {
                exchange,
                projection,
            } => (Step::Complete, exchange, projection),
            Self::Accepted {
                exchange,
                projection,
            } => (Step::Accepted, exchange, projection),
            _ => anyhow::bail!("restore_peer_expected_file_echo"),
        };
        ensure!(
            actual == step && exchange == expected_exchange && projection == expected_projection,
            "restore_peer_file_echo_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn sender_role(&self) -> NativeRole {
        match self {
            Self::Hello { .. }
            | Self::Confirm { .. }
            | Self::Accepted { .. }
            | Self::ActivatedAck { .. }
            | Self::AppPrepared { .. }
            | Self::AppInstalled { .. } => NativeRole::AppHost,
            Self::Ready { .. }
            | Self::Offer { .. }
            | Self::Durable { .. }
            | Self::Activated { .. }
            | Self::Released { .. }
            | Self::RoleReady { .. }
            | Self::RoleDecision { .. }
            | Self::PreparedAccepted { .. }
            | Self::InstalledAccepted { .. } => NativeRole::EpochController,
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_stage_purpose(
        &self,
        expected: StagePurpose,
    ) -> Result<()> {
        ensure!(
            expected == StagePurpose::CurrentRole,
            "restore_peer_current_original_required"
        );
        match self {
            Self::Ready { controller, .. } | Self::Offer { controller, .. } => ensure!(
                controller.original.purpose == expected,
                "restore_peer_original_purpose_changed"
            ),
            // The App has distinct restore admission, never an ordinary
            // Current/initial/bootstrap role. Its real owner and signature
            // are checked through the closed restored-message path.
            Self::Hello { .. } => {}
            _ => {}
        }
        Ok(())
    }

    // The closed restore transcript and its separate role-handoff purpose are
    // registered by the shared wire owner; the old nine-step order stays exact.
    #[cfg(any(test, target_os = "linux"))]
    pub(in crate::security_epoch::native_enrollment) fn step(&self) -> super::handshake::Step {
        use super::handshake::Step;
        match self {
            Self::Ready { .. } => Step::BeginReady,
            Self::Hello { .. } => Step::Hello,
            Self::Offer { .. } => Step::Offer,
            Self::Confirm { .. } => Step::Confirm,
            Self::Durable { .. } => Step::Complete,
            Self::Accepted { .. } => Step::Accepted,
            Self::Activated { .. } => Step::Known,
            Self::ActivatedAck { .. } => Step::Consumed,
            Self::Released { .. } => Step::Released,
            Self::RoleReady { .. } => Step::RoleReady,
            Self::RoleDecision { .. } => Step::RoleDecision,
            Self::AppPrepared { .. } => Step::AppPrepared,
            Self::PreparedAccepted { .. } => Step::PreparedAccepted,
            Self::AppInstalled { .. } => Step::AppInstalled,
            Self::InstalledAccepted { .. } => Step::InstalledAccepted,
        }
    }
}

#[cfg(test)]
mod tests;
