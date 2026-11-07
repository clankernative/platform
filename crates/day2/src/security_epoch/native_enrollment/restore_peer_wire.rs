//! Closed restore-exchange DATA. No message, projection, digest or phase can
//! construct an enrolled role, consumed approval, creator, holder or writer.
use super::{NativeRole, protocol::StagePurpose, storage_peer_wire::StageStatement};
use crate::security_epoch::{
    kernel::UpdateTime, kernel::restore::completion::TargetReport, restore_approval::TargetBinding,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};

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
// Historical document selectors only, not initial-file/holder authority. They
// let the App read the same complete record set without receiving a send port.
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
        app: &StageStatement,
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
root_version: UpdateTime, sentinel_version: UpdateTime, receipt_version: UpdateTime } }

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
    Hello { #[serde(deserialize_with = "map_only")] app: Box<StageStatement>, nonce: Digest, controller_nonce: Digest, selection: Selection },
    Offer { #[serde(deserialize_with = "map_only")] controller: Box<StageStatement>, exchange: Exchange, projection: Box<Projection> },
    Confirm { exchange: Digest, projection: Digest },
    Durable { exchange: Digest, projection: Digest },
    Accepted { exchange: Digest, projection: Digest },
    Activated { exchange: Digest, activation: Activation },
    ActivatedAck { exchange: Digest, activation: Digest },
    Released { exchange: Digest, activation: Digest },
}

impl RestoreBody {
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
    ) -> Result<(&StageStatement, &Digest)> {
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
        Ok((app, nonce))
    }

    pub(in crate::security_epoch::native_enrollment) fn offer(
        &self,
        expected: &Selection,
        app: &StageStatement,
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
            | Self::ActivatedAck { .. } => NativeRole::AppHost,
            Self::Ready { .. }
            | Self::Offer { .. }
            | Self::Durable { .. }
            | Self::Activated { .. }
            | Self::Released { .. } => NativeRole::EpochController,
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
            Self::Hello { app, .. } => ensure!(
                app.original.purpose == expected,
                "restore_peer_original_purpose_changed"
            ),
            _ => {}
        }
        Ok(())
    }

    // One closed nine-step transcript, registered by the shared wire owner.
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
        }
    }
}

#[cfg(test)]
mod tests;
