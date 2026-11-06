//! Fixed native approval time, publication and signature transport. The actual
//! action/UV owner guards every exchange; a bearer header, clock sample, row or
//! valid signature cannot construct it. Live qualification remains separate.
use crate::security_epoch::NativeAcquisition;
use crate::security_epoch::restore_approval::signed::{ApprovalStatement, SignedApprovalRecord};
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use day2_capabilities::restore_signing::KeySelection;
use reqwest::{Method, blocking::Client, header::HeaderValue};
use serde_json::{Value, json};
use std::{io::Read, marker::PhantomData, rc::Rc};

use super::{
    AcquiredProviderAuthentication, CurrentVolumePhase, ProviderAuthentication, VolumeAdmission,
};
use crate::security_epoch::{
    CompletedCeremony, CurrentControllerStoragePhase, RestoreAuthenticationAction,
    firestore::{Budget, EpochReply, Port, Sample},
    kernel::approval_time::{Interval, Plan, Utc},
    native_enrollment::{NativeRole, SameEnrolledOwner, StagePurpose},
    restore_host_clock::{HostTimeData, UnfencedControllerClock},
    transport::Route as EpochRoute,
};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::time::Duration;

/// Fixed native approval source, never a read-port promotion or token getter.
/// Only the genuine current physical phase constructs it. Its public operations
/// additionally require the actual authentication action/completed UV owner.
pub(crate) struct NativeApprovalSource {
    material: Box<AcquiredProviderAuthentication>,
    signing_credential: Option<crate::security_epoch::CredentialMaterial>,
    original: NativeAcquisition,
    same: SameEnrolledOwner,
    clock: UnfencedControllerClock,
    store: EpochStore,
    policy: InitialBootstrapPolicy,
    qualified: Option<QualifiedTime>,
    signed: Option<Digest>,
    publication_attempted: bool,
    kms: Option<Kms>,
    valid: bool,
    finished: bool,
}

struct QualifiedTime {
    operation: Digest,
    upper: Duration,
    plan: Plan,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <NativeApprovalSource as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
};

impl CurrentVolumePhase<'_, '_> {
    pub(in crate::security_epoch::storage_authority) fn capture_approval_source(
        &mut self,
        clock: UnfencedControllerClock,
    ) -> Result<NativeApprovalSource> {
        let requested = (|| {
            self.resources.check_current(&mut self.reader)?;
            self.reader
                .stage
                .require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                matches!(
                    self.reader.authentication,
                    ProviderAuthentication::ConnectionRequest
                ),
                "restore_approval_current_reader_required"
            );
            let mut original = self
                .reader
                .stage
                .narrow_io_acquisition(self.reader.store.max_lease_seconds)?;
            original.exchange_current_views(&mut self.reader.acquisition)?;
            let material = self.reader.acquire_material()?;
            self.reader.authentication = ProviderAuthentication::Acquired(Box::new(material));
            self.check_durability_profile()?;
            self.resources.check_current(&mut self.reader)?;
            let same = self.reader.stage.capture_same_owner()?;
            let mut original = self
                .reader
                .stage
                .narrow_io_acquisition(self.reader.store.max_lease_seconds)?;
            original.exchange_current_views(&mut self.reader.acquisition)?;
            let ProviderAuthentication::Acquired(material) = std::mem::replace(
                &mut self.reader.authentication,
                ProviderAuthentication::ConnectionRequest,
            ) else {
                anyhow::bail!("restore_approval_material_changed");
            };
            Ok(NativeApprovalSource {
                material,
                signing_credential: None,
                original,
                same,
                clock,
                store: self.reader.store.clone(),
                policy: self.reader.policy.clone(),
                qualified: None,
                signed: None,
                publication_attempted: false,
                kms: Some(Kms::new()?),
                valid: true,
                finished: false,
            })
        })();
        if requested.is_err() {
            self.resources.admission = VolumeAdmission::Refused;
            self.reader.acquisition.refuse();
        }
        requested
    }
}

impl NativeApprovalSource {
    pub(in crate::security_epoch) fn check_phase(
        &mut self,
        phase: &mut CurrentControllerStoragePhase<'_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                self.valid && !self.finished,
                "restore_approval_source_refused"
            );
            phase.check()?;
            let stage = phase.controller_stage()?;
            self.same
                .meet_current_read_view(stage, &mut self.original)?;
            stage.check_current_selection(
                &self.policy,
                &self.store,
                NativeRole::EpochController,
            )?;
            self.original.remaining()?;
            self.clock.observe(phase)?;
            phase.check()
        })();
        if requested.is_err() {
            self.refuse();
            phase.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn current_time(
        &mut self,
        action: &mut RestoreAuthenticationAction<'_, '_, '_>,
    ) -> Result<HostTimeData> {
        let requested = (|| {
            action.check_approval_source(self)?;
            let time = action.approval_clock_data(&mut self.clock)?;
            if let Some(qualified) = &self.qualified {
                ensure!(
                    time.lower >= qualified.upper,
                    "restore_approval_qualified_time_rewound"
                );
            }
            action.check_approval_source(self)?;
            Ok(time)
        })();
        if requested.is_err() {
            self.refuse();
            action.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn qualify_time(
        &mut self,
        action: &mut RestoreAuthenticationAction<'_, '_, '_>,
        operation: Digest,
    ) -> Result<HostTimeData> {
        let requested = (|| {
            ensure!(
                self.qualified.is_none(),
                "restore_approval_time_already_qualified"
            );
            let time = self.current_time(action)?;
            let (selected, before) = action.approval_snapshot_data(self)?;
            ensure!(
                selected == self.store,
                "restore_approval_source_selection_changed"
            );
            let interval = Interval {
                domain: time.domain.clone(),
                lower: Utc {
                    seconds: time.lower.as_secs(),
                    nanos: time.lower.subsec_nanos(),
                },
                upper: Utc {
                    seconds: time.upper.as_secs(),
                    nanos: time.upper.subsec_nanos(),
                },
            };
            let budget = self.original.budget()?;
            let mut port = ApprovalPort {
                source: &mut *self,
                owner: PortOwner::Action(&mut *action),
            };
            let plan = crate::security_epoch::firestore::advance_approval_time(
                &mut port,
                budget,
                &selected,
                &before,
                operation.clone(),
                interval,
            )?;
            drop(port);
            action.check_approval_source(self)?;
            self.qualified = Some(QualifiedTime {
                operation,
                upper: time.upper,
                plan,
            });
            Ok(time)
        })();
        if requested.is_err() {
            self.refuse();
            action.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn require_qualified(
        &mut self,
        operation: &Digest,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                self.valid
                    && !self.finished
                    && self
                        .qualified
                        .as_ref()
                        .is_some_and(|actual| &actual.operation == operation),
                "restore_approval_time_not_qualified"
            );
            self.original.remaining()?;
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn sign_completed(
        &mut self,
        owner: &mut CompletedCeremony<'_, '_, '_>,
    ) -> Result<SignedApprovalRecord> {
        let requested = (|| {
            owner.check_signing_source(self)?;
            ensure!(self.signed.is_none(), "restore_approval_sign_attempt_spent");
            let (selection, statement) = owner.signing_data()?;
            let minted = crate::security_epoch::CredentialMaterial::mint_restore_signer(
                &self.material.source,
                &self.policy.controller.google_service_account,
                &self.material.http,
                &mut self.original,
            );
            let checked = owner.check_signing_source(self);
            let credential = minted?;
            checked?;
            self.signing_credential = Some(credential);
            let mut kms = self
                .kms
                .take()
                .ok_or_else(|| anyhow::anyhow!("restore_approval_signer_busy"))?;
            let result = {
                let mut context = RequestContext::Native {
                    owner: &mut *owner,
                    source: &mut *self,
                };
                kms.sign(&selection, &statement, &mut context)
            };
            self.kms = Some(kms);
            let record = result?;
            owner.check_signing_source(self)?;
            self.signed = Some(Digest::of(&(
                "day2-native-restore-signed-record-v1",
                &record,
            ))?);
            Ok(record)
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn publish_completed(
        &mut self,
        owner: &mut CompletedCeremony<'_, '_, '_>,
        record: &SignedApprovalRecord,
    ) -> Result<()> {
        let requested = (|| {
            owner.check_signing_source(self)?;
            ensure!(
                !self.publication_attempted
                    && self.signed.as_ref()
                        == Some(&Digest::of(&(
                            "day2-native-restore-signed-record-v1",
                            record
                        ))?),
                "restore_approval_publication_spent_or_changed"
            );
            self.publication_attempted = true;
            let (selected, before) = owner.check_publication_source(self)?;
            let plan = self
                .qualified
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("restore_approval_time_not_qualified"))?
                .plan
                .clone();
            let budget = self.original.budget()?;
            let mut port = ApprovalPort {
                source: &mut *self,
                owner: PortOwner::Completed(&mut *owner),
            };
            crate::security_epoch::firestore::publish_restore_approval(
                &mut port, budget, &selected, &before, &plan, record,
            )?;
            drop(port);
            owner.check_signing_source(self)
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn finish_checked(
        mut self,
        action: &mut RestoreAuthenticationAction<'_, '_, '_>,
    ) -> Result<()> {
        self.current_time(action)?;
        action.check_approval_source(&mut self)?;
        self.finished = true;
        Ok(())
    }

    fn refuse(&mut self) {
        self.valid = false;
        self.original.refuse();
    }
}

impl Drop for NativeApprovalSource {
    fn drop(&mut self) {
        if !self.finished {
            self.refuse();
        }
    }
}

enum PortOwner<'borrow, 'metadata, 'storage, 'role> {
    Action(&'borrow mut RestoreAuthenticationAction<'metadata, 'storage, 'role>),
    Completed(&'borrow mut CompletedCeremony<'metadata, 'storage, 'role>),
}

impl PortOwner<'_, '_, '_, '_> {
    fn check(&mut self, source: &mut NativeApprovalSource) -> Result<()> {
        match self {
            Self::Action(owner) => owner.check_approval_source(source),
            Self::Completed(owner) => owner.check_signing_source(source),
        }
    }
}

struct ApprovalPort<'borrow, 'metadata, 'storage, 'role> {
    source: &'borrow mut NativeApprovalSource,
    owner: PortOwner<'borrow, 'metadata, 'storage, 'role>,
}

impl Port for ApprovalPort<'_, '_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.owner.check(self.source)?;
        self.source.original.sample()
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let requested = (|| {
            self.owner.check(self.source)?;
            ensure!(
                max_bytes == 65_536 && body.len() <= 65_536,
                "restore_approval_provider_bound"
            );
            let route = if url.ends_with("/documents:batchGet") {
                EpochRoute::EpochRead
            } else if url.ends_with("/documents:commit") {
                EpochRoute::EpochCommit
            } else if url.ends_with("/documents:rollback") {
                EpochRoute::EpochRollback
            } else {
                anyhow::bail!("restore_approval_provider_route");
            };
            ensure!(
                self.source.material.http.matches(&route, url)?,
                "restore_approval_provider_recipient_changed"
            );
            let timeout = budget.remaining_native(&mut self.source.original)?;
            let authorization = self.source.material.controller.authorization()?;
            let sent = self.source.material.http.request_with_ceiling(
                route,
                &authorization,
                Some(body),
                &mut self.source.original,
                timeout,
            );
            let checked = self.owner.check(self.source);
            let bytes = sent?;
            checked?;
            budget.remaining_native(&mut self.source.original)?;
            Ok(EpochReply {
                status: 200,
                body: bytes,
            })
        })();
        if requested.is_err() {
            self.source.refuse();
        }
        requested
    }

    fn refuse(&mut self) {
        self.source.refuse();
    }
}

enum RequestContext<'borrow, 'metadata, 'storage, 'role> {
    Native {
        owner: &'borrow mut CompletedCeremony<'metadata, 'storage, 'role>,
        source: &'borrow mut NativeApprovalSource,
    },
    #[cfg(test)]
    Fixture {
        authorization: HeaderValue,
        acquisition: &'borrow mut NativeAcquisition,
    },
}

impl RequestContext<'_, '_, '_, '_> {
    fn check(&mut self) -> Result<Duration> {
        match self {
            Self::Native { owner, source } => {
                owner.check_signing_source(source)?;
                source.original.remaining()
            }
            #[cfg(test)]
            Self::Fixture { acquisition, .. } => acquisition.remaining(),
        }
    }

    fn authorization(&self) -> Result<HeaderValue> {
        match self {
            Self::Native { source, .. } => source
                .signing_credential
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("restore_approval_signing_credential_missing"))?
                .authorization(),
            #[cfg(test)]
            Self::Fixture { authorization, .. } => Ok(authorization.clone()),
        }
    }

    fn refuse(&mut self) {
        match self {
            Self::Native { source, .. } => source.refuse(),
            #[cfg(test)]
            Self::Fixture { acquisition, .. } => acquisition.refuse(),
        }
    }
}

const ORIGIN: &str = "https://cloudkms.googleapis.com";
const REPLY_LIMIT: usize = 16_384;
const REQUEST_LIMIT: usize = 24_576;
const ALGORITHM: &str = "EC_SIGN_ED25519";
const PROTECTION: &str = "SOFTWARE";

// Private fields and methods. Production uses only the completed native owner;
// the raw clock/header context exists solely in the controlled codec tests.
struct Kms {
    client: Client,
    attempted: bool,
    local: PhantomData<Rc<()>>,
    #[cfg(test)]
    fixture_origin: Option<String>,
}

impl Kms {
    fn new() -> Result<Self> {
        Ok(Self {
            client: client(true)?,
            attempted: false,
            local: PhantomData,
            #[cfg(test)]
            fixture_origin: None,
        })
    }

    // One attempt, fixed purpose and algorithm. This does not mark durable
    // grant consumption or publish a result; even success returns only DATA.
    fn sign(
        &mut self,
        selected: &KeySelection,
        statement: &ApprovalStatement,
        context: &mut RequestContext<'_, '_, '_, '_>,
    ) -> Result<SignedApprovalRecord> {
        let result = (|| {
            ensure!(!self.attempted, "restore_kms_attempt_spent");
            self.attempted = true;
            context.check()?;
            ensure!(
                statement.signing_key == selected.commitment()?,
                "restore_kms_selection_changed"
            );
            let frame = statement.signature_input_data()?;
            let version = self.request(selected, Route::Version, None, context)?;
            check_version(selected, &version)?;
            let public = self.request(selected, Route::PublicKey, None, context)?;
            check_public(selected, &public)?;
            let body = serde_json::to_vec(&json!({
                "data": STANDARD.encode(&frame),
                "dataCrc32c": crc32c::crc32c(&frame).to_string(),
            }))?;
            ensure!(body.len() <= REQUEST_LIMIT, "restore_kms_request_bound");
            let reply = self.request(selected, Route::Sign, Some(body), context)?;
            ensure!(
                text(&reply, "name")? == selected.version.as_str()
                    && text(&reply, "protectionLevel")? == PROTECTION
                    && reply.get("verifiedDataCrc32c").and_then(Value::as_bool) == Some(true)
                    && reply
                        .get("verifiedDigestCrc32c")
                        .is_none_or(|v| v.as_bool() == Some(false)),
                "restore_kms_sign_integrity"
            );
            let encoded = text(&reply, "signature")?;
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("restore_kms_signature_encoding"))?;
            ensure!(
                bytes.len() == 64 && STANDARD.encode(&bytes) == encoded,
                "restore_kms_signature_encoding"
            );
            check_crc(&reply, "signatureCrc32c", &bytes)?;
            let signed = SignedApprovalRecord {
                statement: statement.clone(),
                signature: URL_SAFE_NO_PAD.encode(bytes),
            };
            // Verify the complete canonical frame with the exact selected
            // version AND public bytes, independently of the provider's CRC.
            signed.verify_signature_data(statement, selected)?;
            // Do not return a signature after observing a disabled/different
            // selected version. Publication still needs its own real owners.
            let version = self.request(selected, Route::Version, None, context)?;
            check_version(selected, &version)?;
            context.check()?;
            signed.encode()?;
            Ok(signed)
        })();
        if result.is_err() {
            self.attempted = true;
            context.refuse();
        }
        result
    }

    fn request(
        &self,
        selected: &KeySelection,
        route: Route,
        body: Option<Vec<u8>>,
        context: &mut RequestContext<'_, '_, '_, '_>,
    ) -> Result<Value> {
        let (method, suffix) = match route {
            Route::Version => (Method::GET, ""),
            Route::PublicKey => (Method::GET, "/publicKey"),
            Route::Sign => (Method::POST, ":asymmetricSign"),
        };
        let origin = ORIGIN;
        #[cfg(test)]
        let origin = self.fixture_origin.as_deref().unwrap_or(origin);
        context.check()?;
        let mut authorization = context.authorization()?;
        authorization.set_sensitive(true);
        let mut request = self
            .client
            .request(
                method,
                format!("{origin}/v1/{}{suffix}", selected.version.as_str()),
            )
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(context.check()?);
        if let Some(body) = body {
            ensure!(body.len() <= REQUEST_LIMIT, "restore_kms_request_bound");
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let requested = request
            .send()
            .map_err(|_| anyhow::anyhow!("restore_kms_transport"));
        // Both actual results are evaluated. The first request error remains
        // primary even when the unchanged original also expires/refuses.
        let checked = context.check();
        let response = requested?;
        checked?;
        ensure!(response.status().is_success(), "restore_kms_status");
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= REPLY_LIMIT as u64),
            "restore_kms_reply_bound"
        );
        let mut bytes = Vec::new();
        let read = response
            .take((REPLY_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("restore_kms_transport"));
        let checked = context.check();
        read?;
        checked?;
        ensure!(bytes.len() <= REPLY_LIMIT, "restore_kms_reply_bound");
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("restore_kms_reply_shape"))
    }
}

enum Route {
    Version,
    PublicKey,
    Sign,
}

fn client(https_only: bool) -> Result<Client> {
    Ok(Client::builder()
        .https_only(https_only)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()?)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("restore_kms_reply_shape"))
}

fn check_crc(value: &Value, field: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        text(value, field)? == crc32c::crc32c(bytes).to_string(),
        "restore_kms_crc_mismatch"
    );
    Ok(())
}

fn check_version(selected: &KeySelection, value: &Value) -> Result<()> {
    ensure!(
        text(value, "name")? == selected.version.as_str()
            && text(value, "algorithm")? == ALGORITHM
            && text(value, "protectionLevel")? == PROTECTION
            && text(value, "state")? == "ENABLED",
        "restore_kms_version_mismatch"
    );
    Ok(())
}

fn check_public(selected: &KeySelection, value: &Value) -> Result<()> {
    ensure!(
        text(value, "name")? == selected.version.as_str()
            && text(value, "algorithm")? == ALGORITHM
            && text(value, "protectionLevel")? == PROTECTION,
        "restore_kms_public_selection"
    );
    let pem = text(value, "pem")?;
    check_crc(value, "pemCrc32c", pem.as_bytes())?;
    let encoded = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|s| s.strip_suffix("\n-----END PUBLIC KEY-----\n"))
        .ok_or_else(|| anyhow::anyhow!("restore_kms_public_encoding"))?;
    ensure!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b)),
        "restore_kms_public_encoding"
    );
    let compact = encoded.replace('\n', "");
    let der = STANDARD
        .decode(&compact)
        .map_err(|_| anyhow::anyhow!("restore_kms_public_encoding"))?;
    // RFC8410 Ed25519 SubjectPublicKeyInfo, no algorithm parameters.
    const PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    ensure!(
        der.len() == 44
            && der.starts_with(PREFIX)
            && der[12..] == selected.public_key
            && STANDARD.encode(&der) == compact,
        "restore_kms_public_mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
