//! Fixed native approval time, publication and signature transport. The actual
//! action/UV owner guards every exchange; a bearer header, clock sample, row or
//! valid signature cannot construct it. Live qualification remains separate.
use crate::artifact::{SecurityKeyPurpose, SecurityKeySelection};
use crate::oauth::approval_keys::{GcpSecretVersion, decode_secret_access_response};
use crate::security_epoch::restore_approval::signed::{ApprovalStatement, SignedApprovalRecord};
use crate::security_epoch::{
    NativeAcquisition,
    bootstrap::ExecutionSourceLoan,
    kernel::restore::{ExactKey, Intent, KeyPurpose},
};
use anyhow::{Context, Result, ensure};
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
    Digest, SecretProvider,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::time::Duration;
use zeroize::Zeroizing;

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
    historical_keys_attempted: bool,
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
            let _ = <HistoricalKeyAvailability as Ambiguous<_>>::check;
            let _ = <KeyBirth as Ambiguous<_>>::check;
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
                historical_keys_attempted: false,
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

    pub(in crate::security_epoch) fn current_fenced_time(
        &mut self,
        phase: &mut CurrentControllerStoragePhase<'_, '_>,
    ) -> Result<HostTimeData> {
        let requested = (|| {
            self.check_phase(phase)?;
            let time = self.clock.observe(phase)?;
            let qualified = self
                .qualified
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("restore_approval_time_not_qualified"))?;
            ensure!(
                time.lower >= qualified.upper,
                "restore_approval_qualified_time_rewound"
            );
            Ok(time)
        })();
        let checked = self.check_phase(phase);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            phase.refuse();
        }
        let time = requested?;
        checked?;
        Ok(time)
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
            let plan = {
                let mut port = ApprovalPort {
                    source: &mut *self,
                    owner: PortOwner::Action(&mut *action),
                };
                crate::security_epoch::firestore::advance_approval_time(
                    &mut port,
                    budget,
                    &selected,
                    &before,
                    operation.clone(),
                    interval,
                )?
            };
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
            {
                let mut port = ApprovalPort {
                    source: &mut *self,
                    owner: PortOwner::Completed(&mut *owner),
                };
                crate::security_epoch::firestore::publish_restore_approval(
                    &mut port, budget, &selected, &before, &plan, record,
                )?;
            }
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

// Exact historical key acquisition stays in this actual native source.
const KEY_ORIGIN: &str = "https://secretmanager.googleapis.com";
const MAX_REPLY: usize = 4096;

/// Real retained secret material, not a list of desired references. Only the
/// actual native source below can create this owner; no key/header getter or
/// serialization exists. Its clock shares the parent's original refusal.
pub(in crate::security_epoch) struct HistoricalKeyAvailability {
    intent: Intent,
    request: Digest,
    operation: Digest,
    material: Vec<HeldKey>,
    original: NativeAcquisition,
}

struct HeldKey {
    selected: ExactKey,
    material: Zeroizing<Vec<u8>>,
}

struct SelectedKey {
    archive: ExactKey,
    provider: GcpSecretVersion,
}

fn archive_purpose(current: SecurityKeyPurpose) -> Option<KeyPurpose> {
    match current {
        SecurityKeyPurpose::CredentialEncryption | SecurityKeyPurpose::OauthCustodyEncryption => {
            Some(KeyPurpose::CustodyEncryption)
        }
        SecurityKeyPurpose::CredentialVerifier | SecurityKeyPurpose::OauthCustodyVerifier => {
            Some(KeyPurpose::CustodyVerifier)
        }
        SecurityKeyPurpose::CredentialShellAttestation
        | SecurityKeyPurpose::OauthShellAttestation => Some(KeyPurpose::ShellAttestation),
        SecurityKeyPurpose::OauthProviderClient
        | SecurityKeyPurpose::OauthReauthenticationClient => None,
    }
}

fn complete_requirements(admitted: &[SecurityKeySelection]) -> Result<Vec<ExactKey>> {
    let mut required = Vec::new();
    for key in admitted {
        let Some(purpose) = archive_purpose(key.purpose) else {
            continue;
        };
        let SecretProvider::GcpVersion { version, .. } = &key.provider;
        required.push(ExactKey {
            binding: key.binding.clone(),
            version: version.to_string(),
            purpose,
        });
    }
    required.sort_by(|a, b| {
        (
            &a.purpose,
            a.binding.id.as_str(),
            a.binding.revision.as_str(),
            a.version.as_str(),
        )
            .cmp(&(
                &b.purpose,
                b.binding.id.as_str(),
                b.binding.revision.as_str(),
                b.version.as_str(),
            ))
    });
    required.dedup();
    ensure!(
        (1..=32).contains(&required.len()),
        "restore_keys_manifest_bound"
    );
    Ok(required)
}

// Pure resolution DATA. Archive strings cannot supply a project, secret name
// or alias. Each requirement must resolve to one exact admitted resource.
fn resolve(required: &[ExactKey], admitted: &[SecurityKeySelection]) -> Result<Vec<SelectedKey>> {
    ensure!(
        (1..=32).contains(&required.len()),
        "restore_keys_manifest_bound"
    );
    // Archive key-set equality with current selection is already required.
    // A caller cannot omit a referenced member by supplying a smaller list.
    ensure!(
        required == complete_requirements(admitted)?,
        "restore_keys_incomplete_manifest"
    );
    let mut result = Vec::new();
    let mut resources = std::collections::BTreeSet::new();
    let mut previous = None;
    for key in required {
        let identity = (
            &key.purpose,
            key.binding.id.as_str(),
            key.binding.revision.as_str(),
            key.version.as_str(),
        );
        ensure!(
            previous.is_none_or(|before| before < identity),
            "restore_keys_manifest_order"
        );
        previous = Some(identity);
        let mut found = None;
        for selected in admitted {
            if selected.binding != key.binding
                || archive_purpose(selected.purpose).as_ref() != Some(&key.purpose)
            {
                continue;
            }
            let SecretProvider::GcpVersion {
                project_number,
                secret,
                version,
            } = &selected.provider;
            if key.version != version.to_string() {
                continue;
            }
            let candidate = GcpSecretVersion {
                project_number: project_number.get(),
                secret: secret.as_str().to_owned(),
                version: version.get(),
            };
            candidate.validate()?;
            // The same physical key may be selected by several namespaces.
            // Conflicting resources for an archive reference are ambiguous.
            ensure!(
                found.as_ref().is_none_or(|before| before == &candidate),
                "restore_keys_ambiguous_resource"
            );
            found = Some(candidate);
        }
        let provider = found.context("restore_keys_version_not_admitted")?;
        ensure!(
            resources.insert(provider.resource_name()),
            "restore_keys_resource_reused"
        );
        result.push(SelectedKey {
            archive: key.clone(),
            provider,
        });
    }
    Ok(result)
}

impl HistoricalKeyAvailability {
    pub(in crate::security_epoch) fn require(
        &mut self,
        intent: &Intent,
        record: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(&self.intent == intent, "restore_keys_intent_substituted");
            self.check_retained(record, operation)
        })();
        if requested.is_err() {
            self.original.refuse();
        }
        requested
    }

    /// SQL-safe retained-material/original checks only. Actual current registry,
    /// file/peer/fence checks remain the retaining parent's responsibility.
    pub(in crate::security_epoch) fn check_retained(
        &mut self,
        record: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let requested = (|| {
            self.original.remaining()?;
            ensure!(
                self.request == record.statement.request.commitment()?
                    && &self.operation == operation
                    && self.intent.operation == *operation
                    && self.intent.archive.full_archive_digest
                        == record.statement.request.full_archive_digest
                    && self.material.len() == self.intent.archive.required_keys.len()
                    && !self.material.is_empty()
                    && self
                        .material
                        .iter()
                        .zip(&self.intent.archive.required_keys)
                        .all(|(held, required)| held.selected == *required
                            && held.material.len() == 32),
                "restore_keys_retained_material_changed"
            );
            self.original.remaining()?;
            Ok(())
        })();
        if requested.is_err() {
            self.original.refuse();
        }
        requested
    }
}

impl Drop for HistoricalKeyAvailability {
    fn drop(&mut self) {
        self.original.refuse();
    }
}

impl NativeApprovalSource {
    pub(in crate::security_epoch) fn retain_historical_keys(
        &mut self,
        owner: &mut ExecutionSourceLoan<'_, '_, '_, '_>,
        intent: &Intent,
    ) -> Result<HistoricalKeyAvailability> {
        let requested = (|| {
            ensure!(
                !self.historical_keys_attempted,
                "restore_keys_attempt_spent"
            );
            self.historical_keys_attempted = true;
            // A nongeneric lost-acquisition owner shares this actual source's
            // refusal before any external work; catching a panic cannot regrant.
            let mut birth = KeyBirth {
                original: Some(
                    self.original
                        .narrow(self.store.max_lease_seconds, Duration::MAX)?,
                ),
            };
            owner.check(self)?;
            let selected = owner.historical_key_data(&self.store, &self.policy, intent);
            let checked = owner.check(self);
            let admitted = selected?;
            checked?;
            let selection = resolve(&intent.archive.required_keys, &admitted)?;
            let minted = crate::security_epoch::CredentialMaterial::mint_restore_key_reader(
                &self.material.source,
                &self.policy.controller.google_service_account,
                &self.material.http,
                &mut self.original,
            );
            let checked = owner.check(self);
            let credential = minted?;
            checked?;
            let http = KeyHttp::new()?;
            let mut context = KeyContext::Native {
                owner: &mut *owner,
                source: &mut *self,
                credential,
            };
            let material = http.read_all(&selection, &mut context)?;
            context.check()?;
            let request = context.request_commitment_data()?;
            let mut keys = HistoricalKeyAvailability {
                intent: intent.clone(),
                request,
                operation: intent.operation.clone(),
                material,
                original: birth
                    .original
                    .take()
                    .context("restore_keys_original_missing")?,
            };
            // One final actual-owner check is required before availability can
            // be installed. Failure drops material and poisons the same clock.
            context.check()?;
            keys.original.remaining()?;
            Ok(keys)
        })();
        if requested.is_err() {
            self.refuse();
            owner.refuse();
        }
        requested
    }
}

enum KeyContext<'borrow, 'fields, 'metadata, 'storage, 'role> {
    Native {
        owner: &'borrow mut ExecutionSourceLoan<'fields, 'metadata, 'storage, 'role>,
        source: &'borrow mut NativeApprovalSource,
        credential: crate::security_epoch::CredentialMaterial,
    },
    #[cfg(test)]
    Fixture {
        authorization: HeaderValue,
        fail_at: Option<usize>,
        checks: usize,
        original: &'borrow mut NativeAcquisition,
    },
}

impl KeyContext<'_, '_, '_, '_, '_> {
    fn check(&mut self) -> Result<Duration> {
        match self {
            Self::Native { owner, source, .. } => {
                owner.check(source)?;
                source.original.remaining()
            }
            #[cfg(test)]
            Self::Fixture {
                original,
                checks,
                fail_at,
                ..
            } => {
                let at = *checks;
                *checks += 1;
                if *fail_at == Some(at) {
                    original.refuse();
                }
                original.remaining()
            }
        }
    }

    fn request_commitment_data(&self) -> Result<Digest> {
        match self {
            Self::Native { owner, .. } => owner.request_commitment_data(),
            #[cfg(test)]
            Self::Fixture { .. } => anyhow::bail!("restore_keys_native_owner_required"),
        }
    }

    fn authorization(&self) -> Result<HeaderValue> {
        match self {
            Self::Native { credential, .. } => credential.authorization(),
            #[cfg(test)]
            Self::Fixture { authorization, .. } => Ok(authorization.clone()),
        }
    }

    fn refuse(&mut self) {
        match self {
            Self::Native { owner, source, .. } => {
                owner.refuse();
                source.refuse();
            }
            #[cfg(test)]
            Self::Fixture { original, .. } => original.refuse(),
        }
    }
}

pub(super) struct KeyBirth {
    original: Option<NativeAcquisition>,
}

impl Drop for KeyBirth {
    fn drop(&mut self) {
        if let Some(original) = &mut self.original {
            original.refuse();
        }
    }
}

struct KeyHttp {
    client: Client,
    #[cfg(test)]
    fixture_origin: Option<String>,
}

impl KeyHttp {
    fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?,
            #[cfg(test)]
            fixture_origin: None,
        })
    }

    fn read_all(
        &self,
        selected: &[SelectedKey],
        context: &mut KeyContext<'_, '_, '_, '_, '_>,
    ) -> Result<Vec<HeldKey>> {
        let requested = (|| {
            ensure!(
                (1..=32).contains(&selected.len()),
                "restore_keys_manifest_bound"
            );
            let mut result = Vec::new();
            for key in selected {
                let material = self.read(&key.provider, context)?;
                ensure!(material.len() == 32, "restore_keys_material_shape");
                result.push(HeldKey {
                    selected: key.archive.clone(),
                    material,
                });
            }
            context.check()?;
            Ok(result)
        })();
        if requested.is_err() {
            context.refuse();
        }
        requested
    }

    fn read(
        &self,
        selected: &GcpSecretVersion,
        context: &mut KeyContext<'_, '_, '_, '_, '_>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let origin = KEY_ORIGIN;
        #[cfg(test)]
        let origin = self.fixture_origin.as_deref().unwrap_or(origin);
        context.check()?;
        let mut authorization = context.authorization()?;
        authorization.set_sensitive(true);
        let request = self
            .client
            .get(format!("{origin}/v1/{}:access", selected.resource_name()))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(context.check()?);
        let sent = request
            .send()
            .map_err(|_| anyhow::anyhow!("restore_keys_transport"));
        let checked = context.check();
        let response = sent?;
        checked?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "restore_keys_unavailable"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_REPLY as u64),
            "restore_keys_reply_bound"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response
            .take((MAX_REPLY + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("restore_keys_transport"));
        let checked = context.check();
        read?;
        checked?;
        ensure!(bytes.len() <= MAX_REPLY, "restore_keys_reply_bound");
        decode_secret_access_response(selected, &bytes).map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "restore_approval/keys/tests.rs"]
mod keys_tests;
