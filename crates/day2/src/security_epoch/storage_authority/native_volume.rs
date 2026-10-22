//! Native controller-only provider/mount acquisition. This reads actual provider
//! and kernel resources under the retained original enrolled stage. It neither
//! creates the initial file nor turns a JSON reply into a P3/writer permission.

use super::{DirectoryIdentity, directory_identity, persistent_disk::PersistentDiskSelection};
use crate::security_epoch::controller::bootstrap_timing::BootstrapTiming;
use crate::security_epoch::controller::evidence::{PreparationFailure, PreparationStep};
use crate::security_epoch::controller::preparation_timing::{Operation, Timings};
use crate::security_epoch::{
    authenticated_reads::{
        ControllerEpochReads, ProviderEpochReads, RefusalGuard, StorageMetadataRead,
    },
    credential_material::CredentialMaterial,
    identity_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole, SameEnrolledOwner, StagePurpose},
    transport::{NativeHttp, Route},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy};
use serde_json::Value;
use std::{fs::File, io::Read};

const ROOT: &str = "/state";
const PROFILE: &str = "/etc/day2-native/storage.json";
const MAX_PROFILE: usize = 16_384;
const PRIVATE_DIRECTORY: &str = "day2-native";

struct ProviderReader<'role> {
    stage: EnrolledRoleStage<'role>,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    profile: PersistentDiskSelection,
    authentication: ProviderAuthentication,
    acquisition: NativeAcquisition,
    timings: Timings,
    bootstrap: BootstrapTiming,
}

enum ProviderAuthentication {
    Acquired(Box<AcquiredProviderAuthentication>),
    Retained(ProviderEpochReads),
}

struct AcquiredProviderAuthentication {
    http: NativeHttp,
    source: CredentialMaterial,
    controller: CredentialMaterial,
    kubernetes: CredentialMaterial,
}

pub(super) struct NativeVolumeObservation<'role> {
    reader: ProviderReader<'role>,
    resources: NativeVolumeResources,
}

/// The original descriptors survive a successful preparation. These resources
/// have no clock or permission of their own. Every use requires a fresh stage
/// from the SAME still-live enrollment owner and a new actual provider read.
pub(super) struct NativeVolumeContinuity {
    resources: NativeVolumeResources,
    owner: SameEnrolledOwner,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    profile: PersistentDiskSelection,
}

pub(super) struct CurrentVolumePhase<'volume, 'role> {
    resources: &'volume mut NativeVolumeResources,
    reader: ProviderReader<'role>,
}

struct NativeVolumeResources {
    directory: File,
    identity: DirectoryIdentity,
    block: File,
    device_name: String,
    valid: bool,
}

fn read_fixed(path: &str, limit: usize, acquisition: &mut NativeAcquisition) -> Result<Vec<u8>> {
    acquisition.remaining()?;
    let file = File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "storage_native_regular_required"
    );
    let mut bytes = Vec::new();
    file.take((limit + 1).try_into()?).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "storage_native_read_bound"
    );
    acquisition.remaining()?;
    Ok(bytes)
}

fn cluster_ca(acquisition: &mut NativeAcquisition) -> Result<Vec<u8>> {
    // Kubernetes' atomic writer uses a projection symlink. These public bytes
    // are authenticated against the selected digest and real GKE response
    // before any Kubernetes credential can be sent.
    acquisition.remaining()?;
    let file = File::from(rustix::fs::open(
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "storage_native_ca_regular_required"
    );
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 65_536,
        "storage_native_ca_bound"
    );
    acquisition.remaining()?;
    Ok(bytes)
}

fn profile(acquisition: &mut NativeAcquisition) -> Result<PersistentDiskSelection> {
    let bytes = read_fixed(PROFILE, MAX_PROFILE, acquisition)?;
    crate::json::decode(&bytes)
}

impl<'role> ProviderReader<'role> {
    fn acquire(
        mut stage: EnrolledRoleStage<'role>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        timings: Timings,
        purpose: StagePurpose,
    ) -> Result<Self> {
        stage.require_purpose(purpose)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let mut acquisition = match purpose {
            StagePurpose::CurrentRole => stage.narrow_io_acquisition(store.max_lease_seconds)?,
            StagePurpose::InitialFirstHolder => {
                stage.initial_first_holder_acquisition(store.max_lease_seconds)?
            }
            StagePurpose::StorageBootstrap | StagePurpose::StorageMetadataObservation => {
                anyhow::bail!("storage_provider_authenticated_purpose_required")
            }
        };
        let selected = profile(&mut acquisition)
            .map_err(|error| PreparationFailure::at(PreparationStep::StorageProfile, error))?;
        selected
            .validate(policy)
            .map_err(|error| PreparationFailure::at(PreparationStep::StorageProfile, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let ca = cluster_ca(&mut acquisition)
            .map_err(|error| PreparationFailure::at(PreparationStep::ClusterCa, error))?;
        let mut http = NativeHttp::new(store, &policy.cluster, &ca)
            .map_err(|error| PreparationFailure::at(PreparationStep::TransportSetup, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let source = timings
            .measure(Operation::MetadataToken, || {
                CredentialMaterial::metadata_source(&mut acquisition)
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::MetadataCredential, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        timings
            .measure(Operation::Project, || {
                identity_protocol::project(
                    store,
                    &http
                        .request(
                            Route::Project,
                            &source.authorization()?,
                            None,
                            &mut acquisition,
                        )
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::ProjectIdentity, error)
                        })?,
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::ProjectIdentity, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        timings
            .measure(Operation::Cluster, || {
                http.verify_cluster(&ca, &source.authorization()?, &mut acquisition)
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::ClusterIdentity, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        timings
            .measure(Operation::ControllerIdentity, || {
                identity_protocol::google_service_account(
                    &policy.controller.google_service_account,
                    &policy.cluster.project,
                    &http
                        .request(
                            Route::GoogleAccount(&policy.controller.google_service_account),
                            &source.authorization()?,
                            None,
                            &mut acquisition,
                        )
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::ControllerIdentity, error)
                        })?,
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::ControllerIdentity, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let controller = timings
            .measure(Operation::ControllerToken, || {
                CredentialMaterial::mint_target(
                    &source,
                    &policy.controller.google_service_account,
                    &http,
                    &mut acquisition,
                )
            })
            .map_err(|error| {
                PreparationFailure::at(PreparationStep::ControllerCredential, error)
            })?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        timings
            .measure(Operation::Database, || {
                identity_protocol::database(
                    store,
                    &http
                        .request(
                            Route::Database,
                            &controller.authorization()?,
                            None,
                            &mut acquisition,
                        )
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::EpochDatabase, error)
                        })?,
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::EpochDatabase, error))?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let kubernetes = CredentialMaterial::kubernetes_api(&mut acquisition).map_err(|error| {
            PreparationFailure::at(PreparationStep::KubernetesCredential, error)
        })?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        Ok(Self {
            stage,
            policy: policy.clone(),
            store: store.clone(),
            profile: selected,
            authentication: ProviderAuthentication::Acquired(Box::new(
                AcquiredProviderAuthentication {
                    http,
                    source,
                    controller,
                    kubernetes,
                },
            )),
            acquisition,
            timings,
            bootstrap: BootstrapTiming::disabled(),
        })
    }

    fn acquire_authenticated(
        mut stage: EnrolledRoleStage<'role>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        timings: Timings,
        mut authentication: ProviderEpochReads,
        bootstrap: BootstrapTiming,
        purpose: StagePurpose,
    ) -> Result<Self> {
        // The actual read-only GKE probe took 3.168939s, including 0.714994s
        // of repeated provider authentication. Reuse ONLY its genuine full
        // same-stage material, not a previous provider observation. All live
        // profile/provider/physical/durability checks remain. The original
        // purpose-bound interval is retained; no margin is inferred here.
        let guard = authentication.arm_refusal()?;
        stage.require_purpose(purpose)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let mut acquisition = match purpose {
            StagePurpose::StorageBootstrap => stage
                .storage()?
                .narrow_storage_bootstrap_io_acquisition(store.max_lease_seconds)?,
            StagePurpose::StorageMetadataObservation => stage
                .storage()?
                .narrow_storage_metadata_observation_io_acquisition(store.max_lease_seconds)?,
            _ => anyhow::bail!("storage_provider_authenticated_purpose_required"),
        };
        authentication.check(&mut stage, policy, store, &mut acquisition)?;
        let selected = profile(&mut acquisition)
            .map_err(|error| PreparationFailure::at(PreparationStep::StorageProfile, error))?;
        selected
            .validate(policy)
            .map_err(|error| PreparationFailure::at(PreparationStep::StorageProfile, error))?;
        authentication.check(&mut stage, policy, store, &mut acquisition)?;
        let reader = Self {
            stage,
            policy: policy.clone(),
            store: store.clone(),
            profile: selected,
            authentication: ProviderAuthentication::Retained(authentication),
            acquisition,
            timings,
            bootstrap,
        };
        guard.complete()?;
        Ok(reader)
    }

    fn refusal_guard(&self) -> Result<Option<RefusalGuard>> {
        match &self.authentication {
            ProviderAuthentication::Acquired(_) => Ok(None),
            ProviderAuthentication::Retained(authentication) => {
                authentication.arm_refusal().map(Some)
            }
        }
    }

    fn check(&mut self) -> Result<()> {
        let guard = self.refusal_guard()?;
        let result = (|| {
            self.stage
                .check_selection(&self.policy, &self.store, NativeRole::EpochController)?;
            if let ProviderAuthentication::Retained(authentication) = &mut self.authentication {
                authentication.check(
                    &mut self.stage,
                    &self.policy,
                    &self.store,
                    &mut self.acquisition,
                )?;
            }
            self.acquisition.remaining()?;
            ensure!(
                profile(&mut self.acquisition).map_err(|error| PreparationFailure::at(
                    PreparationStep::StorageProfile,
                    error
                ))? == self.profile,
                "storage_native_profile_changed"
            );
            self.profile.validate(&self.policy)?;
            self.stage
                .check_selection(&self.policy, &self.store, NativeRole::EpochController)?;
            if let ProviderAuthentication::Retained(authentication) = &mut self.authentication {
                authentication.check(
                    &mut self.stage,
                    &self.policy,
                    &self.store,
                    &mut self.acquisition,
                )?;
            }
            Ok(())
        })();
        if result.is_err()
            && let ProviderAuthentication::Retained(authentication) = &mut self.authentication
        {
            authentication.refuse();
            self.acquisition.refuse();
        }
        result?;
        if let Some(guard) = guard {
            guard.complete()?;
        }
        Ok(())
    }

    fn get(&mut self, read: StorageMetadataRead) -> Result<Value> {
        let guard = self.refusal_guard()?;
        self.check()?;
        let operation = match read {
            StorageMetadataRead::Claim => Operation::Claim,
            StorageMetadataRead::Volume => Operation::Volume,
            StorageMetadataRead::Node => Operation::Node,
            StorageMetadataRead::Disk => Operation::Disk,
            StorageMetadataRead::Instance => Operation::Instance,
        };
        let result = self
            .timings
            .measure(operation, || match &mut self.authentication {
                ProviderAuthentication::Acquired(material) => {
                    let authorization = if read.google() {
                        material.source.authorization()?
                    } else {
                        material.kubernetes.authorization()?
                    };
                    material.http.request(
                        read.route(&self.profile, &self.policy),
                        &authorization,
                        None,
                        &mut self.acquisition,
                    )
                }
                ProviderAuthentication::Retained(authentication) => authentication.get(
                    &mut self.stage,
                    &self.policy,
                    &self.store,
                    &self.profile,
                    read,
                    &mut self.acquisition,
                ),
            });
        // Always perform the original postcheck, including after a failed
        // request. Preserve the first request failure instead of replacing it
        // with the acquisition-refused consequence of that same failure.
        let checked = self.check();
        let bytes = result?;
        checked?;
        let value: Value = crate::json::decode(&bytes)?;
        ensure!(value.is_object(), "storage_provider_reply_object_required");
        if let Some(guard) = guard {
            guard.complete()?;
        }
        Ok(value)
    }

    fn observe_provider(&mut self) -> Result<String> {
        let trace = self.bootstrap.clone();
        trace.provider_round(|| self.observe_provider_inner())
    }

    fn observe_provider_inner(&mut self) -> Result<String> {
        let guard = self.refusal_guard()?;
        // Clone only desired DATA so no self-borrow is held during actual I/O.
        let profile = self.profile.clone();
        let policy = self.policy.clone();
        let claim = self
            .get(StorageMetadataRead::Claim)
            .map_err(|error| PreparationFailure::at(PreparationStep::ClaimBinding, error))?;
        profile
            .claim(&policy, &claim)
            .map_err(|error| PreparationFailure::at(PreparationStep::ClaimBinding, error))?;
        let volume = self
            .get(StorageMetadataRead::Volume)
            .map_err(|error| PreparationFailure::at(PreparationStep::VolumeBinding, error))?;
        profile
            .volume(&policy, &volume)
            .map_err(|error| PreparationFailure::at(PreparationStep::VolumeBinding, error))?;
        self.check()?;
        let boot = read_fixed(
            "/proc/sys/kernel/random/boot_id",
            128,
            &mut self.acquisition,
        )
        .map_err(|error| PreparationFailure::at(PreparationStep::NodeBoot, error))?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|error| PreparationFailure::at(PreparationStep::NodeBoot, error.into()))?
            .trim_end_matches('\n');
        let node = self
            .get(StorageMetadataRead::Node)
            .map_err(|error| PreparationFailure::at(PreparationStep::NodeBinding, error))?;
        profile
            .node(&policy, boot, &node)
            .map_err(|error| PreparationFailure::at(PreparationStep::NodeBinding, error))?;
        let disk = self
            .get(StorageMetadataRead::Disk)
            .map_err(|error| PreparationFailure::at(PreparationStep::DiskBinding, error))?;
        profile
            .disk(&policy, &disk)
            .map_err(|error| PreparationFailure::at(PreparationStep::DiskBinding, error))?;
        let instance = self
            .get(StorageMetadataRead::Instance)
            .map_err(|error| PreparationFailure::at(PreparationStep::InstanceBinding, error))?;
        let device = profile
            .instance(&policy, &instance)
            .map_err(|error| PreparationFailure::at(PreparationStep::InstanceBinding, error))?;
        self.check()?;
        if let Some(guard) = guard {
            guard.complete()?;
        }
        Ok(device)
    }
}

/// One authenticated provider-metadata frontier on the supplied original
/// Current stage. No /state directory or block-device descriptor is opened,
/// no mount is adopted, and no storage/file/peer/writer owner is returned.
/// A detached or changed attachment must still refuse; its validation is not
/// omitted just because this diagnostic returns only unit DATA.
pub(super) fn observe_provider_read_only(
    stage: EnrolledRoleStage<'_>,
    policy: &InitialBootstrapPolicy,
    store: &EpochStore,
    trace: &BootstrapTiming,
    authentication: ProviderEpochReads,
) -> Result<()> {
    let guard = authentication.arm_refusal()?;
    let mut reader = ProviderReader::acquire_authenticated(
        stage,
        policy,
        store,
        trace.timings(),
        authentication,
        trace.clone(),
        StagePurpose::StorageMetadataObservation,
    )?;
    // Three successive fresh validations through ONE genuine authentication
    // and original Current stage, matching the bootstrap's metadata-round
    // count. First error returns immediately; no renew/retry, state/block
    // descriptor, SQL, peer or writer exists in this closed diagnostic.
    for _ in 0..3 {
        reader.observe_provider()?;
    }
    reader.check()?;
    guard.complete()
}

impl<'role> NativeVolumeObservation<'role> {
    pub(super) fn timings(&self) -> Timings {
        self.reader.timings.clone()
    }
    pub(super) fn original_seed(
        &mut self,
    ) -> Result<crate::security_epoch::seed_core::OriginalSeedCore> {
        self.check_current()?;
        let mut nonce = [0_u8; 96];
        crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, &mut nonce)?;
        self.check_current()?;
        let core = crate::security_epoch::seed_core::OriginalSeedCore::new(
            &self.reader.policy,
            &self.reader.store,
            crate::security_epoch::seed_core::Incarnations {
                record: day2_capabilities::Digest::new(&nonce[..32]),
                database: day2_capabilities::Digest::new(&nonce[32..64]),
                activation: day2_capabilities::Digest::new(&nonce[64..]),
            },
        )?;
        self.check_current()?;
        Ok(core)
    }

    pub(super) fn create_initial_directory(
        &mut self,
    ) -> Result<(File, DirectoryIdentity, NativeAcquisition)> {
        self.check_current()?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_native_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags};
            // A failed create is not permission to adopt or retry. Any created
            // leaf remains, and all later constructors refuse EEXIST.
            rustix::fs::mkdirat(
                &self.resources.directory,
                PRIVATE_DIRECTORY,
                Mode::from_raw_mode(0o700),
            )?;
            self.check_current()?;
            let directory = File::from(rustix::fs::openat2(
                &self.resources.directory,
                PRIVATE_DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )?);
            // Do not inherit an fsGroup setgid bit into the private anchor.
            rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o700))?;
            let identity = directory_identity(&directory)?;
            self.check_directory(&directory, &identity)?;
            let acquisition = self.reader.acquisition.narrow(
                self.reader.store.max_lease_seconds,
                std::time::Duration::MAX,
            )?;
            Ok((directory, identity, acquisition))
        }
    }

    pub(super) fn check_directory(
        &mut self,
        directory: &File,
        identity: &DirectoryIdentity,
    ) -> Result<()> {
        self.resources
            .check_directory(&mut self.reader, directory, identity)
    }

    /// Capture only while the original preparation remains valid. The caller
    /// performs its final original-file check before the infallible move below.
    pub(super) fn capture_same_owner(&mut self) -> Result<SameEnrolledOwner> {
        self.check_current()?;
        self.reader.stage.capture_same_owner()
    }

    pub(super) fn retain_resources(self, owner: SameEnrolledOwner) -> NativeVolumeContinuity {
        NativeVolumeContinuity {
            resources: self.resources,
            owner,
            policy: self.reader.policy,
            store: self.reader.store,
            profile: self.reader.profile,
        }
    }

    pub(super) fn acquire(
        stage: EnrolledRoleStage<'role>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        timings: Timings,
    ) -> Result<Self> {
        let mut reader =
            ProviderReader::acquire(stage, policy, store, timings, StagePurpose::CurrentRole)?;
        let device_name = reader.observe_provider()?;
        reader.check()?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = device_name;
            anyhow::bail!("storage_native_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            let directory = File::from(
                rustix::fs::open(
                    ROOT,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| {
                    PreparationFailure::at(PreparationStep::VolumeDirectory, error.into())
                })?,
            );
            let identity = directory_identity(&directory)
                .map_err(|error| PreparationFailure::at(PreparationStep::VolumeIdentity, error))?;
            let block = open_device(&device_name, &mut reader.acquisition)
                .map_err(|error| PreparationFailure::at(PreparationStep::BlockDevice, error))?;
            let mut owner = Self {
                reader,
                resources: NativeVolumeResources {
                    directory,
                    identity,
                    block,
                    device_name,
                    valid: true,
                },
            };
            owner
                .check_current()
                .map_err(|error| PreparationFailure::at(PreparationStep::VolumeCurrent, error))?;
            Ok(owner)
        }
    }

    pub(super) fn check_current(&mut self) -> Result<()> {
        self.resources.check_current(&mut self.reader)
    }
}

impl NativeVolumeResources {
    fn check_directory(
        &mut self,
        reader: &mut ProviderReader<'_>,
        directory: &File,
        identity: &DirectoryIdentity,
    ) -> Result<()> {
        self.check_current(reader)?;
        ensure!(
            directory_identity(directory)? == *identity,
            "storage_native_private_anchor_changed"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_native_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{AtFlags, FileType, StatxFlags};
            use std::os::unix::fs::MetadataExt;
            let metadata = directory.metadata()?;
            ensure!(
                metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o7777 == 0o700
                    && identity.device_major == self.identity.device_major
                    && identity.device_minor == self.identity.device_minor
                    && identity.mount == self.identity.mount,
                "storage_native_private_anchor_profile"
            );
            let flags = StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID;
            let named = rustix::fs::statx(
                &self.directory,
                PRIVATE_DIRECTORY,
                AtFlags::SYMLINK_NOFOLLOW,
                flags,
            )?;
            ensure!(
                named.stx_mask & flags.bits() == flags.bits()
                    && FileType::from_raw_mode(u32::from(named.stx_mode)) == FileType::Directory
                    && named.stx_ino == identity.inode
                    && named.stx_mnt_id == identity.mount
                    && named.stx_dev_major == identity.device_major
                    && named.stx_dev_minor == identity.device_minor,
                "storage_native_private_anchor_path_changed"
            );
            self.check_current(reader)
        }
    }

    fn check_current(&mut self, reader: &mut ProviderReader<'_>) -> Result<()> {
        let timings = reader.timings.clone();
        let result = timings.measure(Operation::NativeCheck, || {
            ensure!(self.valid, "storage_native_volume_refused");
            reader.check()?;
            ensure!(
                directory_identity(&self.directory)? == self.identity,
                "storage_native_mount_changed"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_native_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                use rustix::fs::{AtFlags, FileType, StatxFlags};
                // ext4 on an actual block device is the selected PD profile.
                ensure!(
                    self.identity.filesystem == 0xef53,
                    "storage_native_filesystem_profile"
                );
                let flags = StatxFlags::BASIC_STATS | StatxFlags::MNT_ID;
                let observed = rustix::fs::statx(&self.block, "", AtFlags::EMPTY_PATH, flags)?;
                ensure!(
                    observed.stx_mask & flags.bits() == flags.bits()
                        && FileType::from_raw_mode(u32::from(observed.stx_mode))
                            == FileType::BlockDevice
                        && observed.stx_rdev_major == self.identity.device_major
                        && observed.stx_rdev_minor == self.identity.device_minor,
                    "storage_native_block_device_mismatch"
                );
                let named = File::from(rustix::fs::open(
                    ROOT,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )?);
                ensure!(
                    directory_identity(&named)? == self.identity,
                    "storage_native_anchor_path_changed"
                );
                let current = open_device(&self.device_name, &mut reader.acquisition)?;
                let current = rustix::fs::statx(current, "", AtFlags::EMPTY_PATH, flags)?;
                ensure!(
                    current.stx_mask & flags.bits() == flags.bits()
                        && current.stx_ino == observed.stx_ino
                        && current.stx_mnt_id == observed.stx_mnt_id
                        && current.stx_rdev_major == observed.stx_rdev_major
                        && current.stx_rdev_minor == observed.stx_rdev_minor,
                    "storage_native_device_path_changed"
                );
                let mounts = read_fixed(
                    "/proc/thread-self/mountinfo",
                    65_536,
                    &mut reader.acquisition,
                )?;
                mount(
                    &mounts,
                    self.identity.mount,
                    self.identity.device_major,
                    self.identity.device_minor,
                )?;
                reader.check()
            }
        });
        if result.is_err() {
            self.valid = false;
            reader.acquisition.refuse();
        }
        result
    }
}

impl NativeVolumeResources {
    fn check_durability_profile(&mut self, reader: &mut ProviderReader<'_>) -> Result<()> {
        let result = (|| {
            self.check_current(reader)?;
            // Repeat the authenticated selected disk/attachment join within
            // this SAME original phase, before accepting the provider contract.
            ensure!(
                reader.observe_provider()? == self.device_name,
                "storage_durability_attachment_changed"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_native_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let uevent = read_fixed(
                    &format!(
                        "/sys/dev/block/{}:{}/uevent",
                        self.identity.device_major, self.identity.device_minor
                    ),
                    4096,
                    &mut reader.acquisition,
                )?;
                let device = kernel_block_name(
                    &uevent,
                    self.identity.device_major,
                    self.identity.device_minor,
                )?;
                // ext4_seq_options_show uses nodefs=1 here: unlike mountinfo,
                // it prints the live data mode and barrier choice explicitly.
                let options = read_fixed(
                    &format!("/proc/fs/ext4/{device}/options"),
                    8192,
                    &mut reader.acquisition,
                )?;
                ext4_durability_options(&options)?;
                let mut superblock = [0_u8; 1024];
                let mut offset = 0;
                while offset < superblock.len() {
                    reader.acquisition.remaining()?;
                    let read = rustix::io::pread(
                        &self.block,
                        &mut superblock[offset..],
                        (1024 + offset) as u64,
                    )?;
                    ensure!(
                        read > 0 && read <= superblock.len() - offset,
                        "storage_durability_superblock_read_progress"
                    );
                    offset += read;
                    reader.acquisition.remaining()?;
                }
                ext4_internal_journal(&superblock)?;
                self.check_current(reader)
            }
        })();
        if result.is_err() {
            self.valid = false;
            reader.acquisition.refuse();
        }
        result
    }
}

// All parsers below validate DATA only. Native ownership comes exclusively from
// the retained block/directory FDs and role/provider checks around actual reads.
fn kernel_block_name(bytes: &[u8], major: u32, minor: u32) -> Result<String> {
    let fields = kernel_lines(bytes, 4096)?;
    ensure!(
        fields.get("MAJOR").copied() == Some(major.to_string().as_str())
            && fields.get("MINOR").copied() == Some(minor.to_string().as_str())
            && fields.get("DEVTYPE").copied() == Some("disk"),
        "storage_durability_kernel_device_identity"
    );
    let name = fields
        .get("DEVNAME")
        .context("storage_durability_kernel_device_name")?;
    ensure!(
        !name.is_empty()
            && name.len() <= 63
            && name
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_')),
        "storage_durability_kernel_device_component"
    );
    Ok((*name).to_owned())
}

fn kernel_lines(bytes: &[u8], limit: usize) -> Result<std::collections::BTreeMap<&str, &str>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit && bytes.ends_with(b"\n"),
        "storage_durability_kernel_snapshot_bound"
    );
    let text = std::str::from_utf8(bytes)?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        ensure!(
            !line.is_empty() && line.len() <= 512 && line.bytes().all(|v| v.is_ascii_graphic()),
            "storage_durability_kernel_line"
        );
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        ensure!(
            !key.is_empty() && fields.len() < 128 && fields.insert(key, value).is_none(),
            "storage_durability_kernel_duplicate_or_bound"
        );
    }
    Ok(fields)
}

fn ext4_durability_options(bytes: &[u8]) -> Result<()> {
    let fields = kernel_lines(bytes, 8192)?;
    ensure!(
        fields.get("rw") == Some(&"")
            && !fields.contains_key("ro")
            && fields.get("data") == Some(&"ordered")
            && fields
                .get("barrier")
                .is_some_and(|v| matches!(*v, "" | "1"))
            && fields.get("dax").is_none_or(|v| *v == "never")
            && ![
                "nobarrier",
                "noload",
                "norecovery",
                "journal_dev",
                "journal_path",
                "journal_async_commit",
                "abort",
                "sb"
            ]
            .iter()
            .any(|v| fields.contains_key(*v)),
        "storage_durability_ext4_options"
    );
    Ok(())
}

fn ext4_internal_journal(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() == 1024, "storage_durability_superblock_bound");
    let word = |offset| {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("fixed superblock offsets"),
        )
    };
    ensure!(
        u16::from_le_bytes(bytes[0x38..0x3a].try_into()?) == 0xef53
            && u16::from_le_bytes(bytes[0x3a..0x3c].try_into()?) & 2 == 0
            && word(0x5c) & 4 != 0
            && word(0x60) & 8 == 0
            && word(0xe0) != 0
            && word(0xe4) == 0,
        "storage_durability_internal_journal_required"
    );
    Ok(())
}

impl NativeVolumeContinuity {
    pub(super) fn begin_authenticated<'volume, 'role>(
        &'volume mut self,
        mut stage: EnrolledRoleStage<'role>,
        authentication: ProviderEpochReads,
        trace: &BootstrapTiming,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        let guard = authentication.arm_refusal()?;
        let result = (|| {
            stage.require_purpose(StagePurpose::StorageBootstrap)?;
            ensure!(self.resources.valid, "storage_native_volume_refused");
            self.owner.check(&mut stage)?;
            ProviderReader::acquire_authenticated(
                stage,
                &self.policy,
                &self.store,
                trace.timings(),
                authentication,
                trace.clone(),
                StagePurpose::StorageBootstrap,
            )
        })();
        let phase = self.finish_begin(result)?;
        guard.complete()?;
        Ok(phase)
    }

    pub(super) fn begin_current<'volume, 'role>(
        &'volume mut self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        self.begin_phase(stage, StagePurpose::CurrentRole)
    }

    pub(super) fn begin_first_holder<'volume, 'role>(
        &'volume mut self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        self.begin_phase(stage, StagePurpose::InitialFirstHolder)
    }

    fn begin_phase<'volume, 'role>(
        &'volume mut self,
        mut stage: EnrolledRoleStage<'role>,
        purpose: StagePurpose,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        let result = (|| {
            stage.require_purpose(purpose)?;
            ensure!(self.resources.valid, "storage_native_volume_refused");
            self.owner.check(&mut stage)?;
            ProviderReader::acquire(
                stage,
                &self.policy,
                &self.store,
                Timings::disabled(),
                purpose,
            )
        })();
        self.finish_begin(result)
    }

    fn finish_begin<'volume, 'role>(
        &'volume mut self,
        result: Result<ProviderReader<'role>>,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        let result = result.and_then(|mut reader| {
            ensure!(
                reader.profile == self.profile,
                "storage_native_profile_changed"
            );
            // The reply is read again inside this fresh original bounded phase;
            // a previous successful attachment observation is never authority.
            ensure!(
                reader.observe_provider()? == self.resources.device_name,
                "storage_native_device_selection_changed"
            );
            self.resources.check_current(&mut reader)?;
            self.owner.check(&mut reader.stage)?;
            Ok(reader)
        });
        match result {
            Ok(reader) => Ok(CurrentVolumePhase {
                resources: &mut self.resources,
                reader,
            }),
            Err(error) => {
                self.resources.valid = false;
                Err(error)
            }
        }
    }
}

impl CurrentVolumePhase<'_, '_> {
    pub(super) fn check_authenticated_reads(&mut self, reads: &ControllerEpochReads) -> Result<()> {
        self.reader.check()?;
        ensure!(
            matches!(&self.reader.authentication, ProviderAuthentication::Retained(provider) if provider.matches(reads)),
            "epoch_writer_provider_authentication_changed"
        );
        Ok(())
    }

    /// Observe the live selected filesystem contract, not omitted mountinfo
    /// defaults or desired fsType. This grants no standalone P3 permission.
    pub(super) fn check_durability_profile(&mut self) -> Result<()> {
        self.resources.check_durability_profile(&mut self.reader)
    }

    pub(super) fn check_directory(
        &mut self,
        directory: &File,
        identity: &DirectoryIdentity,
    ) -> Result<()> {
        self.resources
            .check_directory(&mut self.reader, directory, identity)
    }

    // Only the owning fixed file operation uses this interval. No stage, native
    // descriptor or reusable permission is exposed to the application.
    pub(super) fn acquisition(&mut self) -> &mut NativeAcquisition {
        &mut self.reader.acquisition
    }
}

impl<'role> CurrentVolumePhase<'_, 'role> {
    pub(super) fn controller_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.reader.check()?;
        self.reader.acquisition.remaining()?;
        Ok(&mut self.reader.stage)
    }
}

#[cfg(target_os = "linux")]
fn open_device(device: &str, acquisition: &mut NativeAcquisition) -> Result<File> {
    // device is taken only from the exact authenticated selected attachment,
    // validated before it can become a path component.
    ensure!(
        !device.is_empty()
            && device.len() <= 253
            && device
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-'),
        "storage_native_device_name"
    );
    acquisition.remaining()?;
    let root = rustix::fs::open(
        "/dev",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(rustix::fs::openat2(
        root,
        format!("disk/by-id/google-{device}"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?);
    acquisition.remaining()?;
    Ok(file)
}

fn mount(bytes: &[u8], expected: u64, major: u32, minor: u32) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.ends_with('\n') && text.lines().count() <= 512,
        "storage_native_mount_snapshot_bound"
    );
    let mut found = false;
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() <= 64, "storage_native_mount_entry_bound");
        let id = fields
            .first()
            .context("storage_native_mount_entry")?
            .parse::<u64>()?;
        if id != expected {
            continue;
        }
        ensure!(!found, "storage_native_mount_ambiguous");
        found = true;
        let separator = fields
            .iter()
            .position(|value| *value == "-")
            .context("storage_native_mount_separator")?;
        ensure!(
            separator >= 6
                && fields.len() == separator + 4
                && fields[2] == format!("{major}:{minor}")
                && fields[3] == "/"
                && fields[4] == ROOT
                && fields[5].split(',').any(|v| v == "rw")
                && !fields[5].split(',').any(|v| v == "ro")
                && !fields[6..separator].iter().any(|v| v.starts_with("shared:")
                    || v.starts_with("master:")
                    || v.starts_with("propagate_from:"))
                && fields[separator + 1] == "ext4"
                && fields[separator + 3].split(',').any(|v| v == "rw")
                && !fields[separator + 3].split(',').any(|v| v == "ro"),
            "storage_native_mount_binding"
        );
    }
    ensure!(found, "storage_native_mount_missing");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durability_options_require_explicit_live_ordering_and_barriers() {
        let good = "rw\nbarrier\ndata=ordered\nerrors=remount-ro\n";
        ext4_durability_options(good.as_bytes()).unwrap();
        ext4_durability_options(b"rw\nbarrier=1\ndata=ordered\ndax=never\n").unwrap();
        for bad in [
            good.replace("barrier\n", ""),
            good.replace("barrier\n", "barrier=0\n"),
            good.replace("data=ordered", "data=writeback"),
            good.replace("data=ordered", "data=journal"),
            good.replace("data=ordered\n", ""),
            good.replace("rw\n", "ro\n"),
            format!("{good}ro\n"),
            format!("{good}nobarrier\n"),
            format!("{good}noload\n"),
            format!("{good}norecovery\n"),
            format!("{good}journal_dev=8:17\n"),
            format!("{good}journal_path=/another-device\n"),
            format!("{good}journal_async_commit\n"),
            format!("{good}abort\n"),
            format!("{good}sb=2\n"),
            format!("{good}dax\n"),
            format!("{good}dax=always\n"),
            format!("{good}dax=inode\n"),
            format!("{good}data=ordered\n"),
            good.replace('\n', ","),
            good.trim_end().to_owned(),
        ] {
            assert!(ext4_durability_options(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn kernel_device_component_is_bound_to_the_actual_whole_block_device() {
        let good = "MAJOR=8\nMINOR=16\nDEVNAME=sdb\nDEVTYPE=disk\n";
        assert_eq!(kernel_block_name(good.as_bytes(), 8, 16).unwrap(), "sdb");
        for bad in [
            good.replace("MAJOR=8", "MAJOR=9"),
            good.replace("MINOR=16", "MINOR=17"),
            good.replace("DEVTYPE=disk", "DEVTYPE=partition"),
            good.replace("DEVNAME=sdb", "DEVNAME=../../sdb"),
            good.replace("DEVNAME=sdb", "DEVNAME="),
            format!("{good}DEVNAME=sdb\n"),
            good.replace("MAJOR=8", "MAJOR=08"),
            good.trim_end().to_owned(),
            "x".repeat(4097),
        ] {
            assert!(kernel_block_name(bad.as_bytes(), 8, 16).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn durability_superblock_requires_a_healthy_internal_journal() {
        let mut good = [0_u8; 1024];
        good[0x38..0x3a].copy_from_slice(&0xef53_u16.to_le_bytes());
        good[0x5c..0x60].copy_from_slice(&4_u32.to_le_bytes());
        good[0xe0..0xe4].copy_from_slice(&8_u32.to_le_bytes());
        ext4_internal_journal(&good).unwrap();
        for (offset, value) in [
            (0x38, 0),
            (0x3a, 2),
            (0x5c, 0),
            (0x60, 8),
            (0xe0, 0),
            (0xe4, 1),
        ] {
            let mut bad = good;
            bad[offset] = value;
            assert!(ext4_internal_journal(&bad).is_err(), "offset {offset}");
        }
        assert!(ext4_internal_journal(&good[..1023]).is_err());
        assert!(ext4_internal_journal(&[0_u8; 1025]).is_err());
    }

    #[test]
    fn kernel_options_refuse_duplicate_truncated_and_unbounded_metadata() {
        for bytes in [
            b"".as_slice(),
            b"rw\n\n",
            b"rw\nbarrier\nbarrier\n",
            b"rw\nnon graphic=value\n",
            b"rw\nbarrier\x00\n",
            b"rw\nbarrier",
        ] {
            assert!(kernel_lines(bytes, 8192).is_err());
        }
        let too_many = (0..129)
            .map(|v| format!("key{v}=value\n"))
            .collect::<String>();
        assert!(kernel_lines(too_many.as_bytes(), 8192).is_err());
    }

    #[test]
    fn exact_private_ext4_mount_refuses_aliases_propagation_and_partial_snapshots() {
        let good = b"91 1 8:16 / /state rw,nosuid - ext4 /dev/sdb rw\n";
        mount(good, 91, 8, 16).unwrap();
        for bad in [
            "91 1 8:17 / /state rw - ext4 /dev/sdb rw\n",
            "91 1 8:16 /sub /state rw - ext4 /dev/sdb rw\n",
            "91 1 8:16 / /state-copy rw - ext4 /dev/sdb rw\n",
            "91 1 8:16 / /state ro - ext4 /dev/sdb rw\n",
            "91 1 8:16 / /state rw shared:1 - ext4 /dev/sdb rw\n",
            "91 1 8:16 / /state rw - xfs /dev/sdb rw\n",
            "91 1 8:16 / /state rw - ext4 /dev/sdb ro\n",
            "91 1 8:16 / /state rw - ext4 /dev/sdb rw",
        ] {
            assert!(mount(bad.as_bytes(), 91, 8, 16).is_err());
        }
        let duplicate = [good.as_slice(), good.as_slice()].concat();
        assert!(mount(&duplicate, 91, 8, 16).is_err());
    }
}
