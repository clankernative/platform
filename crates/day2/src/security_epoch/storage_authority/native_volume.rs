//! Native controller-only provider/mount acquisition. This reads actual provider
//! and kernel resources under the retained original enrolled stage. It neither
//! creates the initial file nor turns a JSON reply into a P3/writer permission.

use super::{DirectoryIdentity, directory_identity, persistent_disk::PersistentDiskSelection};
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    identity_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole, SameEnrolledOwner},
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
    http: NativeHttp,
    source: CredentialMaterial,
    controller: CredentialMaterial,
    kubernetes: CredentialMaterial,
    acquisition: NativeAcquisition,
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
    ) -> Result<Self> {
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let mut acquisition = stage.narrow_io_acquisition(store.max_lease_seconds)?;
        let selected = profile(&mut acquisition)?;
        selected.validate(policy)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let ca = cluster_ca(&mut acquisition)?;
        let mut http = NativeHttp::new(store, &policy.cluster, &ca)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let source = CredentialMaterial::metadata_source(&mut acquisition)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        identity_protocol::project(
            store,
            &http.request(
                Route::Project,
                &source.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        http.verify_cluster(&ca, &source.authorization()?, &mut acquisition)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        identity_protocol::google_service_account(
            &policy.controller.google_service_account,
            &policy.cluster.project,
            &http.request(
                Route::GoogleAccount(&policy.controller.google_service_account),
                &source.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let controller = CredentialMaterial::mint_target(
            &source,
            &policy.controller.google_service_account,
            &http,
            &mut acquisition,
        )?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        identity_protocol::database(
            store,
            &http.request(
                Route::Database,
                &controller.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        let kubernetes = CredentialMaterial::kubernetes_api(&mut acquisition)?;
        stage.check_selection(policy, store, NativeRole::EpochController)?;
        Ok(Self {
            stage,
            policy: policy.clone(),
            store: store.clone(),
            profile: selected,
            http,
            source,
            controller,
            kubernetes,
            acquisition,
        })
    }

    fn check(&mut self) -> Result<()> {
        self.stage
            .check_selection(&self.policy, &self.store, NativeRole::EpochController)?;
        self.acquisition.remaining()?;
        ensure!(
            profile(&mut self.acquisition)? == self.profile,
            "storage_native_profile_changed"
        );
        self.profile.validate(&self.policy)?;
        self.stage
            .check_selection(&self.policy, &self.store, NativeRole::EpochController)?;
        Ok(())
    }

    fn get(&mut self, route: Route<'_>) -> Result<Value> {
        self.check()?;
        let google = match route {
            Route::ComputeDisk { .. } | Route::ComputeInstance { .. } => true,
            Route::PersistentVolumeClaim { .. } | Route::PersistentVolume(_) | Route::Node(_) => {
                false
            }
            _ => anyhow::bail!("storage_provider_route_unavailable"),
        };
        let authorization = if google {
            self.source.authorization()?
        } else {
            self.kubernetes.authorization()?
        };
        let result = self
            .http
            .request(route, &authorization, None, &mut self.acquisition);
        self.check()?;
        let value: Value = crate::json::decode(&result?)?;
        ensure!(value.is_object(), "storage_provider_reply_object_required");
        Ok(value)
    }

    fn observe_provider(&mut self) -> Result<String> {
        // Clone only desired DATA so no self-borrow is held during actual I/O.
        let profile = self.profile.clone();
        let policy = self.policy.clone();
        let claim = self.get(Route::PersistentVolumeClaim {
            namespace: &policy.app.namespace.name,
            name: &profile.claim.name,
        })?;
        profile.claim(&policy, &claim)?;
        let volume = self.get(Route::PersistentVolume(&profile.volume.name))?;
        profile.volume(&policy, &volume)?;
        self.check()?;
        let boot = read_fixed(
            "/proc/sys/kernel/random/boot_id",
            128,
            &mut self.acquisition,
        )?;
        let boot = std::str::from_utf8(&boot)?.trim_end_matches('\n');
        let node = self.get(Route::Node(&profile.node.name))?;
        profile.node(&policy, boot, &node)?;
        let disk = self.get(Route::ComputeDisk {
            zone: profile.zone.as_str(),
            name: profile.disk.as_str(),
        })?;
        profile.disk(&policy, &disk)?;
        let instance = self.get(Route::ComputeInstance {
            zone: profile.zone.as_str(),
            name: profile.instance.as_str(),
        })?;
        let device = profile.instance(&policy, &instance)?;
        self.check()?;
        Ok(device)
    }
}

impl<'role> NativeVolumeObservation<'role> {
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
    ) -> Result<Self> {
        let mut reader = ProviderReader::acquire(stage, policy, store)?;
        let device_name = reader.observe_provider()?;
        reader.check()?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = device_name;
            anyhow::bail!("storage_native_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            let directory = File::from(rustix::fs::open(
                ROOT,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )?);
            let identity = directory_identity(&directory)?;
            let block = open_device(&device_name, &mut reader.acquisition)?;
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
            owner.check_current()?;
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
        let result = (|| {
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
        })();
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
            && ![
                "nobarrier",
                "noload",
                "norecovery",
                "journal_dev",
                "journal_path",
                "journal_async_commit",
                "abort",
                "sb",
                "dax"
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
    pub(super) fn begin_current<'volume, 'role>(
        &'volume mut self,
        mut stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentVolumePhase<'volume, 'role>> {
        let result = (|| {
            ensure!(self.resources.valid, "storage_native_volume_refused");
            self.owner.check(&mut stage)?;
            let mut reader = ProviderReader::acquire(stage, &self.policy, &self.store)?;
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
        })();
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
