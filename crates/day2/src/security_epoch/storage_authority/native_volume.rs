//! Native controller-only provider/mount acquisition. This reads actual provider
//! and kernel resources under the retained original enrolled stage. It neither
//! creates the initial file nor turns a JSON reply into a P3/writer permission.

use super::{DirectoryIdentity, directory_identity, persistent_disk::PersistentDiskSelection};
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    identity_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole},
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
                &self.directory,
                PRIVATE_DIRECTORY,
                Mode::from_raw_mode(0o700),
            )?;
            self.check_current()?;
            let directory = File::from(rustix::fs::openat2(
                &self.directory,
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
        self.check_current()?;
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
            self.check_current()
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
                directory,
                identity,
                block,
                device_name,
                valid: true,
            };
            owner.check_current()?;
            Ok(owner)
        }
    }

    pub(super) fn check_current(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "storage_native_volume_refused");
            self.reader.check()?;
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
                let current = open_device(&self.device_name, &mut self.reader.acquisition)?;
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
                    &mut self.reader.acquisition,
                )?;
                mount(
                    &mounts,
                    self.identity.mount,
                    self.identity.device_major,
                    self.identity.device_minor,
                )?;
                self.reader.check()
            }
        })();
        if result.is_err() {
            self.valid = false;
            self.reader.acquisition.refuse();
        }
        result
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
