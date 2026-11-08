//! Current desired configuration of the actual restored App. The caller's
//! startup pathname is untrusted DATA; only the authenticated Controller's
//! mandatory Instance digest binds its contents. The birth loan admits only its
//! actual existing database; no ordinary metadata or serving factory is called.
#[cfg(target_os = "linux")]
use super::RestoredObservationOwner;
use super::{
    RestoredActiveKeeperInput, RestoredConfiguredInput, RestoredKeeperBirth, RestoredKeeperInput,
    RestoredMaterialBorrow, RestoredRuntimeBirth,
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, ensure};
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
use day2_capabilities::Digest as InstanceDigest;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{fs::File, path::PathBuf};

const MAX_BYTES: u64 = 1_048_576;
const CHUNK: usize = 64 * 1024;

// Comparison DATA only; neither function admits an App or constructs a loan.
fn require_selected(selected: &Path, pinned: &Path) -> Result<()> {
    anyhow::ensure!(
        selected == pinned,
        "restore_instance_published_selector_changed"
    );
    Ok(())
}

fn require_desired(instance: &crate::artifact::Instance, expected: &InstanceDigest) -> Result<()> {
    anyhow::ensure!(
        &InstanceDigest::of(instance)? == expected,
        "restore_instance_not_authenticated_desired_input"
    );
    Ok(())
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: (u32, u32),
    mount: u64,
    inode: u64,
    user: u32,
    group: u32,
    mode: u16,
    links: u32,
    bytes: u64,
    modified: (i64, u32),
    changed: (i64, u32),
}

pub(super) struct CurrentInstance {
    #[cfg(target_os = "linux")]
    file: File,
    #[cfg(target_os = "linux")]
    selector: PathBuf,
    #[cfg(target_os = "linux")]
    path: PathBuf,
    #[cfg(target_os = "linux")]
    identity: Identity,
    #[cfg(target_os = "linux")]
    bytes: Digest,
    instance: crate::artifact::Instance,
}

impl RestoredKeeperInput {
    /// Consumes the genuine retained artifact owner. A self-consistent file or
    /// a caller-supplied digest cannot substitute for the signed desired input.
    pub(in crate::security_epoch::native_enrollment) fn select_instance(
        mut self,
        published: &Path,
    ) -> Result<RestoredConfiguredInput> {
        self.check()?;
        let requested: Result<CurrentInstance> = (|| {
            let mut loan = RestoredMaterialBorrow::frozen(&mut self)?;
            CurrentInstance::capture(&mut loan, published)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        let configuration = requested?;
        checked?;
        Ok(RestoredConfiguredInput {
            input: self,
            configuration,
        })
    }
}

impl RestoredConfiguredInput {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        self.input.check()?;
        let requested: Result<()> = (|| {
            let mut loan = RestoredMaterialBorrow::frozen(&mut self.input)?;
            self.configuration.check(&mut loan)
        })();
        let checked = self.input.check();
        if requested.is_err() || checked.is_err() {
            self.input.owner.refuse();
        }
        requested?;
        checked
    }
}

impl RestoredActiveKeeperInput {
    pub(super) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_artifact()?;
            let requested: Result<()> = (|| {
                let mut loan = RestoredMaterialBorrow::active(
                    &mut self.owner,
                    &self.artifact,
                    &self.installed,
                )?;
                // The borrow holds the actual App/material fields. Configuration
                // is a disjoint retained field, not a caller-supplied replacement.
                self.configuration.check(&mut loan)
            })();
            let checked = self.check_artifact();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }
}

impl RestoredKeeperBirth<'_> {
    pub(crate) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<()> = (|| {
                ensure!(
                    self.app
                        == self
                            .owner
                            .captured
                            .peer
                            .process
                            .receiver
                            .policy
                            .store
                            .scope
                            .app
                            .as_str(),
                    "restore_keeper_app_label_changed"
                );
                let mut loan = RestoredMaterialBorrow::active(
                    &mut *self.owner,
                    self.artifact,
                    self.installed,
                )?;
                self.configuration.check(&mut loan)
            })();
            let checked = self.owner.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }

    pub(crate) fn admit_database(&mut self, connection: &mut rusqlite::Connection) -> Result<()> {
        self.check_database(connection)?;
        let requested = crate::store::admit_restored_snapshot(
            connection,
            self.artifact,
            &self.scope,
            &self.configuration.instance,
            &self.app,
        );
        // Snapshot validation closes its SQL unit before native/file IO.
        let checked = self.check_database(connection);
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        requested?;
        checked
    }
}

// Even a failed syscall/decode takes the independent actual App/original post.
// This accepts only an already-produced Result, never an effect callback.
fn finish<T>(input: &mut RestoredMaterialBorrow<'_>, requested: Result<T>) -> Result<T> {
    let checked = input.check();
    if requested.is_err() || checked.is_err() {
        input.refuse();
    }
    let value = requested?;
    checked?;
    Ok(value)
}

fn identity(file: &std::fs::File, path: &Path, empty: bool) -> Result<Identity> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, path, empty);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{AtFlags, StatxFlags};
        let mask = StatxFlags::TYPE
            | StatxFlags::MODE
            | StatxFlags::UID
            | StatxFlags::GID
            | StatxFlags::NLINK
            | StatxFlags::INO
            | StatxFlags::SIZE
            | StatxFlags::MNT_ID
            | StatxFlags::MTIME
            | StatxFlags::CTIME;
        let flags = if empty {
            AtFlags::EMPTY_PATH
        } else {
            AtFlags::SYMLINK_NOFOLLOW
        };
        let stat = rustix::fs::statx(file, path, flags, mask)?;
        ensure!(
            stat.stx_mask & mask.bits() == mask.bits() && stat.stx_ino > 0 && stat.stx_mnt_id > 0,
            "restore_instance_identity_missing"
        );
        ensure!(
            rustix::fs::FileType::from_raw_mode(u32::from(stat.stx_mode))
                == rustix::fs::FileType::RegularFile
                && stat.stx_nlink == 1
                && stat.stx_mode & 0o022 == 0
                && stat.stx_size <= MAX_BYTES,
            "restore_instance_file_profile"
        );
        Ok(Identity {
            device: (stat.stx_dev_major, stat.stx_dev_minor),
            mount: stat.stx_mnt_id,
            inode: stat.stx_ino,
            user: stat.stx_uid,
            group: stat.stx_gid,
            mode: stat.stx_mode,
            links: stat.stx_nlink,
            bytes: stat.stx_size,
            modified: (stat.stx_mtime.tv_sec, stat.stx_mtime.tv_nsec),
            changed: (stat.stx_ctime.tv_sec, stat.stx_ctime.tv_nsec),
        })
    }
}

impl CurrentInstance {
    fn capture(input: &mut RestoredMaterialBorrow<'_>, published: &Path) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (input, published);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            input.check()?;
            let path = finish(input, published.canonicalize().map_err(anyhow::Error::from))?;
            ensure!(path.is_absolute(), "restore_instance_path_not_absolute");
            let requested: Result<Self> = (|| {
                input.check()?;
                let opened = rustix::fs::open(
                    &path,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(anyhow::Error::from);
                let file = finish(input, opened)?;
                let stamp = finish(input, identity(&file, Path::new(""), true))?;
                let bytes = Self::read(input, &file, &stamp)?;
                let decoded = crate::artifact::Instance::from_bytes(&bytes);
                let instance = finish(input, decoded)?;
                // SAME canonical semantic digest used by InitialStoreMetadata.
                // No artifact/path/binding-derived work precedes this comparison.
                Self::require_signed_instance(input, &instance)?;
                let configuration = Self {
                    file,
                    selector: published.to_owned(),
                    path: path.clone(),
                    identity: stamp,
                    bytes: Digest::new(&bytes[..]),
                    instance,
                };
                configuration.check(input)?;
                Ok(configuration)
            })();
            // Parsing/binding failure cannot skip the published-selector post.
            let selector_post = published
                .canonicalize()
                .map_err(anyhow::Error::from)
                .and_then(|selected| require_selected(&selected, &path));
            let checked = input.check();
            if requested.is_err() || selector_post.is_err() || checked.is_err() {
                input.refuse();
            }
            let configuration = requested?;
            selector_post?;
            checked?;
            Ok(configuration)
        }
    }

    fn read(
        input: &mut RestoredMaterialBorrow<'_>,
        file: &std::fs::File,
        expected: &Identity,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (input, file, expected);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut bytes = zeroize::Zeroizing::new(vec![0; usize::try_from(expected.bytes)?]);
            let mut offset = 0;
            while offset < bytes.len() {
                input.check()?;
                let end = bytes.len().min(
                    offset
                        .checked_add(CHUNK)
                        .context("restore_instance_read_bound")?,
                );
                let requested = rustix::io::pread(file, &mut bytes[offset..end], offset as u64)
                    .map_err(anyhow::Error::from);
                let read = finish(input, requested)?;
                ensure!(
                    read > 0 && read <= end - offset,
                    "restore_instance_read_progress"
                );
                offset += read;
            }
            input.check()?;
            let mut extra = [0u8; 1];
            let requested =
                rustix::io::pread(file, &mut extra, offset as u64).map_err(anyhow::Error::from);
            ensure!(finish(input, requested)? == 0, "restore_instance_grew");
            let actual = finish(input, identity(file, Path::new(""), true))?;
            ensure!(actual == *expected, "restore_instance_changed_during_read");
            Ok(bytes)
        }
    }

    fn require_signed_instance(
        input: &RestoredMaterialBorrow<'_>,
        instance: &crate::artifact::Instance,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (input, instance);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let process = match &input.owner.owner {
                RestoredObservationOwner::Frozen(owner) => &owner.owner.captured.peer.process,
                RestoredObservationOwner::Active(owner) => &owner.captured.peer.process,
            };
            require_desired(
                instance,
                &process.authorization.statement.data.desired_instance,
            )?;
            let policy = &process.receiver.policy;
            let app = policy.bootstrap.scope.app.as_str();
            ensure!(
                instance.native_bootstrap_for(app)? == Some(&policy.bootstrap)
                    && instance.scope(app)?
                        == format!(
                            "{}/{}/{}",
                            policy.store.scope.installation.as_str(),
                            policy.store.scope.environment.as_str(),
                            app
                        ),
                "restore_instance_native_selection_changed"
            );
            let control = instance
                .control
                .as_ref()
                .context("restore_instance_epoch_catalog_missing")?;
            let mut stores = control
                .security_epochs
                .values()
                .filter(|store| store.scope.app.as_str() == app);
            ensure!(
                stores.next() == Some(&policy.store) && stores.next().is_none(),
                "restore_instance_epoch_selection_changed"
            );
            let binding = instance
                .apps
                .get(app)
                .context("restore_instance_app_missing")?;
            ensure!(
                binding.artifact
                    == format!("artifacts/{}", day2_assets::hash_part(input.artifact.id())?),
                "restore_instance_artifact_reference_changed"
            );
            crate::store::validate_artifact_binding(instance, app, input.artifact)
        }
    }

    fn check(&self, input: &mut RestoredMaterialBorrow<'_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = input;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            input.check()?;
            let requested: Result<()> = (|| {
                let selected = finish(
                    input,
                    self.selector.canonicalize().map_err(anyhow::Error::from),
                )?;
                require_selected(&selected, &self.path)?;
                let held = finish(input, identity(&self.file, Path::new(""), true))?;
                let named = finish(input, identity(&self.file, &self.path, false))?;
                ensure!(
                    held == self.identity && named == self.identity,
                    "restore_instance_held_file_changed"
                );
                let bytes = Self::read(input, &self.file, &self.identity)?;
                ensure!(
                    Digest::new(&bytes[..]) == self.bytes,
                    "restore_instance_bytes_changed"
                );
                Self::require_signed_instance(input, &self.instance)
            })();
            // The selector can switch while held immutable bytes stay equal.
            // This independent post still executes on every primary error.
            let selector_post = self
                .selector
                .canonicalize()
                .map_err(anyhow::Error::from)
                .and_then(|selected| require_selected(&selected, &self.path));
            let checked = input.check();
            if requested.is_err() || selector_post.is_err() || checked.is_err() {
                input.refuse();
            }
            requested?;
            selector_post?;
            checked
        }
    }
}

impl RestoredRuntimeBirth<'_> {
    /// All checks use the same existing first connection and old originals.
    /// In particular, no SQL unit may remain open across the provider read.
    pub(crate) fn check(&mut self) -> Result<()> {
        self.keeper.check()
    }

    pub(crate) fn refuse(&mut self) {
        self.keeper.keeper.refuse();
        self.keeper.input.owner.refuse();
    }

    pub(crate) fn reobserve(&mut self) -> Result<()> {
        self.check()?;
        let requested = self.keeper.input.owner.reobserve_writer();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    /// Admitted inputs DATA only. This supplies no keeper, key, stage, clock,
    /// SQL owner or initialization permission. The fixed store factory still
    /// requires THIS opaque live borrow and its independent full post.
    pub(crate) fn runtime_inputs_data(
        &mut self,
    ) -> Result<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
        String,
        crate::artifact::LoadedArtifact,
        crate::artifact::Instance,
    )> {
        self.check()?;
        let requested: Result<_> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (db, scope, app) = self.keeper.input.keeper_birth_data()?;
                let configuration = &self.keeper.input.configuration;
                Ok((
                    configuration.path.clone(),
                    configuration.selector.clone(),
                    db,
                    app,
                    scope,
                    self.keeper.input.artifact.clone(),
                    configuration.instance.clone(),
                ))
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn desired_instance_uses_authenticated_semantic_digest_and_refuses_another_binding()
    -> Result<()> {
        let bytes=br#"{"installation":"test","environment":"test","apps":{"app":{"artifact":"/artifact","readers":[],"writers":[]}}}"#;
        let instance = crate::artifact::Instance::from_bytes(bytes)?;
        let expected = InstanceDigest::of(&instance)?;
        require_desired(&instance, &expected)?;
        // Semantic hashing canonicalizes the decoded Instance. Canonical file
        // bytes may equal it; valid formatting differences must not select a
        // raw-byte file digest as the authenticated semantic binding.
        let canonical = serde_json::to_vec(&instance)?;
        assert_eq!(expected, InstanceDigest::new(&canonical));
        let mut formatted = b" \n".to_vec();
        formatted.extend_from_slice(&canonical);
        formatted.push(b'\n');
        let same = crate::artifact::Instance::from_bytes(&formatted)?;
        require_desired(&same, &expected)?;
        assert!(require_desired(&same, &InstanceDigest::new(&formatted)).is_err());
        let mut changed: serde_json::Value = serde_json::from_slice(bytes)?;
        changed["apps"]["app"]["readers"] = serde_json::json!(["other@example.com"]);
        let other = crate::artifact::Instance::from_bytes(&serde_json::to_vec(&changed)?)?;
        assert!(require_desired(&other, &expected).is_err());
        require_desired(&instance, &expected)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_selector_switch_refuses_even_while_original_open_file_is_unchanged() -> Result<()>
    {
        use std::io::Read;
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("old.json");
        let new = temp.path().join("new.json");
        std::fs::write(&old, b"retained")?;
        std::fs::write(&new, b"replacement")?;
        let selector = temp.path().join("Instance.json");
        symlink(&old, &selector)?;
        let pinned = selector.canonicalize()?;
        let mut held = std::fs::File::open(&pinned)?;
        require_selected(&selector.canonicalize()?, &pinned)?;
        std::fs::remove_file(&selector)?;
        symlink(&new, &selector)?;
        assert!(require_selected(&selector.canonicalize()?, &pinned).is_err());
        let mut bytes = String::new();
        held.read_to_string(&mut bytes)?;
        assert_eq!(bytes, "retained");
        std::fs::remove_file(&selector)?;
        assert!(selector.canonicalize().is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_config_identity_detects_same_bytes_path_replacement_and_hardlink() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("Instance.json");
        std::fs::write(&path, b"same bytes")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let held = std::fs::File::open(&path)?;
        let before = identity(&held, Path::new(""), true)?;
        let replacement = temp.path().join("next.json");
        std::fs::write(&replacement, b"same bytes")?;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&replacement, &path)?;
        assert!(identity(&held, &path, false)? != before);
        std::fs::hard_link(&path, temp.path().join("alias.json"))?;
        assert!(identity(&held, &path, false).is_err());
        Ok(())
    }

    fn method(name: &str) -> syn::ImplItemFn {
        syn::parse_file(include_str!("configuration.rs"))
            .unwrap()
            .items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(block) = item else {
                    return None;
                };
                block.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn normalized(source: &str) -> String {
        separators(syn::parse_file(source).unwrap().into_token_stream()).to_string()
    }

    fn canonical(source: &str) -> String {
        fn without_commas(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), without_commas(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        without_commas(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn separators(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        stream
            .into_iter()
            .map(|token| match token {
                proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => {
                    proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                        ',',
                        proc_macro2::Spacing::Alone,
                    ))
                }
                proc_macro2::TokenTree::Group(group) => proc_macro2::TokenTree::Group(
                    proc_macro2::Group::new(group.delimiter(), separators(group.stream())),
                ),
                other => other,
            })
            .collect()
    }

    fn tokens(source: &str) -> String {
        // Match syntax emitted by syn for the actual production AST, including
        // its separate question-mark/semicolon punctuation. Raw token spelling
        // may instead make `?;` joint, despite representing the same statement.
        let block = syn::parse_str::<syn::Block>(&format!("{{{source}}}")).unwrap();
        let mut stream = proc_macro2::TokenStream::new();
        for statement in block.stmts {
            statement.to_tokens(&mut stream);
        }
        separators(stream).to_string()
    }

    #[test]
    fn mutation_targets_normalize_joint_comma_reference_spacing_without_dropping_arguments() {
        let compact = tokens("Self::require_signed_instance(input,&instance)?;");
        let spaced = tokens("Self::require_signed_instance(input, &instance)?;");
        assert_eq!(compact, spaced);
        assert_eq!(
            compact,
            tokens("Self::require_signed_instance(input, &instance) ? ;")
        );
        assert_ne!(
            compact,
            tokens("Self::require_signed_instance(other, &instance)?;")
        );
        assert_ne!(
            compact,
            tokens("Self::require_signed_instance(input, &other)?;")
        );
    }

    fn ordered(source: &str, parts: &[&str]) -> bool {
        let mut rest = source;
        for part in parts {
            let part = part.replace(" ,", "");
            let Some(position) = rest.find(&part) else {
                return false;
            };
            rest = &rest[position + part.len()..];
        }
        true
    }

    fn source_is_bound(source: &str) -> bool {
        let source = canonical(&normalized(source));
        ordered(
            &source,
            &[
                "let instance = finish (input , decoded) ?",
                "Self :: require_signed_instance (input , & instance) ?",
                "let configuration = Self",
            ],
        ) && ordered(
            &source,
            &[
                "require_desired (instance , & process . authorization . statement . data . desired_instance) ?",
                "instance . native_bootstrap_for",
                "validate_artifact_binding",
            ],
        ) && ordered(
            &source,
            &[
                "let requested : Result < () > = (| |",
                "let selector_post = self . selector . canonicalize",
                "let checked = input . check ()",
                "requested ? ; selector_post ? ; checked",
            ],
        ) && !source.contains("InitialStoreMetadata :: load")
            && !source.contains("NativeAcquisition :: begin")
    }

    #[test]
    fn actual_configuration_factory_binds_signed_digest_before_selection_and_rechecks_selector_on_error()
     {
        let source = normalized(
            include_str!("configuration.rs")
                .split("#[cfg(test)]")
                .next()
                .unwrap(),
        );
        assert!(source_is_bound(&source));
        for (before, after) in [
            (
                "Self::require_signed_instance(input,&instance)?;",
                "let _unchecked=();",
            ),
            (
                "&process.authorization.statement.data.desired_instance",
                "&caller_digest",
            ),
            (
                "let selector_post=self.selector.canonicalize().map_err(anyhow::Error::from).and_then(|selected|require_selected(&selected,&self.path));",
                "let selector_post=caller_selector.canonicalize().map_err(anyhow::Error::from).and_then(|selected|require_selected(&selected,&self.path));",
            ),
        ] {
            let before = tokens(before);
            let after = tokens(after);
            assert_eq!(
                source.matches(&before).count(),
                1,
                "mutation target {before}"
            );
            assert!(
                !source_is_bound(&source.replacen(&before, &after, 1)),
                "accepted mutation {before}"
            );
        }
        // Both capture and later validation propagate their selector posts.
        // Select the nominal production check method before deleting its post,
        // rather than matching an expression shared by the whole module.
        let file = syn::parse_file(include_str!("configuration.rs")).unwrap();
        let check=file.items.into_iter().find_map(|item| {
            let syn::Item::Impl(owner)=item else{return None};
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident("CurrentInstance")){return None;}
            owner.items.into_iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident=="check"=>Some(method),_=>None,
            })
        }).unwrap();
        let check = separators(check.into_token_stream()).to_string();
        assert_eq!(source.matches(&check).count(), 1);
        let before = tokens("selector_post?");
        assert_eq!(check.matches(&before).count(), 1);
        let omitted = check.replacen(&before, &tokens("()"), 1);
        assert!(!source_is_bound(&source.replacen(&check, &omitted, 1)));
        // The actual outer factory, not a synthetic test helper, retains the
        // independent original post before returning the constructed owner.
        let select = canonical(&method("select_instance").into_token_stream().to_string());
        assert!(ordered(
            &select,
            &[
                "CurrentInstance :: capture",
                "let checked = self . check ()",
                "self . owner . refuse ()",
                "let configuration = requested ?",
                "checked ?",
                "RestoredConfiguredInput"
            ]
        ));
    }

    fn active_check() -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("configuration.rs")).unwrap();
        file.items.into_iter().find_map(|item| {
            let syn::Item::Impl(owner)=item else{return None};
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident("RestoredActiveKeeperInput")){return None;}
            owner.items.into_iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident=="check"=>Some(method),_=>None,
            })
        }).unwrap()
    }

    fn active_loan_is_exact(method: &syn::ImplItemFn) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls {
            count: usize,
            exact: bool,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.len()==2
                    && path.path.segments[0].ident=="RestoredMaterialBorrow" && path.path.segments[1].ident=="active")
                {
                    self.count += 1;
                    self.exact = call.args.len() == 3
                        && call
                            .args
                            .iter()
                            .zip(["&mut self.owner", "&self.artifact", "&self.installed"])
                            .all(|(actual, expected)| {
                                canonical(&actual.to_token_stream().to_string())
                                    == canonical(expected)
                            });
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(method);
        let body = canonical(&method.block.to_token_stream().to_string());
        calls.count == 1
            && calls.exact
            && ordered(
                &body,
                &[
                    "self . check_artifact () ?",
                    "let requested : Result < () > =",
                    "self . configuration . check (& mut loan)",
                    "let checked = self . check_artifact ()",
                    "self . owner . refuse ()",
                    "requested ? ; checked",
                ],
            )
    }

    #[test]
    fn actual_active_configuration_borrow_joins_same_owner_artifact_inventory_and_posts_after_error()
     {
        let actual = active_check();
        assert!(active_loan_is_exact(&actual));
        let source = actual.to_token_stream().to_string();
        for (before, after) in [
            ("&mut self.owner", "&mut other.owner"),
            ("&self.artifact", "&other.artifact"),
            ("&self.installed", "&other.installed"),
            (
                "let checked=self.check_artifact();",
                "let checked:Result<()>=Ok(());",
            ),
            ("requested?;checked", "checked?;requested"),
        ] {
            let before = tokens(before);
            assert_eq!(source.matches(&before).count(), 1);
            let changed = source.replacen(&before, &tokens(after), 1);
            let method = syn::parse_str::<syn::ImplItemFn>(&changed).unwrap();
            assert!(!active_loan_is_exact(&method));
        }
    }
}
