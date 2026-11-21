//! Native, operator-only measurement of the fixed app-image composition.
//! Roc owns capture -> layer proof -> artifact proof -> receipt. No compiler,
//! registry push, app command, Dockerfile override or live deployment runs here.
use super::*;
use day2::runtime_pair::Composition;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const MAX_LAYER: u64 = 512 << 20;
const MAX_ARCHIVE: u64 = 3 << 30;
const ARTIFACT_PARENTS: [&str; 3] = ["srv", "srv/day2", "srv/day2/artifacts"];
const PARENT_WHITEOUTS: [&str; 6] = [
    ".wh.srv",
    ".wh..wh..opq",
    "srv/.wh.day2",
    "srv/.wh..wh..opq",
    "srv/day2/.wh.artifacts",
    "srv/day2/.wh..wh..opq",
];
const ACTIONS: &[&str] = &[
    "runtime-image-capture",
    "runtime-image-layers",
    "runtime-image-artifact",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FileIdentity {
    digest: String,
    bytes: u64,
    mode: u32,
}

#[derive(PartialEq, Eq)]
struct DirectoryMetadata {
    uid: u64,
    gid: u64,
    mode: u32,
}

fn directory_metadata(entry: &tar::Entry<'_, impl Read>) -> Result<DirectoryMetadata> {
    let header = entry.header();
    ensure!(
        header.entry_type().is_dir() && entry.size() == 0,
        "artifact parent must be a real directory"
    );
    Ok(DirectoryMetadata {
        uid: header.uid()?,
        gid: header.gid()?,
        mode: header.mode()?,
    })
}

fn plain_metadata(entry: &mut tar::Entry<'_, impl Read>) -> Result<()> {
    if let Some(extensions) = entry.pax_extensions()? {
        for extension in extensions {
            let extension = extension?;
            ensure!(
                [b"path".as_slice(), b"size", b"mtime", b"atime", b"ctime"]
                    .contains(&extension.key_bytes()),
                "artifact layer extended permissions or attributes"
            );
        }
    }
    Ok(())
}

fn base_directories(
    input: &mut dyn Read,
    parents: &mut BTreeMap<String, DirectoryMetadata>,
) -> Result<()> {
    let mut archive = tar::Archive::new(input.take(MAX_LAYER + 1));
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path_bytes();
        let path = Path::new(std::str::from_utf8(&path)?.trim_start_matches("./"));
        ensure!(
            !PARENT_WHITEOUTS.iter().any(|name| path == Path::new(name)),
            "base artifact parent has ambiguous overlay metadata"
        );
        if let Some(&name) = ARTIFACT_PARENTS.iter().find(|name| path == Path::new(name)) {
            ensure!(seen.insert(name), "duplicate base artifact parent");
            plain_metadata(&mut entry)?;
            parents.insert(name.into(), directory_metadata(&entry)?);
        }
    }
    let mut remainder = archive.into_inner();
    zero_padding(&mut remainder)?;
    ensure!(remainder.limit() > 0, "base layer exceeds byte budget");
    Ok(())
}

fn hash_reader(input: &mut dyn Read, limit: u64) -> Result<(String, u64)> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut total = 0u64;
    let mut buffer = [0; 65_536];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total = total
            .checked_add(size as u64)
            .context("image byte budget")?;
        ensure!(total <= limit, "runtime image byte budget");
        hash.update(&buffer[..size]);
    }
    let hex = hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((format!("sha256:{hex}"), total))
}

fn relative(name: &str) -> Result<&str> {
    let name = name.strip_suffix('/').unwrap_or(name);
    ensure!(
        !name.is_empty()
            && name.len() <= 4096
            && name.split('/').all(|part| !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with(".wh."))
            && !name.contains('\\')
            && !name.chars().any(char::is_control),
        "image archive path invalid"
    );
    Ok(name)
}

fn member<T>(
    archive: &Path,
    name: &str,
    consume: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    let file = fs::File::open(archive)?;
    ensure!(
        file.metadata()?.len() <= MAX_ARCHIVE,
        "saved image byte budget"
    );
    let mut archive = tar::Archive::new(file);
    let mut callback = Some(consume);
    let mut result = None;
    let mut seen = BTreeSet::new();
    // Skip unrelated blob bodies by seeking, rather than rereading the shared
    // runtime for every metadata or layer lookup.
    for entry in archive.entries_with_seek()? {
        let mut entry = entry?;
        let path = entry.path_bytes();
        let path = std::str::from_utf8(&path)?;
        let path = relative(path)?;
        ensure!(
            seen.len() < 4096 && seen.insert(path.to_owned()),
            "duplicate or excessive saved image members"
        );
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "saved image link or special file"
        );
        if path == name {
            ensure!(
                kind.is_file() && entry.size() <= MAX_ARCHIVE,
                "saved image member type or budget"
            );
            result = Some(callback.take().context("duplicate saved image member")?(
                &mut entry,
            )?);
        }
    }
    result.context("saved image member missing")
}

fn json_member(archive: &Path, name: &str) -> Result<Value> {
    member(archive, name, |entry| {
        let mut bytes = Vec::new();
        entry.take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "saved image metadata budget");
        day2::json::decode(&bytes)
    })
}

fn layer<T>(
    archive: &Path,
    name: &str,
    consume: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    member(archive, name, |entry| {
        let mut input = std::io::BufReader::new(entry);
        if input.fill_buf()?.starts_with(&[0x1f, 0x8b]) {
            consume(&mut flate2::read::MultiGzDecoder::new(input))
        } else {
            consume(&mut input)
        }
    })
}

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    platform: Option<Platform>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    architecture: String,
    os: String,
    variant: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    schema_version: u32,
    media_type: String,
    manifests: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageManifest {
    schema_version: u32,
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

fn blob_path(id: &str) -> Result<String> {
    Ok(format!("blobs/sha256/{}", day2_assets::hash_part(id)?))
}

fn blob_json(archive: &Path, id: &str, size: Option<u64>) -> Result<Value> {
    member(archive, &blob_path(id)?, |input| {
        let mut bytes = Vec::new();
        input.take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1_048_576
                && size.is_none_or(|size| size == bytes.len() as u64)
                && digest(&bytes) == id,
            "OCI metadata digest or size changed"
        );
        day2::json::decode(&bytes)
    })
}

fn image_manifest(
    archive: &Path,
    image: &str,
    architecture: &str,
) -> Result<(ImageManifest, Value, String)> {
    ensure!(
        json_member(archive, "oci-layout")? == json!({"imageLayoutVersion":"1.0.0"}),
        "OCI image layout required"
    );
    let id = image
        .rsplit_once('@')
        .context("immutable registry image required")?
        .1;
    let mut value = blob_json(archive, id, None)?;
    let mut selected_id = id.to_owned();
    if value["mediaType"] == OCI_INDEX {
        let index: Index = serde_json::from_value(value)?;
        ensure!(
            index.schema_version == 2
                && index.media_type == OCI_INDEX
                && !index.manifests.is_empty()
                && index.manifests.len() <= 16
                && index.annotations.len() <= 64,
            "bounded OCI index required"
        );
        let mut selected = None;
        for descriptor in index.manifests {
            day2_assets::hash_part(&descriptor.digest)?;
            ensure!(
                descriptor.size > 0
                    && descriptor.size <= 1_048_576
                    && descriptor.media_type == OCI_MANIFEST
                    && descriptor.annotations.len() <= 64,
                "OCI index descriptor invalid"
            );
            let platform = descriptor
                .platform
                .as_ref()
                .context("explicit OCI platform required")?;
            if platform.os == "linux" && platform.architecture == architecture {
                ensure!(
                    selected.is_none()
                        && (platform.variant.is_none()
                            || (architecture == "arm64"
                                && platform.variant.as_deref() == Some("v8"))),
                    "ambiguous or unsupported OCI platform"
                );
                selected = Some(descriptor);
            } else {
                // BuildKit's non-runnable attestation attachment is content-addressed
                // metadata, never runtime qualification or another admitted platform.
                ensure!(
                    platform.os == "unknown"
                        && platform.architecture == "unknown"
                        && platform.variant.is_none()
                        && descriptor
                            .annotations
                            .get("vnd.docker.reference.type")
                            .map(String::as_str)
                            == Some("attestation-manifest"),
                    "unqualified OCI platform refused"
                );
            }
        }
        let selected = selected.context("native OCI platform missing")?;
        value = blob_json(archive, &selected.digest, Some(selected.size))?;
        selected_id = selected.digest;
    }
    let manifest: ImageManifest = serde_json::from_value(value)?;
    ensure!(
        manifest.schema_version == 2
            && manifest.media_type == OCI_MANIFEST
            && manifest.config.media_type == OCI_CONFIG
            && manifest.config.platform.is_none()
            && manifest.config.size > 0
            && manifest.config.size <= 1_048_576
            && !manifest.layers.is_empty()
            && manifest.layers.len() <= 64
            && manifest.annotations.len() <= 64,
        "closed OCI runtime manifest required"
    );
    for descriptor in &manifest.layers {
        day2_assets::hash_part(&descriptor.digest)?;
        ensure!(
            [OCI_LAYER, OCI_GZIP].contains(&descriptor.media_type.as_str())
                && descriptor.platform.is_none()
                && descriptor.size > 0
                && descriptor.size <= MAX_LAYER
                && descriptor.annotations.len() <= 64,
            "OCI runtime layer invalid"
        );
    }
    let config = blob_json(archive, &manifest.config.digest, Some(manifest.config.size))?;
    ensure!(
        config["os"] == "linux" && config["architecture"] == architecture,
        "native OCI configuration required"
    );
    Ok((manifest, config, selected_id))
}

/// The artifact layer may not change any execution setting, base layer or
/// unknown configuration field. Only build timestamps/history and our one
/// artifact label differ. Unknown equal fields remain bound to the base.
fn composition(
    base: &Value,
    app: &Value,
    artifact: &str,
    architecture: &str,
) -> Result<Vec<String>> {
    ensure!(
        base["os"] == "linux" && base["architecture"] == architecture,
        "native image architecture required"
    );
    ensure!(
        base["config"].is_object() && app["config"].is_object(),
        "image execution configuration required"
    );
    let root = |value: &Value| -> Result<Vec<String>> {
        let object = value["rootfs"]
            .as_object()
            .context("image rootfs required")?;
        ensure!(
            object.len() == 2 && object.get("type") == Some(&json!("layers")),
            "closed image rootfs required"
        );
        let ids: Vec<String> =
            serde_json::from_value(object.get("diff_ids").context("image diff ids")?.clone())?;
        ensure!(!ids.is_empty() && ids.len() <= 64, "image layer budget");
        for id in &ids {
            day2_assets::hash_part(id)?;
        }
        Ok(ids)
    };
    let base_layers = root(base)?;
    let app_layers = root(app)?;
    ensure!(
        app_layers.len() == base_layers.len() + 1 && app_layers.starts_with(&base_layers),
        "app image must add exactly one artifact layer"
    );
    let mut expected = base.clone();
    let mut actual = app.clone();
    let label = "dev.day2.artifact-id";
    let mut labels = match &expected["config"]["Labels"] {
        Value::Null => serde_json::Map::new(),
        Value::Object(labels) => labels.clone(),
        _ => bail!("image labels invalid"),
    };
    ensure!(
        !labels.contains_key(label),
        "base image has an app artifact label"
    );
    labels.insert(label.into(), json!(day2_assets::hash_part(artifact)?));
    expected["config"]["Labels"] = Value::Object(labels);
    for value in [&mut expected, &mut actual] {
        let object = value
            .as_object_mut()
            .context("image configuration object")?;
        for field in ["rootfs", "history", "created"] {
            object.remove(field);
        }
    }
    ensure!(
        expected == actual,
        "app image changed runtime execution configuration"
    );
    Ok(app_layers)
}

fn files(root: &Path) -> Result<BTreeMap<String, FileIdentity>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![(root.to_owned(), String::new(), 0)];
    let mut total = 0;
    let mut entries = 0;
    while let Some((directory, prefix, depth)) = pending.pop() {
        ensure!(
            depth <= 32 && fs::symlink_metadata(&directory)?.is_dir(),
            "bounded artifact directory required"
        );
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            entries += 1;
            ensure!(entries <= 8192, "artifact entry budget");
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("artifact path encoding"))?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            relative(&path)?;
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                metadata.permissions().mode() & 0o7022 == 0,
                "artifact has unsafe permissions"
            );
            if metadata.is_dir() {
                pending.push((entry.path(), path, depth + 1));
            } else {
                ensure!(
                    metadata.is_file()
                        && [0o444, 0o555].contains(&(metadata.permissions().mode() & 0o777))
                        && (path != "worker" || metadata.permissions().mode() & 0o777 == 0o555),
                    "read-only regular artifact file required"
                );
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                    )
                    .open(entry.path())?;
                ensure!(
                    file.metadata()?.is_file(),
                    "regular artifact descriptor required"
                );
                let (digest, bytes) = hash_reader(&mut file, MAX_LAYER)?;
                total += bytes;
                ensure!(total <= MAX_LAYER, "artifact byte budget");
                result.insert(
                    path,
                    FileIdentity {
                        digest,
                        bytes,
                        mode: metadata.permissions().mode() & 0o777,
                    },
                );
            }
        }
    }
    ensure!(!result.is_empty(), "artifact files required");
    Ok(result)
}

fn artifact_layer(
    input: &mut dyn Read,
    artifact: &str,
    expected: &BTreeMap<String, FileIdentity>,
    parents: &BTreeMap<String, DirectoryMetadata>,
) -> Result<()> {
    let prefix = format!("srv/day2/artifacts/{}", day2_assets::hash_part(artifact)?);
    let mut seen = BTreeSet::new();
    let mut found = BTreeMap::new();
    let mut archive = tar::Archive::new(input.take(MAX_LAYER + 1));
    for entry in archive.entries()? {
        let mut entry = entry?;
        plain_metadata(&mut entry)?;
        let path = entry.path_bytes();
        let path = relative(std::str::from_utf8(&path)?)?.to_owned();
        ensure!(
            seen.len() < 8192 && seen.insert(path.clone()),
            "duplicate or excessive artifact layer paths"
        );
        let header = entry.header();
        if let Some(inherited) = parents.get(&path) {
            ensure!(
                directory_metadata(&entry)? == *inherited,
                "artifact layer changed an inherited directory"
            );
            continue;
        }
        ensure!(
            header.uid()? == 0 && header.gid()? == 0 && header.mode()? & 0o7000 == 0,
            "artifact layer owner or special mode changed"
        );
        let kind = header.entry_type();
        let mode = header.mode()?;
        if kind.is_dir() {
            ensure!(
                entry.size() == 0 && matches!(mode, 0o755 | 0o555),
                "artifact directory permissions changed"
            );
            ensure!(
                prefix == path
                    || prefix.starts_with(&format!("{path}/"))
                    || (path.starts_with(&format!("{prefix}/"))
                        && expected.keys().any(
                            |file| format!("{prefix}/{file}").starts_with(&format!("{path}/"))
                        )),
                "artifact layer changed a runtime directory"
            );
        } else {
            ensure!(kind.is_file(), "artifact layer link or special file");
            let name = path
                .strip_prefix(&format!("{prefix}/"))
                .context("artifact layer changed a runtime path")?;
            let expected = expected
                .get(name)
                .context("unexpected artifact layer file")?;
            ensure!(
                mode & 0o777 == expected.mode && entry.size() == expected.bytes,
                "artifact layer mode or size changed"
            );
            let (digest, bytes) = hash_reader(&mut entry, MAX_LAYER)?;
            let identity = FileIdentity {
                digest,
                bytes,
                mode: mode & 0o777,
            };
            ensure!(&identity == expected, "artifact layer bytes changed");
            found.insert(name.to_owned(), identity);
        }
    }
    ensure!(found == *expected, "artifact layer omitted a file");
    // Some unpackers accept concatenated archives. Never approve a good first
    // archive while ignoring a second archive or nonzero trailing payload.
    zero_padding(&mut archive.into_inner())
}

fn zero_padding(remainder: &mut dyn Read) -> Result<()> {
    let mut buffer = [0; 65_536];
    loop {
        let size = remainder.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        ensure!(
            buffer[..size].iter().all(|byte| *byte == 0),
            "image layer has trailing data"
        );
    }
    Ok(())
}

struct Session {
    base: String,
    qualified: String,
    app: String,
    artifact: PathBuf,
    output: PathBuf,
    base_id: Option<String>,
    app_id: Option<String>,
    base_config: Option<String>,
    base_manifest: Option<String>,
    app_config: Option<String>,
    app_manifest: Option<String>,
    artifact_id: Option<String>,
    tree: Option<BTreeMap<String, FileIdentity>>,
    app_layer: Option<(String, String)>,
    base_parents: BTreeMap<String, DirectoryMetadata>,
    completed: BTreeSet<String>,
}

impl Session {
    fn inspect(&self, image: &str, name: &str) -> Result<String> {
        linux_qualification::logged(
            &self.output,
            name,
            Command::new("docker").args(["image", "inspect", image]),
            60,
        )?;
        let bytes = fs::read(self.output.join(format!("{name}.log")))?;
        let values: Vec<Value> = day2::json::decode(&bytes)?;
        ensure!(
            values.len() == 1
                && values[0]["RepoDigests"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == image)),
            "exact registry image resolution required"
        );
        let id = values[0]["Id"]
            .as_str()
            .context("native Docker image identity")?;
        day2_assets::hash_part(id)?;
        Ok(id.into())
    }

    fn effect(&mut self, request: &day2::automation::Request) -> Result<Value> {
        let input: Value = request.decode()?;
        let action = request.action.as_str();
        ensure!(
            input == json!({}) && !self.completed.contains(action),
            "closed image verifier effect required"
        );
        ensure!(
            ACTIONS.get(self.completed.len()).copied() == Some(action)
                || (self.completed.len() == ACTIONS.len() && action == "runtime-image-receipt"),
            "image verifier step order changed"
        );
        match action {
            "runtime-image-capture" => {
                linux_qualification::native_platform()?;
                self.base_id = Some(self.inspect(&self.base, "base-inspect")?);
                self.app_id = Some(self.inspect(&self.app, "app-inspect")?);
                ensure!(
                    self.base_id != self.app_id,
                    "composed app configuration required"
                );
                self.artifact_id = Some(
                    linux_qualification::inspect_artifact(&self.artifact)?["artifact"]
                        .as_str()
                        .context("artifact identity")?
                        .into(),
                );
                self.tree = Some(files(&self.artifact)?);
            }
            "runtime-image-layers" => {
                let archive = self.output.join("images.tar");
                linux_qualification::logged_bounded(
                    &self.output,
                    "image-save",
                    Command::new("docker")
                        .args(["image", "save", "--output"])
                        .arg(&archive)
                        .arg(self.base_id.as_ref().context("base capture")?)
                        .arg(self.app_id.as_ref().context("app capture")?),
                    300,
                    Some((&archive, MAX_ARCHIVE)),
                )?;
                fs::set_permissions(&archive, fs::Permissions::from_mode(0o400))?;
                let architecture =
                    if linux_qualification::native_platform()?.architecture == "x86_64" {
                        "amd64"
                    } else {
                        "arm64"
                    };
                let (base_manifest, base, selected_base) =
                    image_manifest(&archive, &self.base, architecture)?;
                let (app_manifest, app, selected_manifest) =
                    image_manifest(&archive, &self.app, architecture)?;
                let ids = composition(
                    &base,
                    &app,
                    self.artifact_id.as_ref().context("artifact capture")?,
                    architecture,
                )?;
                let base_root = self.base.rsplit_once('@').context("base image digest")?.1;
                ensure!(
                    [
                        base_root,
                        selected_base.as_str(),
                        base_manifest.config.digest.as_str()
                    ]
                    .contains(&self.qualified.as_str()),
                    "qualified_image_not_in_base_oci_graph"
                );
                ensure!(
                    app_manifest.layers.len() == ids.len()
                        && base_manifest.layers
                            == app_manifest.layers[..app_manifest.layers.len() - 1],
                    "saved image layers changed"
                );
                // Verify each blob before reading its directory metadata. A
                // configuration witness also binds the uncompressed DiffIDs.
                for (descriptor, diff_id) in base_manifest.layers.iter().zip(ids.iter()) {
                    let path = blob_path(&descriptor.digest)?;
                    ensure!(
                        member(&archive, &path, |input| hash_reader(input, MAX_LAYER))?
                            == (descriptor.digest.clone(), descriptor.size),
                        "base OCI layer changed"
                    );
                    if self.qualified == base_manifest.config.digest {
                        ensure!(
                            layer(&archive, &path, |input| hash_reader(input, MAX_LAYER))?.0
                                == *diff_id,
                            "base OCI diff id changed"
                        );
                    }
                    layer(&archive, &path, |input| {
                        base_directories(input, &mut self.base_parents)
                    })?;
                }
                ensure!(
                    base_manifest.layers.len() + 1 == app_manifest.layers.len(),
                    "one added OCI layer required"
                );
                let added = app_manifest.layers.last().context("app layer")?;
                let path = blob_path(&added.digest)?;
                ensure!(
                    member(&archive, &path, |input| hash_reader(input, MAX_LAYER))?
                        == (added.digest.clone(), added.size),
                    "OCI artifact layer digest or size changed"
                );
                ensure!(
                    layer(&archive, &path, |input| hash_reader(input, MAX_LAYER))?.0
                        == *ids.last().context("app diff id")?,
                    "artifact layer diff id changed"
                );
                self.base_config = Some(base_manifest.config.digest);
                self.base_manifest = Some(selected_base);
                self.app_config = Some(app_manifest.config.digest);
                self.app_manifest = Some(selected_manifest);
                self.app_layer = Some((path, ids.last().context("app diff id")?.clone()));
            }
            "runtime-image-artifact" => {
                layer(
                    &self.output.join("images.tar"),
                    &self.app_layer.as_ref().context("layer proof")?.0,
                    |input| {
                        artifact_layer(
                            input,
                            self.artifact_id.as_ref().context("artifact capture")?,
                            self.tree.as_ref().context("artifact capture")?,
                            &self.base_parents,
                        )
                    },
                )?;
                ensure!(
                    files(&self.artifact)? == *self.tree.as_ref().context("artifact capture")?,
                    "artifact changed during image verification"
                );
            }
            "runtime-image-receipt" => {
                let receipt = Composition {
                    version: 1,
                    base_image: self.base.clone(),
                    base_native: self.qualified.clone(),
                    base_manifest: self.base_manifest.clone().context("native base manifest")?,
                    base_config: self.base_config.clone().context("base OCI configuration")?,
                    image: self.app.clone(),
                    manifest: self.app_manifest.clone().context("native app manifest")?,
                    config: self.app_config.clone().context("app OCI configuration")?,
                    artifact: self.artifact_id.clone().context("artifact capture")?,
                    artifact_tree: digest(&serde_json::to_vec(
                        self.tree.as_ref().context("artifact capture")?,
                    )?),
                    layer: self.app_layer.as_ref().context("layer proof")?.1.clone(),
                    verifier: hash_reader(
                        &mut fs::File::open(std::env::current_exe()?)?,
                        256 << 20,
                    )?
                    .0,
                    recipe: day2::automation::source_digest(),
                };
                receipt.validate()?;
                let bytes = serde_json::to_vec_pretty(&receipt)?;
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(self.output.join("composition.json"))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                fs::remove_file(self.output.join("images.tar"))?;
                self.completed.insert(action.into());
                return Ok(
                    json!({"composition":self.output.join("composition.json"),"digest":digest(&bytes)}),
                );
            }
            _ => bail!("unknown image verification effect"),
        }
        self.completed.insert(action.into());
        Ok(json!({}))
    }
}

pub(super) fn execute(
    root: &Path,
    base: &str,
    qualified: &str,
    app: &str,
    artifact: &Path,
    output: &Path,
) -> Result<()> {
    day2_assets::hash_part(qualified)?;
    // Validate immutable references before creating output or contacting Docker.
    for image in [base, app] {
        let (repository, id) = image
            .rsplit_once('@')
            .context("immutable image reference required")?;
        ensure!(
            !repository.is_empty() && !repository.chars().any(char::is_whitespace),
            "image repository invalid"
        );
        day2_assets::hash_part(id)?;
    }
    ensure!(base != app, "composed app image required");
    fs::create_dir(output)?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    let mut session = Session {
        base: base.into(),
        qualified: qualified.into(),
        app: app.into(),
        artifact: artifact.into(),
        output: output.into(),
        base_id: None,
        app_id: None,
        base_config: None,
        base_manifest: None,
        app_config: None,
        app_manifest: None,
        artifact_id: None,
        tree: None,
        app_layer: None,
        base_parents: BTreeMap::new(),
        completed: BTreeSet::new(),
    };
    // Consumer operation: missing/stale compiled tooling refuses without a
    // workflow/compiler fallback or a write to the shared SDK workspace.
    let runner = day2::automation::checked_runner(&root.join("build-out/bin/day2-workflows"))?;
    day2::automation::run(&runner, &["verify-runtime-image"], |request| {
        session.effect(&request)
    })?;
    ensure!(
        session.completed.len() == ACTIONS.len() + 1
            && session.completed.contains("runtime-image-receipt"),
        "incomplete runtime image verification"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configs() -> (Value, Value, String) {
        let artifact = digest(b"artifact");
        let base = json!({"architecture":"arm64","os":"linux","created":"base",
            "config":{"User":"10001:10001","Entrypoint":["/usr/local/bin/day2-serve"],"Env":["LANG=C"],"WorkingDir":"/srv/day2","Labels":null},
            "rootfs":{"type":"layers","diff_ids":[digest(b"base layer")]},"history":[]});
        let mut app = base.clone();
        app["rootfs"]["diff_ids"]
            .as_array_mut()
            .unwrap()
            .push(json!(digest(b"app layer")));
        app["config"]["Labels"] =
            json!({"dev.day2.artifact-id":day2_assets::hash_part(&artifact).unwrap()});
        app["history"] = json!([{"created_by":"fixed COPY"}]);
        app["created"] = json!("app");
        (base, app, artifact)
    }

    #[test]
    fn only_one_artifact_layer_and_one_label_may_change() -> Result<()> {
        let (base, app, artifact) = configs();
        composition(&base, &app, &artifact, "arm64")?;
        assert!(composition(&base, &app, &artifact, "amd64").is_err());
        for (pointer, value) in [
            ("/config/User", json!("0:0")),
            ("/config/Entrypoint", json!(["/tmp/other"])),
            ("/config/Env", json!(["LD_PRELOAD=/tmp/other"])),
            ("/config/WorkingDir", json!("/tmp")),
            ("/config/Cmd", json!(["serve-other"])),
            ("/architecture", json!("amd64")),
            ("/os", json!("windows")),
            ("/rootfs/type", json!("unknown")),
            ("/rootfs/diff_ids/0", json!(digest(b"replaced base"))),
            ("/config/Labels", json!({"dev.day2.artifact-id":"other"})),
        ] {
            let mut changed = app.clone();
            if let Some(target) = changed.pointer_mut(pointer) {
                *target = value;
            } else {
                changed["config"]["Cmd"] = value;
            }
            assert!(
                composition(&base, &changed, &artifact, "arm64").is_err(),
                "{pointer}"
            );
        }
        let mut changed = app.clone();
        changed["rootfs"]["diff_ids"]
            .as_array_mut()
            .unwrap()
            .push(json!(digest(b"extra")));
        assert!(composition(&base, &changed, &artifact, "arm64").is_err());
        let mut changed = app.clone();
        changed["unknown_setting"] = json!(true);
        assert!(composition(&base, &changed, &artifact, "arm64").is_err());
        let mut changed = app;
        changed["config"]["Labels"]["another"] = json!("label");
        assert!(composition(&base, &changed, &artifact, "arm64").is_err());
        Ok(())
    }

    fn tar_file(path: &str, bytes: &[u8], mode: u32, uid: u64, kind: tar::EntryType) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(0);
        header.set_entry_type(kind);
        if kind.is_symlink() || kind.is_hard_link() {
            header.set_link_name("/usr/local/bin/day2-serve").unwrap();
        }
        header.set_cksum();
        archive.append_data(&mut header, path, bytes).unwrap();
        archive.into_inner().unwrap()
    }

    fn expected() -> BTreeMap<String, FileIdentity> {
        BTreeMap::from([(
            "worker".into(),
            FileIdentity {
                digest: digest(b"worker"),
                bytes: 6,
                mode: 0o555,
            },
        )])
    }

    #[test]
    fn artifact_layer_rejects_overwrites_links_whiteouts_modes_and_different_bytes() -> Result<()> {
        let artifact = digest(b"artifact");
        let path = format!(
            "srv/day2/artifacts/{}/worker",
            day2_assets::hash_part(&artifact)?
        );
        let good = tar_file(&path, b"worker", 0o555, 0, tar::EntryType::Regular);
        let parents = BTreeMap::new();
        artifact_layer(&mut good.as_slice(), &artifact, &expected(), &parents)?;
        let mut concatenated = good.clone();
        concatenated.extend(tar_file(
            "usr/local/bin/day2-serve",
            b"replacement",
            0o555,
            0,
            tar::EntryType::Regular,
        ));
        assert!(
            artifact_layer(
                &mut concatenated.as_slice(),
                &artifact,
                &expected(),
                &parents
            )
            .is_err()
        );
        let mut extended = tar::Builder::new(Vec::new());
        extended.append_pax_extensions([(
            "SCHILY.xattr.security.capability",
            b"capability".as_slice(),
        )])?;
        let mut header = tar::Header::new_ustar();
        header.set_size(6);
        header.set_mode(0o555);
        header.set_cksum();
        extended.append_data(&mut header, &path, b"worker".as_slice())?;
        assert!(
            artifact_layer(
                &mut extended.into_inner()?.as_slice(),
                &artifact,
                &expected(),
                &parents,
            )
            .is_err()
        );
        for (path, bytes, mode, uid, kind) in [
            (
                path.as_str(),
                b"change".as_slice(),
                0o555,
                0,
                tar::EntryType::Regular,
            ),
            (
                path.as_str(),
                b"worker".as_slice(),
                0o755,
                0,
                tar::EntryType::Regular,
            ),
            (
                path.as_str(),
                b"worker".as_slice(),
                0o4555,
                0,
                tar::EntryType::Regular,
            ),
            (
                path.as_str(),
                b"worker".as_slice(),
                0o555,
                10001,
                tar::EntryType::Regular,
            ),
            (
                path.as_str(),
                b"".as_slice(),
                0o555,
                0,
                tar::EntryType::Symlink,
            ),
            (
                path.as_str(),
                b"".as_slice(),
                0o555,
                0,
                tar::EntryType::Link,
            ),
            (
                "usr/local/bin/day2-serve",
                b"worker".as_slice(),
                0o555,
                0,
                tar::EntryType::Regular,
            ),
            (
                "srv/day2/.wh.artifacts",
                b"".as_slice(),
                0o444,
                0,
                tar::EntryType::Regular,
            ),
        ] {
            let bad = tar_file(path, bytes, mode, uid, kind);
            assert!(
                artifact_layer(&mut bad.as_slice(), &artifact, &expected(), &parents).is_err(),
                "{path} {mode:o}"
            );
        }
        let empty = tar::Builder::new(Vec::new()).into_inner()?;
        assert!(artifact_layer(&mut empty.as_slice(), &artifact, &expected(), &parents).is_err());
        let mut extra = expected();
        extra.insert(
            "missing".into(),
            FileIdentity {
                digest: digest(b"missing"),
                bytes: 7,
                mode: 0o444,
            },
        );
        assert!(artifact_layer(&mut good.as_slice(), &artifact, &extra, &parents).is_err());
        Ok(())
    }

    #[test]
    fn artifact_layer_can_repeat_but_cannot_change_an_inherited_directory() -> Result<()> {
        let artifact = digest(b"artifact");
        let worker_path = format!(
            "srv/day2/artifacts/{}/worker",
            day2_assets::hash_part(&artifact)?
        );
        let build = |uid, gid, mode, include_worker| -> Result<Vec<u8>> {
            let mut archive = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_uid(uid);
            header.set_gid(gid);
            header.set_mode(mode);
            header.set_size(0);
            archive.append_data(&mut header, "srv/day2", std::io::empty())?;
            if include_worker {
                let mut header = tar::Header::new_ustar();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mode(0o555);
                header.set_size(6);
                archive.append_data(&mut header, &worker_path, b"worker".as_slice())?;
            }
            Ok(archive.into_inner()?)
        };
        let mut parents = BTreeMap::new();
        base_directories(
            &mut build(10001, 10001, 0o755, false)?.as_slice(),
            &mut parents,
        )?;
        for (uid, gid, mode, permitted) in [
            (10001, 10001, 0o755, true),
            (0, 10001, 0o755, false),
            (10001, 0, 0o755, false),
            (10001, 10001, 0o555, false),
        ] {
            let layer = build(uid, gid, mode, true)?;
            assert_eq!(
                artifact_layer(&mut layer.as_slice(), &artifact, &expected(), &parents).is_ok(),
                permitted
            );
        }
        let whiteout = tar_file("srv/.wh.day2", b"", 0o644, 0, tar::EntryType::Regular);
        assert!(base_directories(&mut whiteout.as_slice(), &mut parents).is_err());
        Ok(())
    }

    #[test]
    fn exact_files_are_read_only_and_symlink_free_and_reads_are_bounded() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("worker");
        fs::write(&path, b"worker")?;
        assert!(files(root.path()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
        assert_eq!(files(root.path())?, expected());
        std::os::unix::fs::symlink(&path, root.path().join("alias"))?;
        assert!(files(root.path()).is_err());
        assert!(hash_reader(&mut b"12345".as_slice(), 4).is_err());
        for path in [
            "/absolute",
            "../up",
            "a/../up",
            "a//b",
            "a/./b",
            "a\\b",
            "a\nb",
            "a/.wh.worker",
            "a/.wh..wh..opq",
            "",
        ] {
            assert!(relative(path).is_err(), "{path:?}");
        }
        Ok(())
    }

    fn oci_fixture(root: &Path, fault: &str) -> Result<(PathBuf, String, String)> {
        let (config, _, _) = configs();
        let config_bytes = serde_json::to_vec(&config)?;
        let config_id = digest(&config_bytes);
        let mut manifest = json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,
            "config":{"mediaType":OCI_CONFIG,"digest":config_id,"size":config_bytes.len()},
            "layers":[{"mediaType":OCI_GZIP,"digest":digest(b"base blob"),"size":100}]});
        if fault == "config-size" {
            manifest["config"]["size"] = json!(config_bytes.len() + 1);
        }
        if fault == "config-type" {
            manifest["config"]["mediaType"] = json!("application/vnd.oci.empty.v1+json");
        }
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_id = digest(&manifest_bytes);
        let descriptor = json!({"mediaType":OCI_MANIFEST,"digest":manifest_id,"size":manifest_bytes.len(),"platform":{"os":"linux","architecture":"arm64"}});
        let mut index = json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[descriptor]});
        match fault {
            "duplicate-platform" => index["manifests"].as_array_mut().unwrap().push(descriptor),
            "foreign-platform" => index["manifests"][0]["platform"]["architecture"] = json!("amd64"),
            "manifest-size" => index["manifests"][0]["size"] = json!(manifest_bytes.len()+1),
            "nested-index" => index["manifests"][0]["mediaType"] = json!(OCI_INDEX),
            "attestation" => index["manifests"].as_array_mut().unwrap().push(json!({"mediaType":OCI_MANIFEST,
                "digest":digest(b"unexecuted metadata"),"size":100,"platform":{"os":"unknown","architecture":"unknown"},
                "annotations":{"vnd.docker.reference.type":"attestation-manifest"}})),
            _ => {},
        }
        let index_bytes = serde_json::to_vec(&index)?;
        let root_id = digest(&index_bytes);
        let mut blobs = BTreeMap::from([
            (
                "oci-layout".into(),
                serde_json::to_vec(&json!({"imageLayoutVersion":"1.0.0"}))?,
            ),
            (blob_path(&config_id)?, config_bytes),
            (blob_path(&manifest_id)?, manifest_bytes),
            (blob_path(&root_id)?, index_bytes),
        ]);
        if fault == "config-bytes" {
            blobs.insert(blob_path(&config_id)?, b"{}".to_vec());
        }
        if fault == "missing-layout" {
            blobs.remove("oci-layout");
        }
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in blobs {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o444);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes.as_slice())?;
        }
        let archive = root.join("images.tar");
        fs::write(&archive, builder.into_inner()?)?;
        Ok((archive, format!("registry/runtime@{root_id}"), config_id))
    }

    #[test]
    fn oci_graph_binds_registry_descriptor_native_platform_and_actual_configuration() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        for fault in ["none", "attestation"] {
            let (archive, image, config_id) = oci_fixture(root.path(), fault)?;
            let (manifest, _, _) = image_manifest(&archive, &image, "arm64")?;
            assert_eq!(manifest.config.digest, config_id);
            assert_ne!(image.rsplit_once('@').unwrap().1, config_id);
            assert!(image_manifest(&archive, &image, "amd64").is_err());
            assert!(
                image_manifest(
                    &archive,
                    &format!("registry/runtime@{}", digest(b"wrong root")),
                    "arm64"
                )
                .is_err()
            );
        }
        for fault in [
            "config-size",
            "config-type",
            "config-bytes",
            "manifest-size",
            "duplicate-platform",
            "foreign-platform",
            "nested-index",
            "missing-layout",
        ] {
            let (archive, image, _) = oci_fixture(root.path(), fault)?;
            assert!(
                image_manifest(&archive, &image, "arm64").is_err(),
                "{fault}"
            );
        }
        Ok(())
    }

    #[test]
    fn actual_roc_recipe_has_exact_closed_obligations() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let runner = workflows::build(&root)?;
        let mut actions = Vec::new();
        day2::automation::run(&runner, &["verify-runtime-image"], |request| {
            assert_eq!(request.decode::<Value>()?, json!({}));
            actions.push(request.action.clone());
            Ok(json!({}))
        })?;
        assert_eq!(
            actions,
            ACTIONS
                .iter()
                .copied()
                .chain(["runtime-image-receipt"])
                .collect::<Vec<_>>()
        );
        Ok(())
    }
}
