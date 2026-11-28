//! Self-hosted Chrome extensions. The instance pins at most one Manifest V3
//! extension per app (day2.json's `extension`), whose source is the app's
//! `.chrome-extension/`. The Platform packs it as a deterministic CRX3 with the
//! extension's signing key, injecting the manifest's `key` and `update_url`, and
//! publishes it through `public-downloads/` with a Chrome update manifest. A
//! person signs each release; CI verifies it against the instance's pin without
//! any private key.
//!
//! These functions are pure. Callers read the instance's pin, the source tree,
//! existing downloads and signing key, and supply randomness for RSA blinding.
use crate::public_downloads;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    digest::{SHA256, digest},
    rand::SecureRandom,
    rsa,
    signature::{self, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// App-root directory holding the extension source and local overlay. The app
/// build never captures it; only signed release bytes enter the artifact.
pub const DIRECTORY: &str = ".chrome-extension";
/// The unpacked extension that every release packs, without the manifest
/// fields the Platform derives.
pub const SOURCE_DIRECTORY: &str = "src";
/// Optional files that replace release sources only in a local unpacked build.
pub const LOCAL_DIRECTORY: &str = "local";
pub const UPDATE_MANIFEST: &str = "updates.xml";
pub const MAX_FILES: usize = 512;
/// A packed release is a single public download, so its sources share that budget.
pub const MAX_SOURCE_BYTES: u64 = public_downloads::MAX_FILE_BYTES;
pub const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_PATH_BYTES: usize = 240;
/// Manifest fields every release carries and no source declares: the signing
/// key's public key, which unpacked builds need to keep the release identity,
/// and the instance's update URL.
const INJECTED: [&str; 2] = ["key", "update_url"];
const SIGNED_DATA_PREFIX: &[u8] = b"CRX3 SignedData\x00";
const RSA_ALGORITHM: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// Relative path to file bytes, using `/` separators.
pub type Files = BTreeMap<String, Vec<u8>>;

/// The extension an instance pins for one app. cli/InstanceSpec.roc derives
/// every name from the app and its pinned ID; the app restates none of them.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// The Chrome extension ID: the first 128 bits of SHA-256 over the signing
    /// key's public key. Changing it creates a different extension for every
    /// managed browser.
    pub id: String,
    /// `<app>.crx`, the CRX filename under `public-downloads/`.
    pub crx: String,
    /// `https://<app host>/downloads/updates.xml`, which every release names.
    pub update_url: String,
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.id.len() == 32 && self.id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)),
            "chrome_extension_id: expected 32 characters a-p"
        );
        ensure!(
            self.crx.ends_with(".crx")
                && self.crx != UPDATE_MANIFEST
                && public_downloads::media_type(&self.crx).is_ok(),
            "chrome_extension_package: expected a public download filename ending in .crx"
        );
        let host = self
            .update_url
            .strip_prefix("https://")
            .and_then(|rest| rest.strip_suffix("/downloads/updates.xml"))
            .unwrap_or_default();
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && !host.starts_with(['.', '-'])
                && !host.ends_with(['.', '-'])
                && !host.contains("..")
                && host.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                }),
            "chrome_extension_update_url: expected https://HOST/downloads/updates.xml"
        );
        Ok(())
    }

    /// The package's URL beside the update manifest.
    fn codebase(&self) -> String {
        let directory = &self.update_url[..self.update_url.len() - UPDATE_MANIFEST.len()];
        format!("{directory}{}", self.crx)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Release {
    pub extension_id: String,
    pub version: String,
    pub package: String,
    pub update_url: String,
    pub codebase: String,
    pub crx_digest: String,
}

/// Signed release bytes for `public-downloads/`.
pub struct Package {
    pub crx: Vec<u8>,
    pub update_manifest: Vec<u8>,
    pub release: Release,
}

/// A source manifest, which declares none of the injected fields.
struct Manifest {
    version: Version,
    minimum_chrome_version: Option<String>,
    value: Map<String, Value>,
}

/// A Chrome version, compared numerically and published exactly as written.
#[derive(Clone, Debug)]
struct Version {
    parts: [u16; 4],
    text: String,
}

/// Chrome's extension ID: the first 128 bits of SHA-256(SubjectPublicKeyInfo),
/// one lowercase letter a-p per hexadecimal digit.
pub fn extension_id(public_key: &[u8]) -> String {
    digest(&SHA256, public_key).as_ref()[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 15])
        .map(|nibble| char::from(b'a' + nibble))
        .collect()
}

/// Check that the committed release is the pinned extension's and packs the
/// current sources. `downloads` is the complete flat `public-downloads/`
/// directory. The release's key is the package's own signing key, which must
/// be the pinned ID's.
pub fn verify(binding: &Binding, source: &Files, downloads: &Files) -> Result<Release> {
    binding.validate()?;
    let manifest = manifest(source)?;
    let names = downloads.keys().map(String::as_str).collect::<Vec<_>>();
    let mut expected = vec![binding.crx.as_str(), UPDATE_MANIFEST];
    expected.sort_unstable();
    ensure!(
        names == expected,
        "chrome_extension_downloads: public-downloads/ must contain exactly {} and {}; run `day2 instance extension pack`",
        binding.crx,
        UPDATE_MANIFEST
    );
    let crx = &downloads[&binding.crx];
    let (public_key, archive) = open(crx)?;
    ensure!(
        extension_id(public_key) == binding.id,
        "chrome_extension_identity: the package is not signed by extension {}, which day2.json pins",
        binding.id
    );
    ensure!(
        archive == zip(&released(binding, source, &manifest, public_key)?)?,
        "chrome_extension_stale: {} differs from {}/{}; bump the manifest version and run `day2 instance extension pack`",
        binding.crx,
        DIRECTORY,
        SOURCE_DIRECTORY
    );
    ensure!(
        downloads[UPDATE_MANIFEST] == update_manifest(binding, &manifest),
        "chrome_extension_update_manifest: {} does not describe this release; run `day2 instance extension pack`",
        UPDATE_MANIFEST
    );
    Ok(release(binding, &manifest, crx))
}

/// An app the instance pins no extension for publishes no downloads: the only
/// public download is a pinned extension's release.
pub fn verify_unpinned(downloads: &Files) -> Result<()> {
    ensure!(
        downloads.is_empty(),
        "chrome_extension_unpinned: public-downloads/ may hold only the release of the extension day2.json pins, and it pins none for this app"
    );
    Ok(())
}

/// Sign the current sources. `downloads` holds the previous release, if any; a
/// changed extension must have a newer version, and a release never downgrades.
pub fn pack(
    binding: &Binding,
    source: &Files,
    downloads: &Files,
    private_key: &[u8],
    random: &dyn SecureRandom,
) -> Result<Package> {
    binding.validate()?;
    let manifest = manifest(source)?;
    let key = signing_key(private_key)?;
    let public_key = subject_public_key_info(key.public().as_ref());
    ensure!(
        extension_id(&public_key) == binding.id,
        "chrome_extension_signing_key: the key does not belong to extension {}, which day2.json pins",
        binding.id
    );
    let archive = zip(&released(binding, source, &manifest, &public_key)?)?;
    if let Some(previous) = previous(binding, downloads)? {
        ensure!(
            manifest.version >= previous.0,
            "chrome_extension_downgrade: version {} is older than the published {}",
            manifest.version,
            previous.0
        );
        ensure!(
            manifest.version > previous.0 || archive == previous.1,
            "chrome_extension_version: the extension changed; increase the manifest version above {}",
            previous.0
        );
    }
    let signed_header = field(1, &digest(&SHA256, &public_key).as_ref()[..16]);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        random,
        &signed_data(&signed_header, &archive)?,
        &mut signature,
    )
    .map_err(|_| anyhow::anyhow!("chrome_extension_signature"))?;
    let header = [
        field(2, &[field(1, &public_key), field(2, &signature)].concat()),
        field(10_000, &signed_header),
    ]
    .concat();
    let crx = [
        b"Cr24".as_slice(),
        &3u32.to_le_bytes(),
        &u32::try_from(header.len())?.to_le_bytes(),
        &header,
        &archive,
    ]
    .concat();
    ensure!(
        crx.len() as u64 <= public_downloads::MAX_FILE_BYTES,
        "chrome_extension_package_budget"
    );
    let update_manifest = update_manifest(binding, &manifest);
    let release = release(binding, &manifest, &crx);
    let downloads = Files::from([
        (binding.crx.clone(), crx.clone()),
        (UPDATE_MANIFEST.to_owned(), update_manifest.clone()),
    ]);
    ensure!(
        verify(binding, source, &downloads)? == release,
        "chrome_extension_self_check"
    );
    Ok(Package {
        crx,
        update_manifest,
        release,
    })
}

/// An unpacked build for `chrome://extensions` → Load unpacked. It never checks
/// for updates and omits permissions only managed installs receive. Without an
/// overlay it keeps the release identity: the key of the committed package in
/// `downloads`, which must be the pinned extension's, though its contents may
/// predate the sources. An overlay changes the behavior, so that build has no
/// key and is named as a local build.
pub fn local(
    binding: &Binding,
    source: &Files,
    downloads: &Files,
    overlay: &Files,
) -> Result<Files> {
    binding.validate()?;
    let manifest = manifest(source)?;
    ensure!(
        !overlay.contains_key("manifest.json"),
        "chrome_extension_local_manifest: {}/{} cannot replace manifest.json",
        DIRECTORY,
        LOCAL_DIRECTORY
    );
    files(overlay)?;
    let mut value = manifest.value;
    // Chrome grants blocking web requests only to policy-installed MV3 extensions.
    if let Some(Value::Array(permissions)) = value.get_mut("permissions") {
        permissions.retain(|permission| permission != "webRequestBlocking");
    }
    if overlay.is_empty() {
        let crx = downloads.get(&binding.crx).with_context(|| {
            format!(
                "chrome_extension_local: public-downloads/{} holds no release to take the extension's key from; pack one first",
                binding.crx
            )
        })?;
        let (public_key, _) = open(crx)?;
        ensure!(
            extension_id(public_key) == binding.id,
            "chrome_extension_identity: the package is not signed by extension {}, which day2.json pins",
            binding.id
        );
        value.insert("key".into(), Value::String(STANDARD.encode(public_key)));
    } else {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .context("chrome_extension_name")?;
        value.insert("name".into(), Value::String(format!("{name} (local)")));
    }
    let mut output = source.clone();
    output.extend(overlay.clone());
    output.insert("manifest.json".into(), pretty(&value)?);
    Ok(output)
}

/// The Google Admin values and equivalent `ExtensionSettings` policy that
/// force-install the release on managed Chrome. A person applies them; the
/// Platform never holds a credential that can change browser policy.
pub fn policy(binding: &Binding, source: &Files) -> Result<Value> {
    binding.validate()?;
    let manifest = manifest(source)?;
    let mut settings = Map::new();
    settings.insert(
        binding.id.clone(),
        json!({
            "installation_mode": "force_installed",
            "update_url": binding.update_url,
            "override_update_url": true,
        }),
    );
    Ok(json!({
        "extension_id": binding.id,
        "version": manifest.version.to_string(),
        "update_url": binding.update_url,
        "admin_console": {
            "add": "Add Chrome app or extension by ID, From a custom URL",
            "installation_policy": "Force install",
            "installation_url": binding.update_url,
            "update_url": "Installation URL (see above)",
        },
        "chrome_policy": { "ExtensionSettings": settings },
    }))
}

/// Hours of edge request logs a fleet report covers. Managed Chrome checks each
/// policy-installed extension for updates about every five hours.
pub const FLEET_WINDOW_HOURS: u32 = 24;

/// One request for a release download, as the edge logged it, oldest first.
/// `client` only groups one address's requests and is never reported.
#[derive(Clone, Debug)]
pub struct DownloadRequest {
    pub url: String,
    pub status: u16,
    pub client: String,
}

/// How managed browsers are taking up the published release.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Fleet {
    pub extension_id: String,
    pub published_version: String,
    pub update_url: String,
    pub window_hours: u32,
    /// Update checks that named this extension, and those from a policy install.
    pub update_checks: u64,
    pub policy_update_checks: u64,
    /// Successful package downloads; each one is an install or an update.
    pub package_downloads: u64,
    /// Responses of 500 or above for the update manifest or the package.
    pub server_errors: u64,
    /// Client addresses by the version their latest update check reported.
    /// `0.0.0.0` is a browser that has not finished its first install. One
    /// address can hide several browsers, so these are lower bounds.
    pub clients_by_version: BTreeMap<String, u64>,
    pub clients_on_published: u64,
    pub problems: Vec<FleetProblem>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FleetProblem {
    /// No policy-installed browser checked for updates: the Google Admin entry
    /// is missing or names another URL, or browsers cannot reach it.
    NoPolicyUpdateChecks,
    /// The edge failed requests for the update manifest or package.
    ServerErrors,
    /// Browsers report a newer version than this release: the checkout is older
    /// than the deployed release, or the served release went backwards.
    ClientsAheadOfRelease,
}

/// Summarize managed-browser update traffic for `release`. `requests` are the
/// edge's requests under the release's download directory, oldest first.
pub fn fleet(release: &Release, requests: &[DownloadRequest]) -> Result<Fleet> {
    let published = Version::parse(&release.version)?;
    let base = release
        .update_url
        .strip_suffix(UPDATE_MANIFEST)
        .context("chrome_extension_fleet: the release has no update manifest URL")?;
    let mut fleet = Fleet {
        extension_id: release.extension_id.clone(),
        published_version: release.version.clone(),
        update_url: release.update_url.clone(),
        window_hours: FLEET_WINDOW_HOURS,
        update_checks: 0,
        policy_update_checks: 0,
        package_downloads: 0,
        server_errors: 0,
        clients_by_version: BTreeMap::new(),
        clients_on_published: 0,
        problems: Vec::new(),
    };
    let mut latest = BTreeMap::<&str, &str>::new();
    for request in requests {
        let Some(rest) = request.url.strip_prefix(base) else {
            continue;
        };
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        if path != UPDATE_MANIFEST && path != release.package {
            continue;
        }
        if request.status >= 500 {
            fleet.server_errors += 1;
        }
        if path == release.package {
            fleet.package_downloads += u64::from((200..300).contains(&request.status));
        } else if let Some(check) = update_check(query, &release.extension_id) {
            fleet.update_checks += 1;
            fleet.policy_update_checks += u64::from(check.policy);
            latest.insert(&request.client, check.version);
        }
    }
    let mut ahead = false;
    for version in latest.values() {
        *fleet
            .clients_by_version
            .entry((*version).to_owned())
            .or_insert(0) += 1;
        if let Ok(reported) = Version::parse(version) {
            fleet.clients_on_published += u64::from(reported == published);
            ahead |= reported > published;
        }
    }
    for (problem, present) in [
        (
            FleetProblem::NoPolicyUpdateChecks,
            fleet.policy_update_checks == 0,
        ),
        (FleetProblem::ServerErrors, fleet.server_errors > 0),
        (FleetProblem::ClientsAheadOfRelease, ahead),
    ] {
        if present {
            fleet.problems.push(problem);
        }
    }
    Ok(fleet)
}

struct UpdateCheck<'a> {
    version: &'a str,
    policy: bool,
}

/// The update check for `id` in a Chrome update request's query. Chrome sends one
/// percent-encoded `x` parameter per extension that shares the update URL, each
/// itself a query: `id=…&v=…&installsource=…&installedby=policy&uc`.
fn update_check<'a>(query: &'a str, id: &str) -> Option<UpdateCheck<'a>> {
    query
        .split('&')
        .filter_map(|parameter| parameter.strip_prefix("x="))
        .find_map(|encoded| {
            let fields = encoded
                .split("%26")
                .filter_map(|field| field.split_once("%3D").or_else(|| field.split_once("%3d")))
                .collect::<BTreeMap<_, _>>();
            (fields.get("id") == Some(&id)).then_some(UpdateCheck {
                version: fields.get("v")?,
                policy: fields.get("installedby") == Some(&"policy"),
            })
        })
}

fn release(binding: &Binding, manifest: &Manifest, crx: &[u8]) -> Release {
    Release {
        extension_id: binding.id.clone(),
        version: manifest.version.to_string(),
        package: binding.crx.clone(),
        update_url: binding.update_url.clone(),
        codebase: binding.codebase(),
        crx_digest: crate::digest(crx),
    }
}

/// The files a release packs: the sources, with a manifest that also names the
/// signing key's public key and the instance's update URL.
fn released(
    binding: &Binding,
    source: &Files,
    manifest: &Manifest,
    public_key: &[u8],
) -> Result<Files> {
    let mut value = manifest.value.clone();
    value.insert("key".into(), Value::String(STANDARD.encode(public_key)));
    value.insert(
        "update_url".into(),
        Value::String(binding.update_url.clone()),
    );
    let mut files = source.clone();
    files.insert("manifest.json".into(), pretty(&value)?);
    Ok(files)
}

fn pretty(value: &Map<String, Value>) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn manifest(source: &Files) -> Result<Manifest> {
    files(source)?;
    let bytes = source.get("manifest.json").with_context(|| {
        format!(
            "chrome_extension_manifest: {DIRECTORY}/{SOURCE_DIRECTORY}/manifest.json is missing"
        )
    })?;
    let value: Map<String, Value> =
        serde_json::from_slice(bytes).context("chrome_extension_manifest: invalid JSON")?;
    let text = |name: &str| -> Result<&str> {
        value
            .get(name)
            .and_then(Value::as_str)
            .with_context(|| format!("chrome_extension_manifest: `{name}` must be a string"))
    };
    ensure!(
        value.get("manifest_version") == Some(&json!(3)),
        "chrome_extension_manifest: manifest_version must be 3"
    );
    text("name")?;
    let version = Version::parse(text("version")?)?;
    for field in INJECTED {
        ensure!(
            !value.contains_key(field),
            "chrome_extension_manifest: remove `{field}` from {DIRECTORY}/{SOURCE_DIRECTORY}/manifest.json; every release derives it from day2.json's pin"
        );
    }
    let minimum_chrome_version = match value.get("minimum_chrome_version") {
        None => None,
        Some(Value::String(minimum)) => Some(Version::parse(minimum)?.to_string()),
        Some(_) => bail!("chrome_extension_manifest: minimum_chrome_version must be a string"),
    };
    Ok(Manifest {
        version,
        minimum_chrome_version,
        value,
    })
}

fn files(files: &Files) -> Result<()> {
    ensure!(files.len() <= MAX_FILES, "chrome_extension_file_count");
    let mut total = 0u64;
    for (path, bytes) in files {
        ensure!(
            path.len() <= MAX_PATH_BYTES
                && path.split('/').enumerate().all(|(index, part)| {
                    !part.is_empty()
                        && !part.starts_with('.')
                        && (!part.starts_with('_') || (index == 0 && part == "_locales"))
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                }),
            "chrome_extension_path: unsupported extension file path {path:?}"
        );
        total += bytes.len() as u64;
    }
    ensure!(total <= MAX_SOURCE_BYTES, "chrome_extension_source_budget");
    let directories = files
        .keys()
        .flat_map(|path| {
            path.match_indices('/')
                .map(|(index, _)| &path[..index])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    ensure!(
        directories
            .iter()
            .all(|directory| !files.contains_key(*directory)),
        "chrome_extension_path: a file and directory share a name"
    );
    Ok(())
}

fn signing_key(pem: &[u8]) -> Result<rsa::KeyPair> {
    ensure!(
        pem.len() as u64 <= MAX_KEY_BYTES,
        "chrome_extension_signing_key_budget"
    );
    let text = std::str::from_utf8(pem).context("chrome_extension_signing_key: expected PEM")?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let label = lines
        .next()
        .and_then(|line| line.strip_prefix("-----BEGIN "))
        .and_then(|line| line.strip_suffix("-----"))
        .context("chrome_extension_signing_key: expected PEM")?;
    let mut body = String::new();
    for line in lines.by_ref() {
        if line == format!("-----END {label}-----") {
            ensure!(
                lines.next().is_none(),
                "chrome_extension_signing_key: one PEM key expected"
            );
            let der = STANDARD
                .decode(&body)
                .context("chrome_extension_signing_key: base64")?;
            let key = match label {
                "PRIVATE KEY" => rsa::KeyPair::from_pkcs8(&der),
                "RSA PRIVATE KEY" => rsa::KeyPair::from_der(&der),
                _ => bail!("chrome_extension_signing_key: expected an unencrypted RSA private key"),
            }
            .map_err(|error| anyhow::anyhow!("chrome_extension_signing_key: {error}"))?;
            ensure!(
                key.public().modulus_len() >= 256,
                "chrome_extension_signing_key: RSA-2048 or larger required"
            );
            return Ok(key);
        }
        body.push_str(line);
    }
    bail!("chrome_extension_signing_key: unterminated PEM")
}

/// Previous release: its verified version and archive.
fn previous(binding: &Binding, downloads: &Files) -> Result<Option<(Version, Vec<u8>)>> {
    let (crx, xml) = match (downloads.get(&binding.crx), downloads.get(UPDATE_MANIFEST)) {
        (None, None) => return Ok(None),
        (Some(crx), Some(xml)) => (crx, xml),
        _ => bail!(
            "chrome_extension_previous: public-downloads/ has only half of a release; restore both {} and {} or remove both",
            binding.crx,
            UPDATE_MANIFEST
        ),
    };
    let (public_key, archive) = open(crx)?;
    ensure!(
        extension_id(public_key) == binding.id,
        "chrome_extension_previous: the existing package belongs to another extension"
    );
    // The XML declaration also has a version attribute; read only updatecheck's.
    let version = std::str::from_utf8(xml)?
        .split_once("<updatecheck ")
        .and_then(|(_, element)| element.split_once(" version=\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(version, _)| Version::parse(version))
        .transpose()?
        .context("chrome_extension_previous: unreadable update manifest version")?;
    Ok(Some((version, archive.to_vec())))
}

/// Verify a CRX3 signed by exactly one RSA key and return that key and the archive.
fn open(crx: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        crx.len() >= 12 && &crx[..4] == b"Cr24" && crx[4..8] == 3u32.to_le_bytes(),
        "chrome_extension_crx: not a CRX3 package"
    );
    let header_length = u32::from_le_bytes(crx[8..12].try_into()?) as usize;
    let header_end = 12usize
        .checked_add(header_length)
        .filter(|end| *end <= crx.len())
        .context("chrome_extension_crx: truncated header")?;
    let (header, archive) = (&crx[12..header_end], &crx[header_end..]);
    let mut proofs = Vec::new();
    let mut signed_header = None;
    for (number, value) in fields(header)? {
        match number {
            2 => proofs.push(value),
            10_000 if signed_header.is_none() => signed_header = Some(value),
            _ => bail!("chrome_extension_crx: unsupported header field {number}"),
        }
    }
    let ([proof], Some(signed_header)) = (proofs.as_slice(), signed_header) else {
        bail!("chrome_extension_crx: expected one RSA proof and signed header");
    };
    let (mut public_key, mut proof_signature) = (None, None);
    for (number, value) in fields(proof)? {
        match number {
            1 if public_key.is_none() => public_key = Some(value),
            2 if proof_signature.is_none() => proof_signature = Some(value),
            _ => bail!("chrome_extension_crx: invalid RSA proof"),
        }
    }
    let (Some(public_key), Some(proof_signature)) = (public_key, proof_signature) else {
        bail!("chrome_extension_crx: incomplete RSA proof");
    };
    let mut crx_id = None;
    for (number, value) in fields(signed_header)? {
        ensure!(
            number == 1 && crx_id.is_none(),
            "chrome_extension_crx: invalid signed header"
        );
        crx_id = Some(value);
    }
    ensure!(
        crx_id == Some(&digest(&SHA256, public_key).as_ref()[..16]),
        "chrome_extension_crx: signed header does not match the signing key"
    );
    UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        rsa_public_key(public_key)?,
    )
    .verify(&signed_data(signed_header, archive)?, proof_signature)
    .map_err(|_| anyhow::anyhow!("chrome_extension_crx: invalid signature"))?;
    Ok((public_key, archive))
}

fn signed_data(signed_header: &[u8], archive: &[u8]) -> Result<Vec<u8>> {
    Ok([
        SIGNED_DATA_PREFIX,
        &u32::try_from(signed_header.len())?.to_le_bytes(),
        signed_header,
        archive,
    ]
    .concat())
}

/// Length-delimited protobuf fields; CRX headers use no other wire type.
fn fields(mut bytes: &[u8]) -> Result<Vec<(u64, &[u8])>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        ensure!(
            key & 7 == 2,
            "chrome_extension_crx: unsupported protobuf wire type"
        );
        let length = usize::try_from(varint(&mut bytes)?)?;
        ensure!(
            length <= bytes.len(),
            "chrome_extension_crx: truncated protobuf field"
        );
        let (value, rest) = bytes.split_at(length);
        fields.push((key >> 3, value));
        bytes = rest;
    }
    Ok(fields)
}

fn varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes
            .split_first()
            .context("chrome_extension_crx: truncated varint")?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("chrome_extension_crx: varint overflow")
}

fn field(number: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() + 8);
    put_varint(&mut bytes, number << 3 | 2);
    put_varint(&mut bytes, value.len() as u64);
    bytes.extend_from_slice(value);
    bytes
}

fn put_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

/// The PKCS#1 RSAPublicKey inside a SubjectPublicKeyInfo for rsaEncryption.
fn rsa_public_key(spki: &[u8]) -> Result<&[u8]> {
    let (body, rest) = der(spki, 0x30)?;
    ensure!(rest.is_empty(), "chrome_extension_public_key");
    let algorithm = body
        .strip_prefix(RSA_ALGORITHM)
        .context("chrome_extension_public_key: RSA required")?;
    let (bits, rest) = der(algorithm, 0x03)?;
    ensure!(rest.is_empty(), "chrome_extension_public_key");
    bits.strip_prefix(&[0])
        .context("chrome_extension_public_key: invalid bit string")
}

fn subject_public_key_info(rsa_public_key: &[u8]) -> Vec<u8> {
    let bits = der_value(0x03, &[&[0], rsa_public_key].concat());
    der_value(0x30, &[RSA_ALGORITHM, &bits].concat())
}

fn der(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (&actual, rest) = bytes.split_first().context("chrome_extension_public_key")?;
    ensure!(actual == tag, "chrome_extension_public_key");
    let (&first, mut rest) = rest.split_first().context("chrome_extension_public_key")?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        ensure!(
            (1..=2).contains(&count) && rest.len() >= count,
            "chrome_extension_public_key"
        );
        let (digits, remaining) = rest.split_at(count);
        rest = remaining;
        digits
            .iter()
            .fold(0, |length, digit| length << 8 | usize::from(*digit))
    };
    ensure!(length <= rest.len(), "chrome_extension_public_key");
    Ok(rest.split_at(length))
}

fn der_value(tag: u8, value: &[u8]) -> Vec<u8> {
    let length = value.len();
    let mut bytes = vec![tag];
    match length {
        0..0x80 => bytes.push(length as u8),
        0x80..0x100 => bytes.extend([0x81, length as u8]),
        _ => bytes.extend([0x82, (length >> 8) as u8, length as u8]),
    }
    bytes.extend_from_slice(value);
    bytes
}

/// A deterministic ZIP archive: sorted stored entries, the DOS epoch timestamp,
/// mode 0644 and no extra fields, comments or directory entries.
fn zip(files: &Files) -> Result<Vec<u8>> {
    const DOS_DATE: u16 = 0x21;
    const MODE: u32 = 0o100_644 << 16;
    let mut archive = Vec::new();
    let mut directory = Vec::new();
    for (path, bytes) in files {
        let offset = u32::try_from(archive.len())?;
        let size = u32::try_from(bytes.len())?;
        let name_length = u16::try_from(path.len())?;
        let crc = crc32(bytes);
        let common = [
            10u16.to_le_bytes(),
            0u16.to_le_bytes(),
            0u16.to_le_bytes(),
            0u16.to_le_bytes(),
            DOS_DATE.to_le_bytes(),
        ]
        .concat();
        let sizes = [crc.to_le_bytes(), size.to_le_bytes(), size.to_le_bytes()].concat();
        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        archive.extend_from_slice(&common);
        archive.extend_from_slice(&sizes);
        archive.extend_from_slice(&name_length.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(path.as_bytes());
        archive.extend_from_slice(bytes);
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&0x0314u16.to_le_bytes());
        directory.extend_from_slice(&common);
        directory.extend_from_slice(&sizes);
        directory.extend_from_slice(&name_length.to_le_bytes());
        directory.extend_from_slice(&[0; 8]);
        directory.extend_from_slice(&MODE.to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(path.as_bytes());
    }
    let count = u16::try_from(files.len())?;
    let directory_offset = u32::try_from(archive.len())?;
    let directory_size = u32::try_from(directory.len())?;
    archive.extend_from_slice(&directory);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&[0; 4]);
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&directory_size.to_le_bytes());
    archive.extend_from_slice(&directory_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    Ok(archive)
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, byte| {
        (0..8).fold(crc ^ u32::from(*byte), |crc, _| {
            (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

fn update_manifest(binding: &Binding, manifest: &Manifest) -> Vec<u8> {
    let minimum = manifest
        .minimum_chrome_version
        .as_ref()
        .map(|minimum| format!(" prodversionmin=\"{minimum}\""))
        .unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\">\n  <app appid=\"{}\">\n    <updatecheck codebase=\"{}\" version=\"{}\"{minimum} />\n  </app>\n</gupdate>\n",
        binding.id,
        binding.codebase(),
        manifest.version
    )
    .into_bytes()
}

impl Version {
    /// One to four dot-separated integers 0-65535, without leading zeros, not all zero.
    fn parse(text: &str) -> Result<Self> {
        let invalid = || format!("chrome_extension_version: invalid Chrome version {text:?}");
        let parts = text.split('.').collect::<Vec<_>>();
        ensure!(
            (1..=4).contains(&parts.len())
                && parts.iter().all(|part| {
                    !part.is_empty()
                        && part.bytes().all(|byte| byte.is_ascii_digit())
                        && (*part == "0" || !part.starts_with('0'))
                }),
            invalid()
        );
        let mut numbers = [0u16; 4];
        for (slot, part) in numbers.iter_mut().zip(&parts) {
            *slot = part.parse().with_context(invalid)?;
        }
        ensure!(numbers != [0; 4], invalid());
        Ok(Self {
            parts: numbers,
            text: text.to_owned(),
        })
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.parts == other.parts
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.parts.cmp(&other.parts)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text)
    }
}

#[cfg(test)]
#[path = "chrome_extension_tests.rs"]
mod tests;
