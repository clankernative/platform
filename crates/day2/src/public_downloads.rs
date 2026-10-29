//! Explicitly public, artifact-pinned downloads. These are never UI resources.
//! A stable URL selects bytes from this app's currently loaded artifact, not
//! from a mutable directory or a caller-supplied filesystem path.
use crate::{digest, store::Runtime, web_assets};
use anyhow::{Result, bail, ensure};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use day2_assets as assets;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

pub const SOURCE_DIRECTORY: &str = "public-downloads";
pub const PREFIX: &str = "/downloads/";
const MAX_FILES: usize = 32;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 16 * 1024 * 1024;

pub type Catalog = BTreeMap<String, File>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub digest: String,
    pub media_type: String,
    pub bytes: u64,
}

fn media_type(name: &str) -> Result<&'static str> {
    ensure!(
        !name.is_empty()
            && name.len() <= 160
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') }),
        "public_download_filename"
    );
    match name.rsplit_once('.').map(|(_, extension)| extension) {
        Some("crx") => Ok("application/x-chrome-extension"),
        Some("xml") => Ok("application/xml; charset=utf-8"),
        _ => bail!("public_download_type: only .crx and .xml downloads are supported"),
    }
}

pub fn validate(catalog: &Catalog) -> Result<()> {
    ensure!(catalog.len() <= MAX_FILES, "public_download_count_budget");
    let mut total = 0;
    for (name, file) in catalog {
        ensure!(
            file.media_type == media_type(name)?,
            "public_download_media_type"
        );
        assets::hash_part(&file.digest)?;
        ensure!(
            file.bytes > 0 && file.bytes <= MAX_FILE_BYTES,
            "public_download_file_budget"
        );
        total += file.bytes;
    }
    ensure!(total <= MAX_PACK_BYTES, "public_download_pack_budget");
    Ok(())
}

fn blob_name(file: &File) -> Result<String> {
    Ok(format!("{}.bin", assets::hash_part(&file.digest)?))
}

pub fn read_blob(directory: &Path, file: &File) -> Result<Vec<u8>> {
    let directory = directory.join(SOURCE_DIRECTORY);
    ensure!(
        fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "public_download_directory_type"
    );
    let bytes = assets::read_regular(&directory.join(blob_name(file)?), MAX_FILE_BYTES)?;
    ensure!(
        bytes.len() as u64 == file.bytes && digest(&bytes) == file.digest,
        "public_download_digest_mismatch"
    );
    Ok(bytes)
}

pub fn validate_blobs(directory: &Path, catalog: &Catalog) -> Result<()> {
    validate(catalog)?;
    for file in catalog.values() {
        read_blob(directory, file)?;
    }
    Ok(())
}

pub fn package(source: &Path, target: &Path) -> Result<Catalog> {
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Catalog::new()),
        metadata => ensure!(
            metadata?.file_type().is_dir(),
            "public_download_directory_type"
        ),
    }
    let entries = fs::read_dir(source)?
        .take(MAX_FILES + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= MAX_FILES, "public_download_count_budget");
    let mut catalog = Catalog::new();
    let mut blobs = BTreeMap::new();
    let mut total = 0;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("public_download_filename"))?;
        let kind = media_type(&name)?;
        let bytes = assets::read_regular(&entry.path(), MAX_FILE_BYTES)?;
        total += bytes.len() as u64;
        ensure!(total <= MAX_PACK_BYTES, "public_download_pack_budget");
        let file = File {
            digest: digest(&bytes),
            media_type: kind.into(),
            bytes: bytes.len() as u64,
        };
        blobs.insert(blob_name(&file)?, bytes);
        catalog.insert(name, file);
    }
    validate(&catalog)?;
    if !catalog.is_empty() {
        fs::create_dir_all(target.join(SOURCE_DIRECTORY))?;
        for (name, bytes) in blobs {
            fs::write(target.join(SOURCE_DIRECTORY).join(name), bytes)?;
        }
    }
    Ok(catalog)
}

pub fn copy_blobs(source: &Path, target: &Path, catalog: &Catalog) -> Result<()> {
    validate_blobs(source, catalog)?;
    if !catalog.is_empty() {
        fs::create_dir_all(target.join(SOURCE_DIRECTORY))?;
        for file in catalog.values() {
            fs::write(
                target.join(SOURCE_DIRECTORY).join(blob_name(file)?),
                read_blob(source, file)?,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn registered(runtime: &Runtime, path: &str) -> bool {
    path.strip_prefix(PREFIX).is_some_and(|name| {
        runtime
            .artifact()
            .contract()
            .public_downloads
            .contains_key(name)
    })
}

pub(crate) fn serve(
    runtime: &Runtime,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response> {
    let Some(file) = path
        .strip_prefix(PREFIX)
        .and_then(|name| runtime.artifact().contract().public_downloads.get(name))
    else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Ok((
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
        )
            .into_response());
    }
    let mut response = web_assets::bytes(
        &file.media_type,
        read_blob(runtime.artifact().directory(), file)?,
        web_assets::CachePolicy::PublicRevalidate,
        headers,
    )?;
    let name = path.strip_prefix(PREFIX).expect("registered download path");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{name}\"").parse()?,
    );
    if *method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn packages_deterministic_pinned_downloads_and_rejects_tampering() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("updates.xml"), b"<gupdate />")?;
        fs::write(source.join("extension.crx"), b"opaque download bytes")?;
        let first = root.path().join("first");
        let catalog = package(&source, &first)?;
        assert_eq!(catalog, package(&source, &root.path().join("second"))?);
        assert_eq!(
            catalog["extension.crx"].media_type,
            "application/x-chrome-extension"
        );
        let copy = root.path().join("copy");
        copy_blobs(&first, &copy, &catalog)?;
        validate_blobs(&copy, &catalog)?;
        let file = &catalog["extension.crx"];
        fs::write(
            copy.join(SOURCE_DIRECTORY).join(blob_name(file)?),
            b"changed",
        )?;
        assert!(validate_blobs(&copy, &catalog).is_err());
        assert!(copy_blobs(&copy, &root.path().join("rejected"), &catalog).is_err());
        Ok(())
    }

    #[test]
    fn rejects_unknown_types_paths_symlinks_directories_and_invalid_metadata() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        fs::create_dir(&source)?;
        for name in [
            "secret.pem",
            "index.html",
            "code.js",
            ".hidden.xml",
            "bad name.xml",
        ] {
            fs::write(source.join(name), b"private")?;
            assert!(
                package(&source, &root.path().join("out")).is_err(),
                "{name}"
            );
            fs::remove_file(source.join(name))?;
        }
        fs::write(root.path().join("outside"), b"private")?;
        symlink(root.path().join("outside"), source.join("updates.xml"))?;
        assert!(package(&source, &root.path().join("out")).is_err());
        fs::remove_file(source.join("updates.xml"))?;
        fs::create_dir(source.join("nested.xml"))?;
        assert!(package(&source, &root.path().join("out")).is_err());
        let file = File {
            digest: digest(b"a"),
            bytes: 1,
            media_type: "application/xml; charset=utf-8".into(),
        };
        for name in [
            "../updates.xml",
            "/updates.xml",
            "nested/updates.xml",
            "a%2fb.xml",
            "a\\b.xml",
        ] {
            assert!(
                validate(&BTreeMap::from([(name.into(), file.clone())])).is_err(),
                "{name}"
            );
        }
        for bytes in [0, MAX_FILE_BYTES + 1] {
            assert!(
                validate(&BTreeMap::from([(
                    "updates.xml".into(),
                    File {
                        bytes,
                        ..file.clone()
                    }
                )]))
                .is_err()
            );
        }
        assert!(validate(&BTreeMap::from([("extension.crx".into(), file)])).is_err());
        Ok(())
    }
}
