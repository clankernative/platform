//! A single sandboxed HTML document backed by one public, input-free Day2 query.
//! A preview installation may also declare a query over its own saved revisions.
use crate::{artifact::Artifact, output_schema::Type, schema::Kind};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use day2_contracts::numeric::Unsigned;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

const PUBLISHED_APP: &str = "app/prototype/App.roc";
const INDEX: &str = "app/prototype/index.html";
const MANIFEST: &str = "app/prototype/page.json";
const MAX_HTML: usize = 16 * 1024;
const MAX_SOURCE: usize = 512 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bindings {
    query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    save_command: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub query: String,
    pub revision_query: Option<String>,
    pub save_command: Option<String>,
    pub html: String,
    manifest: String,
    // Preserve authored files before optional UI assembly. These bytes are
    // private to the build and the owner's source download.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sources: BTreeMap<String, String>,
}

pub fn validate_html(html: &str) -> Result<()> {
    ensure!(
        html.len() <= MAX_HTML && !html.trim().is_empty() && !html.contains('\0'),
        "prototype HTML must be nonblank UTF-8 of at most 16 KiB without NUL"
    );
    Ok(())
}

// Files in an exported source tree will be unpacked on another machine.
fn source_path(key: &str) -> Result<&str> {
    let relative = key.strip_prefix("app/").context("expected app source")?;
    ensure!(
        relative.len() <= 240
            && relative.split('/').all(|part| {
                !part.is_empty()
                    && !part.starts_with('.')
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            }),
        "unsafe prototype source path"
    );
    Ok(relative)
}

pub fn capture(captured: &Path, hashes: &BTreeMap<String, String>) -> Result<Option<Page>> {
    if !captured.join("prototype").try_exists()? {
        return Ok(None);
    }
    let read = |key: &str, limit: usize| -> Result<Vec<u8>> {
        let bytes = day2_assets::read_regular(&captured.join(source_path(key)?), limit as u64)?;
        ensure!(
            hashes.get(key) == Some(&crate::digest(&bytes)),
            "captured prototype source changed"
        );
        Ok(bytes)
    };
    let manifest = String::from_utf8(read(MANIFEST, 2048)?)?;
    let bindings: Bindings = crate::json::decode(manifest.as_bytes())?;
    let html = String::from_utf8(read(INDEX, MAX_HTML)?)?;
    validate_html(&html)?;
    let mut sources = BTreeMap::new();
    if bindings.revision_query.is_some() {
        let mut remaining = MAX_SOURCE;
        for key in hashes
            .keys()
            .filter(|key| key.starts_with("app/") && !matches!(key.as_str(), INDEX | MANIFEST))
        {
            let bytes = read(key, remaining)?;
            remaining -= bytes.len();
            sources.insert(key.clone(), STANDARD.encode(bytes));
        }
    }
    ensure!(
        bindings.revision_query.is_some() == hashes.contains_key(PUBLISHED_APP),
        "only editable prototypes require a publication App.roc"
    );
    Ok(Some(Page {
        query: bindings.query,
        revision_query: bindings.revision_query,
        save_command: bindings.save_command,
        html,
        manifest,
        sources,
    }))
}

pub fn validate(artifact: &Artifact) -> Result<()> {
    let Some(page) = &artifact.prototype else {
        ensure!(
            !artifact.sources.contains_key(INDEX) && !artifact.sources.contains_key(MANIFEST),
            "captured prototype missing its page"
        );
        return Ok(());
    };
    validate_html(&page.html)?;
    ensure!(
        artifact.format == crate::artifact::CURRENT_FORMAT
            && artifact.sources.get(INDEX) == Some(&crate::digest(page.html.as_bytes()))
            && artifact.sources.get(MANIFEST) == Some(&crate::digest(page.manifest.as_bytes())),
        "prototype source identity mismatch"
    );
    let bindings: Bindings = crate::json::decode(page.manifest.as_bytes())?;
    ensure!(
        bindings.query == page.query
            && bindings.revision_query == page.revision_query
            && bindings.save_command == page.save_command,
        "prototype bindings differ from captured source"
    );
    let read = public_operation(artifact, &page.query, "query")?;
    ensure!(
        artifact
            .schema
            .inputs
            .get(&read.input_type)
            .is_some_and(|record| record.fields.is_empty()),
        "prototype query must take empty input"
    );
    match (&page.revision_query, &page.save_command) {
        (None, None) => ensure!(
            page.sources.is_empty(),
            "published prototype contains draft source export"
        ),
        (Some(revision), Some(save)) => {
            validate_editor(artifact, revision, save)?;
            validate_sources(artifact, page)?;
        }
        _ => anyhow::bail!("prototype authoring requires both revision query and save command"),
    }
    Ok(())
}

fn public_operation<'a>(
    artifact: &'a Artifact,
    name: &str,
    kind: &str,
) -> Result<&'a crate::artifact::Operation> {
    artifact
        .operations
        .iter()
        .find(|op| op.name == name && op.kind == kind && !artifact.internal_command(name))
        .context("prototype operation must be registered and public with the declared kind")
}

fn validate_editor(artifact: &Artifact, revision: &str, save: &str) -> Result<()> {
    let definition = artifact
        .app_contract
        .as_ref()
        .context("prototype editor needs checked contracts")?;
    let check_shape =
        |op: &crate::artifact::Operation, input: (&str, Kind), output: (&str, Type)| {
            let expected_input = BTreeMap::from([(input.0.to_owned(), input.1)]);
            let expected_output = Type::Record(BTreeMap::from([(output.0.to_owned(), output.1)]));
            artifact
                .schema
                .inputs
                .get(&op.input_type)
                .is_some_and(|record| record.fields == expected_input)
                && artifact
                    .outputs
                    .get(&op.output_type)
                    .is_some_and(|contract| contract.shape == expected_output)
        };
    let command = public_operation(artifact, save, "command")?;
    ensure!(
        definition
            .operations
            .get(save)
            .is_some_and(|op| op.audience == Some(crate::app_contract::Audience::Owners))
            && check_shape(
                command,
                ("html", Kind::Text),
                ("id", Type::Unsigned(Unsigned::U64))
            ),
        "save command must be owner-only and map {{html: Str}} to {{id: U64}}"
    );
    let lookup = public_operation(artifact, revision, "query")?;
    ensure!(
        definition
            .operations
            .get(revision)
            .is_some_and(|op| op.observations.is_empty())
            && check_shape(
                lookup,
                ("id", Kind::Unsigned(Unsigned::U64)),
                ("html", Type::String)
            ),
        "revision query must read local data and map {{id: U64}} to {{html: Str}}"
    );
    Ok(())
}

fn validate_sources(artifact: &Artifact, page: &Page) -> Result<()> {
    ensure!(
        page.sources.contains_key("app/App.roc")
            && page.sources.contains_key("app/model-identities.json")
            && page.sources.contains_key(PUBLISHED_APP)
            && page.sources.len() <= 512,
        "incomplete prototype source"
    );
    let mut remaining = MAX_SOURCE;
    for (key, encoded) in &page.sources {
        source_path(key)?;
        ensure!(
            !matches!(key.as_str(), INDEX | MANIFEST) && encoded.len() <= remaining.div_ceil(3) * 4,
            "prototype source budget"
        );
        let bytes = STANDARD.decode(encoded)?;
        remaining = remaining
            .checked_sub(bytes.len())
            .context("prototype source budget")?;
        let hash = crate::digest(&bytes);
        ensure!(
            artifact
                .sources
                .get(&format!("ui-source/{key}"))
                .or_else(|| artifact.sources.get(key))
                == Some(&hash),
            "prototype source differs from captured input"
        );
        if key == PUBLISHED_APP {
            crate::app_inference::namespace(std::str::from_utf8(&bytes)?)?;
        }
    }
    Ok(())
}

/// Materialize the reviewed HTML and the admitted wrapper's canonical sources.
/// Grants, API results, sessions and draft rows have no representation here.
pub fn publication(artifact: &Artifact, html: &str) -> Result<Vec<u8>> {
    let page = artifact
        .prototype
        .as_ref()
        .context("prototype page required")?;
    ensure!(
        page.revision_query.is_some(),
        "only a draft has publishable source"
    );
    source_archive(page, html)
}

fn source_archive(page: &Page, html: &str) -> Result<Vec<u8>> {
    validate_html(html)?;
    let app = STANDARD.decode(
        page.sources
            .get(PUBLISHED_APP)
            .context("publication App.roc required")?,
    )?;
    let namespace = crate::app_inference::namespace(std::str::from_utf8(&app)?)?;
    let (_, operation) = page
        .query
        .split_once('.')
        .context("qualified prototype query required")?;
    let published = serde_json::to_vec_pretty(&Bindings {
        query: format!("{namespace}.{operation}"),
        revision_query: None,
        save_command: None,
    })?;
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    let mut append = |key: &str, bytes: &[u8]| -> Result<()> {
        source_path(key)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, key, bytes)?;
        Ok(())
    };
    for (key, source) in &page.sources {
        if key == PUBLISHED_APP {
            continue;
        } else if key == "app/App.roc" {
            append(key, &app)?;
        } else {
            append(key, &STANDARD.decode(source)?)?;
        }
    }
    append(MANIFEST, &published)?;
    append(INDEX, html.as_bytes())?;
    Ok(archive.into_inner()?.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Read};

    #[test]
    fn publication_round_trips_reviewed_bytes_into_a_separate_app() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::create_dir(temp.path().join("prototype"))?;
        let mut hashes = BTreeMap::new();
        let entry = r#"App :: [].{ definition = { namespace: "published", operations: {} } }"#;
        for (name, bytes) in [
            ("App.roc", "editor app"),
            ("model-identities.json", "{}"),
            ("prototype/App.roc", entry),
            ("prototype/index.html", "starter"),
            (
                "prototype/page.json",
                r#"{"query":"editor.history","revision_query":"editor.revision","save_command":"editor.save"}"#,
            ),
        ] {
            fs::write(temp.path().join(name), bytes)?;
            hashes.insert(format!("app/{name}"), crate::digest(bytes.as_bytes()));
        }
        let page = capture(temp.path(), &hashes)?.unwrap();
        let revised = "<!-- Δ -->\r\n<p>the exact saved page</p>";
        let bytes = source_archive(&page, revised)?;
        assert_eq!(source_archive(&page, revised)?, bytes);
        let mut extracted = BTreeMap::new();
        for item in tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..])).entries()? {
            let mut item = item?;
            assert!(item.header().entry_type().is_file());
            let path = item.path()?.display().to_string();
            let mut data = String::new();
            item.read_to_string(&mut data)?;
            assert!(extracted.insert(path, data).is_none());
        }
        assert_eq!(extracted.len(), 4);
        assert_eq!(extracted["app/App.roc"], entry);
        assert_eq!(extracted[INDEX], revised);
        let bindings: Bindings = crate::json::decode(extracted[MANIFEST].as_bytes())?;
        assert_eq!(
            bindings,
            Bindings {
                query: "published.history".into(),
                revision_query: None,
                save_command: None
            }
        );
        fs::write(
            temp.path().join("prototype/App.roc"),
            "changed after capture",
        )?;
        assert!(capture(temp.path(), &hashes).is_err());
        Ok(())
    }

    #[test]
    fn refuses_invalid_html_and_nonportable_archive_paths() {
        for html in [" \n", "a\0b", &"é".repeat(MAX_HTML / 2 + 1)] {
            assert!(validate_html(html).is_err());
        }
        assert!(validate_html(&"é".repeat(MAX_HTML / 2)).is_ok());
        for path in [
            "../App.roc",
            "app/../App.roc",
            "app/.git/config",
            "app//App.roc",
            "app/C:\\file",
        ] {
            assert!(source_path(path).is_err());
        }
    }
}
