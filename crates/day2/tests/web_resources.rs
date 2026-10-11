use anyhow::Result;
use day2::{digest, web_resources};
use std::{fs, os::unix::fs::symlink, path::Path};

fn write(source: &Path, path: &str, value: &str) -> Result<()> {
    write_bytes(source, path, value.as_bytes())
}

fn write_bytes(source: &Path, path: &str, value: &[u8]) -> Result<()> {
    let file = source.join(path);
    fs::create_dir_all(file.parent().unwrap())?;
    fs::write(file, value)?;
    Ok(())
}

// Header-only data for admission limits; these bytes are not a decodable font.
fn test_woff2(length: usize) -> Vec<u8> {
    assert!(length >= 49);
    let mut bytes = vec![0u8; length];
    bytes[..4].copy_from_slice(b"wOF2");
    bytes[4..8].copy_from_slice(b"\0\x01\0\0");
    bytes[8..12].copy_from_slice(&(length as u32).to_be_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_be_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
    bytes
}

#[test]
fn native_modules_keep_relative_paths_and_are_deterministic() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    write(
        &source,
        "app.js",
        "import { title } from './shared/title.js'; export * from './shared/title.js'; document.title = title; import('./lazy.js');",
    )?;
    write(
        &source,
        "shared/title.js",
        "export { title } from '../title.js';",
    )?;
    write(&source, "title.js", "export const title = 'Links';")?;
    write(
        &source,
        "lazy.js",
        "export const ready = () => navigator.clipboard.writeText('Hello');",
    )?;
    write(
        &source,
        "app.css",
        ":root { --gap: 1rem; } .board {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--gap)} @media(max-width:40rem){.board{display:block}}",
    )?;
    let one = directory.path().join("one");
    let two = directory.path().join("two");
    let first = web_resources::package(&source, &one)?;
    let second = web_resources::package(&source, &two)?;
    assert_eq!(first, second);
    assert_eq!(first.len(), 5);
    assert_eq!(first["app.js"].media_type, "text/javascript; charset=utf-8");
    assert_eq!(first["app.css"].media_type, "text/css; charset=utf-8");
    assert_eq!(
        web_resources::read_blob(&one, &first["app.js"])?,
        fs::read(source.join("app.js"))?
    );
    web_resources::validate_blobs(&one, &first)?;
    Ok(())
}

#[test]
fn ui_assembly_lock_is_not_a_browser_resource() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ui = directory.path().join("ui");
    write(&ui, "app.css", "body { color: black; }")?;
    write(&ui, "ui.lock.json", "{\"schemaVersion\":1}")?;
    let catalog = web_resources::package(&ui, &directory.path().join("out"))?;
    assert_eq!(catalog.len(), 1);
    assert!(catalog.contains_key("app.css"));
    write(&ui, "other.json", "{}")?;
    assert!(web_resources::package(&ui, &directory.path().join("out")).is_err());
    Ok(())
}

#[test]
fn module_admission_rejects_unclosed_dependency_graphs() -> Result<()> {
    for source in [
        "import 'https://example.com/library.js';",
        "import '//example.com/library.js';",
        "import '/library.js';",
        "import 'chart.js';",
        "import './missing.js';",
        "export * from 'https://example.com/library.js';",
        "export {value} from './missing.js';",
        "import('./missing.js');",
        "import('https://example.com/library.js');",
        "import('./' + name + '.js');",
        "import(`./app.js`);",
        "import('../../app.js');",
        "import('./app.js?other=1');",
        "import('./%61pp.js');",
        "import './app.css' with { type: 'css' };",
        "import('./app.js', {with:{type:'json'}});",
        "import x from './\\u006dissing.js';",
        "export {",
        "#!/bin/sh\necho('not a browser module');",
    ] {
        let directory = tempfile::tempdir()?;
        write(directory.path(), "ui/app.js", source)?;
        let result =
            web_resources::package(&directory.path().join("ui"), &directory.path().join("out"));
        assert!(result.is_err(), "unexpectedly admitted {source}");
    }
    Ok(())
}

#[test]
fn javascript_strings_comments_and_regex_are_not_treated_as_imports() -> Result<()> {
    let directory = tempfile::tempdir()?;
    write(
        directory.path(),
        "ui/app.js",
        r#"// import 'unapproved';
        const label = "import('not-a-module')";
        const matcher = /import\('https:\/\//;
        document.querySelector('main')?.setAttribute('data-label', label);
        "#,
    )?;
    web_resources::package(&directory.path().join("ui"), &directory.path().join("out"))?;
    Ok(())
}

#[test]
fn css_policy_decodes_escapes_and_checks_nested_loading_tokens() -> Result<()> {
    for value in [
        "--gap: 1rem; display: grid; grid-template-columns: minmax(0, 1fr) auto;",
        "content: 'https://example.com is visible text, not a resource';",
        "clip-path: url(#clip); filter: url(\"#filter\");",
        "color: rgb(10 20 30 / .8); transform: translateX(calc(1px + var(--gap)));",
    ] {
        web_resources::validate_inline_style(value)?;
    }
    for value in [
        "background: url(https://example.com/a.png)",
        "background: url(\"https://example.com/a.png\")",
        "--image: url(https://example.com/a.png); background:var(--image)",
        r"background: u\72l(https://example.com/a.png)",
        r"@\69mport 'https://example.com/a.css';",
        "@import './another.css';",
        "@media (width > 100px) { div {background:url(//example.com/a.png)}}",
        "background: image-set('https://example.com/a.png' 1x)",
        "background: src('https://example.com/a.png')",
        "background: url(data:image/png;base64,AA)",
        "background: url(\"#bad fragment\")",
        "background: url(https://example.com/ bad)",
        "content: 'unterminated\nstring';",
    ] {
        assert!(
            web_resources::validate_inline_style(value).is_err(),
            "unexpectedly admitted {value}"
        );
    }
    Ok(())
}

#[test]
fn resource_hashes_and_metadata_are_rechecked_on_load_and_serve() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    let target = directory.path().join("out");
    write(&source, "app.js", "document.title = 'Original';")?;
    let catalog = web_resources::package(&source, &target)?;
    let resource = &catalog["app.js"];
    let blob = target.join("web_resources").join(format!(
        "{}.js",
        resource.digest.trim_start_matches("sha256:")
    ));
    fs::write(&blob, "document.title = 'Modified';")?;
    assert!(web_resources::read_blob(&target, resource).is_err());
    assert!(web_resources::validate_blobs(&target, &catalog).is_err());

    let mut metadata = catalog.clone();
    metadata.get_mut("app.js").unwrap().digest = "sha256:../../outside".into();
    assert!(web_resources::validate(&metadata).is_err());
    let mut metadata = catalog.clone();
    metadata.get_mut("app.js").unwrap().media_type = "text/html".into();
    assert!(web_resources::validate(&metadata).is_err());

    // A changed manifest cannot admit a new import just by supplying its hash.
    let bytes = b"import './missing.js';";
    let mut metadata = catalog.clone();
    let resource = metadata.get_mut("app.js").unwrap();
    resource.digest = digest(bytes);
    resource.bytes = bytes.len() as u64;
    fs::write(
        target.join("web_resources").join(format!(
            "{}.js",
            resource.digest.trim_start_matches("sha256:")
        )),
        bytes,
    )?;
    assert!(web_resources::validate_blobs(&target, &metadata).is_err());
    Ok(())
}

#[test]
fn resource_sources_reject_symlinks_non_ui_files_and_paths() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    fs::create_dir(&source)?;
    symlink(directory.path().join("absent"), source.join("app.js"))?;
    assert!(web_resources::package(&source, &directory.path().join("out")).is_err());
    fs::remove_file(source.join("app.js"))?;
    symlink(directory.path().join("absent"), source.join("nested"))?;
    assert!(web_resources::package(&source, &directory.path().join("out")).is_err());
    fs::remove_file(source.join("nested"))?;
    write(&source, "package.json", "{}")?;
    assert!(web_resources::package(&source, &directory.path().join("out")).is_err());
    fs::remove_file(source.join("package.json"))?;
    write(&source, "app.ts", "const x: number = 1;")?;
    assert!(web_resources::package(&source, &directory.path().join("out")).is_err());
    fs::remove_file(source.join("app.ts"))?;
    write(&source, "app.js", "export const x = 1;")?;
    let mut catalog = web_resources::package(&source, &directory.path().join("out"))?;
    let resource = catalog.remove("app.js").unwrap();
    for path in [
        "../app.js",
        "/app.js",
        "nested//app.js",
        ".hidden.js",
        "a%20b.js",
    ] {
        let invalid = [(path.to_string(), resource.clone())].into_iter().collect();
        assert!(web_resources::validate(&invalid).is_err(), "{path}");
    }
    Ok(())
}

#[test]
fn woff2_resource_bytes_and_css_font_closure_survive_packaging() -> Result<()> {
    const FONT: &[u8] = include!("fixtures/fonts/test-subset.rs");
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    write_bytes(&source, "fonts/test-subset.woff2", FONT)?;
    write(
        &source,
        "app.css",
        "@font-face { font-family: Test; src: url(./fonts/test-subset.woff2) format(\"woff2\"); }",
    )?;
    let target = directory.path().join("out");
    let catalog = web_resources::package(&source, &target)?;
    assert_eq!(catalog["fonts/test-subset.woff2"].media_type, "font/woff2");
    assert_eq!(
        web_resources::read_blob(&target, &catalog["fonts/test-subset.woff2"])?,
        FONT
    );
    web_resources::validate_blobs(&target, &catalog)?;

    // A replayed stylesheet digest cannot widen its locked font closure.
    let changed_css = b"@font-face { src: url(\"fonts/not-in-catalog.woff2\"); }";
    let mut replayed = catalog.clone();
    let css = replayed.get_mut("app.css").unwrap();
    css.digest = digest(changed_css);
    css.bytes = changed_css.len() as u64;
    fs::write(
        target
            .join("web_resources")
            .join(format!("{}.css", css.digest.trim_start_matches("sha256:"))),
        changed_css,
    )?;
    assert!(web_resources::validate_blobs(&target, &replayed).is_err());

    let second = web_resources::package(&source, &directory.path().join("other"))?;
    assert_eq!(catalog, second);
    Ok(())
}

#[test]
fn font_urls_are_source_stylesheet_only_and_catalog_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    write_bytes(&source, "fonts/geist-sans-variable.woff2", &test_woff2(64))?;
    for css in [
        "@font-face { src: url(\"./fonts/missing.woff2\"); }",
        "@font-face { src: url(\"https://example.com/font.woff2\"); }",
        r#"@font-face { src: url("https\3a //example.com/font.woff2"); }"#,
        "@font-face { src: url(\"//example.com/font.woff2\"); }",
        "@font-face { src: url(\"/fonts/geist-sans-variable.woff2\"); }",
        "@font-face { src: url(\"../fonts/geist-sans-variable.woff2\"); }",
        "@font-face { src: url(\"fonts/geist-sans-variable.woff2?cache=1\"); }",
        ".page { background-image: url(\"fonts/geist-sans-variable.woff2\"); }",
        "@font-face { background-image: url(\"fonts/geist-sans-variable.woff2\"); }",
        "@font-face { src: url(\"fonts/geist-sans-variable.woff2\"), url(\"https://example.com/x.woff2\"); }",
    ] {
        write(&source, "app.css", css)?;
        assert!(
            web_resources::package(&source, &directory.path().join("out")).is_err(),
            "unexpectedly admitted CSS {css}"
        );
    }
    write(
        &source,
        "app.css",
        r#"@font-face { src: url("fonts/geist\2d sans-variable.woff2"); }"#,
    )?;
    web_resources::package(&source, &directory.path().join("escaped"))?;
    assert!(
        web_resources::validate_inline_style(
            "font-family: Geist; src: url(\"fonts/geist-sans-variable.woff2\")"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn woff2_header_type_path_and_budget_are_bounded() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    write_bytes(&source, "fonts/good.woff2", &test_woff2(64))?;
    web_resources::package(&source, &directory.path().join("good"))?;

    for (path, bytes) in [
        ("fonts/wrong.woff2", b"not a font".to_vec()),
        ("fonts/short.woff2", b"wOF2".to_vec()),
    ] {
        let bad = directory.path().join("bad");
        fs::create_dir_all(&bad)?;
        write_bytes(&bad, path, &bytes)?;
        assert!(web_resources::package(&bad, &directory.path().join("bad-out")).is_err());
    }
    let mut mismatch = test_woff2(64);
    mismatch[8..12].copy_from_slice(&63u32.to_be_bytes());
    write_bytes(&source, "fonts/mismatch.woff2", &mismatch)?;
    assert!(web_resources::package(&source, &directory.path().join("mismatch-out")).is_err());
    fs::remove_file(source.join("fonts/mismatch.woff2"))?;
    for (offset, value, message) in [
        (12, 0u32, "ui_woff2_header_invalid"),
        (20, 0u32, "ui_woff2_header_invalid"),
        (20, 17u32, "ui_woff2_compressed_length_invalid"),
    ] {
        let mut bytes = test_woff2(64);
        if offset == 12 {
            bytes[offset..offset + 2].copy_from_slice(&(value as u16).to_be_bytes());
        } else {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        write_bytes(&source, "fonts/header.woff2", &bytes)?;
        let error =
            web_resources::package(&source, &directory.path().join("header-out")).unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
        fs::remove_file(source.join("fonts/header.woff2"))?;
    }
    let mut expanded = test_woff2(64);
    expanded[16..20].copy_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_be_bytes());
    write_bytes(&source, "fonts/expanded.woff2", &expanded)?;
    assert!(web_resources::package(&source, &directory.path().join("expanded-out")).is_err());
    fs::remove_file(source.join("fonts/expanded.woff2"))?;

    write_bytes(&source, "fonts/unsupported.ttf", &test_woff2(64))?;
    assert!(web_resources::package(&source, &directory.path().join("extension-out")).is_err());
    fs::remove_file(source.join("fonts/unsupported.ttf"))?;

    let mut catalog = web_resources::package(&source, &directory.path().join("tamper"))?;
    catalog.get_mut("fonts/good.woff2").unwrap().media_type = "application/octet-stream".into();
    assert!(web_resources::validate(&catalog).is_err());
    Ok(())
}

#[test]
fn woff2_source_symlinks_and_blob_tampering_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    fs::create_dir_all(source.join("fonts"))?;
    let external = directory.path().join("external.woff2");
    fs::write(&external, test_woff2(64))?;
    symlink(&external, source.join("fonts/link.woff2"))?;
    assert!(web_resources::package(&source, &directory.path().join("out")).is_err());

    fs::remove_file(source.join("fonts/link.woff2"))?;
    write_bytes(&source, "fonts/good.woff2", &test_woff2(64))?;
    let target = directory.path().join("out");
    let catalog = web_resources::package(&source, &target)?;
    let resource = &catalog["fonts/good.woff2"];
    let blob = target.join("web_resources").join(format!(
        "{}.woff2",
        resource.digest.trim_start_matches("sha256:")
    ));
    let mut changed = fs::read(&blob)?;
    changed[47] = 1;
    fs::write(&blob, changed)?;
    assert!(web_resources::read_blob(&target, resource).is_err());
    assert!(web_resources::validate_blobs(&target, &catalog).is_err());
    Ok(())
}

#[test]
fn woff2_file_and_pack_budgets_are_preserved() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    let oversized = test_woff2(2 * 1024 * 1024 + 1);
    write_bytes(&source, "fonts/large.woff2", &oversized)?;
    assert!(web_resources::package(&source, &directory.path().join("file-budget")).is_err());

    fs::remove_file(source.join("fonts/large.woff2"))?;
    let one = test_woff2(2 * 1024 * 1024);
    for index in 0..9 {
        write_bytes(&source, &format!("fonts/font-{index}.woff2"), &one)?;
    }
    assert!(web_resources::package(&source, &directory.path().join("pack-budget")).is_err());
    Ok(())
}
