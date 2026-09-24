use anyhow::Result;
use day2::{digest, web_resources};
use std::{fs, os::unix::fs::symlink, path::Path};

fn write(source: &Path, path: &str, value: &str) -> Result<()> {
    let file = source.join(path);
    fs::create_dir_all(file.parent().unwrap())?;
    fs::write(file, value)?;
    Ok(())
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
