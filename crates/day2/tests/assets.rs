use anyhow::Result;
use day2::{
    assets,
    branding::{self, Brand},
};
use proptest::{
    prelude::*,
    test_runner::{Config, RngSeed, TestRunner},
};
use std::{fs, path::Path};

const ICON: &[u8] = include_bytes!("../../../assets/icons/archive.svg");

#[test]
fn assets_are_normalized_deterministically_and_generate_checked_handles() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::create_dir_all(source.join("icons"))?;
    fs::write(source.join("icons/archive.svg"), ICON)?;
    let one = assets::package(&source, &directory.path().join("one"))?;
    let two = assets::package(&source, &directory.path().join("two"))?;
    assert_eq!(one, two);
    assert_eq!(one["icons_archive"].media_type, "image/png");
    let bytes = assets::read_blob(&directory.path().join("one"), &one["icons_archive"])?;
    assert_eq!(image::guess_format(&bytes)?, image::ImageFormat::Png);
    assert!(
        image::load_from_memory(&bytes)?
            .to_rgba8()
            .pixels()
            .any(|pixel| pixel[3] > 0)
    );
    assert!(assets::roc_module(&one)?.contains("icons_archive : Asset"));
    assert!(!assets::roc_module(&one)?.contains("/assets/"));
    assets::validate_blobs(&directory.path().join("one"), &one)?;
    let mut dimensions = one.clone();
    dimensions.get_mut("icons_archive").unwrap().width += 1;
    assert!(assets::validate_blobs(&directory.path().join("one"), &dimensions).is_err());
    let blob = directory.path().join("one/assets").join(format!(
        "{}.png",
        assets::hash_part(&one["icons_archive"].digest)?
    ));
    fs::write(blob, b"changed after admission")?;
    assert!(assets::read_blob(&directory.path().join("one"), &one["icons_archive"]).is_err());
    Ok(())
}

#[test]
fn executable_external_oversized_and_unsupported_asset_inputs_fail_closed() {
    for source in [
        "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
        "<svg xmlns='http://www.w3.org/2000/svg'><image href='/etc/passwd'/></svg>",
        "<svg xmlns='http://www.w3.org/2000/svg'><image href='https://example.com/private.png'/></svg>",
        "<svg xmlns='http://www.w3.org/2000/svg'><foreignObject><html/></foreignObject></svg>",
        "<!DOCTYPE svg [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><svg xmlns='http://www.w3.org/2000/svg'>&secret;</svg>",
        "<?xml-stylesheet href='https://example.com/style.css'?><svg xmlns='http://www.w3.org/2000/svg'/>",
        "<svg xmlns='http://www.w3.org/2000/svg'><use href='#loop' id='loop'/></svg>",
        "<svg xmlns='http://www.w3.org/2000/svg' width='999999' height='999999'><path d='M0 0L5 5'/></svg>",
        "<svg xmlns='http://www.w3.org/2000/svg'><style>@import 'https://example.com/style.css';</style></svg>",
    ] {
        assert!(
            assets::normalize("svg", source.as_bytes()).is_err(),
            "{source}"
        );
    }
    assert!(assets::normalize("html", b"<html>unexpected</html>").is_err());
    assert!(assets::normalize("png", ICON).is_err());
    assert!(assets::normalize("js", b"alert(1)").is_err());
    assert!(assets::normalize("svg", &vec![b' '; 262_145]).is_err());
}

#[test]
fn asset_traversal_symlinks_and_generated_name_collisions_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::create_dir_all(source.join("icons"))?;
    fs::write(source.join("icons/archive.svg"), ICON)?;
    fs::write(source.join("icons_archive.svg"), ICON)?;
    assert!(assets::package(&source, &directory.path().join("collision")).is_err());
    fs::remove_file(source.join("icons_archive.svg"))?;
    std::os::unix::fs::symlink("/private", source.join("outside"))?;
    assert!(assets::package(&source, &directory.path().join("link")).is_err());
    fs::remove_file(source.join("outside"))?;
    std::os::unix::fs::symlink(
        "/definitely-missing-day2-fixture",
        directory.path().join("broken"),
    )?;
    assert!(
        assets::package(
            &directory.path().join("broken"),
            &directory.path().join("broken-output")
        )
        .is_err()
    );
    fs::write(source.join("not-valid.svg"), ICON)?;
    assert!(assets::package(&source, &directory.path().join("invalid-name")).is_err());
    assert!(assets::hash_part("sha256:../../outside").is_err());
    assert!(
        assets::package(
            &directory.path().join("absent"),
            &directory.path().join("empty")
        )?
        .is_empty()
    );
    Ok(())
}

#[test]
fn branding_is_independent_content_addressed_and_non_executable() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::create_dir_all(source.join("assets"))?;
    fs::write(source.join("assets/logo.svg"), ICON)?;
    fs::write(
        source.join("brand.json"),
        br##"{"name":"Example Company","accent":"#8b3150"}"##,
    )?;
    let one = branding::build(&source, &directory.path().join("bundles"))?;
    assert_eq!(
        one,
        branding::build(&source, &directory.path().join("bundles"))?
    );
    let loaded = branding::LoadedBrand::load(&one)?;
    assert_eq!(loaded.bundle.brand.name, "Example Company");
    assert!(
        loaded
            .bundle
            .brand
            .css()?
            .contains("--brand-accent: #8b3150")
    );
    fs::write(
        source.join("brand.json"),
        br##"{"name":"Different Company","accent":"#176e50"}"##,
    )?;
    assert_ne!(
        one,
        branding::build(&source, &directory.path().join("bundles"))?
    );
    for accent in [
        "red; background:url(https://example.com)",
        "#ffffff",
        "#12345z",
    ] {
        assert!(
            Brand {
                name: "Company".into(),
                accent: accent.into()
            }
            .validate()
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn seeded_asset_bytes_never_bypass_format_admission() -> Result<()> {
    let mut runner = TestRunner::new(Config {
        cases: 64,
        rng_seed: RngSeed::Fixed(0xA55E_2026),
        ..Config::default()
    });
    runner.run(&proptest::collection::vec(any::<u8>(), 0..2048), |bytes| {
        for extension in ["js", "html", "css", "exe"] {
            prop_assert!(assets::normalize(extension, &bytes).is_err());
        }
        for extension in ["png", "jpeg", "webp", "svg"] {
            if let Ok((png, width, height)) = assets::normalize(extension, &bytes) {
                prop_assert_eq!(image::guess_format(&png).unwrap(), image::ImageFormat::Png);
                prop_assert!((1..=2048).contains(&width) && (1..=2048).contains(&height));
            }
        }
        Ok(())
    })?;
    Ok(())
}

#[test]
fn app_assets_do_not_require_an_app_owned_project_or_manifest() -> Result<()> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/reports/assets");
    let directory = tempfile::tempdir()?;
    let catalog = assets::package(&source, directory.path())?;
    assert!(catalog.contains_key("report"));
    Ok(())
}
