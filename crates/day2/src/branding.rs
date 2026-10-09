use crate::{artifact::Instance, digest};
use anyhow::{Context, Result, ensure};
use day2_assets::{self as assets, Catalog};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Brand {
    pub name: String,
    pub accent: String,
}
impl Brand {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 80
                && !self.name.chars().any(char::is_control),
            "invalid_brand_name"
        );
        let color = self
            .accent
            .strip_prefix('#')
            .context("invalid_brand_color")?;
        ensure!(
            color.len() == 6 && color.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid_brand_color"
        );
        // Brand controls use white foreground text. Reject inaccessible accents.
        let mut luminance = 0.;
        for (offset, weight) in [(0, 0.2126), (2, 0.7152), (4, 0.0722)] {
            let c = f64::from(u8::from_str_radix(&color[offset..offset + 2], 16)?) / 255.;
            luminance += weight
                * if c <= 0.04045 {
                    c / 12.92
                } else {
                    ((c + 0.055) / 1.055).powf(2.4)
                };
        }
        ensure!(
            1.05 / (luminance + 0.05) >= 4.5,
            "brand_accent_needs_white_text_contrast"
        );
        Ok(())
    }
    pub fn css(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(":root {{ --brand-accent: {}; }}", self.accent))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: u32,
    pub brand: Brand,
    pub assets: Catalog,
}
#[derive(Clone)]
pub struct LoadedBrand {
    pub id: String,
    pub directory: PathBuf,
    pub bundle: Bundle,
}
impl LoadedBrand {
    pub fn load(directory: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(directory)?.file_type().is_dir(),
            "brand_directory_type"
        );
        let value: serde_json::Value = serde_json::from_slice(&assets::read_regular(
            &directory.join("brand.json"),
            65_536,
        )?)?;
        let id = digest(&serde_json::to_vec(&value)?);
        ensure!(
            directory.file_name().and_then(|s| s.to_str()) == Some(assets::hash_part(&id)?),
            "brand_identity_mismatch"
        );
        let bundle: Bundle = serde_json::from_value(value)?;
        ensure!(bundle.format == 1, "unknown_brand_format");
        bundle.brand.validate()?;
        assets::validate_blobs(directory, &bundle.assets)?;
        Ok(Self {
            id,
            directory: directory.to_path_buf(),
            bundle,
        })
    }
    pub fn for_instance(path: &Path) -> Result<Option<Self>> {
        let instance = Instance::load(path)?;
        instance
            .branding
            .map(|binding| {
                ensure!(!binding.is_empty(), "invalid_brand_binding");
                let mut directory = path.parent().context("instance_parent")?.to_path_buf();
                for component in Path::new(&binding).components() {
                    let Component::Normal(part) = component else {
                        anyhow::bail!("brand_must_belong_to_instance");
                    };
                    directory.push(part);
                    ensure!(
                        fs::symlink_metadata(&directory)?.file_type().is_dir(),
                        "brand_directory_type"
                    );
                }
                Self::load(&directory)
            })
            .transpose()
    }
}

pub fn build(source: &Path, output: &Path) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_dir(),
        "brand_source_type"
    );
    let brand: Brand =
        serde_json::from_slice(&assets::read_regular(&source.join("brand.json"), 4096)?)?;
    brand.validate()?;
    fs::create_dir_all(output)?;
    let stage = tempfile::tempdir_in(output)?;
    let assets = assets::package(&source.join("assets"), stage.path())?;
    let value = serde_json::to_value(Bundle {
        format: 1,
        brand,
        assets,
    })?;
    let id = digest(&serde_json::to_vec(&value)?);
    let target = output.join(assets::hash_part(&id)?);
    fs::write(
        stage.path().join("brand.json"),
        serde_json::to_vec_pretty(&value)?,
    )?;
    if target.exists() {
        LoadedBrand::load(&target)?;
    } else {
        fs::rename(stage.path(), &target)?;
    }
    Ok(target)
}
