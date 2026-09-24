use crate::{digest, schema::identifier};
use anyhow::{Context, Result, bail, ensure};
use image::{ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::Path,
};

const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EDGE: u32 = 2048;
pub type Catalog = BTreeMap<String, Asset>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub digest: String,
    pub source_digest: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
}
pub fn hash_part(value: &str) -> Result<&str> {
    let hash = value
        .strip_prefix("sha256:")
        .context("invalid_asset_digest")?;
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_asset_digest"
    );
    Ok(hash)
}
pub fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= limit,
        "asset_file_budget_or_type"
    );
    let mut bytes = vec![];
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "asset_file_budget");
    Ok(bytes)
}
pub fn validate(catalog: &Catalog) -> Result<()> {
    ensure!(catalog.len() <= 64, "asset_count_budget");
    let mut size = 0u64;
    for (key, asset) in catalog {
        identifier(key)?;
        hash_part(&asset.digest)?;
        hash_part(&asset.source_digest)?;
        ensure!(
            asset.media_type == "image/png",
            "unsupported_admitted_asset_type"
        );
        ensure!(
            (1..=MAX_EDGE).contains(&asset.width) && (1..=MAX_EDGE).contains(&asset.height),
            "asset_dimension_budget"
        );
        ensure!(
            asset.bytes > 0 && asset.bytes <= MAX_SOURCE_BYTES,
            "asset_file_budget"
        );
        size = size.checked_add(asset.bytes).context("asset_pack_budget")?;
    }
    ensure!(size <= MAX_PACK_BYTES, "asset_pack_budget");
    Ok(())
}
pub fn read_blob(directory: &Path, asset: &Asset) -> Result<Vec<u8>> {
    let directory = directory.join("assets");
    ensure!(
        fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "asset_directory_type"
    );
    let bytes = read_regular(
        &directory.join(format!("{}.png", hash_part(&asset.digest)?)),
        MAX_SOURCE_BYTES,
    )?;
    ensure!(
        bytes.len() as u64 == asset.bytes && digest(&bytes) == asset.digest,
        "asset_digest_mismatch"
    );
    Ok(bytes)
}
pub fn validate_blobs(directory: &Path, catalog: &Catalog) -> Result<()> {
    validate(catalog)?;
    for asset in catalog.values() {
        let bytes = read_blob(directory, asset)?;
        let (_, width, height) = normalize("png", &bytes)?;
        ensure!(
            width == asset.width && height == asset.height,
            "asset_dimension_mismatch"
        );
    }
    Ok(())
}

/// Assets are build inputs, not Roc I/O. Decode and re-encode raster files to
/// remove metadata/trailing payloads; SVG never reaches a browser as markup.
pub fn normalize(extension: &str, bytes: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_SOURCE_BYTES,
        "asset_source_budget"
    );
    if extension == "svg" {
        return rasterize_svg(bytes);
    }
    let format = match extension {
        "png" => ImageFormat::Png,
        "jpg" | "jpeg" => ImageFormat::Jpeg,
        "webp" => ImageFormat::WebP,
        _ => bail!("unsupported_asset_source_type"),
    };
    ensure!(
        image::guess_format(bytes)? == format,
        "asset_extension_mismatch"
    );
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_EDGE);
    limits.max_image_height = Some(MAX_EDGE);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode()?.to_rgba8();
    let (width, height) = image.dimensions();
    let mut out = Cursor::new(vec![]);
    image.write_to(&mut out, ImageFormat::Png)?;
    let out = out.into_inner();
    ensure!(
        out.len() as u64 <= MAX_SOURCE_BYTES,
        "normalized_asset_budget"
    );
    Ok((out, width, height))
}

fn rasterize_svg(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    ensure!(bytes.len() <= 262_144, "svg_source_budget");
    let source = std::str::from_utf8(bytes)?;
    let document = roxmltree::Document::parse_with_options(
        source,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 4096,
            ..Default::default()
        },
    )?;
    ensure!(
        document.root_element().tag_name().name() == "svg",
        "invalid_svg_root"
    );
    for node in document.descendants() {
        ensure!(!node.is_pi(), "svg_processing_instruction_forbidden");
        if !node.is_element() {
            continue;
        }
        ensure!(
            node.ancestors().count() <= 24
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/svg"),
            "invalid_svg_namespace_or_depth"
        );
        ensure!(
            [
                "svg",
                "g",
                "path",
                "rect",
                "circle",
                "ellipse",
                "line",
                "polyline",
                "polygon",
                "defs",
                "linearGradient",
                "radialGradient",
                "stop",
                "clipPath",
                "title",
                "desc"
            ]
            .contains(&node.tag_name().name()),
            "unsupported_svg_element"
        );
        for attr in node.attributes() {
            ensure!(
                attr.namespace().is_none()
                    && [
                        "id",
                        "class",
                        "viewBox",
                        "width",
                        "height",
                        "x",
                        "y",
                        "x1",
                        "x2",
                        "y1",
                        "y2",
                        "cx",
                        "cy",
                        "r",
                        "rx",
                        "ry",
                        "d",
                        "points",
                        "fill",
                        "fill-rule",
                        "fill-opacity",
                        "stroke",
                        "stroke-width",
                        "stroke-linecap",
                        "stroke-linejoin",
                        "stroke-miterlimit",
                        "stroke-dasharray",
                        "stroke-dashoffset",
                        "stroke-opacity",
                        "opacity",
                        "transform",
                        "preserveAspectRatio",
                        "gradientUnits",
                        "gradientTransform",
                        "offset",
                        "stop-color",
                        "stop-opacity",
                        "clip-path",
                        "clip-rule",
                        "color",
                        "version",
                        "fx",
                        "fy"
                    ]
                    .contains(&attr.name()),
                "unsupported_svg_attribute"
            );
            ensure!(attr.value().len() <= 32_768, "svg_attribute_budget");
        }
    }
    let options = resvg::usvg::Options {
        resources_dir: None,
        image_href_resolver: resvg::usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..Default::default()
    };
    let tree = resvg::usvg::Tree::from_data(bytes, &options)?;
    let size = tree.size().to_int_size();
    ensure!(
        (1..=MAX_EDGE).contains(&size.width()) && (1..=MAX_EDGE).contains(&size.height()),
        "asset_dimension_budget"
    );
    let mut pixels =
        resvg::tiny_skia::Pixmap::new(size.width(), size.height()).context("svg_allocation")?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::identity(),
        &mut pixels.as_mut(),
    );
    ensure!(
        pixels.pixels().iter().any(|pixel| pixel.alpha() > 0),
        "empty_svg"
    );
    let out = pixels.encode_png()?;
    ensure!(
        out.len() as u64 <= MAX_SOURCE_BYTES,
        "normalized_asset_budget"
    );
    Ok((out, size.width(), size.height()))
}

pub fn package(source: &Path, target: &Path) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(catalog),
        metadata => ensure!(metadata?.file_type().is_dir(), "asset_directory_type"),
    }
    fs::create_dir_all(target.join("assets"))?;
    let mut source_bytes = 0;
    collect(source, target, "", 0, &mut source_bytes, &mut catalog)?;
    validate(&catalog)?;
    Ok(catalog)
}
fn collect(
    source: &Path,
    target: &Path,
    prefix: &str,
    depth: usize,
    total: &mut u64,
    catalog: &mut Catalog,
) -> Result<()> {
    ensure!(
        depth <= 4 && fs::symlink_metadata(source)?.file_type().is_dir(),
        "asset_directory_type_or_depth"
    );
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= 64, "asset_directory_budget");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("asset_filename"))?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "asset_symlink_forbidden");
        if kind.is_dir() {
            identifier(&name)?;
            collect(
                &entry.path(),
                target,
                &format!("{prefix}{name}_"),
                depth + 1,
                total,
                catalog,
            )?;
        } else {
            ensure!(kind.is_file(), "asset_special_file_forbidden");
            if name.ends_with(".md") {
                continue;
            }
            let (stem, extension) = name.rsplit_once('.').context("asset_extension_required")?;
            identifier(stem)?;
            let key = format!("{prefix}{stem}");
            identifier(&key)?;
            ensure!(
                !catalog.contains_key(&key) && catalog.len() < 64,
                "asset_name_collision_or_count"
            );
            let bytes = read_regular(&entry.path(), MAX_SOURCE_BYTES)?;
            *total += bytes.len() as u64;
            ensure!(*total <= MAX_PACK_BYTES, "asset_source_pack_budget");
            let (normalized, width, height) =
                normalize(extension, &bytes).with_context(|| format!("asset {key}"))?;
            let hash = digest(&normalized);
            fs::write(
                target
                    .join("assets")
                    .join(format!("{}.png", hash_part(&hash)?)),
                &normalized,
            )?;
            catalog.insert(
                key,
                Asset {
                    digest: hash,
                    source_digest: digest(&bytes),
                    media_type: "image/png".into(),
                    width,
                    height,
                    bytes: normalized.len() as u64,
                },
            );
        }
    }
    Ok(())
}
pub fn roc_module(catalog: &Catalog) -> Result<String> {
    roc_module_profile(catalog, false)
}

pub(crate) fn admission_roc_module(catalog: &Catalog) -> Result<String> {
    roc_module_profile(catalog, true)
}

fn roc_module_profile(catalog: &Catalog, admission: bool) -> Result<String> {
    validate(catalog)?;
    let prefix = if admission { "admission_" } else { "" };
    let mut code = "import pf.Asset\n\nAssets :: [].{\n".to_string();
    for key in catalog.keys() {
        let body = format!("Asset.{prefix}define(\"{key}\")");
        code.push_str(&format!("    {key} : Asset\n    {key} = {body}\n"));
    }
    code.push_str("}\n");
    Ok(code)
}
