use crate::{
    artifact::Instance,
    assets::{self, Asset},
    branding::LoadedBrand,
    digest,
    store::Runtime,
    web_security::Session,
};
use anyhow::{Context, Result, ensure};
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use maud::{Markup, html};

pub(crate) struct Appearance {
    scope: String,
    artifact: String,
    name: String,
    binding: Option<String>,
    brand: Option<LoadedBrand>,
}
impl Appearance {
    pub fn load(runtime: &Runtime) -> Result<Self> {
        let instance = Instance::load(runtime.instance_path())?;
        Ok(Self {
            scope: assets::hash_part(&digest(runtime.scope().as_bytes()))?.into(),
            artifact: assets::hash_part(runtime.artifact().id())?.into(),
            name: instance.installation,
            binding: instance.branding,
            brand: LoadedBrand::for_instance(runtime.instance_path())?,
        })
    }
    pub fn check_binding(&self, runtime: &Runtime) -> Result<()> {
        ensure!(
            Instance::load(runtime.instance_path())?.branding == self.binding,
            crate::error::Failure::BrandingBindingChanged
        );
        Ok(())
    }
    pub fn name(&self) -> &str {
        self.brand
            .as_ref()
            .map_or(&self.name, |brand| &brand.bundle.brand.name)
    }
    fn brand_prefix(&self) -> Result<Option<String>> {
        self.brand
            .as_ref()
            .map(|brand| {
                Ok(format!(
                    "/assets/instance/{}/{}",
                    self.scope,
                    assets::hash_part(&brand.id)?
                ))
            })
            .transpose()
    }
    pub fn theme_url(&self) -> Result<Option<String>> {
        Ok(self
            .brand_prefix()?
            .map(|prefix| format!("{prefix}/theme.css")))
    }
    pub fn logo_url(&self) -> Result<Option<String>> {
        match &self.brand {
            Some(brand) => brand
                .bundle
                .assets
                .get("logo")
                .map(|asset| {
                    Ok(format!(
                        "{}/logo/{}.png",
                        self.brand_prefix()?.context("brand prefix")?,
                        assets::hash_part(&asset.digest)?
                    ))
                })
                .transpose(),
            None => Ok(None),
        }
    }
    pub fn app_url(&self, runtime: &Runtime, key: &str) -> Result<String> {
        let asset = runtime
            .artifact()
            .contract()
            .assets
            .get(key)
            .context("unregistered_app_asset")?;
        Ok(format!(
            "/assets/app/{}/{}/{key}/{}.png",
            self.scope,
            self.artifact,
            assets::hash_part(&asset.digest)?
        ))
    }
    pub fn resource_prefix(&self) -> String {
        format!("/assets/ui/{}/{}/", self.scope, self.artifact)
    }
    pub fn resource_url(&self, runtime: &Runtime, path: &str) -> Result<String> {
        ensure!(
            runtime
                .artifact()
                .contract()
                .web_resources
                .contains_key(path),
            "unregistered_ui_resource"
        );
        Ok(format!("{}{path}", self.resource_prefix()))
    }
    pub fn stylesheet_url(&self, runtime: &Runtime) -> Result<Option<String>> {
        if let Some(definition) = &runtime.artifact().contract().app_contract {
            return (!definition.presentation.stylesheet.is_empty())
                .then(|| self.resource_url(runtime, &definition.presentation.stylesheet))
                .transpose();
        }
        runtime
            .artifact()
            .contract()
            .web_resources
            .contains_key("app.css")
            .then(|| self.resource_url(runtime, "app.css"))
            .transpose()
    }
    pub fn script_url(&self, runtime: &Runtime) -> Result<Option<String>> {
        if let Some(definition) = &runtime.artifact().contract().app_contract {
            return (!definition.presentation.script.is_empty())
                .then(|| self.resource_url(runtime, &definition.presentation.script))
                .transpose();
        }
        runtime
            .artifact()
            .contract()
            .web_resources
            .contains_key("app.js")
            .then(|| self.resource_url(runtime, "app.js"))
            .transpose()
    }
    pub fn image(&self, runtime: &Runtime, key: &str, alt: &str, icon: bool) -> Result<Markup> {
        let asset = runtime
            .artifact()
            .contract()
            .assets
            .get(key)
            .context("unregistered_app_asset")?;
        let url = self.app_url(runtime, key)?;
        Ok(
            html! { img class=(if icon { "app-icon" } else { "app-image" }) src=(url) alt=(alt) aria-hidden=[icon.then_some("true")] width=(asset.width) height=(asset.height) decoding="async"; },
        )
    }
    pub fn serve(
        &self,
        runtime: &Runtime,
        path: &str,
        session: Option<&Session>,
        headers: &HeaderMap,
    ) -> Result<Response> {
        self.check_binding(runtime)?;
        if path.starts_with("/assets/platform/") {
            return platform(path, headers);
        }
        if path.starts_with("/assets/app/") || path.starts_with("/assets/ui/") {
            let session = session.context(crate::error::Failure::SignInRequired)?;
            ensure!(
                runtime
                    .artifact()
                    .contract()
                    .pages
                    .iter()
                    .any(|page| runtime.authorize(&page.operation, &session.actor).is_ok()),
                crate::error::Failure::Forbidden
            );
            for (key, asset) in &runtime.artifact().contract().assets {
                if path == self.app_url(runtime, key)? {
                    return blob(
                        runtime.artifact().directory(),
                        asset,
                        CachePolicy::PrivateRevalidate,
                        headers,
                    );
                }
            }
            for (key, resource) in &runtime.artifact().contract().web_resources {
                if path == self.resource_url(runtime, key)? {
                    return bytes(
                        &resource.media_type,
                        crate::web_resources::read_blob(runtime.artifact().directory(), resource)?,
                        CachePolicy::PrivateRevalidate,
                        headers,
                    );
                }
            }
        } else if let Some(brand) = &self.brand {
            let prefix = self.brand_prefix()?.context("brand prefix")?;
            if path == format!("{prefix}/theme.css") {
                return bytes(
                    "text/css",
                    brand.bundle.brand.css()?.into_bytes(),
                    CachePolicy::PublicImmutable,
                    headers,
                );
            }
            for (key, asset) in &brand.bundle.assets {
                if path == format!("{prefix}/{key}/{}.png", assets::hash_part(&asset.digest)?) {
                    return blob(
                        &brand.directory,
                        asset,
                        CachePolicy::PublicImmutable,
                        headers,
                    );
                }
            }
        }
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
fn blob(
    directory: &std::path::Path,
    asset: &Asset,
    policy: CachePolicy,
    headers: &HeaderMap,
) -> Result<Response> {
    bytes(
        &asset.media_type,
        assets::read_blob(directory, asset)?,
        policy,
        headers,
    )
}

enum CachePolicy {
    PublicImmutable,
    PublicRevalidate,
    PrivateRevalidate,
}

fn bytes(
    kind: &str,
    bytes: impl AsRef<[u8]> + Into<Body>,
    policy: CachePolicy,
    headers: &HeaderMap,
) -> Result<Response> {
    // Callers authorize and verify packaged bytes before evaluating a validator.
    // A matching ETag must never bypass a revoked grant or a corrupted artifact.
    let etag = format!("\"{}\"", digest(bytes.as_ref()));
    let length = bytes.as_ref().len();
    let mut response = if if_none_match(headers, etag.as_bytes()) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = Body::into_response(bytes.into());
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, kind.parse()?);
        response
    };
    // On 304, Content-Length describes the selected representation, not its
    // empty response body. Supplying it prevents Axum from inserting zero.
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, length.into());
    response.headers_mut().insert(header::ETAG, etag.parse()?);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        match policy {
            CachePolicy::PublicImmutable => "public, max-age=31536000, immutable",
            CachePolicy::PublicRevalidate => "no-cache",
            CachePolicy::PrivateRevalidate => "private, no-cache",
        }
        .parse()?,
    );
    if matches!(policy, CachePolicy::PrivateRevalidate) {
        response
            .headers_mut()
            .insert(header::VARY, "Cookie".parse()?);
    }
    Ok(response)
}

// If-None-Match uses weak comparison, supports lists and repeated field lines,
// and allows commas inside quoted tags. Ignore malformed conditions rather than
// incorrectly approving reuse of a cached response.
fn if_none_match(headers: &HeaderMap, etag: &[u8]) -> bool {
    let values = headers.get_all(header::IF_NONE_MATCH);
    let mut matched = false;
    for value in &values {
        let mut remaining = value.as_bytes().trim_ascii();
        if remaining == b"*" {
            return values.iter().count() == 1;
        }
        while !remaining.is_empty() {
            if let Some(rest) = remaining.strip_prefix(b",") {
                remaining = rest.trim_ascii_start();
                continue;
            }
            remaining = remaining.strip_prefix(b"W/").unwrap_or(remaining);
            let Some(rest) = remaining.strip_prefix(b"\"") else {
                return false;
            };
            let Some(end) = rest.iter().position(|byte| *byte == b'"') else {
                return false;
            };
            if !rest[..end]
                .iter()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e | 0x80..=0xff))
            {
                return false;
            }
            matched |= &remaining[..end + 2] == etag;
            remaining = rest[end + 1..].trim_ascii_start();
            if !remaining.is_empty() {
                let Some(rest) = remaining.strip_prefix(b",") else {
                    return false;
                };
                remaining = rest.trim_ascii_start();
            }
        }
    }
    matched
}

// Only platform chrome is embedded. No app asset names or company brands live
// in this catalog; those are resolved exclusively from admitted bundles above.
fn platform(path: &str, headers: &HeaderMap) -> Result<Response> {
    let (kind, data): (&str, &[u8]) = match path {
        "/assets/platform/web.css" => ("text/css", include_bytes!("../../../assets/web.css")),
        "/assets/platform/api-docs.css" => {
            ("text/css", include_bytes!("../../../assets/api-docs.css"))
        }
        "/assets/platform/api-docs.js" => (
            "text/javascript",
            include_bytes!("../../../assets/api-docs.js"),
        ),
        "/assets/platform/forms.js" => (
            "text/javascript",
            include_bytes!("../../../assets/forms.js"),
        ),
        "/assets/platform/datastar-1.0.1.js" => (
            "text/javascript",
            include_bytes!("../../../assets/datastar-1.0.1.js"),
        ),
        "/assets/platform/icons/link.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/link.svg"),
        ),
        "/assets/platform/icons/history.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/history.svg"),
        ),
        "/assets/platform/icons/log-out.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/log-out.svg"),
        ),
        "/assets/platform/icons/arrow-up-right.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/arrow-up-right.svg"),
        ),
        "/assets/platform/icons/list-filter.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/list-filter.svg"),
        ),
        "/assets/platform/icons/shield-check.svg" => (
            "image/svg+xml",
            include_bytes!("../../../assets/icons/shield-check.svg"),
        ),
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };
    // These paths are not content-addressed, even when a filename has a version.
    bytes(kind, data, CachePolicy::PublicRevalidate, headers)
}
