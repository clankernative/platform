//! The one anonymous native-login bootstrap route. It projects public instance
//! metadata only; it cannot create a session or exercise application authority.
use crate::{artifact::Instance, store::Runtime};
use anyhow::{Result, ensure};
use axum::{
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub const PATH: &str = "/.well-known/day2-cli.json";

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Discovery {
    document: Document,
    iap_audience: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct Document {
    schema_version: u8,
    instance_origin: String,
    installation: String,
    environment: String,
    identity: Identity,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct Identity {
    scheme: crate::artifact::IdentityScheme,
    desktop_client_id: day2_capabilities::cli_login::DesktopClientId,
    hosted_domain: String,
}

impl Discovery {
    pub(crate) fn load(runtime: &Runtime, origin: &str) -> Result<Option<Self>> {
        let instance = Instance::load(runtime.instance_path())?;
        let Some(client) = instance
            .identity
            .as_ref()
            .and_then(|identity| identity.cli_desktop_client_id.as_ref())
        else {
            return Ok(None);
        };
        let (identity, edge) = instance.edge(runtime.app())?;
        ensure!(
            edge.origin == origin
                && instance.scope(runtime.app())? == runtime.scope()
                && Some(identity.hosted_domain.as_str()) == runtime.hosted_domain(),
            crate::error::Failure::InstallationChanged
        );
        Ok(Some(Self {
            iap_audience: edge.iap_audience.clone(),
            document: Document {
                schema_version: 1,
                instance_origin: edge.origin.clone(),
                installation: instance.installation.clone(),
                environment: instance.environment.clone(),
                identity: Identity {
                    scheme: identity.scheme,
                    desktop_client_id: client.clone(),
                    hosted_domain: identity.hosted_domain.clone(),
                },
            },
        }))
    }

    pub(crate) fn serve(
        &self,
        runtime: &Runtime,
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> Result<Response> {
        if method != Method::GET {
            return Ok((StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET")]).into_response());
        }
        ensure!(
            uri.query().is_none() && body.is_empty(),
            crate::error::Failure::InvalidInput
        );
        // A live configuration change needs a fresh listener admission. Never
        // publish stale metadata or silently select a replacement registration.
        ensure!(
            Self::load(runtime, &self.document.instance_origin)?.as_ref() == Some(self),
            crate::error::Failure::InstallationChanged
        );
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            serde_json::to_vec(&self.document)?,
        )
            .into_response())
    }
}
