//! Startup composition owned by the native provider host. Static instance
//! parsing cannot supply either reviewed code or independently live readiness.

use super::{admission, approval_keys, approval_registry, connect, shell_transport};
use crate::{artifact::Instance, store::Runtime};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;

pub(crate) struct Providers {
    pub catalog: admission::ReviewedCatalog,
    pub readiness: Arc<dyn admission::OutboundReadiness>,
    pub registrations: Option<Arc<super::registration::GoogleReadiness>>,
}

impl Providers {
    /// Publishing reviewed code does not populate registration readiness. A
    /// native qualification session must supply fresh non-serializable receipts.
    pub(crate) fn google(readiness: Arc<super::registration::GoogleReadiness>) -> Result<Self> {
        Ok(Self {
            catalog: super::google::catalog()?,
            readiness: readiness.clone(),
            registrations: Some(readiness),
        })
    }
}

struct Registrations {
    authority: Arc<admission::ArtifactApprovalAuthority>,
    readiness: Arc<super::registration::GoogleReadiness>,
}

impl shell_transport::RegistrationSink for Registrations {
    fn receive(
        &self,
        proof: &super::registration::publication::Publication,
        app: &str,
        identity: &crate::iap::Verified,
        now: i64,
    ) -> Result<()> {
        self.authority
            .receive_registration(proof, app, identity, &self.readiness, now)
    }
}

pub(crate) fn require_providers(
    instance: &Instance,
    app: &str,
    edge: bool,
    providers: Option<&Providers>,
) -> Result<bool> {
    let binding = instance
        .apps
        .get(app)
        .context("OAuth app binding missing")?;
    if binding.oauth_connections.is_empty() {
        return Ok(false);
    }
    ensure!(edge, "OAuth requires the qualified edge host");
    ensure!(providers.is_some(), "OAuth provider host is not published");
    instance.security_edge()?;
    instance
        .oauth_shell_transport
        .as_ref()
        .context("OAuth shell transport missing")?
        .validate()?;
    Ok(true)
}

pub(crate) fn app_receiver(
    runtime: &Runtime,
    providers: &Providers,
) -> Result<Arc<shell_transport::AppApprovalReceiver>> {
    let selected = admission::QualifiedConnections::from_runtime(runtime, &providers.catalog)?;
    let instance = selected.instance().clone();
    let authority = Arc::new(admission::ArtifactApprovalAuthority::with_gcp(
        selected,
        providers.readiness.clone(),
        Arc::new(approval_keys::GkeMetadataAccessTokens::new()?),
    )?);
    runtime.initialize()?;
    connect::install_schema(&crate::store::open(runtime.db())?)?;
    let backend = Arc::new(approval_registry::StoredAppApprovals::new(
        runtime.app().into(),
        runtime.db().to_path_buf(),
        authority.clone(),
    )?);
    let receiver = shell_transport::AppApprovalReceiver::from_instance(&instance, backend)?;
    match &providers.registrations {
        Some(readiness) => receiver.with_registrations(Arc::new(Registrations {
            authority,
            readiness: readiness.clone(),
        })),
        None => Ok(receiver),
    }
}
