//! Startup composition owned by the native provider host. Static instance
//! parsing cannot supply either reviewed code or independently live readiness.

use super::{admission, approval_keys, approval_registry, connect, shell_transport};
use crate::{artifact::Instance, store::Runtime};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;

pub(crate) struct Providers {
    pub catalog: admission::ReviewedCatalog,
    pub readiness: Arc<dyn admission::OutboundReadiness>,
    pub registrations: Option<Arc<super::registration::ProviderReadiness>>,
}

impl Providers {
    pub(crate) fn from_gke_runtime(runtime: &Runtime) -> Result<Self> {
        let catalog = super::catalog::reviewed()?;
        let selected = admission::QualifiedConnections::from_runtime(runtime, &catalog)?;
        let config = selected
            .instance()
            .oauth_runtime
            .as_ref()
            .context("OAuth runtime not selected")?;
        let app = config
            .apps
            .iter()
            .find(|(name, _)| name.as_str() == runtime.app())
            .context("OAuth runtime app missing")?;
        let tokens = Arc::new(approval_keys::GkeMetadataAccessTokens::selected(
            &app.1.service_account,
        )?);
        let facts = Arc::new(admission::live::Facts::from_gke(
            selected,
            runtime.db().to_path_buf(),
            tokens,
        )?);
        Self::reviewed(Arc::new(super::registration::ProviderReadiness::new(facts)))
    }

    /// Publishing reviewed code does not populate registration readiness. A
    /// native qualification session must supply fresh non-serializable receipts.
    pub(crate) fn reviewed(readiness: Arc<super::registration::ProviderReadiness>) -> Result<Self> {
        Ok(Self {
            catalog: super::catalog::reviewed()?,
            readiness: readiness.clone(),
            registrations: Some(readiness),
        })
    }
}

struct Registrations {
    authority: Arc<admission::ArtifactApprovalAuthority>,
    readiness: Arc<super::registration::ProviderReadiness>,
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
    ensure!(
        providers.is_some() || instance.oauth_runtime.is_some(),
        "OAuth provider host is not published"
    );
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
    let tokens = match &instance.oauth_runtime {
        Some(config) => approval_keys::GkeMetadataAccessTokens::selected(
            &config
                .apps
                .iter()
                .find(|(name, _)| name.as_str() == runtime.app())
                .context("OAuth runtime app missing")?
                .1
                .service_account,
        )?,
        None => approval_keys::GkeMetadataAccessTokens::new()?,
    };
    let authority = Arc::new(admission::ArtifactApprovalAuthority::with_gcp(
        selected,
        providers.readiness.clone(),
        Arc::new(tokens),
    )?);
    runtime.initialize()?;
    let db = crate::store::open(runtime.db())?;
    super::schema::admit_with_runtime_hook(&db, connect::install_schema)?;
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
