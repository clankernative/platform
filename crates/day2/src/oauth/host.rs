//! Startup composition owned by the native provider host. Static instance
//! parsing cannot supply either reviewed code or independently live readiness.

use super::{admission, approval_keys, approval_registry, shell_transport};
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
    runtime: Arc<Runtime>,
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
        super::native_management::with_runtime_consumer(
            &self.runtime,
            super::native_management::RuntimePhase::Registration,
            |current| {
                current.require_runtime(&self.runtime)?;
                self.authority
                    .receive_registration(proof, app, identity, &self.readiness, now)
            },
        )
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
    runtime: &mut Arc<Runtime>,
    providers: &Providers,
) -> Result<Arc<shell_transport::AppApprovalReceiver>> {
    // Configure the actual stable Runtime before sharing it with any retained
    // consumer. An unexpected alias refuses rather than cloning/replacing it.
    let current = Arc::get_mut(runtime).context("OAuth Runtime escaped before configuration")?;
    let selected = admission::QualifiedConnections::from_runtime(current, &providers.catalog)?;
    let instance = selected.instance().clone();
    let tokens = match &instance.oauth_runtime {
        Some(config) => approval_keys::GkeMetadataAccessTokens::selected(
            &config
                .apps
                .iter()
                .find(|(name, _)| name.as_str() == current.app())
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
    // Serving admitted the store, including this app's private OAuth schema,
    // in `deployment::admit_store` before it builds the receiver.
    let backend = Arc::new(approval_registry::UnavailableAppApprovals::new(
        current.app().into(),
    )?);
    current.connections = Some(authority.clone());
    let receiver = shell_transport::AppApprovalReceiver::from_instance(&instance, backend)?;
    let receiver = match &providers.registrations {
        Some(readiness) => receiver.with_registrations(Arc::new(Registrations {
            runtime: Arc::clone(runtime),
            authority: authority.clone(),
            readiness: readiness.clone(),
        })),
        None => Ok(receiver),
    }?;
    let receiver = receiver.with_management(Arc::new(super::management::app::Manager::new(
        Arc::clone(runtime),
        authority,
    )))?;
    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnusedReadiness;

    impl admission::OutboundReadiness for UnusedReadiness {
        fn current(
            &self,
            _: &day2_capabilities::oauth::OutboundConnectionBinding,
            _: &day2_capabilities::oauth::ConnectionSlotKey,
            _: i64,
            _: &mut admission::SubjectReader<'_, '_, '_, '_>,
        ) -> Result<Option<super::super::profiles::OutboundInstanceEvidence>> {
            anyhow::bail!("test readiness must not be used during configuration")
        }
    }

    #[test]
    fn app_receiver_refuses_runtime_aliases_before_loading_configuration() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (runtime, _, _) = admission::tests::management_fixture(directory.path())?;
        let original = runtime.instance_path().to_path_buf();
        let unavailable = directory.path().join("unavailable-instance.json");
        std::fs::rename(&original, &unavailable)?;
        let mut runtime = Arc::new(runtime);
        let pointer = Arc::as_ptr(&runtime);
        let providers = Providers {
            catalog: admission::ReviewedCatalog::new(Vec::new())?,
            readiness: Arc::new(UnusedReadiness),
            registrations: None,
        };
        let alias = Arc::clone(&runtime);
        let error = app_receiver(&mut runtime, &providers).err().unwrap();
        assert_eq!(
            error.to_string(),
            "OAuth Runtime escaped before configuration"
        );
        assert_eq!(Arc::as_ptr(&runtime), pointer);
        assert!(Arc::ptr_eq(&runtime, &alias));
        assert!(runtime.connections.is_none());
        drop(alias);
        let weak = Arc::downgrade(&runtime);
        let error = app_receiver(&mut runtime, &providers).err().unwrap();
        assert_eq!(
            error.to_string(),
            "OAuth Runtime escaped before configuration"
        );
        assert_eq!(Arc::as_ptr(&runtime), pointer);
        assert!(runtime.connections.is_none());
        drop(weak);
        // Without aliases the same production function reaches the actual
        // missing file. A cloning/make_mut fallback would have done so above.
        let error = app_receiver(&mut runtime, &providers).err().unwrap();
        assert_ne!(
            error.to_string(),
            "OAuth Runtime escaped before configuration"
        );
        assert_eq!(Arc::as_ptr(&runtime), pointer);
        assert!(runtime.connections.is_none());
        std::fs::rename(unavailable, original)?;
        Ok(())
    }
}
