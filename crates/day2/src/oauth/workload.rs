//! Dedicated shell workload identity. Receiver URLs come from the same instance
//! selection as the transport; a browser cannot select an IAM signing audience.

use super::{
    approval_keys::{AccessTokenSource, GkeMetadataAccessTokens},
    shell_transport::{PATH, PrivateBearerSource},
};
use crate::{artifact::Instance, iap_workload};
use anyhow::{Context, Result, ensure};
use reqwest::header::HeaderValue;
use std::{collections::BTreeMap, sync::Arc};
use url::Url;

struct Tokens(Arc<dyn AccessTokenSource>);

impl iap_workload::AccessTokens for Tokens {
    fn authorization(&self) -> Result<HeaderValue> {
        let token = self.0.access_token()?;
        ensure!(
            !token.is_empty() && token.len() <= 8192 && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid OAuth workload access token"
        );
        let mut header = HeaderValue::from_str(&format!("Bearer {token}"))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

pub(crate) struct IapWorkload {
    targets: BTreeMap<String, Url>,
    signer: iap_workload::Signer,
}

impl IapWorkload {
    pub(crate) fn from_gke_instance(instance: &Instance) -> Result<Self> {
        Self::from_instance(instance, Arc::new(GkeMetadataAccessTokens::new()?))
    }

    fn from_instance(instance: &Instance, tokens: Arc<dyn AccessTokenSource>) -> Result<Self> {
        let instance = Instance::from_bytes(&serde_json::to_vec(instance)?)?;
        let transport = instance
            .oauth_shell_transport
            .as_ref()
            .context("OAuth shell transport missing")?;
        instance.security_edge()?;
        let targets: BTreeMap<_, _> = instance
            .apps
            .iter()
            .filter(|(_, binding)| !binding.oauth_connections.is_empty())
            .map(|(app, binding)| {
                let edge = binding
                    .edge
                    .as_ref()
                    .context("OAuth receiver app edge missing")?;
                Ok((
                    app.clone(),
                    Url::parse(&format!("{}/", edge.origin))?.join(PATH)?,
                ))
            })
            .collect::<Result<_>>()?;
        let signer = iap_workload::Signer::new(
            &transport.service_account,
            targets.values().cloned().collect(),
            Arc::new(Tokens(tokens)),
        )?;
        Ok(Self { targets, signer })
    }
}

impl PrivateBearerSource for IapWorkload {
    fn bearer(&self, app: &str, receiver: &Url) -> Result<String> {
        ensure!(
            self.targets.get(app) == Some(receiver),
            "OAuth workload receiver is not selected"
        );
        Ok(self.signer.sign_for(receiver)?.as_str().into())
    }
}
