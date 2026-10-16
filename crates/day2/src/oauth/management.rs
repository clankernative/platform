//! Native product connection management. Wire views are data; only a fresh
//! purpose-bound shell proof and the owning app's current checks authorize work.

use crate::{authority_state::AuthorityStamp, iap};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) mod app;
pub(super) mod shell;

pub(super) const PREFIX: &str = "/oauth/connections/";
pub(super) const SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Connect,
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotFence {
    pub generation: i64,
    pub epoch: i64,
    pub token_version: i64,
    pub account: String,
    pub affinity: String,
    pub profile: String,
    pub status: String,
}

/// Immutable original pending context, supplied by the owning app host. It has
/// no provider code, token, verifier, private pathname or session credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct View {
    pub id: String,
    pub app: String,
    pub scope: String,
    pub artifact: String,
    pub authority: AuthorityStamp,
    pub registration: String,
    pub logical_id: String,
    pub action: Action,
    pub human: String,
    pub subject: String,
    pub selection: Digest,
    pub slot: Digest,
    pub fence: Option<SlotFence>,
    pub binding_namespace: String,
    pub usage: String,
    pub scopes: BTreeSet<String>,
    pub app_origin: String,
    pub shell_origin: String,
    pub callback_url: String,
    pub challenge: Digest,
    pub created_at: i64,
    pub expires_at: i64,
}

impl View {
    pub(super) fn validate(&self, identity: &iap::Verified, now: i64) -> Result<()> {
        for name in [
            &self.id,
            &self.registration,
            &self.logical_id,
            &self.binding_namespace,
        ] {
            super::connect::identifier(name)?;
        }
        day2_contracts::names::identifier(&self.app)?;
        ensure!(
            self.human == identity.email
                && self.subject == identity.subject
                && !self.subject.is_empty()
                && self.subject.len() <= 256
                && self.created_at >= 0
                && now >= self.created_at
                && now < self.expires_at
                && self.expires_at.checked_sub(self.created_at) == Some(SECONDS)
                && !self.usage.is_empty()
                && self.usage.len() <= 1024
                && !self.usage.chars().any(char::is_control)
                && !self.scopes.is_empty()
                && self.scopes.len() <= 32,
            "OAuth management context refused"
        );
        for scope in &self.scopes {
            ensure!(
                !scope.is_empty()
                    && scope.len() <= 256
                    && !scope.chars().any(|c| c.is_control() || c.is_whitespace()),
                "OAuth management scope refused"
            );
        }
        super::shell_transport::origin(&self.app_origin)?;
        super::shell_transport::origin(&self.shell_origin)?;
        ensure!(
            self.app_origin != self.shell_origin,
            "OAuth management origins collide"
        );
        let callback = url::Url::parse(&self.callback_url)?;
        ensure!(
            format!("{}/", callback.origin().ascii_serialization()) == self.shell_origin
                && callback.path().starts_with("/_day2/oauth/callback/")
                && callback.query().is_none()
                && callback.fragment().is_none()
                && callback.username().is_empty()
                && callback.password().is_none(),
            "OAuth management callback refused"
        );
        match (self.action, &self.fence) {
            (Action::Connect, None) => {}
            (Action::Disconnect, Some(fence)) => ensure!(
                fence.generation > 0
                    && fence.epoch > 0
                    && fence.epoch < i64::MAX
                    && fence.token_version > 0
                    && fence.status == "active",
                "OAuth management slot refused"
            ),
            // This first management profile never replaces an incumbent or
            // adopts a disabled/restored slot. A new installation is explicit.
            _ => anyhow::bail!("OAuth replacement profile unavailable"),
        }
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("oauth-product-management-pending-v1", self))
    }
}

/// Authenticated private transport data. Parsing this never creates a native
/// fresh-human proof; the app verifies its exact current selected shell key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attestation {
    pub view: Digest,
    pub session: Digest,
    pub authenticated_at: i64,
    pub confirmed_at: i64,
    pub key_version: String,
    mac: String,
}

impl Attestation {
    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "oauth-product-management-confirmation-v1",
            &self.view,
            &self.session,
            self.authenticated_at,
            self.confirmed_at,
            &self.key_version,
        ))?)
    }

    pub(super) fn sign(
        view: &View,
        proof: &super::fresh_auth::VerifiedAuthTime,
        identity: &iap::Verified,
        session: Digest,
        key: &[u8; 32],
        version: String,
        now: i64,
    ) -> Result<Self> {
        view.validate(identity, now)?;
        proof.require_intent(
            &super::fresh_auth::FreshIntent::management(view, identity)?,
            identity,
        )?;
        proof.require_current(now)?;
        let mut value = Self {
            view: view.digest()?,
            session,
            authenticated_at: proof.authenticated_at(),
            confirmed_at: now,
            key_version: version,
            mac: String::new(),
        };
        value.mac = crate::hex(
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &value.bytes()?).as_ref(),
        );
        Ok(value)
    }

    pub(super) fn verify(
        &self,
        view: &View,
        identity: &iap::Verified,
        key: &[u8; 32],
        version: &str,
        now: i64,
    ) -> Result<()> {
        view.validate(identity, now)?;
        ensure!(
            self.view == view.digest()?
                && self.key_version == version
                && self.authenticated_at > view.created_at
                && self.confirmed_at >= self.authenticated_at
                && self.confirmed_at < view.expires_at
                && now >= self.confirmed_at
                && now - self.authenticated_at <= SECONDS
                && self.mac.len() == 64
                && self
                    .mac
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "OAuth management confirmation refused"
        );
        let mut mac = [0u8; 32];
        for (index, pair) in self.mac.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |value: u8| {
                if value <= b'9' {
                    value - b'0'
                } else {
                    value - b'a' + 10
                }
            };
            mac[index] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &self.bytes()?,
            &mac,
        )
        .map_err(|_| anyhow::anyhow!("OAuth management signature refused"))
    }
}
