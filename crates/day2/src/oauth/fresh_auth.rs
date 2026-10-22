//! Original pending-purpose ownership for the existing Google verifier. Context
//! is data, not readiness or company-enrollment authority. Only a verified
//! callback can create the production proof carried by the shell session.

use super::{shell_oidc, shell_transport::ApprovalView};
use crate::{iap, managed_credentials::browser::Pending, store::Runtime};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

/// Durable original context is DATA. It cannot reconstruct a fresh-human owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialContextData {
    pub(crate) purpose: CredentialContextPurpose,
    pub(crate) scope: String,
    pub(crate) app: String,
    pub(crate) artifact: String,
    pub(crate) app_origin: String,
    pub(crate) shell_origin: String,
    pub(crate) attempt: String,
    pub(crate) pending_challenge: Digest,
    pub(crate) human: String,
    pub(crate) subject: String,
    pub(crate) pending_created_at: i64,
    pub(crate) pending_expires_at: i64,
    pub(crate) authenticated_at: i64,
    pub(crate) proof_deadline: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialContextPurpose {
    CredentialIntent,
}

impl CredentialContextData {
    pub(crate) fn validate_origins(&self) -> Result<()> {
        ensure!(
            admitted_origin(&self.app_origin)? == self.app_origin
                && admitted_origin(&self.shell_origin)? == self.shell_origin,
            "invalid original credential origins"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(in crate::oauth) enum FreshPurpose {
    OAuthApproval,
    CredentialIntent,
    OAuthConnect,
    OAuthDisconnect,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
enum Context {
    OAuth {
        app: String,
        preview: Digest,
        shell_origin: String,
        expires_at: i64,
    },
    Credential {
        scope: String,
        app: String,
        artifact: String,
        app_origin: String,
        shell_origin: String,
        expires_at: i64,
    },
    Management {
        app: String,
        action: super::management::Action,
        view: Digest,
        shell_origin: String,
        expires_at: i64,
    },
}

/// Captured from the real pending lookup before the Google authorization starts.
/// The credential challenge hashes the complete immutable Pending, including its
/// active authority stamp and binding. Mutable Confirm/Reveal/Ack outcomes are
/// deliberately not part of this original intent.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FreshIntent {
    context: Context,
    attempt: String,
    challenge: Digest,
    human: String,
    subject: String,
    created_at: i64,
}

impl FreshIntent {
    pub(crate) fn commitment(&self) -> Result<Digest> {
        Digest::of(&("original-native-fresh-intent-v1", self))
    }

    /// Purpose DATA only. This never supplies authentication, a current role,
    /// an original lifetime, storage authority or execution permission.
    pub(crate) fn require_oauth_management(&self) -> Result<()> {
        ensure!(
            matches!(
                self.purpose(),
                FreshPurpose::OAuthConnect | FreshPurpose::OAuthDisconnect
            ),
            "OAuth management original purpose required"
        );
        Ok(())
    }

    pub(super) fn human(&self) -> &str {
        &self.human
    }

    pub(super) fn subject(&self) -> &str {
        &self.subject
    }

    pub(in crate::oauth) fn app(&self) -> &str {
        match &self.context {
            Context::OAuth { app, .. }
            | Context::Credential { app, .. }
            | Context::Management { app, .. } => app,
        }
    }

    pub(in crate::oauth) fn management(
        view: &super::management::View,
        identity: &iap::Verified,
    ) -> Result<Self> {
        view.validate(identity, view.created_at)?;
        Ok(Self {
            context: Context::Management {
                app: view.app.clone(),
                action: view.action,
                view: view.digest()?,
                shell_origin: admitted_origin(&view.shell_origin)?,
                expires_at: view.expires_at,
            },
            attempt: view.id.clone(),
            challenge: view.challenge.clone(),
            human: view.human.clone(),
            subject: view.subject.clone(),
            created_at: view.created_at,
        })
    }

    pub(in crate::oauth) fn approval(
        view: &ApprovalView,
        identity: &iap::Verified,
    ) -> Result<Self> {
        view.validate(identity)?;
        Ok(Self {
            context: Context::OAuth {
                app: view.app.clone(),
                preview: view.digest()?,
                shell_origin: admitted_origin(&view.shell_origin)?,
                expires_at: view.expires_at,
            },
            attempt: view.attempt().into(),
            challenge: view.challenge().clone(),
            human: view.human().into(),
            subject: identity.subject.clone(),
            created_at: view.quarantined_at(),
        })
    }

    pub(crate) fn credential(
        runtime: &Runtime,
        pending: &Pending,
        identity: &iap::Verified,
        app_origin: &str,
        shell_origin: &str,
    ) -> Result<Self> {
        ensure!(
            pending.actor == identity.email && pending.artifact == runtime.artifact().id(),
            "fresh credential owner or artifact changed"
        );
        Ok(Self {
            context: Context::Credential {
                scope: runtime.scope().into(),
                app: runtime.app().into(),
                artifact: runtime.artifact().id().into(),
                app_origin: admitted_origin(app_origin)?,
                shell_origin: admitted_origin(shell_origin)?,
                expires_at: pending.expires_at,
            },
            attempt: pending.attempt.clone(),
            challenge: pending.challenge()?,
            human: pending.actor.clone(),
            subject: identity.subject.clone(),
            created_at: pending.created_at,
        })
    }

    pub(in crate::oauth) fn purpose(&self) -> FreshPurpose {
        match &self.context {
            Context::OAuth { .. } => FreshPurpose::OAuthApproval,
            Context::Credential { .. } => FreshPurpose::CredentialIntent,
            Context::Management { action, .. } => match action {
                super::management::Action::Connect => FreshPurpose::OAuthConnect,
                super::management::Action::Disconnect => FreshPurpose::OAuthDisconnect,
            },
        }
    }

    pub(in crate::oauth) fn attempt(&self) -> &str {
        &self.attempt
    }

    pub(in crate::oauth) fn challenge(&self) -> &Digest {
        &self.challenge
    }

    pub(in crate::oauth) fn created_at(&self) -> i64 {
        self.created_at
    }

    pub(in crate::oauth) fn deadline(&self) -> i64 {
        match &self.context {
            Context::OAuth { expires_at, .. }
            | Context::Credential { expires_at, .. }
            | Context::Management { expires_at, .. } => *expires_at,
        }
    }

    pub(in crate::oauth) fn require_identity(&self, identity: &iap::Verified) -> Result<()> {
        ensure!(
            self.human == identity.email && self.subject == identity.subject,
            "fresh intent identity changed"
        );
        Ok(())
    }

    pub(in crate::oauth) fn require_shell_origin(&self, origin: &str) -> Result<()> {
        let expected = match &self.context {
            Context::OAuth { shell_origin, .. }
            | Context::Credential { shell_origin, .. }
            | Context::Management { shell_origin, .. } => shell_origin,
        };
        ensure!(
            expected == &admitted_origin(origin)?,
            "fresh intent security origin changed"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::oauth) fn fixture_oauth(
        identity: &iap::Verified,
        attempt: &str,
        challenge: &Digest,
        origin: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<Self> {
        ensure!(
            created_at >= 0 && expires_at > created_at,
            "parser fixture original interval"
        );
        Ok(Self {
            context: Context::OAuth {
                app: "parserfixture".into(),
                preview: Digest::new(b"OIDC parser fixture; cannot match an app view"),
                shell_origin: admitted_origin(origin)?,
                expires_at,
            },
            attempt: attempt.into(),
            challenge: challenge.clone(),
            human: identity.email.clone(),
            subject: identity.subject.clone(),
            created_at,
        })
    }
}

fn admitted_origin(value: &str) -> Result<String> {
    ensure!(value.len() <= 1024, "fresh intent origin too large");
    let url = url::Url::parse(value)?;
    let origin = url.origin().ascii_serialization();
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && (value == origin || value == format!("{origin}/")),
        "invalid fresh intent origin"
    );
    Ok(origin)
}

/// Owns only verified metadata and the original intent/lifetime. No raw JWT,
/// serialization, clone, or production scalar constructor is available.
pub(crate) struct VerifiedAuthTime {
    google: shell_oidc::Reauthenticated,
}

impl VerifiedAuthTime {
    /// Project the actual original, purpose-bound proof into historical DATA.
    /// Deserializing this result never creates VerifiedAuthTime.
    pub(crate) fn credential_confirmation_context(
        &self,
        current: &FreshIntent,
        identity: &iap::Verified,
        entry_now: i64,
    ) -> Result<CredentialContextData> {
        self.require_credential_authentication(current, identity, entry_now)?;
        let intent = self.google.intent();
        let Context::Credential {
            scope,
            app,
            artifact,
            app_origin,
            shell_origin,
            expires_at,
        } = &intent.context
        else {
            anyhow::bail!("credential original purpose required");
        };
        Ok(CredentialContextData {
            purpose: CredentialContextPurpose::CredentialIntent,
            scope: scope.clone(),
            app: app.clone(),
            artifact: artifact.clone(),
            app_origin: app_origin.clone(),
            shell_origin: shell_origin.clone(),
            attempt: intent.attempt.clone(),
            pending_challenge: intent.challenge.clone(),
            human: intent.human.clone(),
            subject: intent.subject.clone(),
            pending_created_at: intent.created_at,
            pending_expires_at: *expires_at,
            authenticated_at: self.authenticated_at(),
            proof_deadline: self.deadline()?,
        })
    }

    pub(in crate::oauth) fn from_google(google: shell_oidc::Reauthenticated) -> Self {
        Self { google }
    }

    /// The credential consumer has the same mandatory native producer as the
    /// OAuth consumers. Signed ordering DATA cannot mint a session, historical
    /// confirmation context or credential approval while that producer is absent.
    pub(crate) fn require_credential_authentication(
        &self,
        current: &FreshIntent,
        identity: &iap::Verified,
        entry_now: i64,
    ) -> Result<()> {
        ensure!(
            self.purpose() == FreshPurpose::CredentialIntent
                && current.purpose() == FreshPurpose::CredentialIntent,
            "credential original purpose required"
        );
        self.require_intent(current, identity)?;
        self.require_current(entry_now)?;
        self.google.require_post_pending_authentication()
    }

    pub(in crate::oauth) fn require_management_authentication(
        &self,
        current: &mut super::native_management::Consumer<'_, '_, '_>,
    ) -> Result<()> {
        self.google.intent().require_oauth_management()?;
        self.google.require_management_authentication(current)
    }

    /// Observation DATA validation only; this cannot replace the consuming
    /// native producer or authenticate a session/signature by itself.
    pub(in crate::oauth) fn validate_management_observation(&self) -> Result<()> {
        self.google.validate_management_observation()
    }

    pub(in crate::oauth) fn purpose(&self) -> FreshPurpose {
        self.google.intent().purpose()
    }

    pub(crate) fn attempt(&self) -> &str {
        self.google.intent().attempt()
    }

    pub(crate) fn challenge(&self) -> &Digest {
        self.google.intent().challenge()
    }

    pub(crate) fn human(&self) -> &str {
        self.google.human()
    }

    pub(crate) fn subject(&self) -> &str {
        self.google.subject()
    }

    pub(crate) fn authenticated_at(&self) -> i64 {
        self.google.authenticated_at()
    }

    pub(crate) fn deadline(&self) -> Result<i64> {
        self.google.deadline()
    }

    pub(crate) fn require_current(&self, now: i64) -> Result<()> {
        self.google.require_current(now)
    }

    pub(crate) fn observe_current(&self, entry_now: i64) -> Result<i64> {
        self.google.observe_current(entry_now)
    }

    pub(crate) fn require_intent(
        &self,
        current: &FreshIntent,
        identity: &iap::Verified,
    ) -> Result<()> {
        current.require_identity(identity)?;
        ensure!(
            self.google.intent() == current
                && self.human() == identity.email
                && self.subject() == identity.subject,
            "fresh pending purpose or context changed"
        );
        Ok(())
    }

    pub(in crate::oauth) fn require_approval(
        &self,
        view: &ApprovalView,
        identity: &iap::Verified,
    ) -> Result<()> {
        self.require_intent(&FreshIntent::approval(view, identity)?, identity)?;
        self.google.require_post_pending_authentication()
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $trait:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::check;
        }};
    }
    assert_not_impl!(VerifiedAuthTime, Clone);
    assert_not_impl!(VerifiedAuthTime, Copy);
    assert_not_impl!(VerifiedAuthTime, Default);
    assert_not_impl!(VerifiedAuthTime, std::fmt::Debug);
    assert_not_impl!(VerifiedAuthTime, serde::Serialize);
    assert_not_impl!(VerifiedAuthTime, serde::Deserialize<'static>);
    assert_not_impl!(VerifiedAuthTime, AsRef<str>);
    assert_not_impl!(VerifiedAuthTime, AsRef<[u8]>);
    assert_not_impl!(VerifiedAuthTime, std::ops::Deref);
    assert_not_impl!(VerifiedAuthTime, std::borrow::Borrow<str>);
    assert_not_impl!(VerifiedAuthTime, std::borrow::Borrow<[u8]>);
};

#[cfg(test)]
mod purpose_tests {
    use super::*;

    #[test]
    fn matching_actor_attempt_and_challenge_cannot_admit_approval_or_credential_purposes()
    -> Result<()> {
        let mut intent = FreshIntent::fixture_oauth(
            &iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            },
            "same-original-attempt",
            &Digest::new(b"same-original-challenge"),
            "https://security.example.com",
            5,
            305,
        )?;
        assert!(intent.require_oauth_management().is_err());
        let approval = intent.commitment()?;
        intent.context = Context::Credential {
            scope: "example/development/app".into(),
            app: "app".into(),
            artifact: Digest::new(b"artifact").as_str().to_owned(),
            app_origin: "https://app.example.com".into(),
            shell_origin: "https://security.example.com".into(),
            expires_at: 305,
        };
        assert!(intent.require_oauth_management().is_err());
        assert_ne!(intent.commitment()?, approval);
        let mut connect = None;
        for action in [
            super::super::management::Action::Connect,
            super::super::management::Action::Disconnect,
        ] {
            intent.context = Context::Management {
                app: "app".into(),
                action,
                view: Digest::new(b"same-view"),
                shell_origin: "https://security.example.com".into(),
                expires_at: 305,
            };
            intent.require_oauth_management()?;
            let commitment = intent.commitment()?;
            if let Some(connect) = connect.as_ref() {
                assert_ne!(&commitment, connect);
            } else {
                connect = Some(commitment);
            }
        }
        Ok(())
    }
}
