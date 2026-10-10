//! Original pending-purpose ownership for the existing Google verifier. Context
//! is data, not readiness or company-enrollment authority. Only a verified
//! callback can create the production proof carried by the shell session.

use super::{shell_oidc, shell_transport::ApprovalView};
use crate::{iap, managed_credentials::browser::Pending, store::Runtime};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::oauth) enum FreshPurpose {
    OAuthApproval,
    CredentialIntent,
}

#[derive(Clone, PartialEq, Eq)]
enum Context {
    OAuth {
        preview: Digest,
        shell_origin: String,
    },
    Credential {
        scope: String,
        app: String,
        artifact: String,
        app_origin: String,
        shell_origin: String,
        expires_at: i64,
    },
}

/// Captured from the real pending lookup before the Google authorization starts.
/// The credential challenge hashes the complete immutable Pending, including its
/// active authority stamp and binding. Mutable Confirm/Reveal/Ack outcomes are
/// deliberately not part of this original intent.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FreshIntent {
    context: Context,
    attempt: String,
    challenge: Digest,
    human: String,
    subject: String,
    created_at: i64,
}

impl FreshIntent {
    pub(in crate::oauth) fn approval(
        view: &ApprovalView,
        identity: &iap::Verified,
    ) -> Result<Self> {
        view.validate(identity)?;
        Ok(Self {
            context: Context::OAuth {
                preview: view.digest()?,
                shell_origin: admitted_origin(&view.shell_origin)?,
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

    pub(in crate::oauth) fn deadline(&self) -> Option<i64> {
        match &self.context {
            Context::OAuth { .. } => None,
            Context::Credential { expires_at, .. } => Some(*expires_at),
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
            Context::OAuth { shell_origin, .. } | Context::Credential { shell_origin, .. } => {
                shell_origin
            }
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
    ) -> Result<Self> {
        Ok(Self {
            context: Context::OAuth {
                preview: Digest::new(b"OIDC parser fixture; cannot match an app view"),
                shell_origin: admitted_origin(origin)?,
            },
            attempt: attempt.into(),
            challenge: challenge.clone(),
            human: identity.email.clone(),
            subject: identity.subject.clone(),
            created_at: 0,
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
    pub(in crate::oauth) fn from_google(google: shell_oidc::Reauthenticated) -> Self {
        Self { google }
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
        self.require_intent(&FreshIntent::approval(view, identity)?, identity)
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
