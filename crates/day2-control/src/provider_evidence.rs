//! Provider-neutral evidence vocabulary. Opaque tokens support equality, never
//! ordering. A qualified barrier is an explicit trusted-adapter attestation;
//! its receipt digest is an identity, not authentication or a synthesized proof.
use crate::{BindingRef, Digest};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OpaqueToken(String);

impl OpaqueToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OpaqueToken {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && value.len() <= 256
                && value.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid bounded opaque provider token"
        );
        Ok(Self(value))
    }
}

impl From<OpaqueToken> for String {
    fn from(value: OpaqueToken) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevisionToken {
    Ordered {
        stream: Digest,
        sequence: NonZeroU64,
    },
    Opaque {
        token: OpaqueToken,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevisionRelation {
    Same,
    Newer,
    Older,
    Incomparable,
}

impl RevisionToken {
    /// Compare only after the enclosing resource identity has been checked.
    /// Ordered streams also carry an epoch/stream identity to prevent sequence
    /// resets or unrelated providers from acquiring an accidental total order.
    pub fn relation(&self, prior: &Self) -> RevisionRelation {
        use RevisionRelation::*;
        match (self, prior) {
            (
                Self::Ordered { stream, sequence },
                Self::Ordered {
                    stream: old_stream,
                    sequence: old,
                },
            ) if stream == old_stream => match sequence.cmp(old) {
                std::cmp::Ordering::Less => Older,
                std::cmp::Ordering::Equal => Same,
                std::cmp::Ordering::Greater => Newer,
            },
            (Self::Opaque { token }, Self::Opaque { token: old }) if token == old => Same,
            _ => Incomparable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadBarrier {
    pub authority: BindingRef,
    pub resource: Digest,
    pub after_effect: Option<Digest>,
    pub receipt: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateEvidence {
    Observed {
        revision: RevisionToken,
    },
    Qualified {
        revision: RevisionToken,
        barrier: ReadBarrier,
    },
}

impl StateEvidence {
    pub fn revision(&self) -> &RevisionToken {
        match self {
            Self::Observed { revision } | Self::Qualified { revision, .. } => revision,
        }
    }

    pub fn barrier(&self) -> Option<&ReadBarrier> {
        match self {
            Self::Observed { .. } => None,
            Self::Qualified { barrier, .. } => Some(barrier),
        }
    }

    pub fn require(
        &self,
        authority: &BindingRef,
        resource: &Digest,
        after_effect: Option<&Digest>,
    ) -> Result<()> {
        let Some(barrier) = self.barrier() else {
            anyhow::bail!("unqualified provider state")
        };
        ensure!(
            &barrier.authority == authority
                && &barrier.resource == resource
                && barrier.after_effect.as_ref() == after_effect,
            "provider read barrier scope mismatch"
        );
        Ok(())
    }
}

/// A matching request response, distinct from a later observed postcondition.
/// Native hosts separately validate effect identity and qualified read barriers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAcknowledgement {
    pub effect: Digest,
    pub revision: RevisionToken,
    pub receipt: Digest,
}

/// Captured when preparing a deployment, not invented by its later drain proof.
/// The generation identifies the execution scope including controller descendants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentIncarnation {
    pub controller: OpaqueToken,
    pub generation: OpaqueToken,
}

impl DeploymentIncarnation {
    pub fn validate(&self) -> Result<()> {
        OpaqueToken::try_from(self.controller.as_str().to_owned())?;
        OpaqueToken::try_from(self.generation.as_str().to_owned())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_tokens_and_unrelated_streams_never_acquire_an_order() {
        let opaque = |token: &str| RevisionToken::Opaque {
            token: token.to_owned().try_into().unwrap(),
        };
        assert_eq!(
            opaque("999").relation(&opaque("10")),
            RevisionRelation::Incomparable
        );
        assert_eq!(
            opaque("same").relation(&opaque("same")),
            RevisionRelation::Same
        );
        let ordered = |stream, sequence| RevisionToken::Ordered {
            stream: Digest::new(stream),
            sequence: NonZeroU64::new(sequence).unwrap(),
        };
        assert_eq!(
            ordered(b"one", 2).relation(&ordered(b"one", 1)),
            RevisionRelation::Newer
        );
        assert_eq!(
            ordered(b"one", 1).relation(&ordered(b"one", 2)),
            RevisionRelation::Older
        );
        assert_eq!(
            ordered(b"two", 10).relation(&ordered(b"one", 1)),
            RevisionRelation::Incomparable
        );
        assert_eq!(
            opaque("1").relation(&ordered(b"one", 1)),
            RevisionRelation::Incomparable
        );
    }

    #[test]
    fn weak_state_cannot_become_a_scoped_qualified_read() -> Result<()> {
        let authority = BindingRef {
            id: "resources".to_owned().try_into()?,
            revision: Digest::new(b"binding"),
        };
        let resource = Digest::new(b"version");
        let effect = Digest::new(b"disable");
        let revision = RevisionToken::Opaque {
            token: "etag".to_owned().try_into()?,
        };
        assert!(
            StateEvidence::Observed {
                revision: revision.clone()
            }
            .require(&authority, &resource, Some(&effect))
            .is_err()
        );
        let value = StateEvidence::Qualified {
            revision,
            barrier: ReadBarrier {
                authority: authority.clone(),
                resource: resource.clone(),
                after_effect: Some(effect.clone()),
                receipt: Digest::new(b"qualified-protocol"),
            },
        };
        value.require(&authority, &resource, Some(&effect))?;
        assert!(value.require(&authority, &resource, None).is_err());
        assert!(
            value
                .require(&authority, &Digest::new(b"other-version"), Some(&effect))
                .is_err()
        );
        let other = BindingRef {
            revision: Digest::new(b"changed"),
            ..authority
        };
        assert!(value.require(&other, &resource, Some(&effect)).is_err());
        Ok(())
    }

    #[test]
    fn evidence_rejects_invalid_tokens_zero_sequences_and_extra_fields() {
        for token in ["", "two words", "line\nbreak"] {
            assert!(OpaqueToken::try_from(token.to_owned()).is_err());
        }
        let stream = Digest::new(b"stream");
        assert!(
            serde_json::from_value::<RevisionToken>(
                serde_json::json!({"kind":"ordered","stream":stream,"sequence":0})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RevisionToken>(
                serde_json::json!({"kind":"opaque","token":"etag","ordered":true})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<StateEvidence>(serde_json::json!({"kind":"observed","revision":{"kind":"opaque","token":"etag"},"qualified":true})).is_err());
    }
}
