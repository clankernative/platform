//! The native canary receipt stays affine and local. Only this adapter can
//! attest its bounded public facts for the authenticated shell-to-app channel.
//! Parsing a publication is not readiness; current selection, source signature,
//! canary identity and the original expiry are checked before a native import.

use super::{Receipt, TargetIdentity, VALID_SECONDS};
use crate::oauth::effects::Instant;
use crate::{
    iap,
    oauth::{admission, approval_registry, profiles},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{BindingRef, Digest, oauth::SecurityOriginRef};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publication {
    claim: Claim,
    mac: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    version: u32,
    app: String,
    selection: Digest,
    instance: BindingRef,
    namespace: String,
    requirement: Digest,
    logical_id: String,
    shell: Shell,
    registration: BindingRef,
    checked_at: i64,
    expires_at: i64,
    key_version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Shell {
    instance: BindingRef,
    origin: SecurityOriginRef,
    origin_url: String,
    qualification: Digest,
}

impl Shell {
    fn evidence(&self) -> profiles::SecurityShellEvidence {
        profiles::SecurityShellEvidence {
            instance: self.instance.clone(),
            origin: self.origin.clone(),
            origin_url: self.origin_url.clone(),
            qualification: self.qualification.clone(),
        }
    }
}

impl Publication {
    pub(in crate::oauth) fn app(&self) -> &str {
        &self.claim.app
    }

    pub(in crate::oauth) fn id(&self) -> Result<Digest> {
        Digest::of(&("oauth-registration-publication-id-v1", self))
    }
}

fn signed_bytes(claim: &Claim) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        "oauth-registration-publication-v1",
        claim,
    ))?)
}

fn selection(binding: &day2_capabilities::oauth::OutboundConnectionBinding) -> Result<Digest> {
    Digest::of(&("oauth-registration-publication-selection-v1", binding))
}

fn key(
    keys: &dyn approval_registry::ApprovalKeyProvider,
    reference: &approval_registry::ApprovalKeyRef,
) -> Result<hmac::Key> {
    let purpose = approval_registry::ApprovalKeyPurpose::ShellAttestation;
    let material = keys.load(reference, purpose)?;
    ensure!(
        material.binding == reference.binding
            && material.version == reference.version
            && material.purpose == purpose,
        "registration publication key mismatch"
    );
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &material.bytes))
}

pub(in crate::oauth) fn attest(
    receipt: &Receipt,
    selected: &admission::QualifiedConnections,
    keys: &dyn approval_registry::ApprovalKeyProvider,
    now: i64,
) -> Result<Publication> {
    let started = Instant::now();
    ensure!(receipt.fresh(now), "registration receipt expired");
    let (app, binding, reference, target) = selected.registration_publication(
        &receipt.registration.registration,
        &receipt.target.namespace,
        &receipt.target.shell,
    )?;
    ensure!(
        receipt.registration == target.registration_evidence()?
            && receipt.target.instance == target.instance
            && receipt.target.requirement == target.permission.requirement
            && receipt.target.logical_id == target.logical_id,
        "registration receipt selection mismatch"
    );
    let shell = &receipt.target.shell;
    let claim = Claim {
        version: 1,
        app: app.into(),
        selection: selection(binding)?,
        instance: receipt.target.instance.clone(),
        namespace: receipt.target.namespace.clone(),
        requirement: receipt.target.requirement.clone(),
        logical_id: receipt.target.logical_id.clone(),
        shell: Shell {
            instance: shell.instance.clone(),
            origin: shell.origin.clone(),
            origin_url: shell.origin_url.clone(),
            qualification: shell.qualification.clone(),
        },
        registration: receipt.registration.registration.clone(),
        checked_at: receipt.checked_at,
        expires_at: receipt
            .checked_at
            .checked_add(VALID_SECONDS)
            .context("registration clock overflow")?,
        key_version: reference.version.clone(),
    };
    let key = key(keys, reference)?;
    let at = now
        .checked_add(i64::try_from(started.elapsed().as_secs())?)
        .context("registration clock overflow")?;
    ensure!(
        receipt.fresh(at),
        "registration receipt expired during signing"
    );
    Ok(Publication {
        mac: URL_SAFE_NO_PAD.encode(hmac::sign(&key, &signed_bytes(&claim)?).as_ref()),
        claim,
    })
}

pub(in crate::oauth) fn verify(
    proof: &Publication,
    app: &str,
    identity: &iap::Verified,
    selected: &admission::QualifiedConnections,
    keys: &dyn approval_registry::ApprovalKeyProvider,
    now: i64,
) -> Result<Receipt> {
    let started = Instant::now();
    let claim = &proof.claim;
    ensure!(
        claim.version == 1
            && claim.app == app
            && claim.checked_at > 0
            && claim.expires_at
                == claim
                    .checked_at
                    .checked_add(VALID_SECONDS)
                    .context("registration clock overflow")?
            && now >= claim.checked_at
            && now < claim.expires_at,
        "registration publication expired or misrouted"
    );
    let shell = claim.shell.evidence();
    let (selected_app, binding, reference, target) =
        selected.registration_publication(&claim.registration, &claim.namespace, &shell)?;
    ensure!(
        selected_app == app
            && claim.registration == target.registration_evidence()?.registration
            && claim.selection == selection(binding)?
            && claim.instance == target.instance
            && claim.requirement == target.permission.requirement
            && claim.logical_id == target.logical_id
            && claim.key_version == reference.version
            && identity.subject == format!("accounts.google.com:{}", target.canary_subject),
        "registration publication does not match selected canary or binding"
    );
    let signature = URL_SAFE_NO_PAD.decode(&proof.mac)?;
    ensure!(
        signature.len() == 32,
        "invalid registration publication signature"
    );
    hmac::verify(&key(keys, reference)?, &signed_bytes(claim)?, &signature)
        .map_err(|_| anyhow::anyhow!("invalid registration publication signature"))?;
    let at = now
        .checked_add(i64::try_from(started.elapsed().as_secs())?)
        .context("registration clock overflow")?;
    ensure!(
        at < claim.expires_at,
        "registration publication expired during verification"
    );
    // The destination gets only the source's remaining lease. It cannot turn
    // five seconds left on the source into five minutes at the destination.
    let remaining = Duration::from_secs(u64::try_from(claim.expires_at - now)?);
    let deadline = started
        .checked_add(remaining)
        .context("registration deadline overflow")?;
    ensure!(
        Instant::now() < deadline,
        "registration publication deadline reached"
    );
    Ok(Receipt {
        registration: target.registration_evidence()?,
        target: TargetIdentity {
            instance: target.instance,
            namespace: claim.namespace.clone(),
            shell,
            requirement: target.permission.requirement,
            logical_id: target.logical_id,
        },
        checked_at: claim.checked_at,
        deadline,
    })
}

#[cfg(test)]
pub(in crate::oauth) mod tests {
    use super::super::{
        GoogleReadiness,
        tests::{Server, campaign, responses, session},
    };
    use super::*;
    use crate::oauth::{
        admission::OutboundReadiness,
        approval_registry::{
            ApprovalKeyMaterial, ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef,
        },
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    pub(in crate::oauth) fn fixture() -> Result<(admission::QualifiedConnections, Receipt)> {
        let (selected, shell) = admission::tests::publication_fixture()?;
        let target = selected.google_targets(&shell)?.remove(0);
        let server = Server::new(responses())?;
        let mut native = session(target, &server)?;
        campaign(&mut native)?;
        Ok((selected, native.finish()?))
    }

    #[derive(Default)]
    pub(in crate::oauth) struct Keys {
        calls: AtomicUsize,
        delay: Duration,
    }
    impl Keys {
        pub(in crate::oauth) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            assert_eq!(purpose, ApprovalKeyPurpose::ShellAttestation);
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: reference.version.clone(),
                purpose,
                bytes: [91; 32],
            })
        }
    }

    pub(in crate::oauth) fn identity() -> iap::Verified {
        iap::Verified {
            email: "canary@example.com".into(),
            subject: "accounts.google.com:google-canary-subject".into(),
        }
    }

    #[test]
    fn native_publication_replay_cannot_renew_virtual_or_wall_expiry() -> Result<()> {
        use crate::oauth::{effects, registration, simulation::World};
        for seed in 0..8 {
            let run = || -> Result<_> {
                let world = World::new(seed);
                world.script(responses(), None);
                effects::scope(world.clone(), || {
                    let (selected, shell) = admission::tests::publication_fixture()?;
                    let target = selected.google_targets(&shell)?.remove(0);
                    let codes = crate::oauth::simulation::registration_codes(&target)?;
                    let mut native = registration::Session::new(
                        target,
                        codes,
                        Arc::new(crate::oauth::registration::tests::TokensSource(
                            AtomicUsize::new(0),
                        )),
                    )?;
                    for action in crate::oauth::simulation::REGISTRATION_ACTIONS {
                        native.call(crate::automation::Request {
                            protocol: 1,
                            action: action.into(),
                            input: "{}".into(),
                        })?;
                    }
                    let receipt = native.finish()?;
                    let keys = Keys::default();
                    let now = effects::wall_time()?;
                    let proof = attest(&receipt, &selected, &keys, now)?;
                    let imported = verify(&proof, "workspace", &identity(), &selected, &keys, now)?;
                    assert!(imported.fresh(now));
                    world.advance(299);
                    let near_expiry = verify(
                        &proof,
                        "workspace",
                        &identity(),
                        &selected,
                        &keys,
                        now + 299,
                    )?;
                    assert!(near_expiry.fresh(now + 299));
                    world.advance(1);
                    assert!(!receipt.fresh(now));
                    assert!(!near_expiry.fresh(now + 299));
                    assert!(
                        verify(
                            &proof,
                            "workspace",
                            &identity(),
                            &selected,
                            &keys,
                            now + 300
                        )
                        .is_err()
                    );
                    assert!(attest(&receipt, &selected, &keys, now).is_err());
                    Ok((serde_json::to_value(proof)?, world.requests()))
                })
            };
            assert_eq!(run()?, run()?);
        }
        Ok(())
    }

    #[test]
    fn native_publication_requires_exact_canary_selection_signature_and_original_expiry()
    -> Result<()> {
        let (selected, receipt) = fixture()?;
        let now = receipt.checked_at;
        let keys = Keys::default();
        let proof = attest(&receipt, &selected, &keys, now)?;
        let imported = verify(
            &proof,
            "workspace",
            &identity(),
            &selected,
            &keys,
            now + 295,
        )?;
        assert_eq!(imported.registration, receipt.registration);
        assert_eq!(imported.checked_at, now);
        assert!(imported.deadline <= Instant::now() + Duration::from_secs(5));
        let encoded = serde_json::to_vec(&proof)?;
        for forbidden in [
            "private-fixture-client-canary",
            "private-fixture-code-canary",
            "private-fixture-access-canary",
            "private-fixture-refresh-canary",
        ] {
            assert!(!String::from_utf8_lossy(&encoded).contains(forbidden));
        }
        let before = keys.calls.load(Ordering::SeqCst);
        for at in [now - 1, now + VALID_SECONDS] {
            assert!(verify(&proof, "workspace", &identity(), &selected, &keys, at).is_err());
        }
        assert!(verify(&proof, "other_app", &identity(), &selected, &keys, now).is_err());
        let mut wrong_human = identity();
        wrong_human.subject = "accounts.google.com:another".into();
        assert!(verify(&proof, "workspace", &wrong_human, &selected, &keys, now).is_err());
        assert_eq!(keys.calls.load(Ordering::SeqCst), before);
        for field in [
            "app",
            "selection",
            "namespace",
            "requirement",
            "logical_id",
            "key_version",
            "checked_at",
            "expires_at",
        ] {
            let mut value = serde_json::to_value(&proof)?;
            value["claim"][field] = match field {
                "checked_at" | "expires_at" => serde_json::json!(now + 1),
                "selection" | "requirement" => serde_json::to_value(Digest::of(&"substitution")?)?,
                _ => serde_json::json!("substitution"),
            };
            let changed = crate::json::decode::<Publication>(&serde_json::to_vec(&value)?)?;
            assert!(
                verify(&changed, "workspace", &identity(), &selected, &keys, now).is_err(),
                "accepted {field}"
            );
        }
        let mut value = serde_json::to_value(&proof)?;
        value["mac"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
        let changed = crate::json::decode::<Publication>(&serde_json::to_vec(&value)?)?;
        assert!(verify(&changed, "workspace", &identity(), &selected, &keys, now).is_err());
        value["claim"]["ready"] = serde_json::json!(true);
        assert!(crate::json::decode::<Publication>(&serde_json::to_vec(&value)?).is_err());
        let duplicate =
            String::from_utf8(encoded)?.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(crate::json::decode::<Publication>(duplicate.as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn expiry_during_key_acquisition_cannot_import_or_attest_readiness() -> Result<()> {
        let (selected, mut receipt) = fixture()?;
        let now = receipt.checked_at;
        let proof = attest(&receipt, &selected, &Keys::default(), now)?;
        let slow = Keys {
            delay: Duration::from_millis(1100),
            ..Keys::default()
        };
        assert!(
            verify(
                &proof,
                "workspace",
                &identity(),
                &selected,
                &slow,
                now + 299
            )
            .is_err()
        );
        receipt.deadline = Instant::now();
        let keys = Keys::default();
        assert!(attest(&receipt, &selected, &keys, now).is_err());
        assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    struct Facts {
        evidence: profiles::OutboundInstanceEvidence,
        available: AtomicBool,
    }
    impl OutboundReadiness for Facts {
        fn current(
            &self,
            _: &day2_capabilities::oauth::OutboundConnectionBinding,
            _: &day2_capabilities::oauth::ConnectionSlotKey,
            _: i64,
        ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
            Ok(self
                .available
                .load(Ordering::SeqCst)
                .then(|| self.evidence.clone()))
        }
    }

    #[test]
    fn imported_registration_still_requires_independent_facts_and_replay_cannot_renew_it()
    -> Result<()> {
        let (selected, receipt) = fixture()?;
        let now = receipt.checked_at;
        let proof = attest(&receipt, &selected, &Keys::default(), now)?;
        let binding = &selected.instance().apps["workspace"].oauth_connections["calendar"];
        let fixture = super::super::tests::fixture()?;
        let mut evidence = fixture.evidence;
        evidence.instance = receipt.target.instance.clone();
        evidence.shell = receipt.target.shell.clone();
        evidence.binding_namespace = receipt.target.namespace.clone();
        evidence.registration = receipt.registration.clone();
        let facts = Arc::new(Facts {
            evidence,
            available: AtomicBool::new(false),
        });
        let readiness = GoogleReadiness::new(facts.clone());
        readiness.publish(verify(
            &proof,
            "workspace",
            &identity(),
            &selected,
            &Keys::default(),
            now,
        )?)?;
        assert!(readiness.current(binding, &fixture.slot, now)?.is_none());
        facts.available.store(true, Ordering::SeqCst);
        assert!(readiness.current(binding, &fixture.slot, now)?.is_some());
        let id = binding.registration.id.as_str();
        readiness
            .receipts
            .write()
            .unwrap()
            .get_mut(id)
            .unwrap()
            .deadline = Instant::now();
        readiness.publish(verify(
            &proof,
            "workspace",
            &identity(),
            &selected,
            &Keys::default(),
            now,
        )?)?;
        assert!(readiness.current(binding, &fixture.slot, now)?.is_none());
        assert!(
            GoogleReadiness::new(facts)
                .current(binding, &fixture.slot, now)?
                .is_none()
        );
        Ok(())
    }
}
