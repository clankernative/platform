use day2_kernel::{
    BindingRef, BuildPlan, BuildProfile, Digest, GitOid, Name,
    kernel::{
        BuildFailureEvidence, CredentialPresence, EffectKind, FailureCode, Observation, State,
        VerificationEvidence, effect_id,
    },
};

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

fn plan() -> BuildPlan {
    BuildPlan {
        version: 1,
        company: name("example"),
        app: name("links"),
        request: name("kernel-boundary"),
        commit: GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned()).unwrap(),
        profile: BuildProfile {
            source: BindingRef::pin(name("source"), &"repository-v1").unwrap(),
            builder: BindingRef::pin(name("builder"), &"runner-v1").unwrap(),
            durability: BindingRef::pin(name("durability"), &"queue-v1").unwrap(),
            platform: Digest::new(b"platform"),
            recipe: Digest::new(b"recipe"),
        },
    }
}

fn verification(plan: &BuildPlan, source: &Digest) -> VerificationEvidence {
    VerificationEvidence {
        plan: plan.fingerprint().unwrap(),
        source: source.clone(),
        platform: plan.profile.platform.clone(),
        recipe: plan.profile.recipe.clone(),
        builder: plan.profile.builder.clone(),
        artifact: Digest::new(b"artifact"),
        checks: Digest::new(b"checks"),
        credential_presence: CredentialPresence::Absent,
    }
}

fn failure(evidence: &VerificationEvidence) -> BuildFailureEvidence {
    BuildFailureEvidence {
        plan: evidence.plan.clone(),
        source: evidence.source.clone(),
        platform: evidence.platform.clone(),
        recipe: evidence.recipe.clone(),
        builder: evidence.builder.clone(),
        checks: evidence.checks.clone(),
        code: FailureCode::Contract,
    }
}

#[test]
fn successful_build_requires_ordered_observations_and_matching_publication() {
    let plan = plan();
    let source = Digest::new(b"source");
    let state = State::Accepted;
    assert_eq!(state.next_effect(), Some(EffectKind::FetchSource));
    let state = state
        .observe(
            &plan,
            &Observation::Source {
                source: source.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        state,
        State::SourceReady {
            source: source.clone()
        }
    );
    assert_eq!(state.next_effect(), Some(EffectKind::VerifyArtifact));
    let evidence = verification(&plan, &source);
    let receipt = Digest::of(&evidence).unwrap();
    let state = state
        .observe(&plan, &Observation::Verified { evidence })
        .unwrap();
    assert_eq!(state.next_effect(), Some(EffectKind::PublishCheck));
    assert!(
        state
            .observe(
                &plan,
                &Observation::Published {
                    evidence: Digest::new(b"another-evidence"),
                    publication: Digest::new(b"publication"),
                }
            )
            .is_err()
    );
    let publication = Digest::new(b"publication");
    let state = state
        .observe(
            &plan,
            &Observation::Published {
                evidence: receipt.clone(),
                publication: publication.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        state,
        State::Succeeded {
            artifact: Digest::new(b"artifact"),
            evidence: receipt,
            publication,
        }
    );
    assert_eq!(state.next_effect(), None);
}

#[test]
fn failed_build_requires_publication_of_the_bound_failure_evidence() {
    let plan = plan();
    let source = Digest::new(b"source");
    let evidence = failure(&verification(&plan, &source));
    let receipt = Digest::of(&evidence).unwrap();
    let state = State::SourceReady {
        source: source.clone(),
    }
    .observe(&plan, &Observation::BuildRejected { evidence })
    .unwrap();
    assert_eq!(
        state,
        State::VerificationFailed {
            source,
            evidence: receipt.clone(),
            code: FailureCode::Contract,
        }
    );
    assert_eq!(state.next_effect(), Some(EffectKind::PublishCheck));
    assert!(
        state
            .observe(
                &plan,
                &Observation::Published {
                    evidence: Digest::new(b"another-evidence"),
                    publication: Digest::new(b"publication"),
                }
            )
            .is_err()
    );
    assert_eq!(
        state
            .observe(
                &plan,
                &Observation::Published {
                    evidence: receipt,
                    publication: Digest::new(b"publication"),
                }
            )
            .unwrap(),
        State::Failed {
            code: FailureCode::Contract
        }
    );
}

#[test]
fn successful_and_failed_verification_reject_every_mismatched_binding() {
    let plan = plan();
    let source = Digest::new(b"source");
    let state = State::SourceReady {
        source: source.clone(),
    };
    for field in 0..6 {
        let mut evidence = verification(&plan, &source);
        match field {
            0 => evidence.plan = Digest::new(b"another-plan"),
            1 => evidence.source = Digest::new(b"another-source"),
            2 => evidence.platform = Digest::new(b"another-platform"),
            3 => evidence.recipe = Digest::new(b"another-recipe"),
            4 => evidence.builder.id = name("another-builder"),
            _ => evidence.builder.revision = Digest::new(b"another-builder-revision"),
        }
        assert!(
            state
                .observe(
                    &plan,
                    &Observation::BuildRejected {
                        evidence: failure(&evidence),
                    }
                )
                .is_err(),
            "failure accepted mismatched field {field}"
        );
        assert!(
            state
                .observe(&plan, &Observation::Verified { evidence })
                .is_err(),
            "verification accepted mismatched field {field}"
        );
    }
}

#[test]
fn terminal_states_reject_every_observation_and_have_no_effect() {
    let plan = plan();
    let source = Digest::new(b"source");
    let verified = verification(&plan, &source);
    let observations = [
        Observation::Source { source },
        Observation::Verified {
            evidence: verified.clone(),
        },
        Observation::BuildRejected {
            evidence: failure(&verified),
        },
        Observation::Published {
            evidence: Digest::of(&verified).unwrap(),
            publication: Digest::new(b"publication"),
        },
        Observation::Rejected {
            code: FailureCode::Denied,
        },
    ];
    for state in [
        State::Succeeded {
            artifact: verified.artifact.clone(),
            evidence: Digest::of(&verified).unwrap(),
            publication: Digest::new(b"publication"),
        },
        State::Failed {
            code: FailureCode::Contract,
        },
        State::Cancelled,
    ] {
        assert_eq!(state.next_effect(), None);
        for observation in &observations {
            assert!(state.observe(&plan, observation).is_err());
        }
    }
}

#[test]
fn publication_cannot_skip_source_or_verification() {
    let plan = plan();
    let source = Digest::new(b"source");
    let evidence = verification(&plan, &source);
    let publication = Observation::Published {
        evidence: Digest::of(&evidence).unwrap(),
        publication: Digest::new(b"publication"),
    };
    assert!(State::Accepted.observe(&plan, &publication).is_err());
    assert!(
        State::Accepted
            .observe(
                &plan,
                &Observation::Verified {
                    evidence: evidence.clone(),
                }
            )
            .is_err()
    );
    assert!(
        State::Accepted
            .observe(
                &plan,
                &Observation::BuildRejected {
                    evidence: failure(&evidence),
                }
            )
            .is_err()
    );
    assert!(
        State::SourceReady { source }
            .observe(&plan, &publication)
            .is_err()
    );
}

#[test]
fn plan_validation_preserves_request_identity_and_exact_execution_fingerprints() {
    let original = plan();
    let mut changed = original.clone();
    changed.commit =
        GitOid::try_from("abcdef1234567890abcdef1234567890abcdef12".to_owned()).unwrap();
    assert_eq!(
        changed.execution_id().unwrap(),
        original.execution_id().unwrap()
    );
    assert_ne!(
        changed.fingerprint().unwrap(),
        original.fingerprint().unwrap()
    );
    for kind in [
        EffectKind::FetchSource,
        EffectKind::VerifyArtifact,
        EffectKind::PublishCheck,
    ] {
        assert_ne!(
            effect_id(&original, kind).unwrap(),
            effect_id(&changed, kind).unwrap()
        );
    }
    let mut invalid = original.clone();
    invalid.version = 2;
    assert!(invalid.validate().is_err());
    assert!(invalid.fingerprint().is_err());
    for pair in 0..3 {
        let mut invalid = original.clone();
        match pair {
            0 => invalid.profile.source.id = invalid.profile.builder.id.clone(),
            1 => invalid.profile.source.id = invalid.profile.durability.id.clone(),
            _ => invalid.profile.builder.id = invalid.profile.durability.id.clone(),
        }
        assert!(invalid.validate().is_err());
        assert!(effect_id(&invalid, EffectKind::FetchSource).is_err());
    }
}

#[test]
fn wire_contracts_reject_unknown_fields_and_preserve_historical_credential_classification() {
    assert!(serde_json::from_str::<State>(r#"{"state":"untrusted_state"}"#).is_err());
    let invalid = serde_json::json!({
        "state": "source_ready",
        "source": Digest::new(b"source"),
        "untrusted_claim": true,
    });
    assert!(serde_json::from_value::<State>(invalid).is_err());
    let plan = plan();
    let evidence = verification(&plan, &Digest::new(b"source"));
    let mut wire = serde_json::to_value(&evidence).unwrap();
    wire.as_object_mut().unwrap().remove("credential_presence");
    let historical: VerificationEvidence = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(historical.credential_presence, CredentialPresence::Unknown);
    assert!(
        serde_json::to_value(&historical)
            .unwrap()
            .get("credential_presence")
            .is_none()
    );
    wire.as_object_mut()
        .unwrap()
        .insert("untrusted_claim".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<VerificationEvidence>(wire).is_err());
    let mut wire = serde_json::to_value(plan).unwrap();
    wire.as_object_mut()
        .unwrap()
        .insert("untrusted_claim".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<BuildPlan>(wire).is_err());
}
