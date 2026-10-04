use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::{BuildProfile, Instance},
    kernel::{CredentialPresence, EffectKind, Observation, State, VerificationEvidence},
};
use std::collections::BTreeMap;

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

#[test]
fn existing_instance_and_kernel_paths_use_the_extracted_production_types() {
    let instance = Instance {
        version: 1,
        company: name("example"),
        build_profiles: BTreeMap::from([(
            name("default"),
            BuildProfile {
                source: BindingRef::pin(name("source"), &"repository-v1").unwrap(),
                builder: BindingRef::pin(name("builder"), &"runner-v1").unwrap(),
                durability: BindingRef::pin(name("durability"), &"queue-v1").unwrap(),
                platform: Digest::new(b"platform"),
                recipe: Digest::new(b"recipe"),
            },
        )]),
    };
    let plan: BuildPlan = instance
        .plan(
            &name("default"),
            name("links"),
            name("compatibility"),
            GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned()).unwrap(),
        )
        .unwrap();
    // These assignments establish nominal identity, rather than comparing two
    // separate implementations that could drift while agreeing on one example.
    let extracted_plan: day2_kernel::BuildPlan = plan;
    let state: day2_kernel::kernel::State = State::Accepted;
    assert_eq!(state.next_effect(), Some(EffectKind::FetchSource));
    let source = Digest::new(b"source");
    let state: State = state
        .observe(
            &extracted_plan,
            &Observation::Source {
                source: source.clone(),
            },
        )
        .unwrap();
    let evidence: day2_kernel::kernel::VerificationEvidence = VerificationEvidence {
        plan: extracted_plan.fingerprint().unwrap(),
        source,
        platform: extracted_plan.profile.platform.clone(),
        recipe: extracted_plan.profile.recipe.clone(),
        builder: extracted_plan.profile.builder.clone(),
        artifact: Digest::new(b"artifact"),
        checks: Digest::new(b"checks"),
        credential_presence: CredentialPresence::Absent,
    };
    let receipt = Digest::of(&evidence).unwrap();
    let state = state
        .observe(&extracted_plan, &Observation::Verified { evidence })
        .unwrap();
    let result = state
        .observe(
            &extracted_plan,
            &Observation::Published {
                evidence: receipt,
                publication: Digest::new(b"publication"),
            },
        )
        .unwrap();
    assert!(matches!(result, State::Succeeded { .. }));
}
