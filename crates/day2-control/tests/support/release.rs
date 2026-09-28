#![allow(dead_code)]

use day2_control::provider_evidence::{
    DeploymentIncarnation, ReadBarrier, RevisionToken, StateEvidence,
};
use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::BuildProfile,
    journal::{Claim, Journal, OperatorActor},
    kernel::{CredentialPresence, Observation, State, VerificationEvidence},
    release::{
        GitApproval, ImmutableSecretRef, ReleaseApproval, ReleaseAuthority, ReleaseTarget,
        SecretObservation,
    },
};

pub fn incarnation(effect: &Digest) -> DeploymentIncarnation {
    DeploymentIncarnation {
        controller: effect.as_str().to_owned().try_into().unwrap(),
        generation: "generation-1".to_owned().try_into().unwrap(),
    }
}

pub fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

pub fn actor(value: &str) -> OperatorActor {
    value.to_owned().try_into().unwrap()
}

pub fn target(company: &str) -> ReleaseTarget {
    ReleaseTarget {
        company: name(company),
        environment: name("production"),
        app: name("reports"),
    }
}

pub fn plan(company: &str, revision: u8) -> BuildPlan {
    BuildPlan {
        version: 1,
        company: name(company),
        app: name("reports"),
        request: name(&format!("build-{revision}")),
        commit: GitOid::try_from(format!("{revision:040x}")).unwrap(),
        profile: BuildProfile {
            source: BindingRef::pin(name("forge"), &"company-repository").unwrap(),
            builder: BindingRef::pin(name("builder"), &"runner-v1").unwrap(),
            durability: BindingRef::pin(name("temporal"), &"namespace-v1").unwrap(),
            platform: Digest::new(b"platform"),
            recipe: Digest::new(b"recipe"),
        },
    }
}

pub fn authority(plan: &BuildPlan) -> ReleaseAuthority {
    ReleaseAuthority {
        source: plan.profile.source.clone(),
        policy: Digest::new(b"protected-branch-policy"),
        actor: actor("installation-operator"),
    }
}

pub fn configure(journal: &mut Journal, target: &ReleaseTarget, plan: &BuildPlan) {
    journal
        .observe_release_authority(target, &name("configure"), 0, &authority(plan))
        .unwrap();
}

pub fn succeed(journal: &mut Journal, plan: &BuildPlan) -> (Digest, Digest) {
    succeed_with_presence(journal, plan, CredentialPresence::Absent)
}

pub fn succeed_with_presence(
    journal: &mut Journal,
    plan: &BuildPlan,
    credential_presence: CredentialPresence,
) -> (Digest, Digest) {
    journal.accept_as(plan, "developer").unwrap();
    let id = plan.execution_id().unwrap();
    for now in 0..3 {
        let Claim::Acquired(lease) = journal.claim(&id, name("worker"), now, 10).unwrap() else {
            panic!("expected build lease")
        };
        let observation = match &lease.execution.state {
            State::Accepted => Observation::Source {
                source: Digest::of(&plan.commit).unwrap(),
            },
            State::SourceReady { source } => Observation::Verified {
                evidence: VerificationEvidence {
                    plan: plan.fingerprint().unwrap(),
                    source: source.clone(),
                    platform: plan.profile.platform.clone(),
                    recipe: plan.profile.recipe.clone(),
                    builder: plan.profile.builder.clone(),
                    artifact: Digest::of(&(&plan.company, &plan.commit, "artifact")).unwrap(),
                    checks: Digest::new(b"all-checks-pass"),
                    credential_presence,
                },
            },
            State::Verified { evidence, .. } => Observation::Published {
                evidence: evidence.clone(),
                publication: Digest::new(b"check-publication"),
            },
            other => panic!("unexpected build state {other:?}"),
        };
        journal.complete(&lease, &observation, now).unwrap();
    }
    let State::Succeeded {
        artifact, evidence, ..
    } = journal.get(&id).unwrap().state
    else {
        panic!("expected succeeded build")
    };
    (artifact, evidence)
}

pub fn approval(
    journal: &mut Journal,
    company: &str,
    revision: u8,
    generation: u64,
) -> ReleaseApproval {
    approval_with_presence(
        journal,
        company,
        revision,
        generation,
        CredentialPresence::Absent,
    )
}

pub fn approval_with_presence(
    journal: &mut Journal,
    company: &str,
    revision: u8,
    generation: u64,
    credential_presence: CredentialPresence,
) -> ReleaseApproval {
    let plan = plan(company, revision);
    let (artifact, evidence) = succeed_with_presence(journal, &plan, credential_presence);
    let policy = authority(&plan).policy;
    let approval = ReleaseApproval {
        target: target(company),
        request: name(&format!("release-{revision}")),
        expected_generation: generation,
        build_execution: plan.execution_id().unwrap(),
        artifact,
        evidence,
        git: GitApproval {
            source: plan.profile.source.clone(),
            commit: plan.commit,
            policy,
            receipt: Digest::of(&(company, revision, "reviewed-merge")).unwrap(),
            actor: actor("reviewer"),
        },
        secret: ImmutableSecretRef {
            binding: BindingRef::pin(name("secrets"), &"numeric-project-1234").unwrap(),
            secret: name("api-credential"),
            version: u64::from(revision).try_into().unwrap(),
        },
    };
    journal
        .register_runtime_secret(
            &approval.target,
            &approval.secret,
            &day2_control::runtime_secret::ProviderResource {
                provider: name("test"),
                account: name(company),
                secret: name("api-credential"),
            },
            &actor("installation-operator"),
        )
        .unwrap();
    approval
}

pub fn observation(approval: &ReleaseApproval, provider_revision: u64) -> SecretObservation {
    SecretObservation {
        reference: approval.secret.clone(),
        provider_state: StateEvidence::Qualified {
            revision: RevisionToken::Ordered {
                stream: Digest::of(&approval.secret).unwrap(),
                sequence: provider_revision.try_into().unwrap(),
            },
            barrier: ReadBarrier {
                authority: approval.secret.binding.clone(),
                resource: Digest::of(&approval.secret).unwrap(),
                after_effect: None,
                receipt: Digest::of(&(&approval.secret, provider_revision, "qualified-read"))
                    .unwrap(),
            },
        },
        evidence: Digest::of(&(&approval.secret, provider_revision)).unwrap(),
        enabled: true,
        access_granted: true,
        projection_ready: true,
    }
}

pub fn metadata(journal: &mut Journal, approval: &ReleaseApproval) {
    journal
        .observe_release_secret(
            &approval.target,
            &name("secret-ready"),
            0,
            &observation(approval, 1),
        )
        .unwrap();
}
