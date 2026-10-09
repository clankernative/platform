use super::validate_presentation_delivery;
use crate::{authority_state::AuthorityStamp, error::Failure};

#[test]
fn slow_render_delivery_uses_current_session_and_exclusive_expiry() {
    let stamp = AuthorityStamp {
        epoch: "epoch".into(),
        revision: 4,
    };
    for (session, wall, accepted) in [
        (Some(("alice".into(), 100)), Ok(99), true),
        (Some(("alice".into(), 100)), Ok(100), false),
        (Some(("alice".into(), 100)), Ok(101), false),
        (Some(("bob".into(), 100)), Ok(99), false),
        (None, Ok(99), false),
        (
            Some(("alice".into(), 100)),
            Err(anyhow::anyhow!("clock unavailable")),
            false,
        ),
    ] {
        let result =
            validate_presentation_delivery(&stamp, &stamp, "alice", session.as_ref(), wall);
        assert_eq!(result.is_ok(), accepted);
        if !accepted {
            assert!(matches!(
                result.unwrap_err().downcast_ref::<Failure>(),
                Some(Failure::SignInRequired)
            ));
        }
    }
}

#[test]
fn seeded_revocation_and_aba_schedules_never_deliver_prepared_scenes() {
    fn replay(seed: u32) -> Vec<bool> {
        let prepared = AuthorityStamp {
            epoch: "original".into(),
            revision: 4,
        };
        let mut current = prepared.clone();
        let mut random = seed;
        let mut wall = 80;
        let mut alive = true;
        let mut actor = "alice";
        let mut policy_allowed = true;
        let mut transcript = Vec::new();
        for step in 0..64 {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            match (random >> 8) % 6 {
                0 => wall += 1,
                1 => alive = !alive,
                2 => actor = if actor == "alice" { "bob" } else { "alice" },
                3 => {
                    policy_allowed = !policy_allowed;
                    current.revision += 1;
                }
                4 => current.epoch = "restored".into(),
                _ => {}
            }
            let session = alive.then(|| (actor.into(), 100));
            let accepted = validate_presentation_delivery(
                &prepared,
                &current,
                "alice",
                session.as_ref(),
                Ok(wall),
            )
            .is_ok();
            let expected = current.epoch == "original"
                && current.revision == 4
                && alive
                && actor == "alice"
                && wall < 100;
            assert_eq!(
                accepted, expected,
                "seed={seed} step={step} policy={policy_allowed}"
            );
            transcript.push(accepted);
        }
        transcript
    }
    for seed in 1..=64 {
        assert_eq!(replay(seed), replay(seed), "seed={seed}");
    }

    let original = AuthorityStamp {
        epoch: "original".into(),
        revision: 4,
    };
    let restored_policy = AuthorityStamp {
        revision: 6,
        ..original.clone()
    };
    let session = ("alice".into(), 100);
    let error = validate_presentation_delivery(
        &original,
        &restored_policy,
        "alice",
        Some(&session),
        Ok(99),
    )
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<Failure>(),
        Some(Failure::AuthorityPolicyChanged)
    ));
}
