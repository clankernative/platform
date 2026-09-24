//! Signed webhook ingress hold gate.
//!
//! The pure half of this gate lives beside the verifier and checks it against
//! Slack's published vector. This half answers the questions that need a real
//! runtime and a real database: does a repeated delivery commit once, and is a
//! delivery that fails verification refused *before* anything exists to observe it.
//!
//! If a delivery can be processed twice, ingress is worse than no ingress, because
//! the application cannot tell — the standard the schedule hold gate was held to.

#[path = "support/commands.rs"]
mod support;
use anyhow::Result;
use day2::{
    ingress::{self, Endpoint, IdentitySource, Refused, Scheme, Signing},
    store::Runtime,
};
use serde_json::json;
use support::World;

const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
/// A body this application's command actually accepts.
/// The body is exactly what the bound command accepts.
///
/// The decode function an application declares is type-checked against its command
/// but is not yet invoked by the host, so the envelope reaches the command as-is.
/// This endpoint therefore takes its identity from a header rather than a payload
/// field, which keeps the body a valid command input. The payload-field and
/// composite paths are covered by the unit tests over `IdentitySource::extract`.
fn body() -> Vec<u8> {
    body_for("a\nb")
}

fn body_for(text: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"title": "Webhook", "text": text})).expect("serialisable")
}

/// The headers one delivery arrives with: the signature, the signed timestamp,
/// and — when the delivery carries one — the identifier.
///
/// Signature and timestamp live here rather than beside the body because that is
/// where they are on the wire, and because the provider names them. `id` is
/// optional so a delivery that carries no identifier is still a *signed* delivery,
/// which is the only way to test that identity is refused on its own merits rather
/// than because the signature went missing with it.
fn headers_for(
    signature: &str,
    signed_at: i64,
    id: Option<&str>,
) -> std::collections::BTreeMap<String, String> {
    let mut headers = std::collections::BTreeMap::from([
        ("x-slack-signature".to_owned(), signature.to_owned()),
        (
            "x-slack-request-timestamp".to_owned(),
            signed_at.to_string(),
        ),
    ]);
    if let Some(id) = id {
        headers.insert("x-delivery-id".to_owned(), id.to_owned());
    }
    headers
}

fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("key");
    mac.update(format!("v0:{timestamp}:").as_bytes());
    mac.update(body);
    format!("v0={:x}", mac.finalize().into_bytes())
}

fn endpoint() -> Endpoint {
    Endpoint {
        app: "reports".into(),
        name: "submissions".into(),
        // An ordinary command. It does not know a webhook triggered it.
        operation: "reports.submit".into(),
        provider_identity: IdentitySource::Header("x-delivery-id"),
        // This gate is about admission and exactly-once, not about any one
        // provider's signature scheme, so it signs the way the published Slack
        // vector beside the verifier does.
        signing: Signing {
            scheme: Scheme::SlackV0,
            signature_header: "x-slack-signature",
            timestamp_header: Some("x-slack-request-timestamp"),
        },
    }
}

/// One delivery. `signed_at` is the timestamp the provider signed; `now` is the
/// clock when it arrives. They are separate because that is the whole of replay:
/// a captured request keeps its original timestamp and signature while time moves
/// on. A harness that ties them together cannot express a replay at all.
fn deliver(
    runtime: &Runtime,
    signature: &str,
    body: &[u8],
    id: &str,
    signed_at: i64,
    now: i64,
) -> Result<String, Refused> {
    let headers = headers_for(signature, signed_at, Some(id));
    ingress::admit(
        runtime,
        &endpoint(),
        &ingress::Binding {
            actor: "alice",
            secret: SECRET,
        },
        &ingress::Delivery {
            body,
            headers: &headers,
        },
        now,
    )
}

fn invocations(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(
        db.query_row("SELECT count(*) FROM day2_invocations", [], |row| {
            row.get(0)
        })?,
    )
}

fn reports(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(db.query_row("SELECT count(*) FROM reports", [], |row| row.get(0))?)
}

#[test]
fn one_delivery_arriving_three_times_commits_once() -> Result<()> {
    let world = World::new()?;
    let now = 1_758_067_230;
    let body = body();
    let signature = sign(SECRET, now, &body);

    // Slack retries three times over six minutes carrying the same event_id, and
    // GitHub reuses its GUID on redelivery for three days. Each arrival derives the
    // same identity, so the runtime absorbs the repeats.
    let first = deliver(&world.runtime, &signature, &body, "D-1", now, now)
        .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
    for later in [now + 1, now + 60] {
        // A retry is freshly signed at the moment it is sent.
        let signature = sign(SECRET, later, &body);
        let again = deliver(&world.runtime, &signature, &body, "D-1", later, later)
            .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
        assert_eq!(again, first, "a retry derived a different identity");
    }
    world.runtime.execute(&first, day2::store::Fault::None)?;
    day2::invocations::drain(&world.runtime, 64)?;
    assert_eq!(reports(&world)?, 1, "the retries created extra work");
    Ok(())
}

#[test]
fn a_replayed_delivery_inside_the_signature_window_is_refused_by_identity() -> Result<()> {
    let world = World::new()?;
    let now = 1_758_067_230;
    let body = body();
    let signature = sign(SECRET, now, &body);
    let first = deliver(&world.runtime, &signature, &body, "D-1", now, now)
        .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
    world.runtime.execute(&first, day2::store::Fault::None)?;

    // A captured request replayed within the five-minute window verifies perfectly:
    // the signature is genuine and the timestamp is fresh enough. Nothing about the
    // signature can reject it. Only the derived identity can, which is why an
    // endpoint whose provider supplies no identifier must derive one.
    let replay = deliver(&world.runtime, &signature, &body, "D-1", now, now + 120)
        .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
    assert_eq!(replay, first);
    day2::invocations::drain(&world.runtime, 64)?;
    assert_eq!(reports(&world)?, 1, "a replay produced a second report");
    Ok(())
}

#[test]
fn a_delivery_that_fails_verification_creates_nothing_at_all() -> Result<()> {
    let world = World::new()?;
    let now = 1_758_067_230;
    let body = body();
    let signature = sign(SECRET, now, &body);
    let before = invocations(&world)?;

    let tampered = serde_json::to_vec(&json!({
        "event_id": "Ev0PV52K21", "title": "Webhook", "text": "tampered"
    }))?;
    // A correctly signed delivery carrying no identifier at all. It cannot be made
    // exactly-once, so it is refused rather than run once and hoped about.
    for (label, signature, body, signed_at) in [
        ("tampered body", signature.clone(), tampered, now),
        (
            "foreign secret",
            sign("another-workspaces-secret", now, &body),
            body.clone(),
            now,
        ),
        (
            // Correctly signed, but signed long enough ago that it is outside the
            // replay tolerance by the time it arrives.
            "stale timestamp",
            sign(SECRET, now - 400, &body),
            body.clone(),
            now - 400,
        ),
    ] {
        let refused = deliver(&world.runtime, &signature, &body, "D-1", signed_at, now);
        assert!(refused.is_err(), "{label} was admitted");
        // The point of the gate: refusal happens before the runtime is touched, so
        // there is no invocation to execute, retry or audit as application work.
        assert_eq!(
            invocations(&world)?,
            before,
            "{label} created an invocation before being refused"
        );
        assert_eq!(reports(&world)?, 0, "{label} reached the application");
    }

    // An identifier-less delivery, correctly signed, is still refused.
    assert!(
        ingress::admit(
            &world.runtime,
            &endpoint(),
            &ingress::Binding {
                actor: "alice",
                secret: SECRET,
            },
            &ingress::Delivery {
                body: &body,
                headers: &headers_for(&signature, now, None),
            },
            now,
        )
        .is_err(),
        "a delivery with no identifier was admitted"
    );
    assert_eq!(invocations(&world)?, before);

    // And the same request, correctly signed, is admitted — so the refusals above
    // are the signature failing, not the fixture being broken.
    assert!(deliver(&world.runtime, &signature, &body, "D-1", now, now).is_ok());
    assert_eq!(invocations(&world)?, before + 1);
    Ok(())
}

#[test]
fn distinct_deliveries_are_distinct_work() -> Result<()> {
    let world = World::new()?;
    let now = 1_758_067_230;
    let body = body();
    let signature = sign(SECRET, now, &body);

    // Deduplication must not be so eager that an endpoint only ever runs once.
    // Same body, same signature, different delivery identifiers — which is what a
    // provider sending two genuinely distinct events looks like.
    for delivery in ["D-1", "D-2"] {
        let identity = deliver(&world.runtime, &signature, &body, delivery, now, now)
            .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
        world.runtime.execute(&identity, day2::store::Fault::None)?;
    }
    day2::invocations::drain(&world.runtime, 64)?;
    assert_eq!(reports(&world)?, 2);
    Ok(())
}

#[test]
fn a_scheduled_run_and_a_delivery_cannot_collide_in_the_identity_space() -> Result<()> {
    // Both derive identities into the same invocation id space. A provider that
    // chose its delivery identifier adversarially must not be able to name a
    // schedule's occurrence, or a webhook could suppress a scheduled run.
    let endpoint = endpoint();
    let hostile = endpoint.identity("schedule.reports.sweep.0001758067200000");
    assert!(hostile.starts_with("ingress.reports.submissions."));
    let schedule = day2::schedules::Schedule {
        app: "reports".into(),
        name: "sweep".into(),
        interval_ms: day2::schedules::MINIMUM_INTERVAL_MS,
        missed: day2::schedules::Missed::Coalesce,
    };
    assert_ne!(hostile, schedule.identity(1_758_067_200_000));
    Ok(())
}
