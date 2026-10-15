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

// The real HTTP dispatcher/query/template/form path pauses at its presentation
// port. Production startup still admits only an independently pinned worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_delivery_rechecks_revocation_after_render() -> anyhow::Result<()> {
    use super::{Grant, ListenerOptions, LocalServer, PresentationSource, SignIn};
    use crate::{
        artifact::Instance,
        host_inputs::{Inputs, simulation::VirtualClock},
        presentation::Port,
    };
    use anyhow::Context;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex, mpsc},
        time::Duration,
    };

    struct Paused {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl Port for Paused {
        fn render(&self, _renderer: &str, _input: &Value) -> anyhow::Result<Value> {
            self.entered.send(())?;
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(20))?;
            Ok(
                json!({"plot":{"x":"0","y":"0","width":"640","height":"240"},
                "points":[],"paths":[],"labels":[{"anchor":"start","baseline":"auto","font_size":"12","font_weight":"400",
                "text":"PREPARED_SCENE_SENTINEL","transform":"","x":"0","y":"12"}]}),
            )
        }
    }

    for scenario in ["allowed", "session", "expiry", "policy", "policy_aba"] {
        let world = crate::chart_live_tests::World::new()?;
        world.append("alice", 1_735_689_600_000, 59, false)?;
        let clock = Arc::new(VirtualClock(Mutex::new((
            Duration::from_secs(100),
            Duration::ZERO,
        ))));
        let runtime = world.runtime.clone().with_inputs(Inputs {
            clock: clock.clone(),
            ..Inputs::default()
        });
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let authority = listener.local_addr()?.to_string();
        let origin = format!("http://{authority}");
        let (grant, token) =
            Grant::issue("alice", runtime.inputs().entropy.as_ref(), clock.as_ref())?;
        let (entered, paused) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let server = LocalServer::bind_listener(
            runtime.clone(),
            listener,
            authority,
            origin.clone(),
            SignIn::Link(Mutex::new(Some(grant))),
            ListenerOptions {
                concurrency: 4,
                health_endpoints: false,
                presentation: PresentationSource::Test(Arc::new(Paused {
                    entered,
                    resume: Mutex::new(resumed),
                })),
            },
        )?;
        let (shutdown, done) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.serve(async {
            let _ = done.await;
        }));
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let login = client
            .get(format!("{origin}/login?token={token}"))
            .send()
            .await?;
        assert_eq!(login.status(), reqwest::StatusCode::OK);
        let fields = {
            let document = scraper::Html::parse_document(&login.text().await?);
            document
                .select(&scraper::Selector::parse("form input[name]").unwrap())
                .map(|node| {
                    (
                        node.value().attr("name").unwrap().to_string(),
                        node.value().attr("value").unwrap_or("").to_string(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            client
                .post(format!("{origin}/login"))
                .header("Origin", &origin)
                .form(&fields)
                .send()
                .await?
                .status(),
            reqwest::StatusCode::SEE_OTHER
        );
        let page_client = client.clone();
        let page_origin = origin.clone();
        let page = tokio::spawn(async move {
            let response = page_client
                .get(format!("{page_origin}/chart"))
                .send()
                .await?;
            Ok::<_, anyhow::Error>((response.status(), response.text().await?))
        });
        tokio::task::spawn_blocking(move || paused.recv_timeout(Duration::from_secs(15))).await??;
        let db = rusqlite::Connection::open(runtime.db())?;
        match scenario {
            "session" => {
                db.execute("DELETE FROM day2_web_sessions", [])?;
            }
            "expiry" => {
                let expires: i64 =
                    db.query_row("SELECT expires FROM day2_web_sessions", [], |row| {
                        row.get(0)
                    })?;
                clock.0.lock().unwrap().0 = Duration::from_secs(expires.try_into()?);
            }
            "policy" | "policy_aba" => {
                let original = std::fs::read(runtime.instance_path())?;
                let mut changed: Value = serde_json::from_slice(&original)?;
                changed["apps"]["chart"]["authority"]["operations"]["chart_live.chart"]["actors"] =
                    json!(["bob"]);
                let operator = crate::authority_state::LocalOperator::assert_local("chart-test")?;
                for (index, bytes) in std::iter::once(serde_json::to_vec(&changed)?)
                    .chain((scenario == "policy_aba").then_some(original))
                    .enumerate()
                {
                    Instance::from_bytes(&bytes)?;
                    std::fs::write(runtime.instance_path(), bytes)?;
                    let stamp = crate::authority_state::current(&db)?.stamp;
                    crate::authority_state::apply_desired(
                        &runtime,
                        &operator,
                        &format!("policy-{index}"),
                        Some(stamp),
                    )?;
                }
            }
            "allowed" => {}
            _ => unreachable!(),
        }
        resume.send(()).context("resume paused renderer")?;
        let response = page.await?;
        let _ = shutdown.send(());
        serving.await??;
        let (status, body) = response?;
        if scenario == "allowed" {
            assert_eq!(status, reqwest::StatusCode::OK, "{body}");
            assert!(body.contains("PREPARED_SCENE_SENTINEL"));
        } else {
            assert!(status.is_client_error(), "{scenario}: {status}: {body}");
            assert!(!body.contains("PREPARED_SCENE_SENTINEL"), "{scenario}");
            assert!(!body.contains("sample-revisions"), "{scenario}");
        }
        // Retain the disposable directory through all database and HTTP work.
        assert!(world.directory.path().exists());
    }
    Ok(())
}
