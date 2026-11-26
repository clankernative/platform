//! One real compiled prototype, with each browser signed in as its own actor.
#[path = "support/http_session.rs"]
mod http;

use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
    authority_state::{self, LocalOperator},
    development,
    store::Runtime,
};
use reqwest::{StatusCode, blocking::Client};
use scraper::{Html, Selector};
use serde_json::json;
use std::{collections::BTreeSet, fs, io::Read, path::PathBuf};

fn activate(runtime: &Runtime, instance: &Instance, event: &str) -> Result<()> {
    fs::write(runtime.instance_path(), serde_json::to_vec(instance)?)?;
    let current = authority_state::current(&rusqlite::Connection::open(runtime.db())?)?;
    authority_state::apply_desired(
        runtime,
        &LocalOperator::assert_local("http-test-operator")?,
        event,
        Some(current.stamp),
    )?;
    Ok(())
}

fn browser_url(doc: &Html, selector: &str, attribute: &str) -> Result<String> {
    Ok(doc
        .select(&Selector::parse(selector).unwrap())
        .next()
        .and_then(|node| node.attr(attribute))
        .context("expected browser URL")?
        .to_owned())
}

fn connector(client: &http::Session, url: &str) -> Result<reqwest::blocking::Response> {
    Ok(client
        .get(url)
        .header("X-Day2-Prototype-Query", "1")
        .send()?)
}

#[test]
fn pinned_revisions_recheck_viewer_grants_and_export_the_exact_saved_source() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_SLACK_DASHBOARD_ARTIFACT")
        .map(PathBuf::from)
        .context("verified Slack dashboard artifact required")?;
    let directory = tempfile::tempdir()?;
    let runtime =
        development::create_for(&artifact, &directory.path().join("instance"), None, "alice")?;
    assert!(development::uses_simulated_providers(&runtime));
    let page = runtime
        .artifact()
        .contract()
        .prototype
        .as_ref()
        .context("prototype declaration")?;
    let history = page.query.as_str();
    let revision = page.revision_query.as_deref().context("revision query")?;
    let save = page.save_command.as_deref().context("save command")?;
    let mut instance = Instance::load(runtime.instance_path())?;
    let app = instance.apps.get_mut("app").unwrap();
    for actor in ["viewer", "history_only", "revision_only", "unbound"] {
        app.readers.insert(actor.into());
    }
    let policy = app.authority.as_mut().unwrap();
    for (op, additional) in [(history, "history_only"), (revision, "revision_only")] {
        policy.operations.get_mut(op).unwrap().actors.extend(
            ["viewer", "unbound", additional]
                .into_iter()
                .map(str::to_owned),
        );
    }
    let (resources, mut bindings) =
        development::resource_fixture_for_artifact("app", runtime.artifact(), policy)?;
    bindings
        .iter_mut()
        .find(|binding| binding.operation == history)
        .context("history resource")?
        .actors = Some(BTreeSet::from([
        "alice".into(),
        "viewer".into(),
        "history_only".into(),
    ]));
    app.resource_policies = bindings;
    instance.resources = Some(resources);
    activate(&runtime, &instance, "test-viewers")?;

    let owner = http::Session::start(runtime.clone(), "alice")?;
    let viewer = http::Session::start(runtime.clone(), "viewer")?;
    let root = viewer.get("/").send()?;
    assert_eq!(root.status(), StatusCode::SEE_OTHER);
    assert_eq!(root.headers()["location"], "/_prototype/published");
    for (key, invalid) in [("blank", "  "), ("nul", "<p>\0</p>")] {
        let rejected = owner.post(save, key, &json!({"html":invalid})).send()?;
        assert!(rejected.status().is_client_error());
    }
    let saved = "<main id='first'>My first draft</main>";
    for (id, html) in [(1, saved), (2, "<p>Changed dashboard</p>")] {
        assert_eq!(
            http::value(
                owner
                    .post(save, &format!("save-{id}"), &json!({"html":html}))
                    .send()?,
                StatusCode::OK
            )?["id"],
            id
        );
    }

    let shell = "/_prototype/revisions/1";
    let owner_doc = Html::parse_document(&owner.get(shell).send()?.error_for_status()?.text()?);
    let source = browser_url(&owner_doc, "a[download]", "href")?;
    let viewer_doc = Html::parse_document(&viewer.get(shell).send()?.error_for_status()?.text()?);
    assert!(
        viewer_doc
            .select(&Selector::parse("a[download], textarea").unwrap())
            .next()
            .is_none()
    );
    assert!(
        owner_doc
            .select(&Selector::parse("textarea").unwrap())
            .next()
            .is_some()
    );
    let frame = browser_url(&viewer_doc, "script[data-frame]", "data-frame")?;
    let query = browser_url(&viewer_doc, "script[data-query]", "data-query")?;
    let body = viewer.get(&frame).send()?.error_for_status()?;
    assert!(
        body.headers()["content-security-policy"]
            .to_str()?
            .contains("sandbox allow-scripts")
    );
    assert_eq!(body.headers()["cache-control"], "no-store");
    assert!(body.text()?.contains(saved));
    let stale = frame.replace("/revisions/1/", "/revisions/2/");
    assert_eq!(viewer.get(&stale).send()?.status(), StatusCode::CONFLICT);
    assert_eq!(
        viewer.get("/_prototype/revisions/99").send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(viewer.get(&query).send()?.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        viewer.acting_get(&query, "alice").send()?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(viewer.get(&source).send()?.status(), StatusCode::FORBIDDEN);

    let data = connector(&viewer, &query)?;
    let invocation = data.headers()["x-day2-invocation"].to_str()?.to_owned();
    let pin = query.split_once("?pin=").context("pinned query")?.1;
    assert!(invocation.starts_with(&format!("proto-r1-{pin}-")));
    let trace = runtime.trace(&invocation)?;
    assert_eq!(trace.request.context.actor, "viewer");
    assert_eq!(trace.request.operation, history);
    let result = http::value(data, StatusCode::OK)?;
    assert_eq!(result["channel"], "C0DASHBOARD");
    assert!(result.to_string().contains("The draft is ready to review."));

    let second_doc = Html::parse_document(
        &viewer
            .get("/_prototype/revisions/2")
            .send()?
            .error_for_status()?
            .text()?,
    );
    let second_query = browser_url(&second_doc, "script[data-query]", "data-query")?;
    let second_data = connector(&viewer, &second_query)?.error_for_status()?;
    let second_id = second_data.headers()["x-day2-invocation"].to_str()?;
    let second_pin = second_query
        .split_once("?pin=")
        .context("second query pin")?
        .1;
    assert!(second_id.starts_with(&format!("proto-r2-{second_pin}-")));
    assert_ne!(pin, second_pin);
    assert_eq!(runtime.trace(second_id)?.artifact, trace.artifact);

    let exported = owner.get(&source).send()?.error_for_status()?;
    assert_eq!(exported.headers()["content-type"], "application/gzip");
    assert_eq!(
        exported.headers()["content-disposition"],
        "attachment; filename=\"app.tar.gz\""
    );
    let bytes = exported.bytes()?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_ref()));
    let mut index = None;
    let mut published_bindings = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        match path.to_str() {
            Some("app/prototype/index.html") => {
                let mut text = String::new();
                entry.read_to_string(&mut text)?;
                assert!(index.replace(text).is_none());
            }
            Some("app/prototype/page.json") => {
                assert!(
                    published_bindings
                        .replace(serde_json::from_reader(entry)?)
                        .is_none()
                );
            }
            _ => {}
        }
    }
    assert_eq!(index.as_deref(), Some(saved));
    assert_eq!(
        published_bindings,
        Some(json!({ "query": "channelhistory.history" }))
    );

    let anonymous = Client::new();
    for url in [shell, &frame, &query, &source] {
        assert_eq!(
            anonymous
                .get(format!("{}{url}", owner.origin))
                .send()?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for actor in ["history_only", "revision_only"] {
        let limited = http::Session::start(runtime.clone(), actor)?;
        assert_eq!(limited.get(shell).send()?.status(), StatusCode::FORBIDDEN);
        assert_eq!(limited.get(&frame).send()?.status(), StatusCode::FORBIDDEN);
        assert_eq!(connector(&limited, &query)?.status(), StatusCode::FORBIDDEN);
    }
    let unbound = http::Session::start(runtime.clone(), "unbound")?;
    assert_eq!(unbound.get(shell).send()?.status(), StatusCode::OK);
    assert_eq!(connector(&unbound, &query)?.status(), StatusCode::FORBIDDEN);

    // A viewer who keeps an already-open page loses both its frame and bridge as
    // soon as revision access is revoked, even though the Slack query is still theirs.
    instance
        .apps
        .get_mut("app")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .operations
        .get_mut(revision)
        .unwrap()
        .actors
        .remove("viewer");
    activate(&runtime, &instance, "revoke-viewer-revision")?;
    assert_eq!(
        viewer.get("/_prototype/published").send()?.status(),
        StatusCode::OK
    );
    for path in [shell, &frame] {
        assert_eq!(viewer.get(path).send()?.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(connector(&viewer, &query)?.status(), StatusCode::FORBIDDEN);
    Ok(())
}
