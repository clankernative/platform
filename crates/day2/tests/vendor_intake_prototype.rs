//! The real pinned submit bridge reaches the admitted command and membership
//! preparation for both the starter and a saved revision.
#[path = "support/http_session.rs"]
mod http;

use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
    authority_state::{self, LocalOperator},
    development,
    integrations::simulated,
};
use reqwest::{StatusCode, blocking::RequestBuilder};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

const MEMBER: &str = "ada@synthetic.example";
const NONMEMBER: &str = "calendar-reader@synthetic.example";
const REVIEWER: &str = "grace@synthetic.example";
const FOLDER: &str = "https://drive.google.com/drive/folders/synthetic_vendor_contracts";
const FILE: &str = "https://drive.google.com/file/d/synthetic_contract/view";
const TRIAGE: &str = "vendorintake.triage";
const GROUP: &str = "product-owners@synthetic.example";
const SUBMIT: &str = "vendorintake.submit_request";

struct Page {
    submit: String,
    query: String,
    source: Option<String>,
}

fn page(viewer: &http::Session, path: &str) -> Result<Page> {
    let html = viewer.get(path).send()?.error_for_status()?.text()?;
    let doc = Html::parse_document(&html);
    let attr = |selector: &str, key: &str| {
        doc.select(&Selector::parse(selector).unwrap())
            .next()?
            .attr(key)
            .map(str::to_owned)
    };
    assert_eq!(
        attr("dialog#submit-review", "data-operation").as_deref(),
        Some(SUBMIT)
    );
    Ok(Page {
        submit: attr("dialog#submit-review", "data-url").context("pinned submit URL")?,
        query: attr("script[data-query]", "data-query").context("pinned query URL")?,
        source: attr("a[download]", "href"),
    })
}

fn history(viewer: &http::Session, url: &str) -> Result<Value> {
    let data = http::value(
        viewer
            .get(url)
            .header("X-Day2-Prototype-Query", "1")
            .send()?,
        StatusCode::OK,
    )?;
    Ok(data["requests"]["items"].clone())
}

fn rejected(response: reqwest::blocking::Response, code: &str) -> Result<()> {
    let status = response.status();
    let error: Value = serde_json::from_str(&response.text()?)?;
    assert!(status.is_client_error(), "{status} {error}");
    assert_eq!(
        error["error"]["code"],
        format!("app:vendorintake.{code}"),
        "{error}"
    );
    Ok(())
}

fn at(viewer: &http::Session, path: &str, key: &str) -> Result<RequestBuilder> {
    let session = http::value(viewer.get("/api/session").send()?, StatusCode::OK)?;
    Ok(viewer
        .client
        .post(format!("{}{path}", viewer.origin))
        .header("Origin", &viewer.origin)
        .header(
            "X-CSRF-Token",
            session["csrf_token"].as_str().context("session CSRF")?,
        )
        .header("Idempotency-Key", key)
        .header("Content-Type", "application/json")
        .header("X-Day2-Prototype-Submit", "1"))
}

#[test]
fn signed_in_members_submit_exact_inputs_on_pinned_pages() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_VENDOR_INTAKE_ARTIFACT")
        .map(PathBuf::from)
        .context("verified vendor intake artifact required")?;
    let temp = tempfile::tempdir()?;
    let runtime = development::create_for(&artifact, &temp.path().join("instance"), None, MEMBER)?;
    assert!(development::uses_simulated_providers(&runtime));
    let mut instance = Instance::load(runtime.instance_path())?;
    let app = instance.apps.get_mut("app").unwrap();
    for actor in [NONMEMBER, REVIEWER] {
        app.readers.insert(actor.into());
        app.writers.insert(actor.into());
    }
    let policy = app.authority.as_mut().unwrap();
    for name in ["vendorintake.my_requests", "vendorintake.revision", SUBMIT] {
        policy
            .operations
            .get_mut(name)
            .unwrap()
            .actors
            .insert(NONMEMBER.into());
    }
    for name in [
        "vendorintake.review_queue",
        "vendorintake.proposal",
        TRIAGE,
        "vendorintake.my_requests",
    ] {
        policy
            .operations
            .get_mut(name)
            .unwrap()
            .actors
            .extend([REVIEWER.to_owned(), MEMBER.to_owned()]);
    }
    let (catalog, bindings) =
        development::resource_fixture_for_artifact("app", runtime.artifact(), policy)?;
    app.resource_policies = bindings;
    instance.resources = Some(catalog);
    fs::write(runtime.instance_path(), serde_json::to_vec(&instance)?)?;
    let stamp = authority_state::current(&rusqlite::Connection::open(runtime.db())?)?.stamp;
    authority_state::apply_desired(
        &runtime,
        &LocalOperator::assert_local("vendor-prototype-test")?,
        "vendor-prototype-membership",
        Some(stamp),
    )?;

    let member = http::Session::start(runtime.clone(), MEMBER)?;
    let nonmember = http::Session::start(runtime.clone(), NONMEMBER)?;
    let reviewer = http::Session::start(runtime.clone(), REVIEWER)?;
    http::value(
        member
            .post(
                "vendorintake.configure",
                "settings",
                &json!({
                    "product_owners":GROUP, "reviewer":REVIEWER, "contract_folder":FOLDER
                }),
            )
            .send()?,
        StatusCode::OK,
    )?;
    let starter = page(&member, "/_prototype/published")?;
    assert_eq!(
        member.acting_get(&starter.query, NONMEMBER).send()?.status(),
        StatusCode::BAD_REQUEST
    );
    let published = starter.submit;
    let payload = json!({
        "vendor": "Example vendor", "business_reason": "Reporting", "budget_owner": "Operations",
        "spend_cents": 240075, "spend_period": "one_time", "spend_start": "2028-02-29",
        "ramp_limit_cents": 20109, "ramp_cadence": "monthly", "has_contract": true, "contract_url": FILE
    });
    assert_eq!(
        member.get(&published).send()?.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        at(&member, &published, "acting")?
            .header("X-Day2-Act-As", NONMEMBER)
            .body(payload.to_string())
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        member
            .client
            .post(format!("{}{published}", member.origin))
            .body(payload.to_string())
            .send()?
            .status()
            .is_client_error()
    );
    assert!(
        at(&member, &published, "bad_fields")?
            .body(r#"{"vendor":"A","vendor":"B"}"#)
            .send()?
            .status()
            .is_client_error()
    );
    let no_csrf = member
        .client
        .post(format!("{}{published}", member.origin))
        .header("Origin", &member.origin)
        .header("X-Day2-Prototype-Submit", "1")
        .header("Idempotency-Key", "without_csrf")
        .header("Content-Type", "application/json")
        .body(payload.to_string())
        .send()?;
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
    let mut wrong = payload.clone();
    wrong["spend_cents"] = json!("25000");
    assert!(
        at(&member, &published, "bad_type")?
            .body(wrong.to_string())
            .send()?
            .status()
            .is_client_error()
    );
    let mut extra = payload.clone();
    extra["actor"] = json!(MEMBER);
    assert!(
        at(&member, &published, "bad_actor")?
            .body(extra.to_string())
            .send()?
            .status()
            .is_client_error()
    );

    let first = at(&member, &published, "member_first")?
        .body(payload.to_string())
        .send()?;
    let id = first.headers()["x-day2-invocation"].to_str()?.to_owned();
    let result = http::value(first, StatusCode::OK)?;
    assert_eq!(result["id"], 1);
    let trace = runtime.trace(&id)?;
    assert_eq!(trace.request.operation, SUBMIT);
    assert_eq!(trace.request.context.actor, MEMBER);
    assert_eq!(
        http::value(
            member.post(SUBMIT, "member_first", &payload).send()?,
            StatusCode::OK
        )?,
        result,
        "the ordinary command API and prototype share the same receipt"
    );

    let saved_html = runtime
        .artifact()
        .contract()
        .prototype
        .as_ref()
        .context("prototype declaration")?
        .html
        .clone()
        + "\n<!-- Reviewed intake revision -->";
    let saved = http::value(
        member
            .post(
                "vendorintake.save_revision",
                "draft",
                &json!({"html":saved_html}),
            )
            .send()?,
        StatusCode::OK,
    )?;
    let draft_path = format!(
        "/_prototype/revisions/{}",
        saved["id"].as_u64().context("revision")?
    );
    let revision = page(&member, &draft_path)?;
    let source = member
        .get(
            revision
                .source
                .as_deref()
                .context("owner source download")?,
        )
        .send()?
        .error_for_status()?;
    assert_eq!(source.headers()["content-type"], "application/gzip");
    let bytes = source.bytes()?;
    assert_eq!(
        bytes.as_ref(),
        day2::prototype::publication(runtime.artifact().contract(), &saved_html)?
    );
    if let Some(destination) = std::env::var_os("DAY2_TEST_VENDOR_PUBLICATION") {
        // A publication campaign can admit this exact authenticated source download.
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?
            .write_all(&bytes)?;
    }
    let draft = revision.submit;
    let stale =
        draft.split_once('?').unwrap().0.to_owned() + "?" + published.split_once('?').unwrap().1;
    assert_eq!(
        at(&member, &stale, "stale")?
            .body(payload.to_string())
            .send()?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        http::value(
            at(&member, &draft, "member_second")?
                .body(payload.to_string())
                .send()?,
            StatusCode::OK
        )?["id"],
        2
    );

    let outsiders_view = page(&nonmember, &draft_path)?;
    rejected(
        at(&nonmember, &outsiders_view.submit, "not_member")?
            .body(payload.to_string())
            .send()?,
        "membership_required",
    )?;
    assert_eq!(history(&nonmember, &outsiders_view.query)?, json!([]));

    let requester_queue = member.get("/review").send()?.error_for_status()?.text()?;
    assert!(!requester_queue.contains("Example vendor"));
    let hidden = member.get("/review/1").send()?.error_for_status()?.text()?;
    assert!(hidden.contains("Request unavailable") && !hidden.contains(FILE));
    let queue = reviewer.get("/review").send()?.error_for_status()?.text()?;
    assert!(queue.contains("Example vendor") && queue.contains("/review/1"));
    let detail = reviewer
        .get("/review/1")
        .send()?
        .error_for_status()?
        .text()?;
    for term in [
        MEMBER,
        "Reporting",
        "Operations",
        "$2,400.75",
        "one_time",
        "2028-02-29",
        "$201.09",
        "monthly",
        FILE,
        FOLDER,
        TRIAGE,
    ] {
        assert!(detail.contains(term), "missing reviewed term {term}");
    }
    let mut decision = json!({"id":1,"decision":"approved","review_note":"Terms and contract verified.","checked_folder":false});
    rejected(
        member.post(TRIAGE, "requester_review", &decision).send()?,
        "reviewer_required",
    )?;
    rejected(
        reviewer
            .post(TRIAGE, "missing_folder_check", &decision)
            .send()?,
        "invalid_review",
    )?;
    let before = history(&member, &starter.query)?;
    assert_eq!(before[1]["id"], 1);
    assert_eq!(before[1]["status"], "pending");
    decision["checked_folder"] = true.into();
    let doc = Html::parse_document(&detail);
    let form = doc
        .select(&Selector::parse("form[data-command='vendorintake.triage']").unwrap())
        .next()
        .context("visible review form")?;
    let action = form.attr("action").context("review action")?;
    let mut fields: BTreeMap<_, _> = form
        .select(&Selector::parse("input[type='hidden'][name]").unwrap())
        .map(|field| {
            (
                field.attr("name").unwrap().to_owned(),
                field.attr("value").unwrap_or_default().to_owned(),
            )
        })
        .collect();
    for name in ["decision", "review_note", "checked_folder"] {
        assert!(
            form.select(&Selector::parse(&format!("[name='{name}']")).unwrap())
                .next()
                .is_some(),
            "missing review control {name}"
        );
        fields.insert(
            name.to_owned(),
            match &decision[name] {
                Value::String(value) => value.clone(),
                value => value.to_string(),
            },
        );
    }
    let confirm = || {
        reviewer
            .client
            .post(format!("{}{action}", reviewer.origin))
            .header("Origin", &reviewer.origin)
            .form(&fields)
            .send()
    };
    let first = confirm()?;
    assert_eq!(first.status(), StatusCode::SEE_OTHER, "{}", first.text()?);
    assert_eq!(first.headers()["location"], "/review/1");
    let receipt = first.headers()["x-day2-invocation"].to_str()?.to_owned();
    let again = confirm()?;
    assert_eq!(again.status(), StatusCode::SEE_OTHER, "{}", again.text()?);
    assert_eq!(again.headers()["x-day2-invocation"], receipt);
    assert_eq!(runtime.trace(&receipt)?.request.context.actor, REVIEWER);
    rejected(
        reviewer
            .post(TRIAGE, "another_decision", &decision)
            .send()?,
        "unavailable_request",
    )?;
    let after = history(&member, &revision.query)?;
    assert_eq!(after[0]["status"], "pending");
    assert_eq!(
        after[1],
        json!({"id":1,"vendor":"Example vendor","status":"approved","review_note":"Terms and contract verified."})
    );
    assert_eq!(history(&nonmember, &outsiders_view.query)?, json!([]));
    let reviewed = reviewer
        .get("/review/1")
        .send()?
        .error_for_status()?
        .text()?;
    assert!(
        reviewed.contains("Terms and contract verified.")
            && !reviewed.contains("id=\"decide-request\"")
    );

    simulated::update_google_workspace(runtime.db(), runtime.scope(), |state| {
        state
            .world
            .groups
            .get_mut(GROUP)
            .context("product owners group")?
            .members
            .remove(MEMBER);
        Ok(())
    })?;
    rejected(
        at(&member, &draft, "membership_removed")?
            .body(payload.to_string())
            .send()?,
        "membership_required",
    )?;
    assert_eq!(
        runtime.inspect()?["requests"]
            .as_array()
            .context("request rows")?
            .len(),
        2
    );
    Ok(())
}
