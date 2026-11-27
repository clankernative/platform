//! Authenticated presentation of one artifact-declared, input-free public query.
//! The draft only supplies HTML. It cannot choose an operation, input or actor.
use super::{Host, Session, security};
use crate::{
    authority_state::{AuthorityStamp, authorize_in},
    error::Failure,
    owners::{self, Permission},
    prototype::Page,
    store::{Fault, RequestIdentity},
    web_api,
};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{HeaderMap, Method, Uri, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

const PREFIX: &str = "/_prototype";

pub(super) fn matches(path: &str) -> bool {
    path == PREFIX || path.starts_with("/_prototype/")
}

pub(super) fn is_query(path: &str) -> bool {
    matches(path) && path.ends_with("/query")
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Part {
    Shell,
    Frame,
    Query,
    Source,
}

#[derive(PartialEq, Eq, Debug)]
struct Route {
    revision: Option<u64>,
    part: Part,
}

impl Route {
    fn parse(path: &str) -> Result<Self> {
        let mut segments = path
            .strip_prefix("/_prototype/")
            .context(Failure::NotFound)?
            .split('/');
        let revision = match segments.next() {
            Some("published") => None,
            Some("revisions") => {
                let raw = segments.next().context(Failure::NotFound)?;
                let id = raw
                    .parse::<u64>()
                    .ok()
                    .filter(|&id| id > 0)
                    .context(Failure::NotFound)?;
                ensure!(raw == id.to_string(), Failure::NotFound);
                Some(id)
            }
            _ => anyhow::bail!(Failure::NotFound),
        };
        let part = match segments.next() {
            None => Part::Shell,
            Some("frame") => Part::Frame,
            Some("query") => Part::Query,
            Some("source") if revision.is_some() => Part::Source,
            _ => anyhow::bail!(Failure::NotFound),
        };
        ensure!(segments.next().is_none(), Failure::NotFound);
        Ok(Self { revision, part })
    }
}

fn require_shell_fetch(origin: &str, headers: &HeaderMap) -> Result<()> {
    let optional = |name, values: &[&str]| {
        !headers.contains_key(name)
            || web_api::single_header(headers, name).is_some_and(|v| values.contains(&v))
    };
    ensure!(
        web_api::single_header(headers, "x-day2-prototype-query") == Some("1")
            && optional("origin", &[origin])
            && optional("sec-fetch-site", &["same-origin"])
            && optional("sec-fetch-mode", &["cors", "same-origin"])
            && optional("sec-fetch-dest", &["empty"]),
        Failure::InvalidOrigin
    );
    Ok(())
}

struct Viewer<'a> {
    host: &'a Host,
    page: &'a Page,
    session: &'a Session,
    route: Route,
    at: i64,
}

#[derive(PartialEq, Eq)]
struct Access {
    stamp: AuthorityStamp,
    data_revision: Option<i64>,
    owner: bool,
    can_edit: bool,
}

impl Viewer<'_> {
    fn access(&self) -> Result<Access> {
        let runtime = &self.host.runtime;
        let actor = &self.session.actor;
        runtime.sql_read(|tx| {
            let active = authorize_in(tx, runtime, &self.page.query, actor)?;
            let now = self.host.wall_seconds()?;
            let current: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM day2_web_sessions WHERE hash=?1 AND actor=?2 AND expires>?3)",
                rusqlite::params![self.session.hash, actor, now],
                |row| row.get(0),
            )?;
            ensure!(current, Failure::SignInRequired);
            let data_revision = if self.route.revision.is_some() {
                let lookup = self.page.revision_query.as_deref().context(Failure::NotFound)?;
                authorize_in(tx, runtime, lookup, actor)?;
                Some(crate::live::revision(tx)?)
            } else {
                None
            };
            if self.route.part == Part::Source {
                owners::authorize_in(tx, runtime, actor, Permission::PrototypeSourceDownload)?;
            }
            let owner = active.document.authorize_audit(actor).is_ok();
            let can_edit = self.route.part == Part::Shell && owner && self.page.save_command.as_deref().is_some_and(
                |save| authorize_in(tx, runtime, save, actor).is_ok(),
            );
            Ok(Access {
                stamp: active.stamp,
                data_revision,
                owner,
                can_edit,
            })
        })
    }

    fn html(&self) -> Result<String> {
        let Some(id) = self.route.revision else {
            return Ok(self.page.html.clone());
        };
        let operation = self
            .page
            .revision_query
            .as_deref()
            .context(Failure::NotFound)?;
        let runtime = &self.host.runtime;
        let outcome = runtime.invoke_verified(
            operation,
            RequestIdentity {
                actor: &self.session.actor,
                origin: self.session.origin.as_ref(),
            },
            &format!(
                "prototype-revision-{}-{}",
                id,
                security::random(self.host.entropy.as_ref())?
            ),
            &json!({"id":id}),
            self.at,
            Fault::None,
        )?;
        if outcome.status != "success" {
            if outcome.status == "failure"
                && runtime
                    .artifact()
                    .contract()
                    .app_contract
                    .as_ref()
                    .is_some_and(|contract| contract.errors.contains_key(&outcome.error))
            {
                anyhow::bail!(Failure::NotFound);
            }
            anyhow::bail!(Failure::from_code(&outcome.error).unwrap_or(Failure::Internal));
        }
        let html = outcome.result["html"]
            .as_str()
            .context("revision query returned invalid HTML")?;
        crate::prototype::validate_html(html)?;
        Ok(html.to_owned())
    }

    // A local revision can cease to be visible while a provider read is in flight.
    // If business rows changed, reread just this revision before handing data back.
    fn recheck(&self, previous: &Access, html: &str) -> Result<Access> {
        let current = self.access()?;
        ensure!(
            current.stamp == previous.stamp,
            Failure::AuthorityPolicyChanged
        );
        if current.data_revision != previous.data_revision {
            ensure!(self.html()? == html, Failure::Conflict);
            ensure!(self.access()? == current, Failure::Conflict);
        }
        Ok(current)
    }
}

fn document((body, policy): (String, String)) -> Result<Response> {
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, policy.parse()?);
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse()?);
    response
        .headers_mut()
        .insert("x-dns-prefetch-control", "off".parse()?);
    Ok(response)
}

pub(super) fn serve(
    host: &Host,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    session: &Session,
    at: i64,
) -> Result<Response> {
    let page = host
        .runtime
        .artifact()
        .contract()
        .prototype
        .as_ref()
        .context(Failure::NotFound)?;
    let route = Route::parse(uri.path())?;
    ensure!(method == Method::GET, Failure::UnsupportedMethod);
    ensure!(
        body.is_empty() && !headers.contains_key(web_api::ACT_AS_HEADER),
        Failure::InvalidInput
    );
    if route.part == Part::Query {
        require_shell_fetch(&host.origin, headers)?;
    }
    let viewer = Viewer {
        host,
        page,
        session,
        route,
        at,
    };
    let access = viewer.access()?;
    let html = viewer.html()?;
    let pin = crate::digest(&serde_json::to_vec(&(
        host.runtime.artifact().id(),
        viewer.route.revision,
        &html,
    ))?);
    let hash = day2_assets::hash_part(&pin)?;
    let parameter = format!("pin={hash}");
    let (_, operation) = page
        .query
        .split_once('.')
        .context("qualified prototype query required")?;
    if viewer.route.part == Part::Shell {
        ensure!(uri.query().is_none(), Failure::InvalidInput);
    } else {
        ensure!(uri.query() == Some(parameter.as_str()), Failure::Conflict);
    }
    let response = match viewer.route.part {
        Part::Shell => {
            let path = uri.path();
            let source = (viewer.route.revision.is_some() && access.owner)
                .then(|| format!("{path}/source?{parameter}"));
            document(crate::prototype_browser::shell(
                &format!("{path}/frame?{parameter}"),
                &format!("{path}/query?{parameter}"),
                operation,
                source.as_deref(),
                page.save_command
                    .as_deref()
                    .filter(|_| access.can_edit)
                    .map(|save| (save, html.as_str())),
            ))?
        }
        Part::Frame => document(crate::prototype_browser::frame(&html, operation))?,
        Part::Source => (
            [
                (header::CONTENT_TYPE, "application/gzip"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"app.tar.gz\"",
                ),
            ],
            crate::prototype::publication(host.runtime.artifact().contract(), &html)?,
        )
            .into_response(),
        Part::Query => {
            viewer.recheck(&access, &html)?;
            // The receipt and audit retain this host-issued provenance. The
            // pin commits to the artifact, selected revision and exact HTML.
            let revision = viewer
                .route
                .revision
                .map(|id| format!("r{id}"))
                .unwrap_or_else(|| "published".into());
            let nonce = security::random(host.entropy.as_ref())?;
            let invocation = format!("proto-{revision}-{hash}-{}", &nonce[..32]);
            web_api::RequestContext {
                runtime: &host.runtime,
                catalog: &host.api,
                secret: &host.secret,
                entropy: host.entropy.as_ref(),
                session,
                origin: &host.origin,
                at,
            }
            .prototype_query(&page.query, invocation)?
        }
    };
    viewer.recheck(&access, &html)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_positive_revision_paths_and_fixed_suffixes() {
        assert_eq!(
            Route::parse("/_prototype/revisions/17/query").unwrap(),
            Route {
                revision: Some(17),
                part: Part::Query
            }
        );
        for path in [
            "/_prototype",
            "/_prototype/revisions",
            "/_prototype/revisions/0/frame",
            "/_prototype/revisions/01",
            "/_prototype/revisions/+1",
            "/_prototype/revisions/%31",
            "/_prototype/revisions/18446744073709551616/source",
            "/_prototype/published/",
            "/_prototype/published/source",
            "/_prototype/published/query/extra",
            "/_prototype/revisions/3/api/another.operation",
        ] {
            assert!(Route::parse(path).is_err(), "{path}");
        }
    }

    #[test]
    fn connector_requests_require_a_bound_shell_fetch() {
        let mut headers = HeaderMap::new();
        assert!(require_shell_fetch("https://app.example", &headers).is_err());
        headers.insert("x-day2-prototype-query", "1".parse().unwrap());
        assert!(require_shell_fetch("https://app.example", &headers).is_ok());
        for (name, value) in [
            ("origin", "null"),
            ("origin", "https://other.example"),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
        ] {
            headers.insert(name, value.parse().unwrap());
            assert!(require_shell_fetch("https://app.example", &headers).is_err());
            headers.remove(name);
        }
        headers.append("x-day2-prototype-query", "1".parse().unwrap());
        assert!(require_shell_fetch("https://app.example", &headers).is_err());
    }
}
