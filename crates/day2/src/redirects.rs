//! Declared redirect routes: `GET /<prefix>/<rest..>` runs one command and answers
//! `302 Found` with a URL that command returned.
//!
//! An application opts one command into one route in its source
//! (`Redirect.route`), and this module is the whole host side of that contract:
//! admission checks the declaration against the command's input and output
//! contracts, request matching decides which paths reach it, and the destination
//! check decides what may become `Location`. Running the command is the ordinary
//! invocation path, with its admission, authority and mandatory audit; nothing
//! here grants anything.
//!
//! Three properties are the point:
//!
//! - Nothing reaches a redirect route that anything else claims. Platform paths
//!   are dispatched first, page routes next, and a redirect never matches a path
//!   in a reserved platform namespace.
//! - Nothing from the request reaches `Location` except through the command's
//!   typed result. The path is the command's input; the query string is dropped.
//! - `Location` is an absolute URL whose scheme the declaration allows and the
//!   platform does not refuse, serialized by a WHATWG parser, so what the browser
//!   follows is exactly what was checked.
use crate::{
    artifact::{self, Artifact},
    output_schema::Type,
    schema::{Kind, Record},
};
use anyhow::{Context, Result, bail, ensure};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const MAXIMUM_ROUTES: usize = 8;
/// Enough for the longest name a go link can have: 255 bytes of one-character
/// segments. Longer requests are refused before any command runs.
const MAX_SEGMENTS: usize = 128;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_LOCATION_BYTES: usize = 8_192;
const MAX_NOT_FOUND: usize = 16;

/// Schemes no redirect may send a browser to, whatever the declaration allows.
/// These destinations contain executable/inline content or address local files.
pub const REFUSED_SCHEMES: &[&str] = &[
    "javascript",
    "vbscript",
    "data",
    "blob",
    "file",
    "filesystem",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schemes {
    /// `http` and `https` only.
    Web,
    /// Any absolute URI except [`REFUSED_SCHEMES`], for links that open an
    /// application (`slack://`, `zoommtg:`) as go links historically could.
    Any,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub name: String,
    pub operation: String,
    prefix: Vec<String>,
    field: String,
    pub(crate) input: Record,
    location: String,
    schemes: Schemes,
    not_found: BTreeSet<String>,
    pub(crate) not_found_page: Option<String>,
}

/// The outcome of matching a request path against the declared routes.
#[derive(Debug, PartialEq)]
pub enum Match<'a> {
    /// No declared route claims this path: an ordinary 404.
    None,
    /// A route claims it, but its segments are not a valid command input: 400,
    /// and no command runs.
    Invalid,
    Route(&'a Route, Value),
}

/// Why a request was not allowed to run a redirect route's command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A browser speculatively fetching a link the person has not followed.
    Prefetch,
    /// A subresource, frame or script fetch rather than a top-level navigation.
    NotNavigation,
}

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    /// Longest literal prefix first, so the first match is the most specific.
    routes: Vec<Route>,
}

impl Catalog {
    pub(crate) fn route(&self, name: &str) -> Result<&Route> {
        self.routes
            .iter()
            .find(|route| route.name == name)
            .context("unknown redirect route name")
    }

    pub fn from_artifact(artifact: &Artifact) -> Result<Self> {
        ensure!(
            artifact.redirects.len() <= MAXIMUM_ROUTES,
            "redirect route count budget"
        );
        let mut names = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        let mut routes = Vec::new();
        for declared in &artifact.redirects {
            ensure!(
                names.insert(declared.name.as_str()),
                "duplicate redirect route name"
            );
            let route = Route::compile(declared, artifact)
                .with_context(|| format!("redirect route {}", declared.name))?;
            ensure!(
                prefixes.insert(route.prefix.clone()),
                "redirect routes {} and another share a path prefix",
                route.name
            );
            routes.push(route);
        }
        routes.sort_by(|a, b| {
            b.prefix
                .len()
                .cmp(&a.prefix.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(Self { routes })
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Match an already percent-encoded request path. The caller has dispatched
    /// platform paths and page routes first; this still refuses every platform
    /// path, so one that reaches here by mistake cannot run a command.
    pub fn resolve(&self, path: &str) -> Match<'_> {
        if self.routes.is_empty()
            || path == "/"
            || !path.starts_with('/')
            || path.len() > MAX_PATH_BYTES
            || path.contains(['?', '#'])
        {
            return Match::None;
        }
        let raw = path[1..].split('/').collect::<Vec<_>>();
        // Decided on the first segment as sent and as decoded, so an encoded
        // spelling of a platform path is the platform's too.
        let first = raw[0];
        let decoded_first = crate::routing::decode_segment(first).ok();
        let platform = |segment: &str| {
            PLATFORM_NAMESPACES.contains(&segment) || (raw.len() == 1 && reserved(segment))
        };
        if platform(first) || decoded_first.as_deref().is_some_and(platform) {
            return Match::None;
        }
        let Some(route) = self.routes.iter().find(|route| {
            raw.len() > route.prefix.len()
                && route
                    .prefix
                    .iter()
                    .zip(&raw)
                    .all(|(literal, segment)| literal == segment)
        }) else {
            return Match::None;
        };
        if raw.len() > MAX_SEGMENTS {
            return Match::Invalid;
        }
        // Decoded as a browser encoded them. An encoded slash would make a
        // segment boundary ambiguous, so the segment decoder refuses it, as it
        // refuses empty, dot and control-character segments.
        let Ok(rest) = raw[route.prefix.len()..]
            .iter()
            .map(|segment| crate::routing::decode_segment(segment))
            .collect::<Result<Vec<_>>>()
        else {
            return Match::Invalid;
        };
        Match::Route(route, json!({ route.field.clone(): rest.join("/") }))
    }
}

impl Route {
    fn compile(declared: &artifact::Redirect, artifact: &Artifact) -> Result<Self> {
        // The name reaches App.definition and the audit trail's route label.
        crate::schema::identifier(&declared.name)?;
        let (prefix, field) = pattern(&declared.path)?;
        let command = artifact
            .operations
            .iter()
            .find(|op| op.name == declared.operation && op.kind == "command")
            .context("redirect route requires a registered command")?;
        // A redirect is a request from a person. An internal command has no
        // request entry point, and a route must not give it one.
        ensure!(
            !artifact.internal_command(&command.name),
            "redirect route requires a public command"
        );
        ensure!(
            command.input_type == declared.input_type
                && command.output_type == declared.output_type,
            "redirect route types differ from the bound command"
        );
        let input = artifact
            .schema
            .inputs
            .get(&command.input_type)
            .context("redirect route requires a registered input")?;
        ensure!(
            input.fields.len() == 1 && input.fields.contains_key(&field),
            "redirect path parameter {field} must be the command's only input field"
        );
        ensure!(
            matches!(input.fields[&field], Kind::Text | Kind::StandardText { .. }),
            "redirect path parameter {field} requires a text input field"
        );
        let output = artifact
            .outputs
            .get(&command.output_type)
            .context("redirect route requires a typed command result")?;
        let Type::Record(fields) = &output.shape else {
            bail!("redirect route requires a record command result");
        };
        ensure!(
            matches!(
                fields.get(&declared.location),
                Some(Type::String | Type::StandardText { .. })
            ),
            "redirect location {} must be a text field of the command result",
            declared.location
        );
        let schemes = match declared.schemes.as_str() {
            "web" => Schemes::Web,
            "any" => Schemes::Any,
            _ => bail!("redirect route requires a declared scheme policy"),
        };
        ensure!(
            declared.not_found.len() <= MAX_NOT_FOUND,
            "redirect not-found failure budget"
        );
        let declared_errors = artifact
            .app_contract
            .as_ref()
            .and_then(|contract| contract.operations.get(&command.name))
            .map(|operation| operation.errors.iter().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        let mut not_found = BTreeSet::new();
        for code in &declared.not_found {
            ensure!(
                declared_errors.contains(code),
                "redirect not-found failure {code} is not declared by the bound command"
            );
            ensure!(
                not_found.insert(code.clone()),
                "duplicate not-found failure"
            );
        }
        let not_found_page = if declared.not_found_page.is_empty() {
            None
        } else {
            ensure!(
                !not_found.is_empty(),
                "not-found page requires declared failures"
            );
            let page = artifact
                .pages
                .iter()
                .find(|page| page.path == declared.not_found_page)
                .context("redirect not-found page must be registered")?;
            ensure!(
                page.input_type == command.input_type,
                "redirect not-found page input differs from the bound command"
            );
            ensure!(!page.live, "redirect not-found page must not be live");
            Some(page.name.clone())
        };
        Ok(Self {
            name: declared.name.clone(),
            operation: command.name.clone(),
            prefix,
            field,
            input: input.clone(),
            location: declared.location.clone(),
            schemes,
            not_found,
            not_found_page,
        })
    }

    /// Build the declared path from logical text, encoding each segment once.
    /// Matching still uses the ordinary platform/page/redirect precedence.
    pub(crate) fn build_url(&self, supplied: &Value) -> Result<String> {
        self.input.validate_input(supplied)?;
        let path = supplied[&self.field]
            .as_str()
            .context("redirect route path requires text")?;
        let mut segments = self.prefix.clone();
        for segment in path.split('/') {
            crate::routing::validate_segment(segment)?;
            segments.push(segment.to_owned());
        }
        ensure!(
            segments.len() <= MAX_SEGMENTS,
            "redirect route segment budget"
        );
        Ok(crate::routing::path_url(&segments)?.path().to_owned())
    }

    /// Whether an application failure means nothing is at this address.
    pub fn not_found(&self, code: &str) -> bool {
        self.not_found.contains(code)
    }

    /// The `Location` for a successful result: the declared field, and only if it
    /// is a destination this route may send a browser to.
    pub fn location(&self, result: &Value) -> Result<String> {
        destination(
            result
                .get(&self.location)
                .and_then(Value::as_str)
                .context("redirect result has no location")?,
            self.schemes,
        )
    }
}

/// Parse `/literal/.../{field..}`: literal segments, then one rest parameter.
fn pattern(path: &str) -> Result<(Vec<String>, String)> {
    ensure!(
        path.starts_with('/') && path.len() <= MAX_PATH_BYTES,
        "redirect route requires a bounded absolute path"
    );
    let segments = path[1..].split('/').collect::<Vec<_>>();
    let (last, literals) = segments
        .split_last()
        .context("redirect route requires a path")?;
    let field = last
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix("..}"))
        .context("redirect route must end in one rest parameter, such as /{path..}")?;
    crate::schema::identifier(field)?;
    ensure!(
        literals.len() < MAX_SEGMENTS,
        "redirect route segment budget"
    );
    let mut prefix = Vec::new();
    for literal in literals {
        ensure!(
            !literal.is_empty() && !literal.contains(['{', '}', '%']),
            "redirect route prefix segments must be plain literals"
        );
        crate::routing::decode_segment(literal)?;
        ensure!(
            crate::routing::path_url(&[(*literal).to_owned()])?.path() == format!("/{literal}"),
            "redirect route prefix segments must use canonical URL spelling"
        );
        prefix.push((*literal).to_owned());
    }
    if let Some(first) = prefix.first() {
        ensure!(
            !reserved(first),
            "reserved platform route namespace: {first}"
        );
    }
    Ok((prefix, field.to_owned()))
}

/// First segments under which the platform serves paths of its own. A path
/// beneath one of these is never a link. Other reserved names (`docs`, `audit`,
/// `login`, ...) are single platform endpoints: the endpoint itself is never a
/// link, but a longer path beginning with the same word, such as `/docs/intro`
/// for a `docs/%s` link, is not the platform's and may be.
const PLATFORM_NAMESPACES: &[&str] = &["api", "assets", "health", "ingress", "_live"];

/// Every name the platform reserves as a first segment. A declared literal prefix
/// may not begin with one, so no application route is ever inside the platform's.
fn reserved(segment: &str) -> bool {
    crate::routing::reserved_namespace(segment)
        || segment == crate::ingress::ROUTE_PREFIX.trim_matches('/')
}

/// Check a destination and return the exact `Location` to send.
pub fn destination(raw: &str, schemes: Schemes) -> Result<String> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_LOCATION_BYTES,
        "redirect location budget"
    );
    // The URL parser strips surrounding whitespace and removes tabs and newlines
    // inside a URL, so "java\nscript:" would parse as "javascript:". Refuse the
    // characters instead of relying on what the parser makes of them.
    ensure!(
        !raw.chars().any(|c| c.is_control() || c.is_whitespace()),
        "redirect location contains whitespace or control characters"
    );
    // A base-less parse succeeds only for an absolute URL, so a relative, a
    // scheme-relative ("//host") or a bare-host destination is refused here.
    let url = url::Url::parse(raw).context("redirect location is not an absolute URL")?;
    let scheme = url.scheme();
    ensure!(
        !REFUSED_SCHEMES.contains(&scheme),
        "redirect location scheme {scheme} is refused"
    );
    match schemes {
        Schemes::Web => ensure!(
            matches!(scheme, "http" | "https"),
            "redirect location scheme {scheme} is not http or https"
        ),
        Schemes::Any => {}
    }
    let serialized = url.as_str();
    ensure!(
        serialized.len() <= MAX_LOCATION_BYTES && serialized.is_ascii(),
        "redirect location budget"
    );
    Ok(serialized.to_owned())
}

/// Whether a request may run a redirect route's command at all.
///
/// A redirect runs a command on a GET, so a request the person did not make as
/// a navigation must not reach it: a speculative prefetch would count a visit
/// nobody made, and an `<img>` or `fetch()` on another site would count one
/// silently. Fetch metadata is checked only when the browser sends it, so a
/// command-line client still works; a browser always sends it.
pub fn refusal(headers: &HeaderMap) -> Option<Refusal> {
    let values = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap_or("").to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let prefetch = values("sec-purpose")
        .iter()
        .chain(&values("purpose"))
        .chain(&values("x-purpose"))
        .chain(&values("x-moz"))
        .any(|value| value.contains("prefetch") || value.contains("preview"));
    if prefetch {
        return Some(Refusal::Prefetch);
    }
    for (name, expected) in [
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
    ] {
        if values(name).iter().any(|value| value != expected) {
            return Some(Refusal::NotNavigation);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn route(prefix: &[&str], name: &str) -> Route {
        Route {
            name: name.into(),
            operation: "go.visit".into(),
            prefix: prefix.iter().map(|segment| (*segment).to_owned()).collect(),
            field: "path".into(),
            input: Record {
                fields: std::collections::BTreeMap::from([("path".into(), Kind::Text)]),
                roc_type: None,
                identity: None,
            },
            location: "url".into(),
            schemes: Schemes::Any,
            not_found: BTreeSet::from(["app:go.missing".to_owned()]),
            not_found_page: None,
        }
    }

    fn catalog() -> Catalog {
        // Sorted as from_artifact sorts: longest prefix first.
        Catalog {
            routes: vec![route(&["go"], "prefixed"), route(&[], "bare")],
        }
    }

    fn matched(catalog: &Catalog, path: &str) -> Option<(String, Value)> {
        match catalog.resolve(path) {
            Match::Route(route, input) => Some((route.name.clone(), input)),
            _ => None,
        }
    }

    #[test]
    fn patterns_are_a_literal_prefix_and_one_rest_parameter() {
        assert_eq!(pattern("/{path..}").unwrap(), (vec![], "path".into()));
        assert_eq!(
            pattern("/go/{name..}").unwrap(),
            (vec!["go".to_owned()], "name".into())
        );
        for invalid in [
            "",
            "/",
            "go/{path..}",
            "/{path}",
            "/{path..}/more",
            "/{Path..}",
            "/go//{path..}",
            "/{a}/{path..}",
            "/go%2F/{path..}",
            "/api/{path..}",
            "/audit/{path..}",
            "/assets/{path..}",
            "/ingress/{path..}",
            "/docs/{path..}",
            "/_live/{path..}",
            "/health/{path..}",
            "/go here/{path..}",
            "/caf\u{e9}/{path..}",
        ] {
            assert!(pattern(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn the_longest_literal_prefix_wins_and_the_rest_is_decoded_and_joined() {
        let catalog = catalog();
        assert_eq!(
            matched(&catalog, "/hello"),
            Some(("bare".into(), json!({"path":"hello"})))
        );
        assert_eq!(
            matched(&catalog, "/go/hello"),
            Some(("prefixed".into(), json!({"path":"hello"})))
        );
        // A bare `go` is a name, not an empty prefixed request.
        assert_eq!(
            matched(&catalog, "/go"),
            Some(("bare".into(), json!({"path":"go"})))
        );
        assert_eq!(
            matched(&catalog, "/go/docs/Read%20Me+now"),
            Some(("prefixed".into(), json!({"path":"docs/Read Me+now"})))
        );
        // Noncanonical but unambiguous encodings are decoded, not refused.
        assert_eq!(
            matched(&catalog, "/docs/%7Euser"),
            Some(("bare".into(), json!({"path":"docs/~user"})))
        );
    }

    #[test]
    fn navigation_encodes_logical_segments_once_and_rejects_invalid_inputs() -> Result<()> {
        let catalog = catalog();
        let route = catalog.route("prefixed")?;
        for (path, expected) in [
            ("hello", "/go/hello"),
            ("docs/Read Me", "/go/docs/Read%20Me"),
            ("docs/%2F", "/go/docs/%252F"),
            ("docs/a?b#c", "/go/docs/a%3Fb%23c"),
            ("docs/caf\u{e9}", "/go/docs/caf%C3%A9"),
        ] {
            let input = json!({"path":path});
            let url = route.build_url(&input)?;
            assert_eq!(url, expected);
            assert_eq!(matched(&catalog, &url), Some(("prefixed".into(), input)));
        }
        for path in [
            "", "/hello", "hello/", "a//b", "a/../b", "a/./b", "a\\b", "a\nb",
        ] {
            assert!(route.build_url(&json!({"path":path})).is_err(), "{path:?}");
        }
        for input in [
            json!({}),
            json!({"path":1}),
            json!({"path":"hello", "extra":"x"}),
        ] {
            assert!(route.build_url(&input).is_err(), "{input}");
        }
        assert!(
            route
                .build_url(&json!({"path":(["a"; MAX_SEGMENTS].join("/"))}))
                .is_err()
        );
        assert!(
            route
                .build_url(&json!({"path":"a".repeat(MAX_PATH_BYTES)}))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn platform_namespaces_and_malformed_paths_never_run_a_command() {
        let catalog = catalog();
        for path in [
            "/",
            "/api",
            "/api/x",
            "/audit",
            "/assets/x",
            "/docs",
            "/%64ocs",
            "/login",
            "/logout",
            "/actions",
            "/_live",
            "/health/live",
            "/ingress/slack",
            "/mcp",
            "/openapi.json",
            "/%61pi/x",
            "/health",
            "",
            "hello",
        ] {
            assert_eq!(catalog.resolve(path), Match::None, "{path}");
        }
        // A single platform endpoint reserves only itself: `docs/%s` and
        // `audit/%s` links are reachable beneath it.
        for (path, rest) in [("/docs/intro", "docs/intro"), ("/audit/q3", "audit/q3")] {
            assert_eq!(
                matched(&catalog, path),
                Some(("bare".into(), json!({"path":rest})))
            );
        }
        for path in [
            "/docs%2Ffoo",
            "/go/a%2Fb",
            "/go/a//b",
            "/go/a/",
            "/go/./a",
            "/go/..",
            "/go/%FF",
            "/go/%zz",
            "/go/%0a",
        ] {
            assert_eq!(catalog.resolve(path), Match::Invalid, "{path}");
        }
        let long = format!("/{}", ["a"; MAX_SEGMENTS + 1].join("/"));
        assert_eq!(catalog.resolve(&long), Match::Invalid);
        assert_eq!(Catalog::default().resolve("/hello"), Match::None);
    }

    #[test]
    fn only_absolute_destinations_with_an_allowed_scheme_become_a_location() {
        for (raw, expected) in [
            ("https://example.com/docs", "https://example.com/docs"),
            ("HTTPS://Example.COM", "https://example.com/"),
            (
                "https://example.com/caf\u{e9}",
                "https://example.com/caf%C3%A9",
            ),
            (
                "https://example.com/search?q=a%20b#top",
                "https://example.com/search?q=a%20b#top",
            ),
        ] {
            assert_eq!(destination(raw, Schemes::Web).unwrap(), expected);
            assert_eq!(destination(raw, Schemes::Any).unwrap(), expected);
        }
        for raw in [
            "codex://session/open?id=abc123",
            "slack://channel?team=T1",
            "zoommtg:join?confno=1",
            "mailto:someone@example.com",
        ] {
            assert_eq!(destination(raw, Schemes::Any).unwrap(), raw);
            assert!(destination(raw, Schemes::Web).is_err(), "{raw}");
        }
        for raw in [
            "",
            "/relative",
            "//evil.example/",
            "evil.example",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "java\nscript:alert(1)",
            " https://example.com",
            "https://example.com/\r\nSet-Cookie: x=1",
            "https://exa mple.com",
            "https://example.com/\u{a0}",
            "vbscript:msgbox",
            "data:text/html,<script>alert(1)</script>",
            "blob:https://example.com/uuid",
            "file:///etc/passwd",
            "FILE://localhost/Users/example/document.html",
            "filesystem:https://example.com/temporary/x",
            "https://",
        ] {
            assert!(destination(raw, Schemes::Any).is_err(), "{raw:?}");
        }
        assert!(
            destination(
                &format!("https://e.com/{}", "a".repeat(9_000)),
                Schemes::Any
            )
            .is_err()
        );
    }

    #[test]
    fn only_a_top_level_navigation_may_run_the_command() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.append(*name, HeaderValue::from_static(value));
            }
            map
        };
        assert_eq!(refusal(&headers(&[])), None);
        assert_eq!(
            refusal(&headers(&[
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-site", "cross-site"),
            ])),
            None,
            "a link followed from another site is a visit, as it always was"
        );
        for pairs in [
            &[("sec-purpose", "prefetch")][..],
            &[("sec-purpose", "prefetch;prerender")][..],
            &[("purpose", "prefetch")][..],
            &[("x-moz", "prefetch")][..],
            &[("x-purpose", "preview")][..],
        ] {
            assert_eq!(refusal(&headers(pairs)), Some(Refusal::Prefetch));
        }
        for pairs in [
            &[("sec-fetch-dest", "image")][..],
            &[("sec-fetch-dest", "iframe")][..],
            &[("sec-fetch-dest", "empty"), ("sec-fetch-mode", "cors")][..],
            &[("sec-fetch-mode", "no-cors")][..],
            &[("sec-fetch-dest", "document"), ("sec-fetch-dest", "image")][..],
        ] {
            assert_eq!(refusal(&headers(pairs)), Some(Refusal::NotNavigation));
        }
    }
}
