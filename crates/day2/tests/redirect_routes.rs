//! Declared redirect routes, end to end: IAP assertion -> edge admission -> route
//! match -> the bound Roc command under its authority policy -> `302 Location`.
//!
//! The fixture (`fixtures/redirect-conformance`) declares the GoLinks shape: a
//! `/go/{path..}` and a bare `/{path..}` route bound to one visit command that
//! resolves exact names first and `name/%s` wildcards second, beside two page
//! routes. Nothing here stands in for the runtime: links are created through the
//! app's own command and every visit is a real invocation with its audit record.
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    artifact::{Edge, Instance},
    iap::{ISSUER, KeySource, Verifier},
    store::{Fault, Runtime},
    web::LocalServer,
};
use reqwest::{
    Method, StatusCode,
    blocking::{Client, RequestBuilder, Response},
    header::{CACHE_CONTROL, HOST, LOCATION},
    redirect::Policy,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ORIGIN: &str = "https://go.v2.exampleco.test";
const AUTHORITY: &str = "go.v2.exampleco.test";
const AUDIENCE: &str = "/projects/1234/global/backendServices/5678";
/// May follow links.
const VISITOR: &str = "ada@exampleco.test";
/// May browse the directory, but holds no grant for the visit command.
const BROWSER: &str = "grace@exampleco.test";

struct Keys(String);

impl KeySource for Keys {
    fn fetch(&self) -> Result<String> {
        Ok(self.0.clone())
    }
}

struct Signer(EcdsaKeyPair);

impl Signer {
    fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("keygen"))?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| anyhow::anyhow!("key"))?;
        Ok(Self(pair))
    }

    fn keys(&self) -> String {
        let point = self.0.public_key().as_ref();
        json!({"keys":[{"kid":"edge","kty":"EC","crv":"P-256","alg":"ES256",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
        .to_string()
    }

    fn person(&self, email: &str) -> String {
        let claims = json!({"iss":ISSUER,"aud":AUDIENCE,"iat":now(),"exp":now() + 600,
            "sub":format!("accounts.google.com:{email}"),"email":email,"hd":"exampleco.test"});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"edge","typ":"JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .0
            .sign(&SystemRandom::new(), signed.as_bytes())
            .expect("sign");
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn instance(artifact: &str) -> Value {
    let everyone = json!([VISITOR, BROWSER]);
    let links = |grant: Value| json!({"links": grant});
    json!({"installation":"goco","environment":"test",
    "identity":{"scheme":"google_iap","hosted_domain":"exampleco.test"},
    "apps":{"go":{"artifact":artifact,"readers":everyone,"writers":everyone,
        "edge":{"origin":ORIGIN,"iap_audience":AUDIENCE},
        "authority":{"version":1,"admins":[],"operations":{
            "go.list":{"actors":everyone,"mode":{"kind":"read"},
                "models":links(json!({"read":true,"rows":{"kind":"all"}}))},
            "go.create":{"actors":[VISITOR],"mode":{"kind":"current_state"},
                "models":links(json!({"read":true,"create":true,"rows":{"kind":"all"}}))},
            "go.delete":{"actors":[VISITOR],"mode":{"kind":"current_state"},
                "models":links(json!({"read":true,"update_fields":["deleted"],"rows":{"kind":"all"}}))},
            // Following a link is an ordinary grant on an ordinary command.
            "go.visit":{"actors":[VISITOR],"mode":{"kind":"current_state"},
                "models":links(json!({"read":true,"update_fields":["visits"],"rows":{"kind":"all"}}))}
        }}}}})
}

struct Server {
    origin: String,
    client: Client,
    runtime: Runtime,
    signer: Signer,
    _directory: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl Server {
    fn start() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_REDIRECT_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_REDIRECT_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        fs::write(
            &path,
            serde_json::to_vec(&instance(artifact.to_str().context("artifact path")?))?,
        )?;
        let loaded = Instance::load(&path)?;
        let edge: Edge = loaded.edge("go")?.1.clone();
        let runtime = Runtime::load(&path, "go")?;
        runtime.initialize()?;
        let signer = Signer::new()?;
        let verifier = Verifier::new(AUDIENCE, "exampleco.test", Box::new(Keys(signer.keys())))?;
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let served = runtime.clone();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let server =
                        LocalServer::bind_edge_listener(served, listener, &edge, verifier, 4)?;
                    send.send(format!("http://{address}"))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let origin = receive.recv_timeout(Duration::from_secs(10))?;
        let server = Self {
            origin,
            client: Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            runtime,
            signer,
            _directory: directory,
            stop: Some(stop),
            thread: Some(thread),
        };
        for (name, url) in [
            ("docs", "https://example.com/docs"),
            ("docs/%s", "https://example.com/search?q=%s"),
            ("hello", "https://example.com/hello"),
            ("codex", "codex://session/open?id=abc123"),
            // A page route has this path; the page must still win.
            ("about", "https://example.com/about"),
            ("audit/%s", "https://example.com/reviews/%s"),
            // The application stores it; the host must refuse to follow it.
            ("script", "javascript:alert(document.cookie)"),
            ("old", "https://example.com/old"),
        ] {
            server.create(name, url)?;
        }
        let old = server.link("old")?;
        let deleted = server.runtime.invoke(
            "go.delete",
            VISITOR,
            "seed-delete-old",
            &json!({"link_id": old["id"]}),
            now(),
            Fault::None,
        )?;
        assert_eq!(deleted.status, "success", "{}", deleted.error);
        Ok(server)
    }

    fn create(&self, name: &str, url: &str) -> Result<()> {
        let id = format!("seed-{}", name.replace(['/', '%'], "-"));
        let outcome = self.runtime.invoke(
            "go.create",
            VISITOR,
            &id,
            &json!({"name": name, "url": url}),
            now(),
            Fault::None,
        )?;
        assert_eq!(outcome.status, "success", "{name}: {}", outcome.error);
        Ok(())
    }

    fn link(&self, name: &str) -> Result<Value> {
        let outcome = self.runtime.invoke(
            "go.list",
            VISITOR,
            &format!("list-{}", now_nanos()),
            &json!({"after": "", "limit": 50}),
            now(),
            Fault::None,
        )?;
        assert_eq!(outcome.status, "success", "{}", outcome.error);
        outcome.result["items"]
            .as_array()
            .context("items")?
            .iter()
            .find(|item| item["name"] == name)
            .cloned()
            .with_context(|| format!("link {name}"))
    }

    fn visits(&self, name: &str) -> Result<u64> {
        self.link(name)?["visits"].as_u64().context("visits")
    }

    /// A top-level navigation, as a browser sends it at the edge.
    fn follow(&self, path: &str, email: &str) -> Result<Response> {
        Ok(self
            .navigate(Method::GET, path)
            .header("x-goog-iap-jwt-assertion", self.signer.person(email))
            .send()?)
    }

    fn navigate(&self, method: Method, path: &str) -> RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.origin))
            .header(HOST, AUTHORITY)
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "cross-site")
    }

    /// Every lifecycle event of the visit command — admission, refusal and
    /// completion — from the platform's own audit stream.
    fn audited_visits(&self) -> Result<Vec<(String, String, String)>> {
        let db = rusqlite::Connection::open(self.runtime.db())?;
        let mut statement = db.prepare(
            "SELECT identity, actor, outcome FROM day2_audit_events
             WHERE operation='go.visit' ORDER BY sequence",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("HTTP server").is_ok());
        }
    }
}

/// Assert a redirect and return its invocation id.
fn redirected(response: Response, location: &str) -> Result<String> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text()?;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert_eq!(headers[LOCATION], location);
    assert_eq!(headers[CACHE_CONTROL], "no-store");
    assert!(body.is_empty());
    let id = headers["x-day2-invocation"].to_str()?.to_owned();
    assert!(id.starts_with("redirect-"), "{id}");
    Ok(id)
}

/// Assert the platform error page with this status, and whether a command ran.
fn refused(response: Response, status: StatusCode, ran: bool) -> Result<String> {
    let actual = response.status();
    let headers = response.headers().clone();
    let body = response.text()?;
    assert_eq!(actual, status, "{body}");
    assert!(!headers.contains_key(LOCATION), "{headers:?}");
    assert_eq!(
        headers.contains_key("x-day2-invocation"),
        ran,
        "{headers:?}"
    );
    assert!(
        headers[reqwest::header::CONTENT_TYPE]
            .to_str()?
            .starts_with("text/html"),
        "{headers:?}"
    );
    Ok(body)
}

#[test]
fn a_followed_link_runs_its_command_and_redirects_to_the_result() -> Result<()> {
    let server = Server::start()?;

    let id = redirected(
        server.follow("/hello", VISITOR)?,
        "https://example.com/hello",
    )?;
    assert_eq!(server.visits("hello")?, 1);
    // The visit is an ordinary invocation by the admitted person, in the
    // mandatory audit, admitted and then completed.
    let audited = server.audited_visits()?;
    assert!(
        audited
            .iter()
            .any(|(identity, actor, _)| identity == &id && actor == VISITOR),
        "{audited:?}"
    );

    // `/go/<name>` and `/<name>` are the same link; the longest prefix wins.
    redirected(
        server.follow("/go/hello", VISITOR)?,
        "https://example.com/hello",
    )?;
    assert_eq!(server.visits("hello")?, 2);

    // Every followed link is its own invocation: a new visit, never a replay.
    let again = redirected(
        server.follow("/hello", VISITOR)?,
        "https://example.com/hello",
    )?;
    assert_ne!(again, id);
    assert_eq!(server.visits("hello")?, 3);

    // A multi-segment path reaches the command whole and decoded, and the
    // wildcard's capture is re-encoded by the application, not reflected.
    redirected(
        server.follow("/docs/Read%20Me", VISITOR)?,
        "https://example.com/search?q=Read%20Me",
    )?;
    redirected(
        server.follow("/go/docs/a+b", VISITOR)?,
        "https://example.com/search?q=a%2Bb",
    )?;
    // The host decodes once: the logical capture is literal `%2F`, not a slash.
    redirected(
        server.follow("/docs/%252F", VISITOR)?,
        "https://example.com/search?q=%252F",
    )?;
    assert_eq!(server.visits("docs/%s")?, 3);
    // A platform endpoint reserves only itself, so `audit/%s` resolves.
    redirected(
        server.follow("/audit/q3", VISITOR)?,
        "https://example.com/reviews/q3",
    )?;

    // The declaration allows any scheme but the refused ones, so an
    // application deep link opens, as go links always could.
    redirected(
        server.follow("/codex", VISITOR)?,
        "codex://session/open?id=abc123",
    )?;

    // The query string never reaches the command or the Location.
    redirected(
        server.follow("/hello?next=https://evil.example/", VISITOR)?,
        "https://example.com/hello",
    )?;
    // A link followed from another site is a visit, as it always was.
    assert_eq!(server.visits("hello")?, 4);
    Ok(())
}

#[test]
fn unknown_deleted_and_unsafe_links_answer_the_platform_error_page() -> Result<()> {
    let server = Server::start()?;

    // An unknown name is the command's declared not-found failure: 404, with the
    // application's own description of it, and the attempt is audited.
    let body = refused(
        server.follow("/nowhere", VISITOR)?,
        StatusCode::NOT_FOUND,
        true,
    )?;
    assert!(body.contains("No active link or wildcard matches this address."));
    // So is a bare `/go`, which is a name, and a wildcard with no match.
    refused(server.follow("/go", VISITOR)?, StatusCode::NOT_FOUND, true)?;
    refused(
        server.follow("/team/unknown", VISITOR)?,
        StatusCode::NOT_FOUND,
        true,
    )?;
    // A deleted link no longer resolves.
    refused(server.follow("/old", VISITOR)?, StatusCode::NOT_FOUND, true)?;
    refused(
        server.follow("/go/old", VISITOR)?,
        StatusCode::NOT_FOUND,
        true,
    )?;
    assert_eq!(server.visits("old")?, 0);

    // The application returned a destination the platform will not follow.
    // The command ran — the visit is counted — but nothing is redirected.
    let body = refused(
        server.follow("/script", VISITOR)?,
        StatusCode::INTERNAL_SERVER_ERROR,
        true,
    )?;
    assert!(!body.contains("javascript"), "{body}");
    assert_eq!(server.visits("script")?, 1);

    // A path no command input could be is refused before any command runs.
    for path in ["/go/a%2Fb", "/hello/", "/go/%FF", "/a//b"] {
        refused(
            server.follow(path, VISITOR)?,
            StatusCode::BAD_REQUEST,
            false,
        )?;
    }
    Ok(())
}

#[test]
fn platform_paths_and_page_routes_keep_precedence() -> Result<()> {
    let server = Server::start()?;
    let before = server.audited_visits()?.len();

    // Page routes first: a link named `about` does not replace the page.
    for path in ["/", "/about"] {
        let response = server.follow(path, VISITOR)?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(!response.headers().contains_key(LOCATION));
    }
    assert_eq!(server.visits("about")?, 0);
    // A link named `docs` does not replace the API reference at `/docs`.
    let response = server.follow("/docs", VISITOR)?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.text()?.contains("openapi"));
    assert_eq!(server.visits("docs")?, 0);

    // Platform namespaces never reach a command, whatever lies beneath them.
    for (path, status) in [
        ("/api/unknown", StatusCode::NOT_FOUND),
        ("/assets/unknown", StatusCode::NOT_FOUND),
        // Deliveries carry no person, so a GET here has no session at all.
        ("/ingress/unknown", StatusCode::UNAUTHORIZED),
        ("/health/unknown", StatusCode::NOT_FOUND),
        // A noncanonical spelling of one is refused as noncanonical.
        ("/%61pi/unknown", StatusCode::BAD_REQUEST),
        ("/login", StatusCode::NOT_FOUND),
        ("/logout", StatusCode::NOT_FOUND),
        ("/actions", StatusCode::NOT_FOUND),
        ("/audit", StatusCode::FORBIDDEN),
    ] {
        let response = server.follow(path, VISITOR)?;
        assert_eq!(response.status(), status, "{path}");
        assert!(
            !response.headers().contains_key("x-day2-invocation"),
            "{path}"
        );
        assert!(!response.headers().contains_key(LOCATION), "{path}");
    }
    assert_eq!(server.audited_visits()?.len(), before, "no visit ran");
    Ok(())
}

#[test]
fn only_an_admitted_granted_navigation_runs_the_command() -> Result<()> {
    let server = Server::start()?;

    // No assertion: refused at the edge, before any route is chosen.
    assert_eq!(
        server.navigate(Method::GET, "/hello").send()?.status(),
        StatusCode::UNAUTHORIZED
    );
    // Admitted, but not granted the command: the command's own authority
    // refuses it, and the refusal is audited.
    refused(
        server.follow("/hello", BROWSER)?,
        StatusCode::FORBIDDEN,
        false,
    )?;
    let audited = server.audited_visits()?;
    assert!(
        audited.iter().any(|(_, actor, _)| actor == BROWSER),
        "{audited:?}"
    );
    assert_eq!(server.visits("hello")?, 0);

    let assertion = server.signer.person(VISITOR);
    let with = |request: RequestBuilder| {
        request
            .header("x-goog-iap-jwt-assertion", &assertion)
            .send()
    };
    // A speculative prefetch is declined, so only the real navigation counts.
    for (name, value) in [
        ("sec-purpose", "prefetch"),
        ("sec-purpose", "prefetch;prerender"),
        ("purpose", "prefetch"),
    ] {
        refused(
            with(server.navigate(Method::GET, "/hello").header(name, value))?,
            StatusCode::SERVICE_UNAVAILABLE,
            false,
        )?;
    }
    // An image, frame or script on another site cannot count a visit.
    for (dest, mode) in [
        ("image", "no-cors"),
        ("iframe", "navigate"),
        ("empty", "cors"),
    ] {
        let request = server
            .client
            .get(format!("{}/hello", server.origin))
            .header(HOST, AUTHORITY)
            .header("sec-fetch-dest", dest)
            .header("sec-fetch-mode", mode)
            .header("sec-fetch-site", "cross-site");
        refused(with(request)?, StatusCode::FORBIDDEN, false)?;
    }
    // Only GET follows a link.
    for method in [Method::HEAD, Method::POST, Method::PUT, Method::DELETE] {
        let response = with(server.navigate(method.clone(), "/hello"))?;
        assert!(
            response.status().is_client_error(),
            "{method}: {}",
            response.status()
        );
        assert!(!response.headers().contains_key(LOCATION));
    }
    assert_eq!(server.visits("hello")?, 0, "nothing above counted a visit");

    // A client that sends no fetch metadata is not a browser subresource.
    let plain = server
        .client
        .get(format!("{}/hello", server.origin))
        .header(HOST, AUTHORITY);
    redirected(with(plain)?, "https://example.com/hello")?;
    assert_eq!(server.visits("hello")?, 1);
    Ok(())
}

/// Admission checks each declaration against the bound command's real contract,
/// so a route cannot name a query, an absent or non-text result field, a failure
/// its command never declares, or a path inside the platform's namespaces.
#[test]
fn declarations_are_admitted_only_against_the_bound_command_contract() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_REDIRECT_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REDIRECT_ARTIFACT")?;
    let loaded = day2::artifact::LoadedArtifact::load(&artifact)?;
    let admitted = loaded.contract().clone();
    // The positive control: the fixture as built is admitted.
    day2::redirects::Catalog::from_artifact(&admitted)?;
    let mut collision = admitted.clone();
    collision.redirects[0].name = collision.pages[0].name.clone();
    assert!(day2::routing::Catalog::from_artifact(&collision).is_err());
    let bare = admitted
        .redirects
        .iter()
        .position(|route| route.name == "bare")
        .context("bare route")?;
    let query = admitted
        .operations
        .iter()
        .find(|operation| operation.name == "go.list")
        .context("list query")?
        .clone();
    type Change = Box<dyn Fn(&mut day2::artifact::Redirect)>;
    let cases: Vec<(&str, Change)> = vec![
        (
            "a query",
            Box::new(move |route| {
                route.operation = query.name.clone();
                route.input_type = query.input_type.clone();
                route.output_type = query.output_type.clone();
            }),
        ),
        (
            "an absent operation",
            Box::new(|route| route.operation = "go.nothing".into()),
        ),
        (
            "a different input type",
            Box::new(|route| route.input_type = "input_1".into()),
        ),
        (
            "a non-text location",
            Box::new(|route| route.location = "visits".into()),
        ),
        (
            "an absent location",
            Box::new(|route| route.location = "destination".into()),
        ),
        (
            "no rest parameter",
            Box::new(|route| route.path = "/{path}".into()),
        ),
        (
            "a rest parameter the command lacks",
            Box::new(|route| route.path = "/{name..}".into()),
        ),
        (
            "a platform namespace",
            Box::new(|route| route.path = "/api/{path..}".into()),
        ),
        (
            "a platform endpoint",
            Box::new(|route| route.path = "/docs/{path..}".into()),
        ),
        (
            "the other route's prefix",
            Box::new(|route| route.path = "/go/{path..}".into()),
        ),
        (
            "an undeclared scheme policy",
            Box::new(|route| route.schemes = "all".into()),
        ),
        (
            "another command's failure",
            Box::new(|route| route.not_found = vec!["app:go.invalid_link".into()]),
        ),
        (
            "an invalid name",
            Box::new(|route| route.name = "Bare".into()),
        ),
    ];
    for (case, change) in cases {
        let mut contract = admitted.clone();
        change(&mut contract.redirects[bare]);
        assert!(
            day2::redirects::Catalog::from_artifact(&contract).is_err(),
            "admitted a route naming {case}"
        );
    }
    Ok(())
}

#[test]
fn template_redirect_helpers_check_arguments_and_encode_each_path_segment() -> Result<()> {
    use day2::{output_schema::Type, web_templates};
    let artifact = std::env::var_os("DAY2_TEST_REDIRECT_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REDIRECT_ARTIFACT")?;
    let loaded = day2::artifact::LoadedArtifact::load(&artifact)?;
    let routes = day2::routing::Catalog::from_artifact(loaded.contract())?;
    let shape = Type::Record(BTreeMap::from([
        ("path".into(), Type::String),
        ("number".into(), Type::Integer),
    ]));
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("ui");
    let packaged = directory.path().join("artifact");
    fs::create_dir_all(source.join("pages"))?;
    let package = |markup: &str| -> Result<web_templates::Catalog> {
        fs::write(source.join("pages/test.html"), markup)?;
        web_templates::package(&source, &packaged)
    };
    let admit = |catalog: &web_templates::Catalog| {
        web_templates::validate_routed_page(
            &packaged,
            catalog,
            "pages/test.html",
            &shape,
            &day2::assets::Catalog::new(),
            &routes,
        )
    };
    for markup in [
        "<a href=\"{{ routes.bare() }}\">Missing</a>",
        "<a href=\"{{ routes.bare(path=number) }}\">Wrong type</a>",
        "<a href=\"{{ routes.bare(path=path, extra=path) }}\">Unknown</a>",
        "<a href=\"{{ routes.bare(path) }}\">Positional</a>",
        "<a href=\"/prefix{{ routes.bare(path=path) }}\">Concatenation</a>",
    ] {
        assert!(admit(&package(markup)?).is_err(), "{markup}");
    }
    let catalog = package(
        "<a href=\"{{ routes.bare(path=path) }}\">Bare</a><a href=\"{{ routes.prefixed(path=path) }}\">Prefixed</a>",
    )?;
    admit(&catalog)?;
    let render = |path: &str| {
        web_templates::render_routed(
            &packaged,
            &catalog,
            "pages/test.html",
            json!({"path":path,"number":1}),
            BTreeMap::new(),
            &routes,
            ORIGIN,
        )
    };
    for (path, encoded) in [
        ("docs/Read Me", "docs/Read%20Me"),
        ("docs/%2F", "docs/%252F"),
        ("docs/a?b#c", "docs/a%3Fb%23c"),
    ] {
        let html = render(path)?;
        let document = scraper::Html::parse_fragment(&html);
        let hrefs = document
            .select(&scraper::Selector::parse("a").unwrap())
            .map(|link| link.value().attr("href").unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(hrefs, [format!("/{encoded}"), format!("/go/{encoded}")]);
    }
    for path in ["a/../b", "a//b", "/a", "a\\b"] {
        assert!(render(path).is_err(), "{path}");
    }
    Ok(())
}
