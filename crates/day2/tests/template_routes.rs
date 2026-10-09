use anyhow::Result;
use day2::{
    artifact::{Operation, Page},
    output_schema::Type,
    routing,
    schema::{Kind, Record, Schema},
    web_templates,
};
use day2_assets as assets;
use scraper::Selector;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

const ORIGIN: &str = "https://links.example.test";

struct Templates {
    _directory: tempfile::TempDir,
    artifact: PathBuf,
    catalog: web_templates::Catalog,
    routes: routing::Catalog,
}

impl Templates {
    fn new(markup: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("ui");
        let artifact = directory.path().join("artifact");
        fs::create_dir_all(source.join("pages"))?;
        fs::write(source.join("pages/directory.html"), markup)?;
        let catalog = web_templates::package(&source, &artifact)?;
        Ok(Self {
            _directory: directory,
            artifact,
            catalog,
            routes: routes()?,
        })
    }

    fn admit(&self) -> Result<()> {
        web_templates::validate_routed_page(
            &self.artifact,
            &self.catalog,
            "pages/directory.html",
            &context_type(),
            &assets::Catalog::new(),
            &self.routes,
        )
    }

    fn render(&self, value: Value) -> Result<String> {
        web_templates::render_routed(
            &self.artifact,
            &self.catalog,
            "pages/directory.html",
            value,
            BTreeMap::new(),
            &self.routes,
            ORIGIN,
        )
    }
}

fn context_type() -> Type {
    Type::Record(BTreeMap::from([
        (
            "company".into(),
            Type::Record(BTreeMap::from([("name".into(), Type::String)])),
        ),
        (
            "link".into(),
            Type::Record(BTreeMap::from([
                ("id".into(), Type::String),
                ("destination".into(), Type::String),
                ("version".into(), Type::Integer),
            ])),
        ),
    ]))
}

fn context() -> Value {
    json!({"company":{"name":"Example"}, "link":{"id":"7", "version":1, "destination":"https://example.net/path"}})
}

fn routes() -> Result<routing::Catalog> {
    let input = |fields| Record {
        identity: None,
        fields,
        roc_type: None,
    };
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::new(),
        inputs: BTreeMap::from([
            (
                "list_links".into(),
                input(BTreeMap::from([
                    ("search".into(), Kind::Text),
                    ("limit".into(), Kind::Integer),
                ])),
            ),
            (
                "get_link".into(),
                input(BTreeMap::from([(
                    "link_id".into(),
                    Kind::Reference {
                        target: "links".into(),
                    },
                )])),
            ),
        ]),
        foreign_keys: vec![],
        rollups: Vec::new(),
        indexes: vec![],
    };
    let operations: Vec<_> = [("links.list", "list_links"), ("links.get", "get_link")]
        .into_iter()
        .map(|(name, input_type)| Operation {
            name: name.into(),
            kind: "query".into(),
            input_type: input_type.into(),
            output_type: String::new(),
        })
        .collect();
    let pages: Vec<_> = [
        (
            "links",
            "/",
            "links.list",
            "list_links",
            json!({"limit":20,"search":""}),
        ),
        (
            "link",
            "/links/{link_id}",
            "links.get",
            "get_link",
            json!({}),
        ),
    ]
    .into_iter()
    .map(|(name, path, operation, input_type, defaults)| Page {
        name: name.into(),
        title: name.into(),
        operation: operation.into(),
        defaults: defaults.to_string(),
        path: path.into(),
        template: "pages/directory.html".into(),
        input_type: input_type.into(),
        output_type: String::new(),
        live: false,
        live_refresh_ms: 0,
    })
    .collect();
    routing::Catalog::compile(&pages, &operations, &schema)
}

#[test]
fn checked_route_calls_validate_names_arguments_types_and_contexts() -> Result<()> {
    for markup in [
        "<a href=\"{{ routes.missing() }}\">Missing</a>",
        "<a href=\"{{ routes.link() }}\">Missing argument</a>",
        "<a href=\"{{ routes.links(unknown=1) }}\">Unknown argument</a>",
        "<a href=\"{{ routes.links(limit=company.name) }}\">Wrong type</a>",
        "<a href=\"{{ routes.link(link_id=link.version) }}\">Reference is a canonical string</a>",
        "<a href=\"{{ routes.link('7') }}\">Positional argument</a>",
        "<a href=\"{{ platform.missing() }}\">Unknown platform route</a>",
        "<a href=\"{{ platform.audit(extra=1) }}\">Unexpected argument</a>",
        "<a href=\"{{ platform.docs(path='/custom') }}\">Cannot override docs</a>",
        "<a href=\"{{ platform.openapi(path='/custom') }}\">Cannot override spec</a>",
        "<a href=\"/prefix{{ routes.links() }}\">Concatenated route</a>",
        "<a href=\"{{ routes.links() }}?limit=10\">Concatenated query</a>",
        "<span>{{ routes.links() }}</span>",
        "<div title=\"{{ routes.links() }}\"></div>",
        "<a href=\"{{ routes.links() if true else routes.links() }}\">Nested helper</a>",
        "<a href=\"{{ routes.links(search=routes.links()) }}\">Helper argument</a>",
        "<a href=\"{{ routes.links() | length }}\">Filtered helper</a>",
        "<a href=\"{{ '/' }}\">Unchecked internal constant</a>",
        "<a href=\"/\">Unchecked internal path</a>",
        "<a href=\"/audit\">Unchecked platform path</a>",
        "<a href=\"//example.net\">Protocol-relative URL</a>",
        "{% if false %}<a href=\"{{ routes.missing() }}\">Unreachable typo</a>{% endif %}",
    ] {
        let templates = Templates::new(markup)?;
        assert!(templates.admit().is_err(), "unexpected admission: {markup}");
    }
    Templates::new("<a href=\"{{ routes.links() }}\">Home</a><a href=\"{{ routes.link(link_id=link.id) }}\">Link</a><a href=\"{{ platform.audit() }}\">Audit</a>")?.admit()?;
    Ok(())
}

#[test]
fn route_helpers_use_the_shared_codec_for_whole_urls() -> Result<()> {
    let templates = Templates::new(
        "<a id=\"search\" href=\"{{ routes.links(search=company.name,limit=10) }}\">Search</a><a id=\"detail\" href=\"{{ routes.link(link_id=link.id) }}\">Link</a><a id=\"audit\" href=\"{{ platform.audit() }}\">Audit</a><a id=\"docs\" href=\"{{ platform.docs() }}\">API docs</a><a id=\"spec\" href=\"{{ platform.openapi() }}\">OpenAPI</a>",
    )?;
    templates.admit()?;
    let mut value = context();
    let needle = "a & b/?#%\"\u{e9}";
    value["company"]["name"] = json!(needle);
    let first = templates.render(value.clone())?;
    assert_eq!(first, templates.render(value)?);
    let html = web_templates::parse_checked(&first)?;
    let urls: BTreeMap<_, _> = html
        .select(&Selector::parse("a").unwrap())
        .map(|element| {
            (
                element.value().attr("id").unwrap(),
                element.value().attr("href").unwrap(),
            )
        })
        .collect();
    let expected = templates
        .routes
        .build_url("links", &json!({"search":needle,"limit":10}))?;
    assert_eq!(urls["search"], expected);
    let parsed = url::Url::parse(ORIGIN)?.join(urls["search"])?;
    let query: BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert_eq!(query["search"], needle);
    assert_eq!(query["limit"], "10");
    assert_eq!(urls["detail"], "/links/7");
    assert_eq!(urls["audit"], "/audit");
    assert_eq!(urls["docs"], "/docs");
    assert_eq!(urls["spec"], "/openapi.json");
    Ok(())
}

#[test]
fn dynamic_external_links_cannot_smuggle_internal_navigation() -> Result<()> {
    let templates = Templates::new(
        "<a href=\"{{ routes.link(link_id=link.id) }}\">Checked</a><a href=\"{{ link.destination }}\">External</a>",
    )?;
    templates.admit()?;
    for destination in [
        "/",
        "/links/7",
        "/audit",
        "//links.example.test/",
        "https://links.example.test/links/7",
        "https://LINKS.EXAMPLE.TEST:443/",
        "#target",
        "javascript:alert(1)",
    ] {
        let mut value = context();
        value["link"]["destination"] = json!(destination);
        assert!(
            templates.render(value).is_err(),
            "unexpected navigation: {destination}"
        );
    }
    templates.render(context())?;
    Ok(())
}

#[test]
fn rendered_navigation_preserves_provenance_and_reference_codecs() -> Result<()> {
    for markup in [
        "<a href=\"{{ routes.links() }}?limit=1\">Concatenation</a>",
        "<p>{{ routes.links() }}</p>",
        "<a href=\"https://links.example.test/\">Absolute internal literal</a>",
    ] {
        let templates = Templates::new(markup)?;
        assert!(
            templates.render(context()).is_err(),
            "unexpected runtime acceptance: {markup}"
        );
    }
    let templates = Templates::new("<a href=\"{{ routes.link(link_id=link.id) }}\">Link</a>")?;
    templates.admit()?;
    for id in ["0", "-1", "07", "7/8", "../audit"] {
        let mut value = context();
        value["link"]["id"] = json!(id);
        assert!(
            templates.render(value).is_err(),
            "unexpected reference: {id}"
        );
    }
    Ok(())
}

#[test]
fn literal_fragment_targets_are_checked_against_the_rendered_document() -> Result<()> {
    let templates = Templates::new(
        "<a href=\"#section\">Section</a><a href=\"#day2-main\">Main</a><section id=\"section\">Content</section>",
    )?;
    templates.admit()?;
    templates.render(context())?;
    let missing = Templates::new("<a href=\"#missing\">Missing section</a>")?;
    missing.admit()?;
    assert!(missing.render(context()).is_err());
    Ok(())
}

#[test]
fn generated_template_handles_have_no_arbitrary_path_constructor() -> Result<()> {
    let templates = Templates::new("<p>Directory</p>")?;
    let sdk = web_templates::roc_sdk_module(&templates.catalog)?;
    let app = web_templates::roc_module(&templates.catalog)?;
    assert!(sdk.contains("directory : Template"));
    assert!(sdk.contains("directory = { file: \"pages/directory.html\" }"));
    assert!(!sdk.contains("from_file"));
    assert!(app.contains("directory = Template.directory"));
    let template = templates.catalog["pages/directory.html"].clone();
    let collision = BTreeMap::from([
        ("pages/a/b.html".into(), template.clone()),
        ("pages/a_b.html".into(), template.clone()),
    ]);
    assert!(web_templates::roc_module(&collision).is_err());
    let reserved = BTreeMap::from([("pages/path.html".into(), template)]);
    assert!(web_templates::roc_sdk_module(&reserved).is_err());
    Ok(())
}
