use anyhow::Result;
use day2::{
    artifact::Operation,
    output_schema::Type,
    schema::{Kind, Record, Schema},
    web_templates,
};
use day2_assets as assets;
use scraper::Selector;
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf};

struct Templates {
    _directory: tempfile::TempDir,
    source: PathBuf,
    artifact: PathBuf,
}

impl Templates {
    fn new(page: &str, components: &[(&str, &str)]) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("ui");
        let artifact = directory.path().join("artifact");
        fs::create_dir_all(source.join("pages"))?;
        fs::create_dir_all(source.join("components"))?;
        fs::create_dir_all(&artifact)?;
        fs::write(source.join("pages/links.html"), page)?;
        for (name, value) in components {
            fs::write(source.join("components").join(name), value)?;
        }
        Ok(Self {
            _directory: directory,
            source,
            artifact,
        })
    }

    fn admit(&self) -> Result<web_templates::Catalog> {
        let catalog = web_templates::package(&self.source, &self.artifact)?;
        web_templates::validate_page(
            &self.artifact,
            &catalog,
            "pages/links.html",
            &context_type(),
            &assets::Catalog::new(),
        )?;
        Ok(catalog)
    }
}

fn context_type() -> Type {
    Type::Record(BTreeMap::from([
        (
            "company".into(),
            Type::Record(BTreeMap::from([("name".into(), Type::String)])),
        ),
        (
            "links".into(),
            Type::Record(BTreeMap::from([
                ("has_more".into(), Type::Boolean),
                ("next_after".into(), Type::String),
                (
                    "items".into(),
                    Type::List(Box::new(Type::Record(BTreeMap::from([
                        ("id".into(), Type::String),
                        ("version".into(), Type::Integer),
                        ("title".into(), Type::String),
                        ("destination".into(), Type::String),
                        ("archived".into(), Type::Boolean),
                    ])))),
                ),
            ])),
        ),
    ]))
}

fn commands() -> (Vec<Operation>, Schema) {
    let operations = [
        ("links.create", "command", "create"),
        ("links.archive", "command", "archive"),
        ("links.list", "query", "list_links"),
    ]
    .map(|(name, kind, input_type)| Operation {
        name: name.into(),
        kind: kind.into(),
        input_type: input_type.into(),
        output_type: String::new(),
    })
    .into();
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::new(),
        inputs: BTreeMap::from([
            (
                "create".into(),
                Record {
                    identity: None,
                    fields: BTreeMap::from([
                        ("title".into(), Kind::Text),
                        ("destination".into(), Kind::WebUrl),
                    ]),
                    roc_type: None,
                },
            ),
            (
                "archive".into(),
                Record {
                    identity: None,
                    fields: BTreeMap::from([
                        (
                            "link_id".into(),
                            Kind::Reference {
                                target: "links".into(),
                            },
                        ),
                        ("expected_version".into(), Kind::Integer),
                    ]),
                    roc_type: None,
                },
            ),
            (
                "list_links".into(),
                Record {
                    identity: None,
                    fields: BTreeMap::new(),
                    roc_type: None,
                },
            ),
        ]),
        foreign_keys: vec![],
        rollups: Vec::new(),
        indexes: vec![],
    };
    (operations, schema)
}

fn validate_commands(templates: &Templates) -> Result<()> {
    let catalog = templates.admit()?;
    let (operations, schema) = commands();
    web_templates::validate_bindings(
        &templates.artifact,
        &catalog,
        "pages/links.html",
        &context_type(),
        &assets::Catalog::new(),
        &operations,
        &schema,
    )
}

#[test]
fn template_contract_checks_every_branch_and_included_component() -> Result<()> {
    for page in [
        "<p>{{ company.nmae }}</p>",
        "{% for link in links.items %}<p>{{ link.titel }}</p>{% endfor %}",
        "{% if links.has_more %}<p>{{ links.missing }}</p>{% else %}<p>Empty</p>{% endif %}",
        "{% if false %}<p>{{ company.missing }}</p>{% endif %}",
        "{% for link in company.name %}<p>{{ link.title }}</p>{% endfor %}",
        "{% include 'components/missing.html' %}",
        "{% include company.name %}",
    ] {
        let templates = Templates::new(page, &[])?;
        assert!(templates.admit().is_err(), "unexpected admission: {page}");
    }
    let templates = Templates::new(
        "{% for link in links.items %}{% include 'components/row.html' %}{% endfor %}",
        &[("row.html", "<p>{{ link.unknown }}</p>")],
    )?;
    assert!(templates.admit().is_err());
    Ok(())
}

#[test]
fn templates_reject_unknown_assets_and_executable_interpolation() -> Result<()> {
    for page in [
        "<img src=\"{{ asset('missing') }}\" alt=\"Missing\">",
        "<button data-on:click=\"{{ company.name }}\">Click</button>",
        "<div data-effect=\"{{ company.name }}\"></div>",
        "<div data-signals=\"{{ company.name }}\"></div>",
        "<script>{{ company.name }}</script>",
        "<p>{{ company.name | safe }}</p>",
        "{% autoescape false %}<p>{{ company.name }}</p>{% endautoescape %}",
    ] {
        let templates = Templates::new(page, &[])?;
        assert!(templates.admit().is_err(), "unexpected admission: {page}");
    }
    Ok(())
}

#[test]
fn command_bindings_validate_names_types_and_all_control_flow_paths() -> Result<()> {
    for page in [
        "<form data-command=\"links.missing\"></form>",
        "<form data-command=\"links.list\"></form>",
        "<form data-command=\"links.create\"><input name=\"titel\"><input name=\"destination\"></form>",
        "<form data-command=\"links.create\"><input name=\"title\"></form>",
        "<form data-command=\"links.create\"><input name=\"title\"><input name=\"title\"><input name=\"destination\"></form>",
        "<form data-command=\"links.create\"><input name=\"title\"><input name=\"destination\"><input name=\"actor\"></form>",
        "{% if false %}<form data-command=\"links.missing\"></form>{% endif %}",
        "<form data-platform=\"sign-out\"><input name=\"_csrf\"></form>",
        "{% for link in links.items %}<form data-command=\"links.archive\"><input type=\"hidden\" name=\"link_id\" value=\"{{ link.id }}\"><input type=\"hidden\" name=\"expected_version\" value=\"{{ company.name }}\"></form>{% endfor %}",
        "{% for link in links.items %}<form data-command=\"links.archive\"><input type=\"hidden\" name=\"link_id\" value=\"{{ link.version }}\"><input type=\"hidden\" name=\"expected_version\" value=\"{{ link.version }}\"></form>{% endfor %}",
    ] {
        let templates = Templates::new(page, &[])?;
        assert!(
            validate_commands(&templates).is_err(),
            "unexpected command admission: {page}"
        );
    }
    let templates = Templates::new(
        "{% for link in links.items %}<article data-title=\"{{ link.title }}\"><form data-command=\"links.archive\"><input type=\"hidden\" name=\"link_id\" value=\"{{ link.id }}\"><input type=\"hidden\" name=\"expected_version\" value=\"{{ link.version }}\"><button type=\"submit\">Archive</button></form></article>{% endfor %}",
        &[],
    )?;
    validate_commands(&templates)?;
    Ok(())
}

#[test]
fn admitted_template_output_is_escaped_and_repeatable() -> Result<()> {
    let templates = Templates::new(
        "<section aria-label=\"{{ company.name }}\" data-label=\"{{ company.name }}\">{% for link in links.items %}{% include 'components/row.html' %}{% else %}<p>Empty</p>{% endfor %}</section>",
        &[("row.html", "<p class=\"link-title\">{{ link.title }}</p>")],
    )?;
    let catalog = templates.admit()?;
    let company = "\" onmouseover=\"alert(1) <script>";
    let title = "<img src=x onerror=alert(1)> & private text";
    let value = json!({
        "company":{"name":company},
        "links":{
            "items":[{"id":"one","version":1,"title":title,"destination":"https://example.com/","archived":false}],
            "has_more":false,"next_after":"1"
        }
    });
    context_type().validate_value(&value)?;
    let first = web_templates::render(
        &templates.artifact,
        &catalog,
        "pages/links.html",
        value.clone(),
        BTreeMap::new(),
    )?;
    let second = web_templates::render(
        &templates.artifact,
        &catalog,
        "pages/links.html",
        value.clone(),
        BTreeMap::new(),
    )?;
    assert_eq!(first, second);
    fs::write(
        templates.source.join("pages/links.html"),
        "<p>Unadmitted workspace edit</p>",
    )?;
    assert_eq!(
        web_templates::render(
            &templates.artifact,
            &catalog,
            "pages/links.html",
            value,
            BTreeMap::new(),
        )?,
        first
    );
    let document = web_templates::parse_checked(&first)?;
    let section = document
        .select(&Selector::parse("section").unwrap())
        .next()
        .unwrap();
    assert_eq!(section.value().attr("aria-label"), Some(company));
    assert_eq!(section.value().attr("data-label"), Some(company));
    assert!(section.value().attr("onmouseover").is_none());
    let content = document
        .select(&Selector::parse(".link-title").unwrap())
        .next()
        .unwrap()
        .text()
        .collect::<String>();
    assert_eq!(content, title);
    assert_eq!(
        document
            .select(&Selector::parse("script, img").unwrap())
            .count(),
        0
    );
    Ok(())
}

#[test]
fn runtime_template_rendering_rejects_missing_values() -> Result<()> {
    let templates = Templates::new("<p>{{ company.name }}</p>", &[])?;
    let catalog = templates.admit()?;
    assert!(
        web_templates::render(
            &templates.artifact,
            &catalog,
            "pages/links.html",
            json!({"company":{}}),
            BTreeMap::new(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn template_bytes_and_rendered_resource_contexts_are_validated_at_runtime() -> Result<()> {
    let templates = Templates::new("<a href=\"{{ company.name }}\">Destination</a>", &[])?;
    let catalog = templates.admit()?;
    assert!(
        web_templates::render(
            &templates.artifact,
            &catalog,
            "pages/links.html",
            json!({"company":{"name":"javascript:alert(1)"}}),
            BTreeMap::new(),
        )
        .is_err()
    );
    let template = &catalog["pages/links.html"];
    let blob = templates
        .artifact
        .join("web_templates")
        .join(format!("{}.html", assets::hash_part(&template.digest)?));
    fs::write(blob, "<p>Changed admitted template</p>")?;
    assert!(web_templates::validate_blobs(&templates.artifact, &catalog).is_err());
    assert!(
        web_templates::render(
            &templates.artifact,
            &catalog,
            "pages/links.html",
            json!({"company":{"name":"https://example.com/"}}),
            BTreeMap::new(),
        )
        .is_err()
    );
    Ok(())
}
