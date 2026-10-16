use anyhow::Result;
use day2::{output_schema::Type, presentation, web_templates};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Adapter {
    calls: AtomicUsize,
    invalid: bool,
}
impl presentation::Port for Adapter {
    fn render(&self, renderer: &str, input: &Value) -> Result<Value> {
        assert_eq!(renderer, "plot_v1");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.invalid {
            return Ok(json!({"paths": "not a scene"}));
        }
        Ok(json!({"paths":[{"d":format!("M0 0L10 {}", input["value"])}]}))
    }
}

fn contract() -> presentation::Contract {
    presentation::Contract {
        input: Type::Record(BTreeMap::from([("value".into(), Type::Integer)])),
        output: Type::Record(BTreeMap::from([(
            "paths".into(),
            Type::List(Box::new(Type::Record(BTreeMap::from([(
                "d".into(),
                Type::String,
            )])))),
        )])),
    }
}

struct Template {
    root: tempfile::TempDir,
    catalog: web_templates::Catalog,
    shape: Type,
}
fn template(source: &str) -> Result<Template> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("ui/pages"))?;
    fs::create_dir_all(root.path().join("artifact"))?;
    fs::write(root.path().join("ui/pages/plot.html"), source)?;
    let contract = contract();
    fs::write(
        root.path().join("ui/presentation.json"),
        serde_json::to_vec(&json!({
            "schemaVersion":1,"renderers":{"plot_v1":contract}
        }))?,
    )?;
    let catalog = web_templates::package(&root.path().join("ui"), &root.path().join("artifact"))?;
    let shape = Type::Record(BTreeMap::from([("plot".into(), contract.input)]));
    Ok(Template {
        root,
        catalog,
        shape,
    })
}
const SOURCE: &str = "<section id=\"plot-region\" data-live><svg viewBox=\"0 0 20 20\"><g>{% for path in ui_scene('plot_v1', plot).paths %}<path d=\"{{ path.d }}\" stroke=\"#a84716\" fill=\"none\"></path>{% endfor %}</g><text>{{ ui_scene('plot_v1', plot).paths | length }}</text></svg></section>";

#[test]
fn typed_scene_is_memoized_only_within_one_request_and_uses_normal_rendering() -> Result<()> {
    let fixture = template(SOURCE)?;
    web_templates::validate_page(
        &fixture.root.path().join("artifact"),
        &fixture.catalog,
        "pages/plot.html",
        &fixture.shape,
        &BTreeMap::new(),
    )?;
    web_templates::validate_live_page(
        &fixture.root.path().join("artifact"),
        &fixture.catalog,
        "pages/plot.html",
        &fixture.shape,
        &BTreeMap::new(),
        None,
    )?;
    let adapter = Arc::new(Adapter {
        calls: AtomicUsize::new(0),
        invalid: false,
    });
    for (index, value) in [3, 7, 3].into_iter().enumerate() {
        let context = json!({"plot":{"value":value}});
        fixture.shape.validate_value(&context)?;
        let html = web_templates::render_with_presentations(
            &fixture.root.path().join("artifact"),
            &fixture.catalog,
            "pages/plot.html",
            context,
            BTreeMap::new(),
            Some(adapter.clone()),
        )?;
        assert!(html.contains(&format!("M0 0L10 {value}")));
        assert!(
            web_templates::live_regions(&html)?["plot-region"]
                .contains(&format!("M0 0L10 {value}"))
        );
        let routed = web_templates::render_routed_with_presentations(
            web_templates::RoutedRender {
                directory: &fixture.root.path().join("artifact"),
                catalog: &fixture.catalog,
                path: "pages/plot.html",
                context: json!({"plot":{"value":value}}),
                asset_urls: BTreeMap::new(),
                routes: &day2::routing::Catalog::default(),
                origin: "https://native.test",
            },
            Some(adapter.clone()),
        )?;
        assert_eq!(routed, html);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), (index + 1) * 2);
    }
    Ok(())
}

#[test]
fn undeclared_dynamic_wrongly_typed_and_raw_scene_calls_are_not_admitted() -> Result<()> {
    for source in [
        "<p>{{ ui_scene('missing', plot).paths | length }}</p>",
        "<p>{{ ui_scene(plot, plot).paths | length }}</p>",
        "<p>{{ ui_scene('plot_v1', 'untyped').paths | length }}</p>",
        "<p>{{ ui_scene('plot_v1', plot) }}</p>",
    ] {
        let fixture = template(source)?;
        assert!(
            web_templates::validate_page(
                &fixture.root.path().join("artifact"),
                &fixture.catalog,
                "pages/plot.html",
                &fixture.shape,
                &BTreeMap::new()
            )
            .is_err(),
            "{source}"
        );
    }
    Ok(())
}

#[test]
fn approval_is_required_and_test_adapter_outputs_are_checked() -> Result<()> {
    let fixture = template(SOURCE)?;
    let context = json!({"plot":{"value":3}});
    assert!(
        web_templates::render(
            &fixture.root.path().join("artifact"),
            &fixture.catalog,
            "pages/plot.html",
            context.clone(),
            BTreeMap::new()
        )
        .is_err()
    );
    let adapter = Arc::new(Adapter {
        calls: AtomicUsize::new(0),
        invalid: true,
    });
    assert!(
        web_templates::render_with_presentations(
            &fixture.root.path().join("artifact"),
            &fixture.catalog,
            "pages/plot.html",
            context,
            BTreeMap::new(),
            Some(adapter)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn presentation_declarations_are_captured_and_not_served_as_browser_code() -> Result<()> {
    let fixture = template(SOURCE)?;
    let expected = fixture.catalog["pages/plot.html"].presentations.clone();
    fs::write(
        fixture.root.path().join("ui/presentation.json"),
        "invalid after capture",
    )?;
    assert_eq!(
        web_templates::presentation_catalog(&fixture.catalog)?,
        expected
    );
    assert!(presentation::read_declarations(&fixture.root.path().join("ui")).is_err());
    let resources = day2::web_resources::package(
        &fixture.root.path().join("ui"),
        &fixture.root.path().join("artifact"),
    )?;
    assert!(resources.is_empty());
    Ok(())
}
