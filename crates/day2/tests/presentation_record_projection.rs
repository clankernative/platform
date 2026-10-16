use anyhow::Result;
use day2::{output_schema::Type, web_templates};
use std::{collections::BTreeMap, fs};

#[test]
fn presentation_projection_requires_literal_unique_keys_and_exact_typed_fields() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("ui/pages"))?;
    fs::create_dir(root.path().join("artifact"))?;
    fs::write(
        root.path().join("ui/presentation.json"),
        r#"{"schemaVersion":1,"renderers":{"plot_v1":{"input":{"record":{"value":"integer"}},"output":{"record":{"label":"string"}}}}}"#,
    )?;
    let context = Type::Record(BTreeMap::from([("value".into(), Type::Integer)]));
    for (expression, valid) in [
        ("{'value': value}", true),
        ("{'value': 'wrong type'}", false),
        ("{'value': value, 'unknown': value}", false),
        ("{'value': value, 'value': value}", false),
        ("{value: value}", false),
        ("{'value': missing}", false),
        ("{'value': unsafe(value)}", false),
    ] {
        fs::write(
            root.path().join("ui/pages/plot.html"),
            format!("<p>{{{{ ui_scene('plot_v1', {expression}).label }}}}</p>"),
        )?;
        let catalog =
            web_templates::package(&root.path().join("ui"), &root.path().join("artifact"))?;
        assert_eq!(
            web_templates::validate_page(
                &root.path().join("artifact"),
                &catalog,
                "pages/plot.html",
                &context,
                &BTreeMap::new()
            )
            .is_ok(),
            valid,
            "{expression}"
        );
    }
    Ok(())
}
