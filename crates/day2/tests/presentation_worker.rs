//! Opt-in conformance for an independently reviewed renderer executable.
//! Run with DAY2_PRESENTATION_PIN_JSON and DAY2_TEST_PRESENTATION_DECLARATIONS.
use anyhow::{Context, Result};
use day2::presentation;
use serde_json::{Value, json};

#[test]
#[ignore = "requires an explicitly reviewed local renderer pin and declaration file"]
fn real_confined_renderer_replays_current_range_and_changed_values() -> Result<()> {
    let source = std::env::var("DAY2_TEST_PRESENTATION_DECLARATIONS")
        .context("provide reviewed declaration file")?;
    let declarations: Value = serde_json::from_slice(&std::fs::read(source)?)?;
    assert_eq!(declarations["schemaVersion"], 1);
    let catalog: presentation::Catalog = serde_json::from_value(declarations["renderers"].clone())?;
    let renderer = catalog
        .keys()
        .next()
        .context("renderer declaration required")?;
    assert_eq!(catalog.len(), 1);
    let port = presentation::load_environment(&catalog)?.context("approved renderer required")?;
    let input = json!({"width":640,"height":240,"start":1735689600000i64,
    "end":1736294400000i64,"y_min":0,"y_max":100,"title":"Current samples","kind":"line",
    "samples":[
        {"time":1735689600000i64,"value":0,"missing":false,"key":"measured_zero"},
        {"time":1735862400000i64,"value":72,"missing":false,"key":"observed"},
        {"time":1736035200000i64,"value":0,"missing":true,"key":"gap"},
        {"time":1736208000000i64,"value":91,"missing":false,"key":"observed_end"}
    ]});
    let full = port.render(renderer, &input)?;
    assert_eq!(full["points"].as_array().unwrap().len(), 4);
    assert_eq!(full["points"][0]["value"], 0);
    assert_eq!(full["points"][0]["missing"], false);
    assert_eq!(full["points"][2]["missing"], true);
    assert!(!full["paths"].as_array().unwrap().is_empty());
    assert_eq!(full, port.render(renderer, &input)?);
    let mut selected = input.clone();
    selected["start"] = json!(1735862400000i64);
    selected["end"] = json!(1736208000000i64);
    selected["samples"] = json!([input["samples"][1], input["samples"][2]]);
    let range = port.render(renderer, &selected)?;
    assert_eq!(range["points"].as_array().unwrap().len(), 2);
    assert_ne!(full, range);
    selected["samples"][0]["value"] = json!(12);
    let changed = port.render(renderer, &selected)?;
    assert_ne!(range["paths"], changed["paths"]);
    assert_eq!(full, port.render(renderer, &input)?);
    selected["kind"] = json!("unrestricted_options");
    assert!(port.render(renderer, &selected).is_err());
    // A rejected job cannot poison the next approved job or carry old chart state.
    assert_eq!(full, port.render(renderer, &input)?);
    // Ordinary live + acknowledgement contention must serialize rather than
    // rejecting a second fast job merely because the first owns the worker.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let port = port.clone();
            let barrier = barrier.clone();
            let input = input.clone();
            let renderer = renderer.clone();
            std::thread::spawn(move || {
                barrier.wait();
                port.render(&renderer, &input)
            })
        })
        .collect();
    for job in jobs {
        assert_eq!(job.join().expect("confined job thread")?, full);
    }
    Ok(())
}
