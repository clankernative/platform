use anyhow::Result;
use day2::{
    artifact::{Operation, Page},
    routing::Catalog,
    schema::{Kind, Record, Schema},
};
use proptest::{
    prelude::*,
    test_runner::{Config, RngSeed, TestRunner},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

struct Spec {
    name: &'static str,
    path: &'static str,
    fields: Vec<(&'static str, Kind)>,
    defaults: Value,
}

fn spec(
    name: &'static str,
    path: &'static str,
    fields: Vec<(&'static str, Kind)>,
    defaults: Value,
) -> Spec {
    Spec {
        name,
        path,
        fields,
        defaults,
    }
}

fn reference() -> Kind {
    Kind::Reference {
        target: "links".into(),
    }
}

fn exact(specs: Vec<Spec>) -> Result<Catalog> {
    let mut pages = Vec::new();
    let mut operations = Vec::new();
    let mut inputs = BTreeMap::new();
    for spec in specs {
        let operation = format!("{}.read", spec.name);
        pages.push(serde_json::from_value::<Page>(json!({
            "name":spec.name, "path":spec.path, "title":spec.name,
            "operation":operation, "template":format!("pages/{}.html", spec.name),
            "defaults":spec.defaults.to_string(), "input_type":spec.name, "output_type":"view"
        }))?);
        operations.push(serde_json::from_value::<Operation>(json!({
            "name":operation,"kind":"query","input_type":spec.name,"output_type":"view"
        }))?);
        inputs.insert(
            spec.name.into(),
            Record {
                identity: None,
                fields: spec
                    .fields
                    .into_iter()
                    .map(|(name, kind)| (name.into(), kind))
                    .collect(),
                roc_type: None,
            },
        );
    }
    Catalog::compile(
        &pages,
        &operations,
        &Schema {
            domains: BTreeMap::new(),
            models: BTreeMap::new(),
            inputs,
            foreign_keys: Vec::new(),
            rollups: Vec::new(),
            indexes: vec![],
        },
    )
}

fn catalog(mut specs: Vec<Spec>) -> Result<Catalog> {
    if !specs.iter().any(|spec| spec.path == "/") {
        specs.push(spec("home", "/", vec![], json!({})));
    }
    exact(specs)
}

fn decode(catalog: &Catalog, url: &str) -> Result<(String, Value)> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    Ok(catalog
        .resolve(path, query)?
        .expect("generated route exists"))
}

#[test]
fn explicit_root_and_partial_query_defaults_are_enforced() -> Result<()> {
    let routes = exact(vec![spec(
        "links",
        "/",
        vec![("after", Kind::Integer), ("limit", Kind::Integer)],
        json!({"after":0,"limit":20}),
    )])?;
    assert_eq!(routes.build_url("links", &json!({}))?, "/");
    assert_eq!(
        routes.build_url("links", &json!({"after":0,"limit":20}))?,
        "/"
    );
    assert_eq!(
        routes.build_url("links", &json!({"after":42}))?,
        "/?after=42"
    );
    assert_eq!(
        routes.resolve("/", "")?,
        Some(("links".into(), json!({"after":0,"limit":20})))
    );
    assert_eq!(
        routes.resolve("/", "after=42")?,
        Some(("links".into(), json!({"after":42,"limit":20})))
    );
    assert!(exact(vec![spec("missing", "/other", vec![], json!({}))]).is_err());
    assert!(
        exact(vec![spec(
            "root",
            "/",
            vec![("required", Kind::Text)],
            json!({})
        )])
        .is_err()
    );
    assert_eq!(exact(vec![])?.names().count(), 0);
    let decimal_default = exact(vec![spec(
        "links",
        "/",
        vec![("after", Kind::Integer)],
        json!({"after":0.0}),
    )])
    .expect_err("decimal defaults must not be coerced into integers");
    assert_eq!(
        decimal_default.to_string(),
        "route links default after: expected I64"
    );
    Ok(())
}

#[test]
fn pagination_routes_use_lossless_opaque_wire_codecs_and_enforce_page_size() -> Result<()> {
    let routes = exact(vec![spec(
        "links",
        "/",
        vec![("after", Kind::Cursor), ("limit", Kind::PageSize)],
        json!({"after":"0","limit":20}),
    )])?;
    assert_eq!(routes.build_url("links", &json!({}))?, "/");
    assert_eq!(
        decode(&routes, "/?after=9223372036854775807&limit=100")?.1,
        json!({"after":"9223372036854775807","limit":100})
    );
    for query in [
        "after=01",
        "after=-1",
        "after=9223372036854775808",
        "limit=0",
        "limit=101",
        "limit=20.0",
        "after=1&after=2",
    ] {
        assert!(routes.resolve("/", query).is_err(), "{query}");
    }
    for input in [
        json!({"after":0}),
        json!({"after":"01"}),
        json!({"limit":101}),
        json!({"limit":"20"}),
    ] {
        assert!(routes.build_url("links", &input).is_err(), "{input}");
    }
    for after in [0, 1, 100, i64::MAX] {
        for size in [1, 20, 100] {
            let input = json!({"after":after.to_string(),"limit":size});
            assert_eq!(
                decode(&routes, &routes.build_url("links", &input)?)?.1,
                input
            );
        }
    }
    Ok(())
}

#[test]
fn route_input_handle_must_match_even_when_nominal_contracts_have_the_same_wire_shape() -> Result<()>
{
    let input = |name: &str| Record {
        identity: None,
        fields: BTreeMap::from([("term".into(), Kind::Text)]),
        roc_type: Some(format!("Contracts.{name}")),
    };
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::new(),
        inputs: BTreeMap::from([
            ("left".into(), input("Left")),
            ("right".into(), input("Right")),
        ]),
        foreign_keys: vec![],
        rollups: Vec::new(),
        indexes: vec![],
    };
    let operations = vec![Operation {
        name: "items.list".into(),
        kind: "query".into(),
        input_type: "left".into(),
        output_type: "view".into(),
    }];
    let mut page: Page = serde_json::from_value(json!({
        "name":"items", "title":"Items", "path":"/", "operation":"items.list",
        "defaults":"{\"term\":\"\"}", "template":"pages/directory.html", "input_type":"left", "output_type":"view"
    }))?;
    Catalog::compile(&[page.clone()], &operations, &schema)?;
    for mismatched in ["right", ""] {
        page.input_type = mismatched.into();
        let error = Catalog::compile(&[page.clone()], &operations, &schema).unwrap_err();
        assert!(error.to_string().contains("same input handle"));
    }
    Ok(())
}

#[test]
fn path_values_are_required_and_never_overridden_by_query_or_defaults() -> Result<()> {
    let routes = catalog(vec![spec(
        "link",
        "/links/{link_id}",
        vec![("link_id", reference()), ("tab", Kind::Text)],
        json!({"tab":"summary"}),
    )])?;
    assert_eq!(
        routes.build_url("link", &json!({"link_id":"9223372036854775807"}))?,
        "/links/9223372036854775807"
    );
    assert_eq!(
        decode(&routes, "/links/123?tab=history")?,
        ("link".into(), json!({"link_id":"123","tab":"history"}))
    );
    for input in [
        json!({}),
        json!({"link_id":123}),
        json!({"link_id":"01"}),
        json!({"link_id":"0"}),
        json!({"link_id":"123","unknown":true}),
    ] {
        assert!(routes.build_url("link", &input).is_err(), "{input}");
    }
    assert!(routes.resolve("/links/123", "link_id=123").is_err());
    assert!(
        catalog(vec![spec(
            "link",
            "/links/{link_id}",
            vec![("link_id", reference())],
            json!({"link_id":"123"})
        )])
        .is_err()
    );
    assert!(
        catalog(vec![spec(
            "link",
            "/links/{link_id}/{link_id}",
            vec![("link_id", reference())],
            json!({})
        )])
        .is_err()
    );
    assert!(
        catalog(vec![spec(
            "link",
            "/links/{unknown}",
            vec![("link_id", reference())],
            json!({})
        )])
        .is_err()
    );
    Ok(())
}

#[test]
fn query_inputs_use_existing_scalar_codecs_and_exact_names() -> Result<()> {
    let routes = catalog(vec![spec(
        "search",
        "/search",
        vec![
            ("q", Kind::Text),
            ("limit", Kind::Integer),
            ("active", Kind::Boolean),
            ("link_id", reference()),
        ],
        json!({"limit":20,"active":false}),
    )])?;
    let input = json!({"q":"a+b c&other=1/100%?\u{fffd}","link_id":"123","limit":-7,"active":true});
    let url = routes.build_url("search", &input)?;
    assert!(url.contains("q=a%2Bb+c%26other%3D1%2F100%25%3F%EF%BF%BD"));
    assert_eq!(decode(&routes, &url)?, ("search".into(), input));
    for query in [
        "",
        "q=x",
        "q=x&link_id=01",
        "q=x&link_id=1&limit=+1",
        "q=x&link_id=1&limit=%2B1",
        "q=x&link_id=1&active=True",
        "q=x&link_id=1&unknown=1",
        "q=x&q=y&link_id=1",
        "q=x&%71=y&link_id=1",
        "q=%&link_id=1",
        "q=%ZZ&link_id=1",
        "q=%FF&link_id=1",
        "q=%C0%AF&link_id=1",
    ] {
        assert!(routes.resolve("/search", query).is_err(), "{query}");
    }
    assert!(routes.build_url("unknown", &json!({})).is_err());
    assert!(routes.build_url("search", &Value::Null).is_err());
    Ok(())
}

#[test]
fn path_plus_and_query_plus_have_different_lossless_encodings() -> Result<()> {
    let routes = catalog(vec![spec(
        "entry",
        "/a+b/{slug}",
        vec![("slug", Kind::Text), ("q", Kind::Text)],
        json!({}),
    )])?;
    let input = json!({"slug":"plus+ space & question? hash# percent%", "q":"plus+ space"});
    let url = routes.build_url("entry", &input)?;
    assert!(url.starts_with("/a+b/plus+%20space%20&%20question%3F%20hash%23%20percent%25?"));
    assert!(url.ends_with("q=plus%2B+space"));
    assert_eq!(decode(&routes, &url)?, ("entry".into(), input));
    assert_eq!(
        routes.resolve("/a+b/literal+plus", "q=query+space")?,
        Some((
            "entry".into(),
            json!({"slug":"literal+plus","q":"query space"})
        ))
    );
    Ok(())
}

#[test]
fn canonical_paths_reject_ambiguous_separators_dot_segments_and_encodings() -> Result<()> {
    let routes = catalog(vec![spec(
        "entry",
        "/x/{slug}",
        vec![("slug", Kind::Text)],
        json!({}),
    )])?;
    for path in [
        "x/value",
        "//x/value",
        "/x/value/",
        "/x//value",
        "/x/.",
        "/x/..",
        "/x/%2E",
        "/x/%2e%2e",
        "/x/a%2Fb",
        "/x/a%5Cb",
        "/x/a\\b",
        "/x/%",
        "/x/%0",
        "/x/%GG",
        "/x/%FF",
        "/x/%00",
        "/x/%61",
        "/x/a b",
        "/x/value?q=1",
        "/x/value#part",
    ] {
        assert!(routes.resolve(path, "").is_err(), "{path}");
    }
    for value in ["", ".", "..", "a/b", "a\\b", "a\nb"] {
        assert!(
            routes.build_url("entry", &json!({"slug":value})).is_err(),
            "{value:?}"
        );
    }
    for path in [
        "relative",
        "/x/",
        "/x//y",
        "/x/..",
        "/x/{slug}/",
        "/x/prefix-{slug}",
        "/x/{}",
        "/x/{bad-name}",
        "/x/%2F",
    ] {
        assert!(
            catalog(vec![spec(
                "bad",
                path,
                vec![("slug", Kind::Text)],
                json!({})
            )])
            .is_err(),
            "{path}"
        );
    }
    assert_eq!(routes.resolve("/does/not/exist", "")?, None);
    Ok(())
}

#[test]
fn codec_aware_overlaps_are_rejected_without_registration_priority() -> Result<()> {
    for kind in [
        Kind::Text,
        Kind::TextDomain {
            roc_type: "Slug".into(),
        },
    ] {
        assert!(
            catalog(vec![
                spec("new", "/links/new", vec![], json!({})),
                spec("link", "/links/{slug}", vec![("slug", kind)], json!({}))
            ])
            .is_err()
        );
    }
    assert!(
        catalog(vec![
            spec(
                "integer",
                "/x/{number}",
                vec![("number", Kind::Integer)],
                json!({})
            ),
            spec(
                "reference",
                "/x/{link_id}",
                vec![("link_id", reference())],
                json!({})
            )
        ])
        .is_err()
    );
    assert!(
        catalog(vec![
            spec(
                "one",
                "/x/{slug}/end",
                vec![("slug", Kind::Text)],
                json!({})
            ),
            spec(
                "two",
                "/x/start/{slug}",
                vec![("slug", Kind::Text)],
                json!({})
            )
        ])
        .is_err()
    );
    assert!(
        catalog(vec![
            spec("one", "/same", vec![], json!({})),
            spec("two", "/same", vec![], json!({}))
        ])
        .is_err()
    );
    let left = vec![
        spec("new", "/links/new", vec![], json!({})),
        spec(
            "link",
            "/links/{link_id}",
            vec![("link_id", reference())],
            json!({}),
        ),
        spec(
            "flag",
            "/links/{enabled}",
            vec![("enabled", Kind::Boolean)],
            json!({}),
        ),
    ];
    let mut right = left
        .iter()
        .map(|item| {
            spec(
                item.name,
                item.path,
                item.fields.clone(),
                item.defaults.clone(),
            )
        })
        .collect::<Vec<_>>();
    right.reverse();
    let left = catalog(left)?;
    let right = catalog(right)?;
    for (path, page, input) in [
        ("/links/new", "new", json!({})),
        ("/links/123", "link", json!({"link_id":"123"})),
        ("/links/true", "flag", json!({"enabled":true})),
    ] {
        assert_eq!(left.resolve(path, "")?, Some((page.into(), input)));
        assert_eq!(left.resolve(path, "")?, right.resolve(path, "")?);
    }
    assert!(left.resolve("/links/not_a_value", "").is_err());
    Ok(())
}

#[test]
fn openapi_namespaces_cannot_be_claimed_by_otherwise_valid_app_routes() {
    for path in [
        "/api",
        "/api/custom",
        "/docs",
        "/docs/custom",
        "/openapi.json",
        "/openapi.json/custom",
        "/mcp",
        "/mcp/custom",
    ] {
        let result = catalog(vec![spec("custom", path, vec![], json!({}))]);
        assert!(result.is_err(), "reserved route admitted: {path}");
        assert!(
            result.err().unwrap().to_string().contains("reserved"),
            "wrong rejection for {path}"
        );
    }
    assert!(catalog(vec![spec("custom", "/documentation", vec![], json!({}))]).is_ok());
}

#[test]
fn platform_namespaces_and_unsupported_field_shapes_fail_admission() {
    for path in [
        "/assets",
        "/assets/custom",
        "/audit",
        "/audit/custom",
        "/actions",
        "/login",
        "/logout",
        "/pages",
        "/pages/link",
        "/_live",
        "/_live/custom",
        "/api",
        "/api/links.list",
        "/api/custom/nested",
        "/docs",
        "/docs/custom",
        "/openapi.json",
        "/openapi.json/custom",
        "/%61pi/custom",
        "/d%6fcs",
        "/{slug}/detail",
    ] {
        assert!(
            catalog(vec![spec(
                "reserved",
                path,
                vec![("slug", Kind::Text)],
                json!({})
            )])
            .is_err(),
            "{path}"
        );
    }
    assert!(
        catalog(vec![spec(
            "optional",
            "/optional",
            vec![("value", Kind::OptionalText)],
            json!({"value":"None"})
        )])
        .is_err()
    );
    assert!(
        catalog(vec![spec(
            "web",
            "/web/{value}",
            vec![("value", Kind::WebUrl)],
            json!({})
        )])
        .is_err()
    );
    assert!(
        catalog(vec![spec(
            "wrong_default",
            "/other",
            vec![("limit", Kind::Integer)],
            json!({"limit":"20"})
        )])
        .is_err()
    );
    assert!(
        catalog(vec![spec(
            "unknown_default",
            "/other",
            vec![],
            json!({"extra":1})
        )])
        .is_err()
    );
}

#[test]
fn url_valued_query_fields_preserve_the_registered_input_representation() -> Result<()> {
    let routes = catalog(vec![spec(
        "target",
        "/target",
        vec![("url", Kind::WebUrl)],
        json!({}),
    )])?;
    let input = json!({"url":"https://example.com/path?q=a+b&next=x%2Fy#part"});
    assert_eq!(
        decode(&routes, &routes.build_url("target", &input)?)?,
        ("target".into(), input)
    );
    assert!(
        routes
            .resolve("/target", "url=javascript%3Aalert%281%29")
            .is_err()
    );
    Ok(())
}

#[test]
fn emitted_urls_and_incoming_requests_share_the_http_byte_budget() -> Result<()> {
    let routes = catalog(vec![spec(
        "search",
        "/search",
        vec![("q", Kind::Text)],
        json!({}),
    )])?;
    let overhead = "/search?q=".len();
    let maximum = day2::routing::MAX_URL_BYTES;
    let boundary = json!({"q":"x".repeat(maximum - overhead)});
    let url = routes.build_url("search", &boundary)?;
    assert_eq!(url.len(), maximum);
    assert_eq!(decode(&routes, &url)?.1, boundary);
    assert!(
        routes
            .build_url("search", &json!({"q":"x".repeat(maximum - overhead + 1)}))
            .is_err()
    );
    assert!(
        routes
            .build_url(
                "search",
                &json!({"q":"\u{e9}".repeat((maximum - overhead) / 6 + 1)})
            )
            .is_err()
    );
    assert!(
        routes
            .resolve(
                "/search",
                &format!("q={}", "x".repeat(maximum - overhead + 1))
            )
            .is_err()
    );
    let compact_but_unencodable = format!("q={}", "!".repeat(3_000));
    assert!("/search".len() + 1 + compact_but_unencodable.len() < maximum);
    assert!(routes.resolve("/search", &compact_but_unencodable).is_err());
    let compact = format!("q={}", "!".repeat(1_000));
    let (_, input) = routes
        .resolve("/search", &compact)?
        .expect("registered route");
    assert_eq!(input, json!({"q":"!".repeat(1_000)}));
    assert!(routes.build_url("search", &input)?.len() <= maximum);
    Ok(())
}

#[test]
fn seeded_route_roundtrips_preserve_unicode_scalars_and_large_reference_ids() -> Result<()> {
    let routes = catalog(vec![spec(
        "entry",
        "/entries/{slug}/{link_id}",
        vec![
            ("slug", Kind::Text),
            ("link_id", reference()),
            ("text", Kind::Text),
            ("number", Kind::Integer),
            ("active", Kind::Boolean),
        ],
        json!({"number":0,"active":false}),
    )])?;
    let path_text = proptest::collection::vec(
        prop_oneof![
            2 => proptest::sample::select(vec!['%', '?', '#', '&', '+', ' ', '\u{e9}']),
            3 => any::<char>().prop_filter("single path segment", |character| !character.is_control() && !['/', '\\'].contains(character)),
        ],
        1..24,
    )
    .prop_map(|characters| characters.into_iter().collect::<String>())
    .prop_filter("not a dot segment", |text| text != "." && text != "..");
    let query_text = proptest::collection::vec(any::<char>(), 0..32)
        .prop_map(|characters| characters.into_iter().collect::<String>());
    let mut runner = TestRunner::new(Config {
        cases: 256,
        rng_seed: RngSeed::Fixed(0xA020_2600_0007),
        ..Config::default()
    });
    runner.run(
        &(
            path_text,
            query_text,
            1i64..i64::MAX,
            any::<i64>(),
            any::<bool>(),
            any::<bool>(),
        ),
        |(slug, text, link_id, number, active, omit_defaults)| {
            let mut supplied = json!({"slug":slug,"link_id":link_id.to_string(),"text":text});
            if !omit_defaults {
                supplied["number"] = json!(number);
                supplied["active"] = json!(active);
            }
            let mut input = supplied.clone();
            input["number"] = json!(if omit_defaults { 0 } else { number });
            input["active"] = json!(!omit_defaults && active);
            let url = routes
                .build_url("entry", &supplied)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let resolved =
                decode(&routes, &url).map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(resolved.0, "entry");
            prop_assert_eq!(&resolved.1, &input);
            prop_assert_eq!(routes.build_url("entry", &resolved.1).unwrap(), url);
            Ok(())
        },
    )?;
    Ok(())
}

/// A page route claims every path of its shape, including one it refuses, so a
/// redirect route declared after it can never answer a path the page rejected.
#[test]
fn page_routes_claim_their_shape_even_when_they_refuse_the_value() -> Result<()> {
    let routes = catalog(vec![spec(
        "link",
        "/links/{link_id}",
        vec![("link_id", Kind::Integer)],
        json!({}),
    )])?;
    assert!(routes.resolve("/links/abc", "").is_err());
    for claimed in ["/", "/links/7", "/links/abc", "/links/%zz", "/%6Cinks/7"] {
        assert!(routes.claims(claimed), "{claimed}");
    }
    for unclaimed in [
        "/hello",
        "/links",
        "/links/7/more",
        "/docs/intro",
        "",
        "links/7",
    ] {
        assert!(!routes.claims(unclaimed), "{unclaimed}");
    }
    Ok(())
}
