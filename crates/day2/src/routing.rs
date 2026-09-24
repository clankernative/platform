use crate::{
    artifact::{Artifact, Operation, Page},
    schema::{Kind, Record, Schema},
};
use anyhow::{Context, Result, bail, ensure};
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PATH_BYTES: usize = 4_096;
const MAX_QUERY_BYTES: usize = 65_536;
pub const MAX_URL_BYTES: usize = 8_192;
const MAX_SEGMENTS: usize = 32;
const RESERVED: &[&str] = &[
    "assets", "audit", "actions", "login", "logout", "pages", "health", "_live",
];

#[derive(Clone, Debug)]
enum Segment {
    Literal(String),
    Parameter(String),
}

#[derive(Clone, Debug)]
pub struct Route {
    pub name: String,
    pub path: String,
    pub input: Record,
    pub path_fields: BTreeSet<String>,
    pub defaults: Map<String, Value>,
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    routes: BTreeMap<String, Route>,
    redirects: crate::redirects::Catalog,
}

pub(crate) struct NavigationInput<'a> {
    pub input: &'a Record,
    pub required: BTreeSet<&'a str>,
}

impl Catalog {
    pub fn from_artifact(artifact: &Artifact) -> Result<Self> {
        ensure!(
            artifact.format >= 7,
            "explicit routes require artifact format 7"
        );
        let mut catalog = Self::compile(&artifact.pages, &artifact.operations, &artifact.schema)?;
        for redirect in &artifact.redirects {
            ensure!(
                !catalog.routes.contains_key(&redirect.name),
                "page and redirect share a route name: {}",
                redirect.name
            );
        }
        catalog.redirects = crate::redirects::Catalog::from_artifact(artifact)?;
        Ok(catalog)
    }

    pub fn compile(pages: &[Page], operations: &[Operation], schema: &Schema) -> Result<Self> {
        ensure!(pages.len() <= 32, "route count budget");
        let mut routes = BTreeMap::new();
        for page in pages {
            page.validate_live()?;
            crate::schema::identifier(&page.name)?;
            let queries = operations
                .iter()
                .filter(|operation| operation.name == page.operation)
                .collect::<Vec<_>>();
            ensure!(
                queries.len() == 1 && queries[0].kind == "query",
                "route requires one registered query"
            );
            ensure!(
                page.input_type == queries[0].input_type,
                "route {} and its registered query require the same input handle",
                page.name
            );
            let input = schema
                .inputs
                .get(&queries[0].input_type)
                .context("route requires registered input")?
                .clone();
            ensure!(input.fields.len() <= 32, "route input field budget");
            for (field, kind) in &input.fields {
                crate::schema::identifier(field)?;
                ensure!(
                    !matches!(kind, Kind::OptionalText | Kind::InputShape { .. }),
                    "optional and structured route fields are not supported"
                );
            }
            let segments = pattern(&page.path)?;
            let mut path_fields = BTreeSet::new();
            for segment in &segments {
                if let Segment::Parameter(name) = segment {
                    ensure!(
                        path_fields.insert(name.clone()),
                        "duplicate route path parameter: {name}"
                    );
                    let kind = input
                        .fields
                        .get(name)
                        .with_context(|| format!("unknown route path parameter: {name}"))?;
                    ensure!(
                        !matches!(
                            kind,
                            Kind::WebUrl | Kind::OptionalText | Kind::InputShape { .. }
                        ),
                        "route path parameter requires a scalar segment codec: {name}"
                    );
                }
            }
            ensure!(
                page.defaults.len() <= MAX_QUERY_BYTES,
                "route defaults budget"
            );
            let defaults: Value = serde_json::from_str(&page.defaults)?;
            let defaults = defaults
                .as_object()
                .context("route defaults must be an object")?
                .clone();
            for (name, value) in &defaults {
                ensure!(
                    !path_fields.contains(name),
                    "route path parameters cannot have defaults: {name}"
                );
                let kind = input
                    .fields
                    .get(name)
                    .with_context(|| format!("unknown route default: {name}"))?;
                validate_field(kind, value).with_context(|| {
                    format!(
                        "route {} default {name}: expected {}",
                        page.name,
                        kind.wire_type(true)
                    )
                })?;
            }
            let route = Route {
                name: page.name.clone(),
                path: page.path.clone(),
                input,
                path_fields,
                defaults,
                segments,
            };
            if let Some(segment) = route.segments.first() {
                for reserved in RESERVED.iter().chain(crate::openapi::RESERVED) {
                    ensure!(
                        !segment_accepts(&route, segment, reserved),
                        "reserved platform route namespace: {reserved}"
                    );
                }
            }
            for existing in routes.values() {
                ensure!(
                    !overlap(existing, &route),
                    "overlapping routes: {} and {}",
                    existing.name,
                    route.name
                );
            }
            ensure!(
                routes.insert(page.name.clone(), route).is_none(),
                "duplicate route name"
            );
        }
        let catalog = Self {
            routes,
            redirects: Default::default(),
        };
        if !catalog.routes.is_empty() {
            let root = catalog
                .routes
                .values()
                .find(|route| route.segments.is_empty())
                .context("an explicit root route '/' is required")?;
            catalog
                .build_url(&root.name, &Value::Object(Map::new()))
                .context("root route must be constructible from its query defaults")?;
        }
        Ok(catalog)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }

    pub fn route(&self, name: &str) -> Result<&Route> {
        self.routes.get(name).context("unknown route name")
    }

    pub(crate) fn navigation_input(&self, name: &str) -> Result<NavigationInput<'_>> {
        if let Some(route) = self.routes.get(name) {
            return Ok(NavigationInput {
                input: &route.input,
                required: route
                    .input
                    .fields
                    .keys()
                    .filter(|name| {
                        route.path_fields.contains(*name) || !route.defaults.contains_key(*name)
                    })
                    .map(String::as_str)
                    .collect(),
            });
        }
        let route = self.redirects.route(name)?;
        Ok(NavigationInput {
            input: &route.input,
            required: route.input.fields.keys().map(String::as_str).collect(),
        })
    }

    pub fn build_url(&self, name: &str, supplied: &Value) -> Result<String> {
        let Some(route) = self.routes.get(name) else {
            return self.redirects.route(name)?.build_url(supplied);
        };
        let supplied = supplied
            .as_object()
            .context("route input must be an object")?;
        let mut input = route.defaults.clone();
        for (name, value) in supplied {
            ensure!(
                route.input.fields.contains_key(name),
                "unknown route input: {name}"
            );
            input.insert(name.clone(), value.clone());
        }
        for name in &route.path_fields {
            ensure!(
                supplied.contains_key(name),
                "missing route path parameter: {name}"
            );
        }
        route.input.validate_input(&Value::Object(input.clone()))?;
        let mut segments = Vec::new();
        for segment in &route.segments {
            let value = match segment {
                Segment::Literal(value) => value.clone(),
                Segment::Parameter(name) => encode_field(&route.input.fields[name], &input[name])?,
            };
            validate_segment(&value)?;
            segments.push(value);
        }
        let mut url = path_url(&segments)?;
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in &input {
                if !route.path_fields.contains(name) && route.defaults.get(name) != Some(value) {
                    query.append_pair(name, &encode_field(&route.input.fields[name], value)?);
                }
            }
        }
        let mut result = url.path().to_string();
        if let Some(query) = url.query().filter(|query| !query.is_empty()) {
            ensure!(query.len() <= MAX_QUERY_BYTES, "route query byte budget");
            result.push('?');
            result.push_str(query);
        }
        ensure!(result.len() <= MAX_URL_BYTES, "route URL byte budget");
        Ok(result)
    }

    /// None is a well-formed unknown route (404). Invalid encoding, path values,
    /// query fields or missing input are errors (400), never alternate routes.
    pub fn resolve(&self, path: &str, raw_query: &str) -> Result<Option<(String, Value)>> {
        ensure!(
            path.len()
                .saturating_add(raw_query.len())
                .saturating_add(usize::from(!raw_query.is_empty()))
                <= MAX_URL_BYTES,
            "route URL byte budget"
        );
        let segments = request_path(path)?;
        let query = query_fields(raw_query)?;
        let mut matched = None;
        let mut structural_match = false;
        for route in self.routes.values() {
            if route.segments.len() != segments.len()
                || !route
                    .segments
                    .iter()
                    .zip(&segments)
                    .all(|(pattern, value)| match pattern {
                        Segment::Literal(literal) => literal == value,
                        Segment::Parameter(_) => true,
                    })
            {
                continue;
            }
            structural_match = true;
            let mut input = route.defaults.clone();
            let mut valid = true;
            for (pattern, value) in route.segments.iter().zip(&segments) {
                if let Segment::Parameter(name) = pattern {
                    match decode_field(&route.input.fields[name], value) {
                        Ok(value) => {
                            input.insert(name.clone(), value);
                        }
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }
            }
            if valid {
                ensure!(
                    matched.replace((route, input)).is_none(),
                    "ambiguous route catalog"
                );
            }
        }
        let Some((route, mut input)) = matched else {
            ensure!(!structural_match, "invalid route path parameter");
            return Ok(None);
        };
        for (name, raw) in query {
            ensure!(
                !route.path_fields.contains(&name),
                "path parameter cannot appear in query: {name}"
            );
            let kind = route
                .input
                .fields
                .get(&name)
                .with_context(|| format!("unknown route query field: {name}"))?;
            input.insert(name, decode_field(kind, &raw)?);
        }
        let input = Value::Object(input);
        route.input.validate_input(&input)?;
        // Redirects and signed page continuations must be constructible even if
        // the incoming query used a shorter, noncanonical component encoding.
        self.build_url(&route.name, &input)?;
        Ok(Some((route.name.clone(), input)))
    }
}

impl Catalog {
    /// Whether some page route has this path's shape, even if the path's
    /// encoding or values are invalid for it. A page route claims such a path
    /// (and answers 400), so nothing after it — a redirect route — may.
    pub fn claims(&self, path: &str) -> bool {
        let Some(raw) = path.strip_prefix('/') else {
            return false;
        };
        let segments = if raw.is_empty() {
            Vec::new()
        } else {
            raw.split('/').collect()
        };
        self.routes.values().any(|route| {
            route.segments.len() == segments.len()
                && route
                    .segments
                    .iter()
                    .zip(&segments)
                    .all(|(pattern, raw)| match pattern {
                        Segment::Literal(literal) => {
                            decode_segment(raw).is_ok_and(|value| &value == literal)
                        }
                        Segment::Parameter(_) => true,
                    })
        })
    }
}

/// A first path segment the platform owns. Nothing an application declares may
/// answer a path in one of these namespaces.
pub(crate) fn reserved_namespace(segment: &str) -> bool {
    RESERVED.contains(&segment) || crate::openapi::RESERVED.contains(&segment)
}

fn pattern(path: &str) -> Result<Vec<Segment>> {
    ensure!(
        path.starts_with('/') && path.len() <= MAX_PATH_BYTES,
        "route requires a bounded absolute path"
    );
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for raw in path[1..].split('/') {
        ensure!(!raw.is_empty(), "route trailing or repeated slash");
        let segment =
            if let Some(parameter) = raw.strip_prefix('{').and_then(|raw| raw.strip_suffix('}')) {
                crate::schema::identifier(parameter)?;
                Segment::Parameter(parameter.into())
            } else {
                ensure!(
                    !raw.contains(['{', '}']),
                    "route parameters must occupy a whole segment"
                );
                let literal = decode_segment(raw)?;
                ensure!(
                    path_url(std::slice::from_ref(&literal))?.path() == format!("/{raw}"),
                    "noncanonical route literal"
                );
                Segment::Literal(literal)
            };
        segments.push(segment);
        ensure!(segments.len() <= MAX_SEGMENTS, "route segment count budget");
    }
    Ok(segments)
}

fn strict_percent(raw: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            ensure!(
                bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit),
                "malformed URL percent encoding"
            );
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

pub(crate) fn validate_segment(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && ![".", ".."].contains(&value)
            && !value.contains(['/', '\\'])
            && !value.chars().any(char::is_control),
        "invalid route path segment"
    );
    Ok(())
}

pub(crate) fn decode_segment(raw: &str) -> Result<String> {
    strict_percent(raw)?;
    let value = percent_decode_str(raw)
        .decode_utf8()
        .context("invalid path UTF-8")?
        .into_owned();
    validate_segment(&value)?;
    Ok(value)
}

pub(crate) fn path_url(segments: &[String]) -> Result<url::Url> {
    let mut url = url::Url::parse("https://day2.invalid/")?;
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("route URL base"))?;
        path.clear();
        for segment in segments {
            path.push(segment);
        }
    }
    ensure!(url.path().len() <= MAX_PATH_BYTES, "route path byte budget");
    Ok(url)
}

fn request_path(path: &str) -> Result<Vec<String>> {
    ensure!(
        path.starts_with('/') && path.len() <= MAX_PATH_BYTES && !path.contains(['?', '#']),
        "invalid route request path"
    );
    let segments = if path == "/" {
        Vec::new()
    } else {
        path[1..]
            .split('/')
            .map(decode_segment)
            .collect::<Result<Vec<_>>>()?
    };
    ensure!(segments.len() <= MAX_SEGMENTS, "route segment count budget");
    ensure!(
        path_url(&segments)?.path() == path,
        "noncanonical route request path"
    );
    Ok(segments)
}

pub(crate) fn query_fields(raw: &str) -> Result<BTreeMap<String, String>> {
    ensure!(raw.len() <= MAX_QUERY_BYTES, "route query byte budget");
    strict_percent(raw)?;
    // Validate UTF-8 before the form decoder, whose default behavior is lossy.
    // A literal '+' stays a path character; only this query decoder maps it to space.
    percent_decode_str(raw)
        .decode_utf8()
        .context("invalid query UTF-8")?;
    let mut fields = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        ensure!(
            fields.len() < 32
                && fields
                    .insert(name.into_owned(), value.into_owned())
                    .is_none(),
            "duplicate or excessive route query fields"
        );
    }
    Ok(fields)
}

fn validate_field(kind: &Kind, value: &Value) -> Result<()> {
    Record {
        fields: BTreeMap::from([("value".into(), kind.clone())]),
        roc_type: None,
        identity: None,
    }
    .validate_input(&serde_json::json!({"value":value}))
}

fn decode_field(kind: &Kind, raw: &str) -> Result<Value> {
    let value = crate::web_security::field_value(kind, raw)?;
    validate_field(kind, &value)?;
    Ok(value)
}

fn encode_field(kind: &Kind, value: &Value) -> Result<String> {
    validate_field(kind, value)?;
    match kind {
        Kind::Integer | Kind::PageSize | Kind::RowVersion => {
            Ok(value.as_i64().context("route integer")?.to_string())
        }
        Kind::Unsigned(_) => Ok(value
            .as_u64()
            .context("route unsigned integer")?
            .to_string()),
        Kind::Boolean => Ok(value.as_bool().context("route boolean")?.to_string()),
        Kind::Text
        | Kind::TextDomain { .. }
        | Kind::StandardText { .. }
        | Kind::WebUrl
        | Kind::Reference { .. }
        | Kind::ModelReference { .. }
        | Kind::IdCursor
        | Kind::Cursor => Ok(value.as_str().context("route string")?.into()),
        Kind::OptionalText | Kind::InputShape { .. } => {
            bail!("optional and structured route fields are not supported")
        }
    }
}

fn segment_accepts(route: &Route, segment: &Segment, value: &str) -> bool {
    match segment {
        Segment::Literal(literal) => literal == value,
        Segment::Parameter(name) => decode_field(&route.input.fields[name], value).is_ok(),
    }
}

fn overlap(left: &Route, right: &Route) -> bool {
    left.segments.len() == right.segments.len()
        && left
            .segments
            .iter()
            .zip(&right.segments)
            .all(|(a, b)| match (a, b) {
                (Segment::Literal(value), other) => segment_accepts(right, other, value),
                (other, Segment::Literal(value)) => segment_accepts(left, other, value),
                (Segment::Parameter(a), Segment::Parameter(b)) => {
                    let a = &left.input.fields[a];
                    let b = &right.input.fields[b];
                    !matches!(
                        (a, b),
                        (
                            Kind::Boolean,
                            Kind::Integer
                                | Kind::Unsigned(_)
                                | Kind::RowVersion
                                | Kind::Reference { .. }
                                | Kind::Cursor
                                | Kind::PageSize
                        ) | (
                            Kind::Integer
                                | Kind::Unsigned(_)
                                | Kind::RowVersion
                                | Kind::Reference { .. }
                                | Kind::Cursor
                                | Kind::PageSize,
                            Kind::Boolean
                        )
                    )
                }
            })
}
