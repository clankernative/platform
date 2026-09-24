use crate::{
    schema::{Kind, Record, web_url},
    store::Runtime,
    web_assets::Appearance,
    web_security::{self as security, Session, Ticket},
};
use anyhow::{Context, Result, bail, ensure};
use maud::{Markup, PreEscaped, html};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Field {
    pub name: String,
    pub label: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attribute {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    pub kind: String,
    pub text: String,
    pub variant: String,
    pub url: String,
    pub operation: String,
    pub bound: String,
    #[serde(default)]
    pub asset: String,
    pub fields: Vec<Field>,
    #[serde(default)]
    pub attrs: Vec<Attribute>,
}
const VOID: &[&str] = &["area", "br", "col", "hr", "img", "input", "wbr"];

fn syntax_name(value: &str) -> bool {
    name_bytes(value, b"-_:")
}

fn attribute_name(value: &str) -> bool {
    name_bytes(value, b"-_:.")
}

fn name_bytes(value: &str, punctuation: &[u8]) -> bool {
    value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
}

fn tag_name(tag: &str) -> Result<()> {
    ensure!(syntax_name(tag) && !tag.contains(':'), "invalid_html_tag");
    ensure!(
        ![
            "script",
            "style",
            "link",
            "meta",
            "base",
            "iframe",
            "frame",
            "frameset",
            "object",
            "embed",
            "form",
            "html",
            "head",
            "body",
            "foreignobject",
            "animate",
            "animatemotion",
            "animatetransform",
            "set"
        ]
        .contains(&tag.to_ascii_lowercase().as_str()),
        "unsupported_html_tag"
    );
    Ok(())
}

fn href(value: &str) -> Result<()> {
    ensure!(
        !value.chars().any(|c| c.is_control() || c.is_whitespace()) && !value.contains('\\'),
        "invalid_href"
    );
    if value.starts_with('#') || (value.starts_with('/') && !value.starts_with("//")) {
        return Ok(());
    }
    web_url(value).map(|_| ())
}

fn attributes(tag: &str, attrs: &[Attribute], transport: bool) -> Result<()> {
    ensure!(attrs.len() <= 64, "attribute_budget");
    let mut names = BTreeSet::new();
    for attr in attrs {
        let name = attr.name.to_ascii_lowercase();
        ensure!(
            attribute_name(&attr.name) && names.insert(name.clone()) && attr.value.len() <= 16_384,
            "invalid_attribute"
        );
        ensure!(
            !name.starts_with("on")
                && ![
                    "src",
                    "srcset",
                    "imagesrcset",
                    "imagesizes",
                    "poster",
                    "srcdoc",
                    "data",
                    "background",
                    "ping",
                    "formaction",
                    "action",
                    "method",
                    "form",
                    "http-equiv",
                    "xmlns",
                    "xmlns:xlink",
                    "xml:base"
                ]
                .contains(&name.as_str()),
            "unsupported_attribute"
        );
        if transport {
            ensure!(
                name != "name"
                    && !name.starts_with("data-on:submit")
                    && !name.starts_with("data-on-submit")
                    && !name.starts_with("data-attr:action")
                    && !name.starts_with("data-attr:method"),
                "reserved_form_attribute"
            );
        }
        if name == "href" || name == "xlink:href" {
            if tag.eq_ignore_ascii_case("a") || tag.eq_ignore_ascii_case("area") {
                href(&attr.value)?;
            } else {
                ensure!(
                    attr.value.starts_with('#') && !attr.value.chars().any(char::is_control),
                    "resource_href_forbidden"
                );
            }
        }
        if name == "style" {
            crate::web_resources::validate_inline_style(&attr.value)?;
        }
        if [
            "fill",
            "stroke",
            "filter",
            "clip-path",
            "mask",
            "cursor",
            "marker",
            "marker-start",
            "marker-mid",
            "marker-end",
        ]
        .contains(&name.as_str())
        {
            crate::web_resources::validate_inline_style(&format!("{name}:{}", attr.value))?;
        }
    }
    Ok(())
}

fn markup_tag(tag: &str, attrs: &[Attribute], content: Markup, void: bool) -> Markup {
    let mut output = format!("<{tag}");
    for attr in attrs {
        output.push(' ');
        output.push_str(&attr.name);
        output.push_str("=\"");
        output.push_str(&html! { (&attr.value) }.into_string());
        output.push('"');
    }
    output.push('>');
    if !void {
        output.push_str(&content.into_string());
        output.push_str(&format!("</{tag}>"));
    }
    PreEscaped(output)
}

pub(crate) fn nodes(value: &Value) -> Result<Vec<Node>> {
    ensure!(
        serde_json::to_vec(value)?.len() <= 524_288,
        "view_byte_budget"
    );
    let nodes: Vec<Node> = serde_json::from_value(value.clone())?;
    ensure!(!nodes.is_empty() && nodes.len() <= 4096, "view_node_budget");
    let mut stack: Vec<(&str, &str)> = vec![("root", "root")];
    let mut command_fields: Option<(BTreeSet<&str>, BTreeSet<&str>)> = None;
    for node in &nodes {
        ensure!(node.text.len() <= 16_384, "view_text_budget");
        ensure!(
            ["open", "void", "command", "signout", "field", "image"].contains(&node.kind.as_str())
                || node.attrs.is_empty(),
            "unexpected_attributes"
        );
        ensure!(
            ["open", "form", "image", "field"].contains(&node.kind.as_str())
                || node.variant.is_empty(),
            "unexpected_style"
        );
        ensure!(
            ["form", "image"].contains(&node.kind.as_str()) || node.asset.is_empty(),
            "unexpected_asset"
        );
        if !node.asset.is_empty() {
            crate::schema::identifier(&node.asset)?;
        }
        ensure!(node.kind == "link" || node.url.is_empty(), "unexpected_url");
        ensure!(
            ["form", "command"].contains(&node.kind.as_str())
                || (node.operation.is_empty() && node.bound.is_empty() && node.fields.is_empty()),
            "unexpected_action"
        );
        if node.kind == "close" {
            ensure!(node.text.is_empty() && stack.len() > 1, "unbalanced_view");
            let (kind, _) = stack.pop().context("view stack")?;
            if kind == "command" {
                let (declared, seen) = command_fields.take().context("form context")?;
                ensure!(declared == seen, "incomplete_form_controls");
            }
            continue;
        }
        let child = if node.kind == "open" || node.kind == "void" {
            node.text.as_str()
        } else if node.kind == "field" {
            node.variant.as_str()
        } else {
            node.kind.as_str()
        };
        let parent = stack.last().context("view root")?.1;
        let valid = match parent {
            "table" => ["thead", "tbody", "tfoot", "caption", "colgroup"].contains(&child),
            "thead" | "tbody" | "tfoot" => child == "tr",
            "tr" => ["th", "td"].contains(&child),
            "ul" | "ol" => child == "li",
            _ => !["thead", "tbody", "tr", "th", "td", "li"].contains(&child),
        };
        ensure!(valid, "invalid_html_nesting");
        match node.kind.as_str() {
            "open" | "void" => {
                tag_name(child)?;
                ensure!(
                    VOID.contains(&child.to_ascii_lowercase().as_str()) == (node.kind == "void"),
                    "invalid_void_element"
                );
                attributes(child, &node.attrs, false)?;
                if command_fields.is_some()
                    && ["input", "select", "textarea", "button"]
                        .contains(&child.to_ascii_lowercase().as_str())
                {
                    ensure!(
                        !node
                            .attrs
                            .iter()
                            .any(|attr| attr.name.eq_ignore_ascii_case("name")),
                        "untyped_form_control"
                    );
                }
                ensure!(stack.len() < 48, "view_depth_budget");
                if node.kind == "open" {
                    stack.push(("open", child));
                }
            }
            "text" => {}
            "link" => {
                web_url(&node.url)?;
            }
            "form" => ensure!(
                command_fields.is_none()
                    && !stack.iter().any(|(kind, _)| *kind == "signout")
                    && !node.text.trim().is_empty()
                    && node.text.len() <= 80
                    && node.fields.len() <= 32
                    && ["primary", "secondary", "danger"].contains(&node.variant.as_str()),
                crate::error::Failure::InvalidForm
            ),
            "command" | "signout" => {
                ensure!(
                    command_fields.is_none()
                        && !stack.iter().any(|(kind, _)| *kind == "signout")
                        && stack.len() < 48,
                    "nested_form"
                );
                attributes("form", &node.attrs, true)?;
                if node.kind == "command" {
                    let declared: BTreeSet<_> = node
                        .fields
                        .iter()
                        .map(|field| field.name.as_str())
                        .collect();
                    ensure!(
                        declared.len() == node.fields.len() && declared.len() <= 32,
                        "invalid_form_fields"
                    );
                    command_fields = Some((declared, BTreeSet::new()));
                }
                stack.push((node.kind.as_str(), "form"));
            }
            "field" => {
                let (declared, seen) = command_fields.as_mut().context("field_outside_command")?;
                ensure!(
                    declared.contains(node.text.as_str()) && seen.insert(node.text.as_str()),
                    "invalid_form_control"
                );
                ensure!(
                    ["input", "textarea", "select"].contains(&child),
                    "invalid_form_control"
                );
                attributes(child, &node.attrs, true)?;
                if child != "input" {
                    ensure!(stack.len() < 48, "view_depth_budget");
                    stack.push(("field", child));
                }
            }
            "company" => ensure!(node.text.is_empty(), "invalid_company_node"),
            "image" => {
                attributes("img", &node.attrs, false)?;
                ensure!(
                    !node
                        .attrs
                        .iter()
                        .any(|attr| attr.name.eq_ignore_ascii_case("alt")),
                    "reserved_image_attribute"
                );
                ensure!(
                    !node.asset.is_empty()
                        && ((node.variant == "content" && !node.text.trim().is_empty())
                            || (node.variant == "icon" && node.text.is_empty())),
                    "invalid_image"
                );
            }
            "next" => ensure!(
                node.text
                    .parse::<i64>()
                    .is_ok_and(|id| id > 0 && id.to_string() == node.text),
                crate::error::Failure::InvalidCursor
            ),
            _ => bail!("unsupported_view_node"),
        }
    }
    ensure!(stack.len() == 1, "unbalanced_view");
    Ok(nodes)
}

#[derive(Clone, Copy)]
pub(crate) struct Submitted<'a> {
    pub operation: &'a str,
    pub bound: &'a Value,
    pub fields: &'a BTreeMap<String, Vec<String>>,
}

impl<'a> Submitted<'a> {
    pub fn value(&self, operation: &str, bound: &Value, field: &str) -> Option<&'a str> {
        (self.operation == operation && self.bound == bound)
            // A rejected single-valued draft is restored as before. A list draft has
            // one value per control, which this restore path does not address, so it
            // is left to the template rather than collapsed into one control.
            .then(|| {
                self.fields
                    .get(field)
                    .filter(|values| values.len() == 1)
                    .map(|values| values[0].as_str())
            })
            .flatten()
    }
}

pub(crate) struct View<'a> {
    pub runtime: &'a Runtime,
    pub appearance: &'a Appearance,
    pub secret: &'a [u8],
    pub session: &'a Session,
    pub page: &'a str,
    pub input: &'a Value,
    pub now: i64,
    pub submitted: Option<Submitted<'a>>,
}
struct Frame<'a> {
    node: Option<&'a Node>,
    children: Vec<Markup>,
}
impl View<'_> {
    pub fn render(&self, value: &Value) -> Result<Markup> {
        let nodes = nodes(value)?;
        let mut stack = vec![Frame {
            node: None,
            children: vec![],
        }];
        for node in &nodes {
            if ["open", "command", "signout"].contains(&node.kind.as_str())
                || (node.kind == "field" && node.variant != "input")
            {
                stack.push(Frame {
                    node: Some(node),
                    children: vec![],
                });
                continue;
            }
            let content = match node.kind.as_str() {
                "close" => {
                    let frame = stack.pop().context("view stack")?;
                    let node = frame.node.context("view node")?;
                    let content = html! { @for child in frame.children { (child) } };
                    let command = stack
                        .iter()
                        .rev()
                        .filter_map(|frame| frame.node)
                        .find(|node| node.kind == "command");
                    match node.kind.as_str() {
                        "command" => {
                            if let Some(hidden) = self.form_hidden(node)? {
                                let attrs = command_attributes(&node.attrs);
                                markup_tag("form", &attrs, html! { (hidden) (content) }, false)
                            } else {
                                html! {}
                            }
                        }
                        "signout" => {
                            let mut attrs = node.attrs.clone();
                            attrs.push(attribute("method", "post"));
                            attrs.push(attribute("action", "/logout"));
                            markup_tag(
                                "form",
                                &attrs,
                                html! { input type="hidden" name="_csrf" value=(security::csrf(self.secret, self.session)?); (content) },
                                false,
                            )
                        }
                        "field" => self.field(node, content, command.context("field command")?)?,
                        _ => {
                            let mut attrs = node.attrs.clone();
                            if !node.variant.is_empty() {
                                attrs.push(attribute("class", &node.variant));
                            }
                            if node.text == "option" {
                                let select =
                                    stack.iter().rev().filter_map(|frame| frame.node).find(
                                        |node| node.kind == "field" && node.variant == "select",
                                    );
                                if let Some(value) =
                                    command.zip(select).and_then(|(command, select)| {
                                        self.submitted_value(command, &select.text)
                                    })
                                {
                                    let selected = attrs
                                        .iter()
                                        .find(|attr| attr.name == "value")
                                        .is_some_and(|attr| attr.value == value);
                                    attrs
                                        .retain(|attr| !attr.name.eq_ignore_ascii_case("selected"));
                                    if selected {
                                        attrs.push(attribute("selected", "selected"));
                                    }
                                }
                            }
                            markup_tag(&node.text, &attrs, content, false)
                        }
                    }
                }
                "void" => markup_tag(&node.text, &node.attrs, html! {}, true),
                "field" => {
                    let command = stack
                        .iter()
                        .rev()
                        .filter_map(|frame| frame.node)
                        .find(|node| node.kind == "command")
                        .context("field command")?;
                    self.field(node, html! {}, command)?
                }
                "text" => html! { (&node.text) },
                "company" => html! { (self.appearance.name()) },
                "link" => {
                    html! { a.external href=(&node.url) target="_blank" rel="noopener noreferrer" { span { (&node.text) } (icon("arrow-up-right")) } }
                }
                "form" => self.form(node)?,
                "image" => self.image(node)?,
                "next" => {
                    let mut input = self.input.clone();
                    ensure!(
                        input.get("after").is_some_and(Value::is_i64),
                        "page_has_no_cursor"
                    );
                    input["after"] = Value::from(node.text.parse::<i64>()?);
                    html! { a.button href=(page_url(self.runtime,self.page,&input)?) { "Next page" (icon("arrow-up-right")) } }
                }
                _ => bail!("unsupported_node"),
            };
            stack
                .last_mut()
                .context("view parent")?
                .children
                .push(content);
        }
        let content = stack.pop().context("view root")?.children;
        Ok(html! { @for child in content { (child) } })
    }
    fn image(&self, node: &Node) -> Result<Markup> {
        let asset = self
            .runtime
            .artifact()
            .contract()
            .assets
            .get(&node.asset)
            .context("unregistered_app_asset")?;
        let mut attrs = node.attrs.clone();
        for (name, value) in [
            (
                "class",
                if node.variant == "icon" {
                    "app-icon".into()
                } else {
                    "app-image".into()
                },
            ),
            ("width", asset.width.to_string()),
            ("height", asset.height.to_string()),
            ("decoding", "async".into()),
        ] {
            if !attrs
                .iter()
                .any(|attr| attr.name.eq_ignore_ascii_case(name))
            {
                attrs.push(attribute(name, &value));
            }
        }
        attrs.push(attribute(
            "src",
            &self.appearance.app_url(self.runtime, &node.asset)?,
        ));
        attrs.push(attribute("alt", &node.text));
        if node.variant == "icon"
            && !attrs
                .iter()
                .any(|attr| attr.name.eq_ignore_ascii_case("aria-hidden"))
        {
            attrs.push(attribute("aria-hidden", "true"));
        }
        Ok(markup_tag("img", &attrs, html! {}, true))
    }
    fn submitted_value<'a>(&'a self, command: &Node, field: &str) -> Option<&'a str> {
        let bound: Value = serde_json::from_str(&command.bound).ok()?;
        self.submitted?.value(&command.operation, &bound, field)
    }
    fn field(&self, node: &Node, children: Markup, command: &Node) -> Result<Markup> {
        let definition = self.runtime.artifact().operation(&command.operation)?;
        let record = &self.runtime.artifact().contract().schema.inputs[&definition.input_type];
        ensure!(record.fields.contains_key(&node.text), "unknown_form_field");
        let mut attrs = node.attrs.clone();
        attrs.push(attribute("name", &node.text));
        let mut children = children;
        if let Some(value) = self.submitted_value(command, &node.text) {
            if node.variant == "input" {
                let kind = attrs
                    .iter()
                    .find(|attr| attr.name.eq_ignore_ascii_case("type"))
                    .map(|attr| attr.value.as_str())
                    .unwrap_or("text");
                if ["checkbox", "radio"].contains(&kind) {
                    let selected = attrs
                        .iter()
                        .find(|attr| attr.name.eq_ignore_ascii_case("value"))
                        .is_some_and(|attr| attr.value == value);
                    attrs.retain(|attr| !attr.name.eq_ignore_ascii_case("checked"));
                    if selected {
                        attrs.push(attribute("checked", "checked"));
                    }
                } else {
                    attrs.retain(|attr| !attr.name.eq_ignore_ascii_case("value"));
                    attrs.push(attribute("value", value));
                }
            } else if node.variant == "textarea" {
                children = html! { (value) };
            }
        }
        Ok(markup_tag(
            &node.variant,
            &attrs,
            children,
            node.variant == "input",
        ))
    }
    fn form_hidden(&self, node: &Node) -> Result<Option<Markup>> {
        let operation = self.runtime.artifact().operation(&node.operation)?;
        ensure!(operation.kind == "command", "form_requires_command");
        let record = &self.runtime.artifact().contract().schema.inputs[&operation.input_type];
        let bound: Value = serde_json::from_str(&node.bound)?;
        let bound_map = bound.as_object().context("invalid_bound_input")?;
        let mut names = BTreeSet::new();
        for (name, value) in bound_map {
            let kind = record.fields.get(name).context("unknown_bound_field")?;
            Record {
                fields: BTreeMap::from([(name.clone(), kind.clone())]),
                roc_type: None,
                identity: None,
            }
            .validate_input(&serde_json::json!({name:value}))?;
            names.insert(name.as_str());
        }
        for field in &node.fields {
            ensure!(
                names.insert(&field.name)
                    && record.fields.contains_key(&field.name)
                    && (node.kind == "command" || !field.label.trim().is_empty())
                    && field.label.len() <= 100,
                "invalid_form_field"
            );
            ensure!(
                !matches!(
                    record.fields[&field.name],
                    Kind::OptionalText | Kind::InputShape { .. }
                ),
                "unsupported_form_field"
            );
        }
        ensure!(
            names.len() == record.fields.len(),
            "incomplete_form_binding"
        );
        if self
            .runtime
            .authorize(&node.operation, &self.session.actor)
            .is_err()
        {
            return Ok(None);
        }
        let ticket = Ticket {
            scope: self.runtime.scope().to_owned(),
            artifact: self.runtime.artifact().id().to_owned(),
            session: self.session.hash.clone(),
            actor: self.session.actor.clone(),
            page: self.page.into(),
            page_input: self.input.clone(),
            operation: node.operation.clone(),
            form_id: None,
            bound,
            editable: node.fields.iter().map(|field| field.name.clone()).collect(),
            nonce: security::random()?,
            issued: self.now,
            expires: (self.now + 1800).min(self.session.expires),
        };
        let ticket = security::sign(self.secret, &serde_json::to_vec(&ticket)?)?;
        let csrf = security::csrf(self.secret, self.session)?;
        Ok(Some(html! {
            input type="hidden" name="_ticket" value=(ticket);
            input type="hidden" name="_csrf" value=(csrf);
        }))
    }
    fn form(&self, node: &Node) -> Result<Markup> {
        let Some(hidden) = self.form_hidden(node)? else {
            return Ok(html! {});
        };
        let operation = self.runtime.artifact().operation(&node.operation)?;
        let record = &self.runtime.artifact().contract().schema.inputs[&operation.input_type];
        let button_icon = if node.asset.is_empty() {
            html! {}
        } else {
            self.appearance.image(self.runtime, &node.asset, "", true)?
        };
        Ok(html! {
            form.command method="post" action="/actions" data-on:submit__prevent="@post(el.action, {contentType:'form', retry:'never'})" {
                (hidden)
                @for field in &node.fields {
                    @let kind = &record.fields[&field.name];
                    @let value = self.submitted_value(node, &field.name).unwrap_or("");
                    label { (&field.label)
                        @if *kind == Kind::Boolean {
                            select name=(&field.name) { option value="false" selected[value != "true"] { "No" } option value="true" selected[value == "true"] { "Yes" } }
                        } @else {
                            input name=(&field.name) type=(if *kind == Kind::WebUrl { "url" } else { "text" })
                                inputmode=(if matches!(kind, Kind::Integer | Kind::Unsigned(_) | Kind::RowVersion | Kind::PageSize) { "numeric" } else { "text" })
                                maxlength=(if *kind == Kind::WebUrl { 2048 } else { 16384 }) required value=(value);
                        }
                    }
                }
                button class=(&node.variant) type="submit" {
                    (button_icon) (&node.text)
                }
            }
        })
    }
}

fn attribute(name: &str, value: &str) -> Attribute {
    Attribute {
        name: name.into(),
        value: value.into(),
    }
}
fn command_attributes(attributes: &[Attribute]) -> Vec<Attribute> {
    let mut attrs = attributes.to_vec();
    attrs.extend([
        attribute("method", "post"),
        attribute("action", "/actions"),
        attribute(
            "data-on:submit__prevent",
            "@post(el.action, {contentType:'form', retry:'never'})",
        ),
    ]);
    attrs
}
pub(crate) fn icon(name: &str) -> Markup {
    html! { img.platform-icon src=(format!("/assets/platform/icons/{name}.svg")) alt="" aria-hidden="true" width="18" height="18"; }
}
pub(crate) fn page_url(runtime: &Runtime, page: &str, input: &Value) -> Result<String> {
    if runtime.artifact().contract().format >= 7 {
        return crate::routing::Catalog::from_artifact(runtime.artifact().contract())?
            .build_url(page, input);
    }
    crate::schema::identifier(page)?;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in input.as_object().context("page_input")? {
        query.append_pair(
            name,
            &match value {
                Value::String(value) => value.clone(),
                Value::Number(_) | Value::Bool(_) => value.to_string(),
                _ => bail!("unsupported_page_input"),
            },
        );
    }
    Ok(format!("/pages/{page}?{}", query.finish()))
}
pub(crate) fn document(
    title: &str,
    appearance: Option<&Appearance>,
    body: Markup,
) -> Result<Markup> {
    let logo = appearance.map(Appearance::logo_url).transpose()?.flatten();
    let theme = appearance.map(Appearance::theme_url).transpose()?.flatten();
    Ok(html! { (maud::DOCTYPE) html lang="en" {
        head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            title { (title) " | " (appearance.map_or("Day2",Appearance::name)) }
            link rel="icon" href=(logo.as_deref().unwrap_or("/assets/platform/icons/link.svg"));
            link rel="stylesheet" href="/assets/platform/web.css";
            @if let Some(theme) = theme { link rel="stylesheet" href=(theme); }
            script type="module" src="/assets/platform/datastar-1.0.1.js" {}
        }
        body { (body) }
    } })
}
pub(crate) fn shell(
    runtime: &Runtime,
    appearance: &Appearance,
    session: &Session,
    secret: &[u8],
    selected: &str,
    content: Markup,
) -> Result<Markup> {
    let csrf = security::csrf(secret, session)?;
    let mut pages = vec![];
    for page in &runtime.artifact().contract().pages {
        if runtime.authorize(&page.operation, &session.actor).is_ok() {
            if runtime.artifact().contract().format >= 7 {
                if page.path == "/" {
                    pages.push((page, page_url(runtime, &page.name, &serde_json::json!({}))?));
                }
            } else {
                pages.push((page, format!("/pages/{}", page.name)));
            }
        }
    }
    Ok(html! {
        header { div.header-inner {
            (brand(appearance)?) span.local { "LOCAL" }
            nav aria-label="Workspace" {
                @for (page,url) in pages { a href=(url) aria-current=[(selected == page.name).then_some("page")] { (&page.title) } }
                a href="/docs" { "API docs" }
                @if runtime.authorize_audit(&session.actor).is_ok() { a href="/audit" aria-current=[(selected == "$audit").then_some("page")] { "Audit log" } }
            }
            div.identity {
                span { (&session.actor) }
                form method="post" action="/logout" { input type="hidden" name="_csrf" value=(csrf); button.icon type="submit" title="Sign out" aria-label="Sign out" { (icon("log-out")) } }
            }
        } }
        (content)
    })
}
pub(crate) fn brand(appearance: &Appearance) -> Result<Markup> {
    Ok(html! { a.brand href="/" {
        @if let Some(logo) = appearance.logo_url()? { img src=(logo) width="34" height="34" alt=""; } @else { (icon("link")) }
        span { (appearance.name()) }
    } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn node(kind: &str, text: &str) -> Value {
        json!({"kind":kind,"text":text,"variant":"","url":"","operation":"","bound":"","asset":"","fields":[],"attrs":[]})
    }

    #[test]
    fn submitted_values_restore_only_the_original_command_target_and_version() {
        let bound = json!({"link_id":"123", "expected_version":4});
        let fields = BTreeMap::from([("title".into(), vec!["Unsubmitted draft".to_string()])]);
        let submitted = Submitted {
            operation: "links.edit",
            bound: &bound,
            fields: &fields,
        };
        assert_eq!(
            submitted.value("links.edit", &bound, "title"),
            Some("Unsubmitted draft")
        );
        assert_eq!(
            submitted.value(
                "links.edit",
                &json!({"link_id":"456", "expected_version":4}),
                "title"
            ),
            None
        );
        assert_eq!(
            submitted.value(
                "links.edit",
                &json!({"link_id":"123", "expected_version":5}),
                "title"
            ),
            None
        );
        assert_eq!(submitted.value("links.create", &bound, "title"), None);
        assert_eq!(submitted.value("links.edit", &bound, "missing"), None);
    }

    #[test]
    fn general_elements_keep_app_classes_custom_elements_and_inline_styles() -> Result<()> {
        let mut root = node("open", "rolling-value");
        root["attrs"] = json!([
            {"name":"class","value":"portfolio-value custom-layout"},
            {"name":"aria-live","value":"polite"},
            {"name":"data-effect","value":"el.textContent = $value"},
            {"name":"data-on:input__debounce.300ms","value":"$value = el.value"},
            {"name":"style","value":"display:grid;grid-template-columns:1fr 2fr;--gap:12px"}
        ]);
        assert_eq!(
            nodes(&json!([root, node("text", "<value>"), node("close", "")]))?.len(),
            3
        );
        Ok(())
    }

    #[test]
    fn generic_output_escapes_attribute_values_without_restricting_app_classes() {
        let attrs = vec![attribute("data-label", "\"<tag>&")];
        let result =
            markup_tag("example-panel", &attrs, html! { ("<script>") }, false).into_string();
        assert_eq!(
            result,
            "<example-panel data-label=\"&quot;&lt;tag&gt;&amp;\">&lt;script&gt;</example-panel>"
        );
    }

    #[test]
    fn resource_loaders_and_browser_parser_escape_hatches_are_not_generic_markup() {
        for tag in [
            "script",
            "SCRIPT",
            "iframe",
            "style",
            "link",
            "base",
            "foreignObject",
            "form",
            "animate",
            "div onclick=x",
        ] {
            assert!(tag_name(tag).is_err(), "{tag}");
        }
        for (name, value) in [
            ("src", "https://example.com/code.js"),
            ("onclick", "run()"),
            ("ping", "https://example.com"),
            ("style", "background:url(https://example.com/image)"),
            ("fill", "url(https://example.com/image)"),
            ("xml:base", "https://example.com"),
        ] {
            assert!(
                attributes("div", &[attribute(name, value)], false).is_err(),
                "{name}"
            );
        }
        assert!(
            attributes(
                "use",
                &[attribute("href", "https://example.com/icon.svg")],
                false
            )
            .is_err()
        );
        assert!(attributes("use", &[attribute("href", "#icon")], false).is_ok());
        assert!(href("/audit").is_ok());
        assert!(href("https://example.com/path").is_ok());
        assert!(href("//example.com/path").is_err());
        assert!(href("javascript:run()").is_err());
        assert!(
            attributes(
                "input",
                &[attribute(
                    "data-on:input__debounce.300ms",
                    "$value = el.value"
                )],
                false
            )
            .is_ok()
        );
        assert!(tag_name("example.panel").is_err());
    }

    #[test]
    fn custom_forms_require_exact_typed_controls_and_reject_nested_forms() -> Result<()> {
        let mut command = node("command", "");
        command["operation"] = json!("links.create");
        command["bound"] = json!("{}");
        command["fields"] = json!([{"name":"title","label":""}]);
        let mut field = node("field", "title");
        field["variant"] = json!("input");
        field["attrs"] = json!([{"name":"class","value":"custom-input"}]);
        assert_eq!(
            nodes(&json!([command.clone(), field.clone(), node("close", "")]))?.len(),
            3
        );
        assert!(nodes(&json!([command.clone(), node("close", "")])).is_err());
        assert!(
            nodes(&json!([
                command.clone(),
                field.clone(),
                field.clone(),
                node("close", "")
            ]))
            .is_err()
        );
        assert!(nodes(&json!([field])).is_err());
        assert!(
            nodes(&json!([
                command.clone(),
                node("signout", ""),
                node("close", ""),
                node("close", "")
            ]))
            .is_err()
        );
        let mut untyped = node("void", "input");
        untyped["attrs"] = json!([{"name":"name","value":"title"}]);
        assert!(nodes(&json!([command, untyped, node("close", "")])).is_err());
        assert!(attributes("input", &[attribute("name", "_csrf")], true).is_err());
        assert!(
            attributes(
                "form",
                &[attribute("data-on:submit__prevent", "arbitrary()")],
                true
            )
            .is_err()
        );
        Ok(())
    }
}
