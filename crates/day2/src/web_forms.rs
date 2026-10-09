use crate::{
    schema::{Kind, Record},
    web_html::View,
    web_security::{self as security, Ticket},
};
use anyhow::{Context, Result, ensure};
use ego_tree::NodeId;
use html5ever::QualName;
use maud::{Markup, PreEscaped};
use scraper::{ElementRef, Html, Node, Selector, node::Element};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("static selector")
}

fn set_attr(document: &mut Html, id: NodeId, name: &str, value: &str) -> Result<()> {
    let mut node = document.tree.get_mut(id).context("form node missing")?;
    let Node::Element(element) = node.value() else {
        anyhow::bail!("expected form element");
    };
    element.attrs.retain(|(key, _)| key.local.as_ref() != name);
    element
        .attrs
        .push((QualName::new(None, "".into(), name.into()), value.into()));
    element
        .attrs
        .sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(())
}

fn remove_attr(document: &mut Html, id: NodeId, name: &str) -> Result<()> {
    let mut node = document.tree.get_mut(id).context("form node missing")?;
    let Node::Element(element) = node.value() else {
        anyhow::bail!("expected form element");
    };
    element.attrs.retain(|(key, _)| key.local.as_ref() != name);
    Ok(())
}

fn hidden(document: &mut Html, form: NodeId, name: &str, value: &str) -> Result<()> {
    let node = Node::Element(Element::new(
        QualName::new(None, "http://www.w3.org/1999/xhtml".into(), "input".into()),
        vec![],
    ));
    let id = document
        .tree
        .get_mut(form)
        .context("form missing")?
        .prepend(node)
        .id();
    for (key, content) in [("type", "hidden"), ("name", name), ("value", value)] {
        set_attr(document, id, key, content)?;
    }
    Ok(())
}

pub(crate) struct Control {
    pub(crate) id: NodeId,
    pub(crate) name: String,
    pub(crate) tag: String,
    pub(crate) hidden: bool,
    pub(crate) value: String,
}

/// A field may repeat only when the operation declares it a list of text. A list
/// of records needs indexed naming, which this protocol does not define, so it
/// stays unsupported rather than being approximated.
pub(crate) fn scalar_list(kind: &crate::schema::Kind) -> bool {
    use crate::output_schema::Type;
    matches!(
        kind,
        crate::schema::Kind::InputShape { shape: Type::List(inner), .. }
            if matches!(**inner, Type::String | Type::StandardText { .. })
    )
}

/// One control carrying an empty value represents the empty collection. A blank
/// item is never a legitimate member, so this cannot collide with a real value and
/// absence never has to mean anything.
pub(crate) fn empty_list(values: &[&str]) -> bool {
    values.len() == 1 && values[0].is_empty()
}

/// How a declared field is carried by form controls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Carrier {
    /// One control, one value.
    Scalar,
    /// Repeated controls sharing the field name; document order is list order.
    List,
    /// Controls named `field.key`; the key lives in the control name, so no index
    /// grammar is needed and a missing pair cannot be represented.
    Map,
    /// Repeated controls sharing the field name, decoded to a canonical set.
    Set,
}

pub(crate) fn carrier(kind: &crate::schema::Kind) -> Carrier {
    use crate::output_schema::Type;
    match kind {
        crate::schema::Kind::InputShape { shape, .. } => match shape {
            Type::List(inner) if matches!(**inner, Type::String | Type::StandardText { .. }) => {
                Carrier::List
            }
            Type::Map(_) => Carrier::Map,
            Type::Set => Carrier::Set,
            _ => Carrier::Scalar,
        },
        _ => Carrier::Scalar,
    }
}

/// Split a control name into the declared field and, for a map, its key. The key
/// is part of the name so that one control always carries one complete entry.
pub(crate) fn split_control(name: &str) -> (&str, Option<&str>) {
    match name.split_once('.') {
        Some((field, key)) => (field, Some(key)),
        None => (name, None),
    }
}

pub(crate) fn controls(form: ElementRef<'_>) -> Result<Vec<Control>> {
    let mut controls = Vec::new();
    let mut names = BTreeSet::new();
    for element in form.descendants().filter_map(ElementRef::wrap) {
        let value = element.value();
        ensure!(
            value.attr("form").is_none(),
            "external_form_association_forbidden"
        );
        ensure!(
            ["formaction", "formmethod", "formenctype", "formtarget"]
                .iter()
                .all(|name| value.attr(name).is_none()),
            "submitter_transport_override_forbidden"
        );
        if value.name() == "fieldset" {
            ensure!(
                value.attr("disabled").is_none(),
                "disabled_form_fields_unsupported"
            );
        }
        let Some(name) = value.attr("name") else {
            continue;
        };
        // Repetition is a property of the declared field kind, not of the parser:
        // only a field the operation declares as a scalar list may appear twice.
        // Schema-aware callers enforce that; here we only bound the control count.
        names.insert(name.to_string());
        ensure!(
            ["input", "textarea", "select"].contains(&value.name())
                && !name.starts_with('_')
                && controls.len() < 32,
            "invalid_or_duplicate_form_field"
        );
        ensure!(
            value.attr("disabled").is_none() && value.attr("multiple").is_none(),
            "omitted_or_multiple_form_fields_unsupported"
        );
        let kind = value.attr("type").unwrap_or("text").to_ascii_lowercase();
        if value.name() == "input" {
            ensure!(
                [
                    "text",
                    "url",
                    "email",
                    "search",
                    "tel",
                    "password",
                    "number",
                    "range",
                    "date",
                    "time",
                    "datetime-local",
                    "month",
                    "week",
                    "color",
                    "hidden"
                ]
                .contains(&kind.as_str()),
                "form_field_mode_unsupported: use scalar controls or select"
            );
        }
        controls.push(Control {
            id: element.id(),
            name: name.into(),
            tag: value.name().into(),
            hidden: value.name() == "input" && kind == "hidden",
            value: value.attr("value").unwrap_or("").into(),
        });
    }
    Ok(controls)
}

fn restore(document: &mut Html, control: &Control, value: &str) -> Result<()> {
    match control.tag.as_str() {
        "input" => set_attr(document, control.id, "value", value)?,
        "textarea" => {
            let children: Vec<_> = document
                .tree
                .get(control.id)
                .context("textarea")?
                .children()
                .map(|node| node.id())
                .collect();
            for child in children {
                document
                    .tree
                    .get_mut(child)
                    .context("textarea child")?
                    .detach();
            }
            document
                .tree
                .get_mut(control.id)
                .context("textarea")?
                .append(Node::Text(scraper::node::Text { text: value.into() }));
        }
        "select" => {
            let options: Vec<_> = document
                .tree
                .get(control.id)
                .context("select")?
                .descendants()
                .filter_map(ElementRef::wrap)
                .filter(|element| element.value().name() == "option")
                .map(|element| {
                    (
                        element.id(),
                        element
                            .value()
                            .attr("value")
                            .map(str::to_owned)
                            .unwrap_or_else(|| element.text().collect()),
                    )
                })
                .collect();
            for (id, option) in options {
                remove_attr(document, id, "selected")?;
                if option == value {
                    set_attr(document, id, "selected", "")?;
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Bind concrete, validated HTML to the same durable command protocol as legacy
/// Roc views. No business operation or visual markup is inferred from field names.
pub(crate) fn bind(view: &View<'_>, markup: &str) -> Result<Markup> {
    ensure!(markup.len() <= 524_288, "rendered_html_budget");
    let mut document = Html::parse_fragment(markup);
    ensure!(
        document.errors.is_empty(),
        "invalid_rendered_html: {:?}",
        document.errors
    );
    let forms: Vec<_> = document
        .select(&selector("form"))
        .map(|form| form.id())
        .collect();
    ensure!(forms.len() <= 128, "rendered_form_budget");
    for form_id in forms {
        let form = ElementRef::wrap(document.tree.get(form_id).context("form missing")?)
            .context("form element")?;
        let operation = form.value().attr("data-command").map(str::to_owned);
        let live_form_id = view
            .runtime
            .artifact()
            .page(view.page)?
            .live
            .then(|| form.value().attr("id").map(str::to_owned))
            .flatten();
        if operation.is_some() && view.runtime.artifact().page(view.page)?.live {
            let id = live_form_id
                .as_deref()
                .context("live_command_form_requires_id")?;
            ensure!(
                document
                    .select(&selector("[id]"))
                    .filter(|element| element.value().attr("id") == Some(id))
                    .count()
                    == 1,
                "live_command_form_id_must_be_unique"
            );
        }
        let sign_out = form.value().attr("data-platform") == Some("sign-out");
        ensure!(
            operation.is_some() != sign_out,
            "form_requires_one_platform_binding"
        );
        for (name, _) in form.value().attrs() {
            ensure!(
                !["action", "method", "enctype", "target"].contains(&name)
                    && !name.starts_with("data-on:submit")
                    && !name.starts_with("data-day2-")
                    && !name.starts_with("data-attr:action")
                    && !name.starts_with("data-attr:method"),
                "reserved_form_transport_attribute"
            );
        }
        let controls = controls(form)?;
        if sign_out {
            ensure!(controls.is_empty(), "sign_out_fields_forbidden");
            set_attr(&mut document, form_id, "method", "post")?;
            set_attr(&mut document, form_id, "action", "/logout")?;
            hidden(
                &mut document,
                form_id,
                "_csrf",
                &security::csrf(view.secret, view.session)?,
            )?;
            continue;
        }
        let operation = operation.context("command binding")?;
        let definition = view.runtime.artifact().operation(&operation)?;
        ensure!(definition.kind == "command", "form_requires_command");
        let record = &view.runtime.artifact().contract().schema.inputs[&definition.input_type];
        // A control may name a map key, so completeness is checked on the declared
        // field rather than the raw control name.
        let names: BTreeSet<_> = controls
            .iter()
            .map(|control| split_control(&control.name).0)
            .collect();
        ensure!(
            names == record.fields.keys().map(String::as_str).collect(),
            "incomplete_or_unknown_form_binding"
        );
        let mut bound = Map::new();
        let mut editable = Vec::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut keys: BTreeSet<(&str, &str)> = BTreeSet::new();
        for control in &controls {
            let (field, key) = split_control(&control.name);
            let kind = &record.fields[field];
            let carried = carrier(kind);
            let first = seen.insert(field);
            // Only a declared collection may contribute more than one control, and a
            // map's controls are distinguished by the key in their names.
            match carried {
                Carrier::Scalar => ensure!(first, "invalid_or_duplicate_form_field"),
                Carrier::Map => {
                    let key = key.context("map_form_field_requires_key")?;
                    day2_contracts::names::identifier(key)?;
                    ensure!(keys.insert((field, key)), "invalid_or_duplicate_form_field");
                }
                Carrier::List | Carrier::Set => {}
            }
            ensure!(
                carried == Carrier::Map || key.is_none(),
                "unexpected_form_field_key"
            );
            ensure!(
                !matches!(kind, Kind::OptionalText)
                    && (!matches!(kind, Kind::InputShape { .. }) || carried != Carrier::Scalar),
                "optional_or_structured_form_field_unsupported"
            );
            ensure!(
                carried == Carrier::Scalar || !control.hidden,
                "hidden_collection_form_field_unsupported"
            );
            if control.hidden {
                let value = security::field_value(kind, &control.value)?;
                Record {
                    fields: BTreeMap::from([(control.name.clone(), kind.clone())]),
                    roc_type: None,
                    identity: None,
                }
                .validate_input(&serde_json::json!({ &control.name: &value }))?;
                bound.insert(control.name.clone(), value);
            } else if first {
                // One entry per declared field, not per control: the ticket names
                // editable fields, and a collection is one field however many
                // controls carry it.
                editable.push(field.to_owned());
            }
        }
        if view
            .runtime
            .authorize(&operation, &view.session.actor)
            .is_err()
        {
            document.tree.get_mut(form_id).context("form")?.detach();
            continue;
        }
        let nonce = security::random()?;
        let ticket = Ticket {
            scope: view.runtime.scope().to_owned(),
            artifact: view.runtime.artifact().id().to_owned(),
            session: view.session.hash.clone(),
            actor: view.session.actor.clone(),
            page: view.page.into(),
            page_input: view.input.clone(),
            operation: operation.clone(),
            form_id: live_form_id,
            bound: Value::Object(bound),
            editable,
            nonce: nonce.clone(),
            issued: view.now,
            expires: (view.now + 1800).min(view.session.expires),
        };
        for control in &controls {
            if let Some(Kind::StandardText { domain }) = record.fields.get(&control.name) {
                let rules = &view
                    .runtime
                    .artifact()
                    .contract()
                    .app_contract
                    .as_ref()
                    .context("application domain contract required")?
                    .domains[domain];
                remove_attr(&mut document, control.id, "maxlength")?;
                remove_attr(&mut document, control.id, "minlength")?;
                remove_attr(&mut document, control.id, "required")?;
                set_attr(
                    &mut document,
                    control.id,
                    "data-day2-max-utf8-bytes",
                    &rules.maximum_bytes.to_string(),
                )?;
                if rules.nonblank {
                    set_attr(&mut document, control.id, "required", "")?;
                    set_attr(&mut document, control.id, "data-day2-nonblank", "true")?;
                }
            }
            if control.hidden {
                document
                    .tree
                    .get_mut(control.id)
                    .context("bound input")?
                    .detach();
            } else if let Some(value) = view
                .submitted
                .and_then(|submitted| submitted.value(&operation, &ticket.bound, &control.name))
            {
                restore(&mut document, control, value)?;
            }
        }
        for (name, value) in [
            ("method", "post"),
            ("action", "/actions"),
            (
                "data-on:submit__prevent",
                "@post(el.action, {contentType:'form', retry:'never'})",
            ),
            ("data-day2-invocation", &format!("web-{nonce}")),
        ] {
            set_attr(&mut document, form_id, name, value)?;
        }
        hidden(
            &mut document,
            form_id,
            "_ticket",
            &security::sign(view.secret, &serde_json::to_vec(&ticket)?)?,
        )?;
        hidden(
            &mut document,
            form_id,
            "_csrf",
            &security::csrf(view.secret, view.session)?,
        )?;
    }
    if view.runtime.artifact().contract().format >= 7 {
        crate::web_templates::validate_fragments(&document)?;
    }
    Ok(PreEscaped(document.root_element().inner_html()))
}
