use crate::{
    digest,
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;

pub(crate) fn random() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("entropy_unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(crate) fn secret(runtime: &Runtime) -> Result<Vec<u8>> {
    let db = open(runtime.db())?;
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("entropy_unavailable"))?;
    db.execute(
        "INSERT OR IGNORE INTO day2_web_secret VALUES(1,?1)",
        [&bytes[..]],
    )?;
    let secret: Vec<u8> =
        db.query_row("SELECT secret FROM day2_web_secret WHERE id=1", [], |row| {
            row.get(0)
        })?;
    ensure!(secret.len() == 32, "invalid_host_secret");
    Ok(secret)
}
#[derive(Clone)]
pub(crate) struct Session {
    pub hash: String,
    pub actor: String,
    pub expires: i64,
}
pub(crate) fn session(
    runtime: &Runtime,
    headers: &HeaderMap,
    cookie_name: &str,
    now: i64,
) -> Result<Session> {
    let mut token = None;
    for value in headers.get_all("cookie") {
        for cookie in cookie::Cookie::split_parse(value.to_str()?) {
            let cookie = cookie?;
            if cookie.name() == cookie_name {
                ensure!(token.is_none(), "ambiguous_session");
                token = Some(cookie.value().to_string());
            }
        }
    }
    session_for_token(
        runtime,
        &token.context(crate::error::Failure::SignInRequired)?,
        now,
    )
}
/// The live session a token names.
pub(crate) fn session_for_token(runtime: &Runtime, token: &str, now: i64) -> Result<Session> {
    ensure!(token.len() == 43, crate::error::Failure::SignInRequired);
    let hash = digest(token.as_bytes());
    let db = open(runtime.db())?;
    runtime.check_binding(&db)?;
    let session = db
        .query_row(
            "SELECT actor,expires FROM day2_web_sessions WHERE hash=?1",
            [&hash],
            |row| {
                Ok(Session {
                    hash: hash.clone(),
                    actor: row.get(0)?,
                    expires: row.get(1)?,
                })
            },
        )
        .optional()?
        .context(crate::error::Failure::SignInRequired)?;
    ensure!(now < session.expires, crate::error::Failure::SignInRequired);
    Ok(session)
}
pub(crate) fn create_session(runtime: &Runtime, actor: &str, now: i64) -> Result<String> {
    let token = random()?;
    let db = open(runtime.db())?;
    db.execute("DELETE FROM day2_web_sessions WHERE expires<=?1", [now])?;
    db.execute(
        "INSERT INTO day2_web_sessions VALUES(?1,?2,?3)",
        params![digest(token.as_bytes()), actor, now + 28_800],
    )?;
    Ok(token)
}
pub(crate) fn sign(secret: &[u8], value: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(value);
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(value),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}
pub(crate) fn verify(secret: &[u8], raw: &str) -> Result<Vec<u8>> {
    ensure!(raw.len() <= 48_000, crate::error::Failure::InvalidTicket);
    let (value, signature) = raw
        .split_once('.')
        .context(crate::error::Failure::InvalidTicket)?;
    let value = URL_SAFE_NO_PAD.decode(value)?;
    let signature = URL_SAFE_NO_PAD.decode(signature)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(&value);
    mac.verify_slice(&signature)
        .map_err(|_| anyhow::anyhow!(crate::error::Failure::InvalidTicket))?;
    Ok(value)
}
pub(crate) fn csrf(secret: &[u8], session: &Session) -> Result<String> {
    sign(secret, format!("csrf:{}", session.hash).as_bytes())
}
pub(crate) fn verify_csrf(secret: &[u8], session: &Session, raw: &str) -> Result<()> {
    ensure!(
        verify(secret, raw)? == format!("csrf:{}", session.hash).as_bytes(),
        crate::error::Failure::InvalidCsrf
    );
    Ok(())
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    pub scope: String,
    pub artifact: String,
    pub session: String,
    pub actor: String,
    pub page: String,
    pub page_input: Value,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_id: Option<String>,
    pub bound: Value,
    pub editable: Vec<String>,
    pub nonce: String,
    pub issued: i64,
    pub expires: i64,
}
impl Ticket {
    pub fn verify(&self, runtime: &Runtime, session: &Session, now: i64) -> Result<()> {
        ensure!(
            self.scope == runtime.scope()
                && self.artifact == runtime.artifact().id()
                && self.session == session.hash
                && self.actor == session.actor,
            crate::error::Failure::TicketScopeMismatch
        );
        ensure!(
            self.issued <= now
                && now < self.expires
                && self.expires <= self.issued + 1800
                && self.expires <= session.expires,
            crate::error::Failure::TicketExpired
        );
        ensure!(
            self.nonce.len() == 43
                && self
                    .nonce
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            crate::error::Failure::InvalidTicket
        );
        runtime.authorize(&self.operation, &session.actor)?;
        ensure!(
            runtime.artifact().operation(&self.operation)?.kind == "command",
            "not_a_command"
        );
        let page = runtime.artifact().page(&self.page)?;
        runtime.authorize(&page.operation, &session.actor)?;
        Ok(())
    }
}

// Parsing stays lossless: browser numeric values never pass through JavaScript
// numbers. Duplicates, malformed UTF-8 and unknown fields are rejected.
pub(crate) fn fields(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    ensure!(
        raw.len() <= 65_536 && std::str::from_utf8(raw).is_ok(),
        crate::error::Failure::InvalidForm
    );
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw) {
        ensure!(
            !key.contains('\u{fffd}') && !value.contains('\u{fffd}'),
            crate::error::Failure::InvalidFormEncoding
        );
        ensure!(
            key.len() <= 64
                && fields.len() < 36
                && fields
                    .insert(key.into_owned(), value.into_owned())
                    .is_none(),
            crate::error::Failure::DuplicateOrExcessFields
        );
    }
    Ok(fields)
}
/// Extract one control field ahead of knowing the operation's declared shape.
/// The value must occur exactly once, so the CSRF token and signed ticket keep
/// their single-value guarantee even though app fields in the same body may repeat.
pub(crate) fn single_field(raw: &[u8], name: &str) -> Result<String> {
    ensure!(
        raw.len() <= 65_536 && std::str::from_utf8(raw).is_ok(),
        crate::error::Failure::InvalidForm
    );
    let mut found = None;
    for (key, value) in url::form_urlencoded::parse(raw) {
        if key != name {
            continue;
        }
        ensure!(
            !value.contains('\u{fffd}') && found.is_none(),
            crate::error::Failure::DuplicateOrExcessFields
        );
        found = Some(value.into_owned());
    }
    found.context(crate::error::Failure::InvalidForm)
}

/// Form bodies where named fields may repeat. Repetition is authorized per field
/// by the caller from the operation's declared input record, so `_csrf`, `_ticket`
/// and every non-list field keep the single-value guarantee that makes parameter
/// pollution unrepresentable rather than merely rejected downstream.
pub(crate) fn list_fields(
    raw: &[u8],
    repeatable: &std::collections::BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    ensure!(
        raw.len() <= 65_536 && std::str::from_utf8(raw).is_ok(),
        crate::error::Failure::InvalidForm
    );
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw) {
        ensure!(
            !key.contains('\u{fffd}') && !value.contains('\u{fffd}'),
            crate::error::Failure::InvalidFormEncoding
        );
        let key = key.into_owned();
        let known = fields.contains_key(&key);
        ensure!(
            key.len() <= 64
                && (known || fields.len() < 36)
                && (!known || repeatable.contains(&key)),
            crate::error::Failure::DuplicateOrExcessFields
        );
        let values = fields.entry(key).or_default();
        ensure!(
            values.len() < 64,
            crate::error::Failure::DuplicateOrExcessFields
        );
        values.push(value.into_owned());
    }
    Ok(fields)
}

/// Decode one field from its submitted occurrences. A declared scalar list takes
/// document order as list order, so permuting controls yields a different value
/// rather than being normalised away. Exactly one empty occurrence is the empty
/// list; a blank among several is rejected rather than silently dropped.
/// Decode a map field from its `field.key` controls. The key travels in the control
/// name, so one control always carries one complete entry and a half-populated pair
/// cannot be expressed. Entries are emitted in canonical key order because the
/// contract admits exactly one encoding per map.
pub(crate) fn map_values(entries: &BTreeMap<String, Vec<String>>) -> Result<Value> {
    let mut items: Vec<Value> = Vec::with_capacity(entries.len());
    for (key, values) in entries {
        ensure!(
            values.len() == 1,
            crate::error::Failure::DuplicateOrExcessFields
        );
        ensure!(!key.trim().is_empty(), crate::error::Failure::InvalidForm);
        ensure!(
            !values[0].trim().is_empty(),
            crate::error::Failure::InvalidForm
        );
        items.push(serde_json::json!({ "key": key, "value": values[0] }));
    }
    Ok(serde_json::json!({ "entries": items }))
}

/// Decode a set field from its repeated controls. Duplicates are refused rather
/// than collapsed, and members are emitted in canonical order.
pub(crate) fn set_values(raw: &[String]) -> Result<Value> {
    let borrowed: Vec<&str> = raw.iter().map(String::as_str).collect();
    if crate::web_forms::empty_list(&borrowed) {
        return Ok(serde_json::json!({ "members": Vec::<Value>::new() }));
    }
    let mut members: Vec<&str> = Vec::with_capacity(raw.len());
    for value in &borrowed {
        ensure!(!value.trim().is_empty(), crate::error::Failure::InvalidForm);
        ensure!(
            !members.contains(value),
            crate::error::Failure::DuplicateOrExcessFields
        );
        members.push(value);
    }
    members.sort_unstable();
    Ok(serde_json::json!({ "members": members }))
}

pub(crate) fn field_values(kind: &crate::schema::Kind, raw: &[String]) -> Result<Value> {
    if crate::web_forms::carrier(kind) == crate::web_forms::Carrier::Set {
        return set_values(raw);
    }
    if !crate::web_forms::scalar_list(kind) {
        ensure!(
            raw.len() == 1,
            crate::error::Failure::DuplicateOrExcessFields
        );
        return field_value(kind, &raw[0]);
    }
    let borrowed: Vec<&str> = raw.iter().map(String::as_str).collect();
    if crate::web_forms::empty_list(&borrowed) {
        return Ok(Value::Array(Vec::new()));
    }
    let mut items = Vec::with_capacity(raw.len());
    for value in raw {
        ensure!(!value.trim().is_empty(), crate::error::Failure::InvalidForm);
        ensure!(
            !items.contains(&Value::String(value.clone())),
            crate::error::Failure::DuplicateOrExcessFields
        );
        items.push(Value::String(value.clone()));
    }
    Ok(Value::Array(items))
}

pub(crate) fn field_value(kind: &crate::schema::Kind, raw: &str) -> Result<Value> {
    use crate::schema::Kind;
    Ok(match kind {
        Kind::Integer | Kind::PageSize | Kind::RowVersion => {
            let integer: i64 = raw.parse().context(crate::error::Failure::InvalidInteger)?;
            ensure!(
                integer.to_string() == raw,
                crate::error::Failure::InvalidInteger
            );
            Value::from(integer)
        }
        Kind::Unsigned(unsigned) => {
            let integer: u64 = raw.parse().context("invalid_unsigned_integer")?;
            let value = Value::from(integer);
            ensure!(
                integer.to_string() == raw && unsigned.valid(&value),
                "invalid_unsigned_integer"
            );
            value
        }
        Kind::Boolean => match raw {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => anyhow::bail!("invalid_boolean"),
        },
        Kind::OptionalText => anyhow::bail!("optional_form_field_not_supported"),
        Kind::InputShape { .. } => anyhow::bail!("structured_form_field_not_supported"),
        _ => Value::String(raw.into()),
    })
}

#[cfg(test)]
mod numeric_tests {
    use super::*;
    use crate::{
        numeric::Unsigned,
        schema::{Kind, Record},
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn url_and_form_integers_preserve_unsigned_precision_and_enforce_domains() -> Result<()> {
        let kind = Kind::Unsigned(Unsigned::U64);
        assert_eq!(field_value(&kind, "18446744073709551615")?, json!(u64::MAX));
        for raw in ["-1", "18446744073709551616", "1.5", "+1", "01", "1e2"] {
            assert!(field_value(&kind, raw).is_err(), "{raw}");
        }
        assert!(field_value(&Kind::Unsigned(Unsigned::U8), "256").is_err());
        let record = Record {
            fields: BTreeMap::from([("revision".into(), Kind::RowVersion)]),
            roc_type: None,
            identity: None,
        };
        for raw in ["-1", "0"] {
            let value = field_value(&Kind::RowVersion, raw)?;
            assert!(record.validate_input(&json!({"revision":value})).is_err());
        }
        record.validate_input(&json!({"revision":field_value(&Kind::RowVersion,"1")?}))?;
        Ok(())
    }
}
