//! Company-approved limits over compiled app contracts, independent of Roc handlers.

use crate::{
    artifact::Operation,
    protocol::Row,
    schema::{Kind, Schema},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub admins: BTreeSet<String>,
    pub operations: BTreeMap<String, OperationPolicy>,
    #[serde(default)]
    pub constraints: BTreeMap<String, BTreeMap<String, TextConstraint>>,
    /// Who may act on behalf of whom. Absent means nobody, which is where every
    /// application starts and where most of them should stay.
    #[serde(default)]
    pub delegations: BTreeMap<String, DelegationRule>,
}

/// One operator-approved way for a principal to act as another.
///
/// This is an admission decision, not a capability: it settles *whose* request
/// this is before any operation is authorized. The operation's own policy then
/// decides what that principal may do, against the effective principal and not
/// the one that authenticated. Two gates, and both must pass — so a service or
/// an administrator acting for someone reaches exactly what that person could
/// reach unaided, and nothing more.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationRule {
    /// The principals this rule is about: the ones doing the acting.
    pub authenticated: BTreeSet<String>,
    pub may_act_as: ActAs,
    /// The authentication paths that may exercise it, as recorded on the
    /// invocation. A session cookie must not be able to use a rule written for
    /// a verified gateway assertion.
    pub paths: BTreeSet<String>,
}

/// Whom a rule permits acting as.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActAs {
    /// Anyone outside the app:/svc: service namespaces who is not an operator
    /// of this installation or an administrator of this application.
    ///
    /// The exclusion is the shape rather than a flag, because "may act as
    /// anyone" and "may not act as an operator" are the same rule: an
    /// impersonation that could reach an operator could reach the authority to
    /// widen itself, and a chain through one is ambiguous about who decided.
    AnyHuman,
    /// Exactly these principals, named.
    Actors { actors: BTreeSet<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationPolicy {
    pub actors: BTreeSet<String>,
    pub mode: Mode,
    pub models: BTreeMap<String, ModelGrant>,
    #[serde(default)]
    pub commands: BTreeSet<String>,
    #[serde(default)]
    pub observations: BTreeSet<String>,
    #[serde(default)]
    pub effects: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mode {
    Read,
    CurrentState,
    Edit {
        model: String,
        id_field: String,
        version_field: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelGrant {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub update_fields: BTreeSet<String>,
    pub rows: Rows,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rows {
    All,
    OwnerOrAdmin { field: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextConstraint {
    pub nonempty: bool,
    pub max_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowFilter {
    All,
    Owner { field: String, actor: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditTarget {
    pub model: String,
    pub id: crate::identity::Id,
    pub version: i64,
}

pub struct Change<'a> {
    pub id: crate::identity::Id,
    pub before: &'a Value,
    pub after: &'a Value,
}

impl Policy {
    fn owned_fields(&self) -> Result<BTreeMap<&str, &str>> {
        let mut fields = BTreeMap::new();
        for operation in self.operations.values() {
            for (model, grant) in &operation.models {
                if let Rows::OwnerOrAdmin { field } = &grant.rows
                    && let Some(previous) = fields.insert(model.as_str(), field.as_str())
                {
                    ensure!(
                        previous == field,
                        "authority model has conflicting owner fields: {model}"
                    );
                }
            }
        }
        Ok(fields)
    }

    pub fn validate(&self, operations: &[Operation], schema: &Schema) -> Result<()> {
        ensure!(self.version == 1, "unsupported authority policy version");
        let owned_fields = self.owned_fields()?;
        ensure!(
            self.operations.len() == operations.len(),
            "authority policy must explicitly cover every operation"
        );
        for actor in &self.admins {
            valid_actor(actor)?;
        }
        // Delegation rules name the principals on both sides of an impersonation;
        // a domain cannot authenticate, and "act as anyone at a domain" is what
        // `any_human` already says, with its exclusions.
        for rule in self.delegations.values() {
            for actor in &rule.authenticated {
                valid_actor(actor)?;
            }
            if let ActAs::Actors { actors } = &rule.may_act_as {
                for actor in actors {
                    valid_actor(actor)?;
                }
            }
        }
        for (name, policy) in &self.operations {
            let operation = operations
                .iter()
                .find(|operation| operation.name == *name)
                .with_context(|| format!("authority policy unknown operation: {name}"))?;
            for actor in &policy.actors {
                entry_domain(actor)?;
            }
            ensure!(
                matches!(
                    (&policy.mode, operation.kind.as_str()),
                    (Mode::Read, "query") | (Mode::CurrentState | Mode::Edit { .. }, "command")
                ),
                "authority policy operation mode mismatch: {name}"
            );
            ensure!(
                operation.kind == "command" || policy.commands.is_empty(),
                "queries cannot request commands"
            );
            for target in &policy.commands {
                ensure!(
                    operations
                        .iter()
                        .any(|operation| operation.kind == "command" && operation.name == *target),
                    "unknown requested command"
                );
            }
            ensure!(
                policy
                    .observations
                    .iter()
                    .all(|name| crate::capabilities::observation(name)),
                "unknown observation grant"
            );
            ensure!(
                (operation.kind == "command" || policy.effects.is_empty())
                    && policy
                        .effects
                        .iter()
                        .all(|name| crate::capabilities::WRITES.contains(&name.as_str())),
                "invalid external effect grant"
            );
            for (model, grant) in &policy.models {
                let record = schema
                    .models
                    .get(model)
                    .with_context(|| format!("authority policy unknown model: {name}/{model}"))?;
                ensure!(
                    !matches!(policy.mode, Mode::Read)
                        || (!grant.create && grant.update_fields.is_empty()),
                    "authority query cannot grant writes: {name}/{model}"
                );
                ensure!(
                    grant.read || (!grant.create && grant.update_fields.is_empty()),
                    "authority mutations return full rows and require read permission: {name}/{model}"
                );
                for field in &grant.update_fields {
                    ensure!(
                        record.fields.contains_key(field),
                        "authority policy unknown update field: {name}/{model}/{field}"
                    );
                }
                if let Rows::OwnerOrAdmin { field } = &grant.rows {
                    ensure!(
                        matches!(
                            record.fields.get(field),
                            Some(Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. })
                        ),
                        "authority owner field must be text: {name}/{model}/{field}"
                    );
                }
                if let Some(field) = owned_fields.get(model.as_str()) {
                    ensure!(
                        !grant.update_fields.contains(*field),
                        "authority owner field is immutable across all grants: {name}/{model}/{field}"
                    );
                }
                if let Mode::Edit { model: target, .. } = &policy.mode {
                    ensure!(
                        !grant.create && (grant.update_fields.is_empty() || model == target),
                        "authority edit may update only its target model: {name}/{model}"
                    );
                }
            }
            if let Mode::Edit {
                model,
                id_field,
                version_field,
            } = &policy.mode
            {
                let input = schema
                    .inputs
                    .get(&operation.input_type)
                    .with_context(|| format!("authority policy unknown operation input: {name}"))?;
                ensure!(
                    matches!(input.fields.get(id_field), Some(Kind::Reference { target } | Kind::ModelReference { target, .. }) if target == model),
                    "authority edit id must reference its target model: {name}/{id_field}"
                );
                ensure!(
                    matches!(
                        input.fields.get(version_field),
                        Some(Kind::Integer | Kind::RowVersion)
                    ),
                    "authority edit version must be I64: {name}/{version_field}"
                );
                ensure!(
                    policy
                        .models
                        .get(model)
                        .is_some_and(|grant| !grant.update_fields.is_empty()),
                    "authority edit requires target update fields: {name}/{model}"
                );
            }
        }
        for (model, constraints) in &self.constraints {
            let record = schema
                .models
                .get(model)
                .with_context(|| format!("authority constraints unknown model: {model}"))?;
            for (field, constraint) in constraints {
                ensure!(
                    matches!(
                        record.fields.get(field),
                        Some(Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. })
                    ),
                    "authority text constraint requires text field: {model}/{field}"
                );
                ensure!(
                    (1..=16_384).contains(&constraint.max_bytes),
                    "authority text constraint byte budget: {model}/{field}"
                );
            }
        }
        for (model, record) in &schema.models {
            for (field, kind) in &record.fields {
                ensure!(
                    !matches!(kind, Kind::TextDomain { .. })
                        || self
                            .constraints
                            .get(model)
                            .is_some_and(|fields| fields.contains_key(field)),
                    "authority nominal text requires an explicit host constraint: {model}/{field}"
                );
            }
        }
        Ok(())
    }

    /// Confine this policy's `domain:` operation actors to the domain the
    /// installation's edge verifies; see [`valid_entry`]. Separate from
    /// [`Policy::validate`] because the hosted domain belongs to the
    /// installation, not to the policy or the artifact.
    pub fn validate_domains(&self, hosted_domain: Option<&str>) -> Result<()> {
        for policy in self.operations.values() {
            for entry in policy
                .actors
                .iter()
                .filter(|actor| actor.starts_with(DOMAIN_PREFIX))
            {
                valid_entry(entry, hosted_domain)?;
            }
        }
        Ok(())
    }

    /// Which rule, if any, lets `authenticated` act as `effective` by `path`.
    ///
    /// Returns the rule's name, which is what the invocation records: an
    /// impersonation whose permitting rule was later removed still says which
    /// rule permitted it at the time.
    pub fn may_act_as(
        &self,
        authenticated: &str,
        effective: &str,
        path: &str,
        operators: &BTreeSet<String>,
    ) -> Result<String> {
        // Acting as yourself is not delegation and needs no rule.
        ensure!(authenticated != effective, "delegation_rule_not_needed");
        let named = self
            .delegations
            .iter()
            .find(|(_, rule)| {
                rule.authenticated.contains(authenticated)
                    && rule.paths.contains(path)
                    && match &rule.may_act_as {
                        ActAs::Actors { actors } => actors.contains(effective),
                        ActAs::AnyHuman => {
                            !self.admins.contains(effective)
                                && !operators.contains(effective)
                                && !effective.starts_with("app:")
                                && !effective.starts_with("svc:")
                                && !effective.starts_with("client/")
                                && !effective.starts_with("credential_client:")
                                && !effective.starts_with(DOMAIN_PREFIX)
                        }
                    }
            })
            .map(|(name, _)| name.clone());
        named.context(crate::error::Failure::Forbidden)
    }

    pub fn authorize(&self, operation: &str, actor: &str) -> Result<()> {
        ensure!(
            self.operations
                .get(operation)
                .is_some_and(|policy| admits(&policy.actors, actor)),
            crate::error::Failure::Forbidden
        );
        Ok(())
    }

    fn grant(&self, operation: &str, model: &str, actor: &str) -> Result<&ModelGrant> {
        self.authorize(operation, actor)?;
        self.operations[operation]
            .models
            .get(model)
            .context(crate::error::Failure::Forbidden)
    }

    /// Apply this predicate before pagination, not by filtering an already selected page.
    pub fn read_scope(&self, operation: &str, model: &str, actor: &str) -> Result<RowFilter> {
        let grant = self.grant(operation, model, actor)?;
        ensure!(grant.read, crate::error::Failure::Forbidden);
        Ok(match &grant.rows {
            Rows::All => RowFilter::All,
            Rows::OwnerOrAdmin { .. } if self.admins.contains(actor) => RowFilter::All,
            Rows::OwnerOrAdmin { field } => RowFilter::Owner {
                field: field.clone(),
                actor: actor.to_string(),
            },
        })
    }

    pub fn check_read(
        &self,
        operation: &str,
        model: &str,
        actor: &str,
        value: &Value,
    ) -> Result<()> {
        let grant = self.grant(operation, model, actor)?;
        ensure!(grant.read, crate::error::Failure::Forbidden);
        self.check_row(&grant.rows, actor, value)
    }

    fn check_row(&self, rows: &Rows, actor: &str, value: &Value) -> Result<()> {
        if let Rows::OwnerOrAdmin { field } = rows {
            ensure!(
                self.admins.contains(actor)
                    || value.get(field).and_then(Value::as_str) == Some(actor),
                crate::error::Failure::Forbidden
            );
        }
        Ok(())
    }

    pub fn edit_target(&self, operation: &str, input: &Value) -> Result<Option<EditTarget>> {
        let policy = self
            .operations
            .get(operation)
            .context(crate::error::Failure::Forbidden)?;
        let Mode::Edit {
            model,
            id_field,
            version_field,
        } = &policy.mode
        else {
            return Ok(None);
        };
        let raw_id = input
            .get(id_field)
            .and_then(Value::as_str)
            .context("invalid_edit_precondition")?;
        let id = crate::identity::parse_public_or_legacy(raw_id)?;
        let version = input
            .get(version_field)
            .and_then(Value::as_i64)
            .context("invalid_edit_precondition")?;
        ensure!(
            id.valid() && id.to_string() == raw_id && version > 0 && version < i64::MAX,
            "invalid_edit_precondition"
        );
        Ok(Some(EditTarget {
            model: model.clone(),
            id,
            version,
        }))
    }

    /// Check the caller's version in the command transaction before starting its worker.
    pub fn check_edit(&self, operation: &str, actor: &str, input: &Value, row: &Row) -> Result<()> {
        self.authorize(operation, actor)?;
        let Some(target) = self.edit_target(operation, input)? else {
            return Ok(());
        };
        let grant = self.grant(operation, &target.model, actor)?;
        ensure!(
            grant.read && !grant.update_fields.is_empty() && row.id == target.id,
            crate::error::Failure::Forbidden
        );
        self.check_row(&grant.rows, actor, &serde_json::from_str(&row.data)?)?;
        ensure!(
            row.version == target.version,
            crate::error::Failure::Conflict
        );
        Ok(())
    }

    pub fn check_create(
        &self,
        operation: &str,
        model: &str,
        actor: &str,
        value: &Value,
    ) -> Result<()> {
        let grant = self.grant(operation, model, actor)?;
        ensure!(
            grant.read
                && grant.create
                && matches!(self.operations[operation].mode, Mode::CurrentState),
            crate::error::Failure::Forbidden
        );
        // Ownership belongs to the model, including operations with broader row access.
        if let Some(field) = self.owned_fields()?.get(model) {
            ensure!(
                value.get(*field).and_then(Value::as_str) == Some(actor),
                crate::error::Failure::Forbidden
            );
        }
        self.check_constraints(model, value)
    }

    pub fn check_update(
        &self,
        operation: &str,
        model: &str,
        actor: &str,
        input: &Value,
        change: &Change<'_>,
    ) -> Result<()> {
        let grant = self.grant(operation, model, actor)?;
        ensure!(
            grant.read
                && !grant.update_fields.is_empty()
                && !matches!(self.operations[operation].mode, Mode::Read),
            crate::error::Failure::Forbidden
        );
        if let Some(target) = self.edit_target(operation, input)? {
            ensure!(
                target.model == model && target.id == change.id,
                crate::error::Failure::Forbidden
            );
        }
        self.check_row(&grant.rows, actor, change.before)?;
        self.check_row(&grant.rows, actor, change.after)?;
        let before = change.before.as_object().context("invalid_model_value")?;
        let next = change.after.as_object().context("invalid_model_value")?;
        ensure!(before.keys().eq(next.keys()), "invalid_model_value");
        if let Some(field) = self.owned_fields()?.get(model) {
            ensure!(
                before.get(*field) == next.get(*field),
                crate::error::Failure::Forbidden
            );
        }
        for (field, value) in next {
            ensure!(
                before.get(field) == Some(value) || grant.update_fields.contains(field),
                crate::error::Failure::Forbidden
            );
        }
        self.check_constraints(model, change.after)
    }

    pub fn check_constraints(&self, model: &str, value: &Value) -> Result<()> {
        if let Some(constraints) = self.constraints.get(model) {
            for (field, constraint) in constraints {
                let value = value
                    .get(field)
                    .and_then(Value::as_str)
                    .context("constraint_violation")?;
                ensure!(
                    value.len() <= constraint.max_bytes
                        && (!constraint.nonempty || !value.trim().is_empty()),
                    "constraint_violation"
                );
            }
        }
        Ok(())
    }
}

/// The prefix of an entry that admits everyone at a domain instead of one person.
///
/// `domain:D` may appear in an app's `readers` and `writers` and in an
/// operation's `actors`, and nowhere else. It admits exactly the addresses
/// [`in_domain`] accepts, and only when `D` is the hosted domain the
/// installation's edge verifies on every request (see [`valid_entry`]). It is
/// never an identity: owners, administrators, delegation rules and the audit
/// always name the one person the edge verified.
pub const DOMAIN_PREFIX: &str = "domain:";

/// A principal the platform can record: one person's address, an `app:` or
/// `svc:` name, or a development name.
///
/// A `domain:` entry is refused here because it names a set of people, not one
/// of them: it cannot own a row, administer an app, take part in a delegation
/// or appear in the audit as who acted.
pub(crate) fn valid_actor(actor: &str) -> Result<()> {
    ensure!(
        !actor.starts_with("credential_client:"),
        "a credential client family is not a principal"
    );
    ensure!(
        !actor.starts_with(DOMAIN_PREFIX),
        "a {DOMAIN_PREFIX} entry names a set of people, not one principal, and is accepted only \
         in readers, writers and operation actors: {actor}"
    );
    ensure!(
        !actor.is_empty()
            && actor.len() <= 256
            && actor.trim() == actor
            && !actor.chars().any(char::is_control),
        "invalid authority actor"
    );
    Ok(())
}

/// One entry of a membership list or an operation's `actors`: a principal, or
/// `domain:D` for the domain the installation's edge verifies.
///
/// `hosted_domain` is the installation's `google_iap` hosted domain, and absent
/// when it declares no identity provider. Only then has the platform checked
/// every request's `hd` claim and address against `D`, so a domain entry for
/// any other domain — or any domain at all without an identity provider, as in
/// local development — is refused rather than left to match nobody.
pub(crate) fn valid_entry(entry: &str, hosted_domain: Option<&str>) -> Result<()> {
    if let Some(family) = entry.strip_prefix("credential_client:") {
        day2_capabilities::Name::try_from(family.to_owned())?;
        return Ok(());
    }
    let Some(domain) = entry_domain(entry)? else {
        return Ok(());
    };
    match hosted_domain {
        Some(hosted) => ensure!(
            hosted == domain,
            "{entry} does not name the installation's hosted_domain ({hosted}): a domain entry \
             admits only the domain its identity provider verifies"
        ),
        None => anyhow::bail!(
            "{entry} requires the installation to declare identity \
             {{\"scheme\":\"google_iap\",\"hosted_domain\":\"{domain}\"}}: without an identity \
             provider nothing has verified that a request comes from that domain"
        ),
    }
    Ok(())
}

/// The domain a well-formed entry admits, or `None` for a principal.
fn entry_domain(entry: &str) -> Result<Option<&str>> {
    if let Some(family) = entry.strip_prefix("credential_client:") {
        day2_capabilities::Name::try_from(family.to_owned())?;
        return Ok(None);
    }
    let Some(domain) = entry.strip_prefix(DOMAIN_PREFIX) else {
        valid_actor(entry)?;
        return Ok(None);
    };
    ensure!(
        crate::artifact::dns_name(domain),
        "invalid {DOMAIN_PREFIX} entry: {entry} (expected {DOMAIN_PREFIX}<lowercase domain>)"
    );
    Ok(Some(domain))
}

/// Whether `entries` admit `actor`: by name, or by a `domain:` entry for the
/// actor's own domain.
///
/// A domain entry is matched on its own spelling here; that it names the
/// domain the installation's edge verifies is established when the entries
/// are validated ([`valid_entry`]) and re-established on every authorization,
/// which checks the activated document against the running installation. An
/// actor spelled as a domain entry is never admitted, even by that same entry.
pub(crate) fn admits(entries: &BTreeSet<String>, actor: &str) -> bool {
    !actor.starts_with(DOMAIN_PREFIX)
        && !actor.starts_with("credential_client:")
        && (entries.contains(actor)
            || client_family(actor)
                .is_some_and(|family| entries.contains(&format!("credential_client:{family}")))
            || actor.split_once('@').is_some_and(|(_, domain)| {
                in_domain(actor, domain) && entries.contains(&format!("{DOMAIN_PREFIX}{domain}"))
            }))
}

/// The host creates this namespace only after verifying a managed client token.
pub(crate) fn client_family(actor: &str) -> Option<&str> {
    let (family, id) = actor.strip_prefix("client/")?.split_once('/')?;
    (day2_capabilities::Name::try_from(family.to_owned()).is_ok()
        && id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
    .then_some(family)
}

/// Whether `actor` is a person's address at exactly `domain`.
///
/// Exactly one `@`, a non-empty local part, and `domain` after it byte for
/// byte: no subdomain, no suffix, no lookalike. Lowercase ASCII without
/// whitespace, because the edge records the address it verified lowercased and
/// trimmed and a differently spelled one is not that person. Service
/// principals (`app:`, `svc:`) and Google service accounts are never members
/// of a domain: neither has a person behind it.
pub(crate) fn in_domain(actor: &str, domain: &str) -> bool {
    let Some((local, host)) = actor.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && host == domain
        && crate::artifact::dns_name(host)
        && !host.ends_with(".gserviceaccount.com")
        && !actor.starts_with("app:")
        && !actor.starts_with("svc:")
        && !actor.starts_with("client/")
        && !actor.starts_with("credential_client:")
        && !actor.starts_with(DOMAIN_PREFIX)
        && local
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase() && b != b'@')
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    const DOMAIN: &str = "wonderly.com";

    fn entries(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn credential_client_membership_is_family_specific_and_never_human_membership() {
        let client = format!("client/client_keys/{}", "a".repeat(64));
        let allowed = entries(&["credential_client:client_keys"]);
        assert!(valid_entry("credential_client:client_keys", None).is_ok());
        assert!(valid_actor("credential_client:client_keys").is_err());
        assert!(admits(&allowed, &client));
        for denied in [
            "alice@example.com".to_owned(),
            "credential_client:client_keys".to_owned(),
            format!("client/personal_keys/{}", "a".repeat(64)),
            format!("client/client_keys/{}", "A".repeat(64)),
            "client/client_keys/short".to_owned(),
            "client/client_keys/alice@example.com".to_owned(),
        ] {
            assert!(!admits(&allowed, &denied), "{denied}");
        }
        assert!(!admits(
            &entries(&["domain:example.com", "alice@example.com"]),
            &client
        ));
        assert!(!in_domain(
            "client/client_keys/alice@example.com",
            "example.com"
        ));
        assert!(valid_entry("credential_client:", None).is_err());
        assert!(valid_entry("credential_client:client_keys/other", None).is_err());
    }

    #[test]
    fn only_a_plain_lowercase_address_at_exactly_the_domain_is_a_member() {
        for member in ["ada@wonderly.com", "a.b+tag@wonderly.com", "x@wonderly.com"] {
            assert!(in_domain(member, DOMAIN), "{member}");
        }
        for outsider in [
            "ada@evil-wonderly.com",
            "ada@wonderly.com.evil.com",
            "ada@sub.wonderly.com",
            "ada@wonderly.co",
            "ada@wonderly.comm",
            "ada@wonderlyxcom",
            "ada@WONDERLY.COM",
            "ada@Wonderly.com",
            "Ada@wonderly.com",
            "ADA@wonderly.com",
            "@wonderly.com",
            "ada@evil.com@wonderly.com",
            "ada@@wonderly.com",
            "ada@wonderly.com@evil.com",
            "wonderly.com",
            "ada",
            "",
            " ada@wonderly.com",
            "ada@wonderly.com ",
            "ada @wonderly.com",
            "ada\t@wonderly.com",
            "ada\n@wonderly.com",
            "adá@wonderly.com",
            "app:links@wonderly.com",
            "svc:gateway@wonderly.com",
            "domain:wonderly.com",
            "domain:x@wonderly.com",
            "bot@tools.iam.gserviceaccount.com",
        ] {
            assert!(!in_domain(outsider, DOMAIN), "{outsider:?}");
        }
        // A service account's domain is never a member of itself either.
        assert!(!in_domain(
            "bot@tools.iam.gserviceaccount.com",
            "tools.iam.gserviceaccount.com"
        ));
    }

    #[test]
    fn a_domain_entry_admits_members_and_names_still_admit_themselves() {
        let listed = entries(&["domain:wonderly.com", "partner@example.com"]);
        assert!(admits(&listed, "newhire@wonderly.com"));
        assert!(admits(&listed, "partner@example.com"));
        for refused in [
            "other@example.com",
            "newhire@evil-wonderly.com",
            "newhire@sub.wonderly.com",
            "NewHire@wonderly.com",
            "svc:gateway@wonderly.com",
            // Spelled as the entry itself, it is still not a principal.
            "domain:wonderly.com",
        ] {
            assert!(!admits(&listed, refused), "{refused}");
        }
        // Without a domain entry, membership is exactly the named set.
        assert!(!admits(
            &entries(&["partner@example.com"]),
            "newhire@wonderly.com"
        ));
        // An entry for one domain admits nobody from another.
        assert!(!admits(
            &entries(&["domain:example.com"]),
            "newhire@wonderly.com"
        ));
    }

    #[test]
    fn a_domain_entry_must_name_the_verified_hosted_domain() {
        assert!(valid_entry("domain:wonderly.com", Some(DOMAIN)).is_ok());
        assert!(valid_entry("ada@wonderly.com", None).is_ok());
        let without = valid_entry("domain:wonderly.com", None).unwrap_err();
        assert!(without.to_string().contains("google_iap"), "{without}");
        for entry in [
            "domain:example.com",
            "domain:sub.wonderly.com",
            "domain:WONDERLY.COM",
            "domain:wonderly.com ",
            "domain: wonderly.com",
            "domain:",
            "domain:com",
            "domain:*.wonderly.com",
            "domain:@wonderly.com",
        ] {
            assert!(valid_entry(entry, Some(DOMAIN)).is_err(), "{entry:?}");
        }
    }

    #[test]
    fn a_domain_is_never_a_principal() {
        let error = valid_actor("domain:wonderly.com").unwrap_err();
        assert!(error.to_string().contains("readers, writers"), "{error}");
        assert!(valid_actor("ada@wonderly.com").is_ok());
    }
}
