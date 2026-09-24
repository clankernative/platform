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
        for (name, policy) in &self.operations {
            let operation = operations
                .iter()
                .find(|operation| operation.name == *name)
                .with_context(|| format!("authority policy unknown operation: {name}"))?;
            for actor in &policy.actors {
                valid_actor(actor)?;
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
                    .all(|name| crate::capabilities::READS.contains(&name.as_str())),
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
                .is_some_and(|policy| policy.actors.contains(actor)),
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

pub(crate) fn valid_actor(actor: &str) -> Result<()> {
    ensure!(
        !actor.is_empty()
            && actor.len() <= 256
            && actor.trim() == actor
            && !actor.chars().any(char::is_control),
        "invalid authority actor"
    );
    Ok(())
}
