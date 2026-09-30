use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Boundary {
    Decide,
    Effects,
    Complete,
    Commit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Write {
    Create,
    Update {
        id: crate::identity::Id,
        version: i64,
    },
    /// Mark a row deleted, or bring it back.
    ///
    /// Separate variants rather than an `Update` carrying a `deleted_at` field,
    /// because an application must not be able to write that column as data.
    /// The only way a row's deletion state changes is through these, which
    /// carry no payload at all — so soft-deleting cannot smuggle an edit, and
    /// an ordinary update cannot smuggle a deletion.
    SoftDelete {
        id: crate::identity::Id,
        version: i64,
    },
    Restore {
        id: crate::identity::Id,
        version: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Filter<'a> {
    pub field: &'a str,
    pub value: &'a crate::identity::Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Database<'a> {
    Get {
        model: &'a str,
        id: crate::identity::Id,
    },
    Page {
        model: &'a str,
        filter: Option<Filter<'a>>,
        after: &'a crate::identity::Id,
        limit: u16,
    },
    Select {
        model: &'a str,
        data: &'a str,
        find: bool,
    },
    Write {
        model: &'a str,
        data: &'a str,
        change: Write,
    },
}

impl<'a> Database<'a> {
    pub(crate) fn model(self) -> &'a str {
        match self {
            Self::Get { model, .. }
            | Self::Page { model, .. }
            | Self::Select { model, .. }
            | Self::Write { model, .. } => model,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step<'a> {
    CredentialIssue,
    Database(Database<'a>),
    Request {
        model: &'a str,
        id: crate::identity::Id,
        version: i64,
        data: &'a str,
    },
    Observe {
        capability: &'a str,
        input: &'a str,
    },
    External {
        capability: &'a str,
        input: &'a str,
    },
    Boundary(Boundary),
}

impl Step<'_> {
    pub(crate) fn mutation(self) -> bool {
        matches!(
            self,
            Self::Database(Database::Write { .. }) | Self::Request { .. } | Self::CredentialIssue
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Prepare,
    Decide,
    Effects,
    Complete,
}

impl Phase {
    pub(crate) fn persisted(code: &str) -> anyhow::Result<Self> {
        match code {
            "effects" => Ok(Self::Effects),
            "complete" => Ok(Self::Complete),
            _ => anyhow::bail!("invalid_execution_phase"),
        }
    }

    pub(crate) fn persistence_code(self) -> anyhow::Result<&'static str> {
        match self {
            Self::Effects => Ok("effects"),
            Self::Complete => Ok("complete"),
            _ => anyhow::bail!("invalid_execution_phase"),
        }
    }
    pub(crate) fn advance(self, step: Step<'_>) -> anyhow::Result<Self> {
        use Boundary::*;
        use anyhow::bail;
        Ok(match (self, step) {
            (
                Self::Prepare,
                Step::Database(
                    Database::Get { .. } | Database::Page { .. } | Database::Select { .. },
                )
                | Step::Observe { .. },
            ) => self,
            (Self::Prepare, Step::Boundary(Decide)) => Self::Decide,
            (
                Self::Decide | Self::Complete,
                Step::Database(_)
                | Step::Request { .. }
                | Step::CredentialIssue
                | Step::Boundary(Commit),
            ) => self,
            (Self::Decide, Step::Boundary(Effects)) => Self::Effects,
            (Self::Effects, Step::External { .. }) => self,
            (Self::Effects, Step::Boundary(Complete)) => Self::Complete,
            _ => bail!("invalid_phase_instruction"),
        })
    }

    pub(crate) fn after(observations: &[Observation], phased: bool) -> anyhow::Result<Self> {
        let mut phase = if phased { Self::Prepare } else { Self::Decide };
        for observation in observations {
            let next = phase.advance(observation.instruction.decode()?)?;
            if observation.error.is_empty() {
                phase = next;
            }
        }
        Ok(phase)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply<'a> {
    Pending(Step<'a>),
    Done(&'a str),
    Failed(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Completion<'a> {
    Success(&'a serde_json::Value),
    Pending(&'a serde_json::Value),
    Failure(&'a str),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub invocation_id: String,
    pub actor: String,
    pub now: i64,
    /// What established this invocation's authority: an authenticated request, a
    /// bound schedule, another command in this app, a verified delivery.
    ///
    /// Read from the invocation record, never from application input — an
    /// application that could name its own caller could name a better one. It is
    /// carried as a string rather than an enum for the same reason the column is
    /// a shape and not an enumeration: a new cause should not be a wire change,
    /// and the Roc side keeps a tag for the ones an app can act on plus one for
    /// everything else.
    pub authentication: String,
    /// The applications this call passed through, oldest first, empty when it
    /// entered the instance from outside.
    ///
    /// Host-written, like the rest of this record. The immediate caller is the
    /// last entry; the first is the application a person actually asked.
    pub caller: Vec<String>,
    /// Who the host verified, when that is not the principal this work is for.
    ///
    /// Empty when they are the same, which is the ordinary case. An application
    /// acting for a person appears here as `app:<name>`, because an application
    /// acting for someone is one case of the same thing an administrator does.
    pub authenticated: String,
    /// The operator rule that permitted acting for this principal. Recorded so
    /// a rule removed later does not erase which rule applied at the time.
    pub delegation_rule: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Instruction {
    pub kind: String,
    pub model: String,
    pub id: crate::identity::Id,
    pub expected_version: i64,
    pub data: String,
    pub filter_field: String,
    pub filter_value: crate::identity::Id,
    pub after: crate::identity::Id,
    pub limit: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionOrder {
    pub model: String,
    pub field: String,
    pub descending: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionPredicate {
    pub kind: String,
    pub model: String,
    pub field: String,
    pub value: String,
    pub children: Vec<String>,
}

impl SelectionPredicate {
    pub(crate) fn validate(raw: &str, depth: usize, remaining: &mut usize) -> anyhow::Result<()> {
        use anyhow::{bail, ensure};
        ensure!(depth <= 16 && *remaining > 0, "selection_predicate_limit");
        *remaining -= 1;
        let node: Self = serde_json::from_str(raw)?;
        match node.kind.as_str() {
            "all" | "any" => {
                ensure!(
                    node.model.is_empty() && node.field.is_empty() && node.value.is_empty(),
                    "invalid_selection_group"
                );
                for child in node.children {
                    Self::validate(&child, depth + 1, remaining)?;
                }
            }
            "equal" | "like" => {
                ensure!(
                    !node.model.is_empty() && !node.field.is_empty() && node.children.is_empty(),
                    "invalid_selection_predicate"
                );
                let _: serde_json::Value = serde_json::from_str(&node.value)?;
            }
            _ => bail!("unsupported_selection_operator"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionPlan {
    pub predicate: String,
    pub orders: Vec<SelectionOrder>,
    pub after: String,
    pub limit: i64,
    /// Which rows are in scope: `exclude` (default), `include`, or `only`.
    ///
    /// Absent means exclude, which is the point: a selection that says nothing
    /// about deletion gets live rows only, so forgetting to exclude deleted
    /// rows is not something an application can do. `only` exists so a trash
    /// view can be built without widening `Entity` — the caller knows every row
    /// it got back is deleted, rather than having to read a flag off each one.
    #[serde(default)]
    pub deleted: String,
}

impl SelectionPlan {
    pub(crate) fn parse(data: &str, find: bool) -> anyhow::Result<Self> {
        use anyhow::ensure;
        ensure!(data.len() <= 65_536, "selection_plan_limit");
        let plan: Self = serde_json::from_str(data)?;
        // An unrecognised scope is a mistake, not a hint. Falling back to
        // `exclude` would be safe for the rows but would silently answer a
        // different question than the one asked, so a trash view built on a
        // typo would render empty forever with nothing to point at.
        ensure!(
            matches!(plan.deleted.as_str(), "" | "exclude" | "include" | "only"),
            "unsupported_selection_scope"
        );
        ensure!(
            (1..=100).contains(&plan.limit) && plan.orders.len() <= 8,
            "invalid_selection_bounds"
        );
        ensure!(
            plan.after.is_empty() || valid_selection_cursor(&plan.after),
            "invalid_selection_cursor"
        );
        ensure!(!find || plan.after.is_empty(), "invalid_find_bounds");
        SelectionPredicate::validate(&plan.predicate, 0, &mut 512)?;
        Ok(plan)
    }
}

/// Only a transport shape check. The store also validates binding and typed values.
pub(crate) fn valid_selection_cursor(raw: &str) -> bool {
    raw.strip_prefix("sel1_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

impl Instruction {
    /// The wire record remains stable. Only validated variants reach interpreters.
    pub(crate) fn decode(&self) -> anyhow::Result<Step<'_>> {
        use anyhow::{bail, ensure};
        let empty_filter = self.filter_field.is_empty() && self.filter_value.empty();
        let empty_page = empty_filter && self.after.empty() && self.limit == 0;
        let empty_row = self.id.empty() && self.expected_version == 0;
        let named = !self.model.is_empty();
        let payload = !self.data.is_empty() && self.data.len() <= 65_536;
        Ok(match self.kind.as_str() {
            "credential_issue" => {
                ensure!(
                    self.model == crate::credential_codegen::ISSUE
                        && empty_row
                        && empty_page
                        && payload,
                    "invalid_credential_issue_instruction"
                );
                Step::CredentialIssue
            }
            "decide" | "effects" | "complete" | "commit" => {
                ensure!(self.only_kind(&self.kind), "invalid_boundary_instruction");
                Step::Boundary(match self.kind.as_str() {
                    "decide" => Boundary::Decide,
                    "effects" => Boundary::Effects,
                    "complete" => Boundary::Complete,
                    _ => Boundary::Commit,
                })
            }
            "get" => {
                ensure!(
                    named
                        && self.id.valid()
                        && self.expected_version == 0
                        && self.data.is_empty()
                        && empty_page,
                    "invalid_get_instruction"
                );
                Step::Database(Database::Get {
                    model: &self.model,
                    id: self.id,
                })
            }
            "page" => {
                ensure!(
                    named
                        && empty_row
                        && self.data.is_empty()
                        && (1..=100).contains(&self.limit)
                        && (empty_filter
                            || (!self.filter_field.is_empty() && self.filter_value.valid()))
                        && (self.after.empty() || self.after.valid()),
                    "invalid_page_instruction"
                );
                Step::Database(Database::Page {
                    model: &self.model,
                    filter: (!empty_filter).then_some(Filter {
                        field: &self.filter_field,
                        value: &self.filter_value,
                    }),
                    after: &self.after,
                    limit: self.limit as u16,
                })
            }
            "select_page" | "find" => {
                ensure!(
                    named && empty_row && empty_page && payload,
                    "invalid_selection_instruction"
                );
                let find = self.kind == "find";
                SelectionPlan::parse(&self.data, find)?;
                Step::Database(Database::Select {
                    model: &self.model,
                    data: &self.data,
                    find,
                })
            }
            "create" => {
                ensure!(
                    named && empty_row && empty_page && payload,
                    "invalid_create_instruction"
                );
                Step::Database(Database::Write {
                    model: &self.model,
                    data: &self.data,
                    change: Write::Create,
                })
            }
            "soft_delete" | "restore" => {
                // No payload: these change only whether the row is deleted.
                ensure!(
                    named
                        && self.id.valid()
                        && (1..i64::MAX).contains(&self.expected_version)
                        && empty_page
                        && self.data.is_empty(),
                    "invalid_deletion_instruction"
                );
                Step::Database(Database::Write {
                    model: &self.model,
                    data: &self.data,
                    change: if self.kind == "soft_delete" {
                        Write::SoftDelete {
                            id: self.id,
                            version: self.expected_version,
                        }
                    } else {
                        Write::Restore {
                            id: self.id,
                            version: self.expected_version,
                        }
                    },
                })
            }
            "update" | "request" => {
                ensure!(
                    named
                        && self.id.valid()
                        && (1..i64::MAX).contains(&self.expected_version)
                        && empty_page
                        && payload,
                    "invalid_mutation_instruction"
                );
                if self.kind == "update" {
                    Step::Database(Database::Write {
                        model: &self.model,
                        data: &self.data,
                        change: Write::Update {
                            id: self.id,
                            version: self.expected_version,
                        },
                    })
                } else {
                    Step::Request {
                        model: &self.model,
                        id: self.id,
                        version: self.expected_version,
                        data: &self.data,
                    }
                }
            }
            "observe" | "external" => {
                ensure!(
                    named && empty_row && empty_page && payload && self.data.len() <= 16_384,
                    "invalid_capability_instruction"
                );
                if self.kind == "observe" {
                    Step::Observe {
                        capability: &self.model,
                        input: &self.data,
                    }
                } else {
                    Step::External {
                        capability: &self.model,
                        input: &self.data,
                    }
                }
            }
            _ => bail!("unsupported_effect"),
        })
    }

    /// Old workers use numeric zero for unused IDs; current workers use "".
    /// Accept both empty representations without accepting any requested effect.
    pub(crate) fn only_kind(&self, kind: &str) -> bool {
        self.kind == kind
            && self.model.is_empty()
            && self.id.empty()
            && self.expected_version == 0
            && self.data.is_empty()
            && self.filter_field.is_empty()
            && self.filter_value.empty()
            && self.after.empty()
            && self.limit == 0
    }
}

#[cfg(test)]
mod instruction_tests {
    use super::*;

    #[test]
    fn generic_selections_validate_protocol_and_prepare_phase() {
        let predicate =
            serde_json::json!({"kind":"all","model":"","field":"","value":"","children":[]})
                .to_string();
        let data = serde_json::json!({"predicate":predicate,"orders":[],"after":"","limit":20})
            .to_string();
        for kind in ["find", "select_page"] {
            let instruction = Instruction {
                kind: kind.into(),
                model: "links".into(),
                data: data.clone(),
                ..Instruction::default()
            };
            let step = instruction.decode().unwrap();
            assert_eq!(Phase::Prepare.advance(step).unwrap(), Phase::Prepare);
            assert!(Phase::Effects.advance(step).is_err());
            assert!(
                Instruction {
                    limit: 1,
                    ..instruction.clone()
                }
                .decode()
                .is_err()
            );
            assert!(
                Instruction {
                    data: "{}".into(),
                    ..instruction
                }
                .decode()
                .is_err()
            );
        }
        for data in [
            serde_json::json!({"predicate":predicate,"orders":[],"after":"","limit":101}),
            serde_json::json!({"predicate":predicate,"orders":[],"after":"sel1_ff","limit":20,"forged":true}),
            serde_json::json!({"predicate":predicate,"orders":[],"after":"sel1_FF","limit":20}),
        ] {
            assert!(SelectionPlan::parse(&data.to_string(), false).is_err());
        }
        assert!(valid_selection_cursor(&format!("sel1_{}", "0f".repeat(32))));
        for invalid in ["sel1_", "sel1_f", "sel1_GG", "sel1_0A", "other_00"] {
            assert!(!valid_selection_cursor(invalid));
        }
    }

    #[test]
    fn selection_predicate_budgets_and_unknown_operators_fail_explicitly() {
        let leaf = serde_json::json!({"kind":"equal","model":"links","field":"active","value":"true","children":[]}).to_string();
        let group = serde_json::json!({"kind":"all","model":"","field":"","value":"","children":vec![&leaf;512]}).to_string();
        assert!(SelectionPredicate::validate(&group, 0, &mut 512).is_err());
        let unknown = leaf.replace("equal", "sql");
        assert!(SelectionPredicate::validate(&unknown, 0, &mut 512).is_err());
        let bad_value = leaf.replace("true", "not-json");
        assert!(SelectionPredicate::validate(&bad_value, 0, &mut 512).is_err());
    }
    #[test]
    fn empty_legacy_and_current_instructions_do_not_admit_effect_fields() {
        for empty in [crate::identity::Id::default(), 0.into()] {
            let guard = Instruction {
                kind: "commit".into(),
                id: empty,
                filter_value: empty,
                after: empty,
                ..Instruction::default()
            };
            assert!(guard.only_kind("commit"));
            assert_eq!(guard.decode().unwrap(), Step::Boundary(Boundary::Commit));
            assert!(!guard.only_kind(""));
            for forged in [
                Instruction {
                    id: 1.into(),
                    ..guard.clone()
                },
                Instruction {
                    after: 1.into(),
                    ..guard.clone()
                },
                Instruction {
                    filter_value: 1.into(),
                    ..guard.clone()
                },
                Instruction {
                    data: "data".into(),
                    ..guard.clone()
                },
            ] {
                assert!(!forged.only_kind("commit"));
            }
        }
    }

    #[test]
    fn decoding_rejects_irrelevant_fields_and_phase_crossings() {
        let read = Instruction {
            kind: "get".into(),
            model: "reports".into(),
            id: 1.into(),
            ..Instruction::default()
        };
        let step = read.decode().unwrap();
        assert_eq!(
            step,
            Step::Database(Database::Get {
                model: "reports",
                id: 1.into()
            })
        );
        for poisoned in [
            Instruction {
                data: "{}".into(),
                ..read.clone()
            },
            Instruction {
                expected_version: 1,
                ..read.clone()
            },
            Instruction {
                limit: 10,
                ..read.clone()
            },
        ] {
            assert!(poisoned.decode().is_err());
        }
        assert!(Phase::Effects.advance(step).is_err());
        let write = Step::Database(Database::Write {
            model: "reports",
            data: "{}",
            change: Write::Create,
        });
        assert!(Phase::Prepare.advance(write).is_err());
        assert_eq!(Phase::Decide.advance(write).unwrap(), Phase::Decide);
        assert!(
            Phase::Complete
                .advance(Step::Boundary(Boundary::Effects))
                .is_err()
        );
        assert!(
            Phase::Decide
                .advance(Step::Observe {
                    capability: "snowflake",
                    input: "{}"
                })
                .is_err()
        );
    }

    #[test]
    fn responses_and_outcomes_cannot_carry_conflicting_variants() {
        let mut response = Response {
            kind: "done".into(),
            instruction: Instruction::default(),
            result: "{}".into(),
            error: String::new(),
            consumed: 0,
        };
        assert!(matches!(response.decode(), Ok(Reply::Done("{}"))));
        response.instruction.model = "reports".into();
        assert!(response.decode().is_err());
        response.instruction = Instruction::default();
        response.error = "forbidden".into();
        assert!(response.decode().is_err());
        let invalid = Outcome {
            status: "failure".into(),
            result: serde_json::json!({"secret":1}),
            error: "forbidden".into(),
        };
        assert!(invalid.decode().is_err());
        let unknown = Outcome {
            status: "finished".into(),
            result: serde_json::Value::Null,
            error: String::new(),
        };
        assert!(unknown.decode().is_err());
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub instruction: Instruction,
    pub result: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: String,
    pub input: String,
    pub context: Context,
    pub observations: Vec<Observation>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub kind: String,
    pub instruction: Instruction,
    pub result: String,
    pub error: String,
    pub consumed: usize,
}

impl Response {
    pub(crate) fn decode(&self) -> anyhow::Result<Reply<'_>> {
        use anyhow::{bail, ensure};
        match self.kind.as_str() {
            "pending" => {
                ensure!(
                    self.result.is_empty() && self.error.is_empty(),
                    "invalid_pending_response"
                );
                Ok(Reply::Pending(self.instruction.decode()?))
            }
            "done" => {
                ensure!(
                    self.instruction.only_kind("") && self.error.is_empty(),
                    "invalid_completion_response"
                );
                Ok(Reply::Done(&self.result))
            }
            "failed" => {
                ensure!(
                    self.instruction.only_kind("")
                        && self.result.is_empty()
                        && !self.error.is_empty(),
                    "invalid_failure_response"
                );
                Ok(Reply::Failed(&self.error))
            }
            _ => bail!("unsupported_worker_response"),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub id: crate::identity::Id,
    pub version: i64,
    pub created_at: i64,
    pub data: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub status: String,
    pub result: serde_json::Value,
    pub error: String,
}

impl Outcome {
    pub(crate) fn decode(&self) -> anyhow::Result<Completion<'_>> {
        use anyhow::{bail, ensure};
        Ok(match self.status.as_str() {
            "success" | "pending" => {
                ensure!(self.error.is_empty(), "invalid_outcome");
                if self.status == "success" {
                    Completion::Success(&self.result)
                } else {
                    Completion::Pending(&self.result)
                }
            }
            "failure" => {
                ensure!(
                    self.result.is_null() && !self.error.is_empty(),
                    "invalid_outcome"
                );
                Completion::Failure(&self.error)
            }
            _ => bail!("invalid_outcome"),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub format: u32,
    pub artifact: String,
    pub scope: String,
    pub request: Request,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<ExecutionGuard>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGuard {
    pub policy: crate::authority::Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<crate::authority_state::AuthorityStamp>,
    pub precondition_row: Option<Row>,
    pub error: String,
}
