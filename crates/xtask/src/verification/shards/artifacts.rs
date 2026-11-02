//! Authenticated, same-run artifact selection. Attempts describe producers, not freshness.
use super::{Identity, identity, reuse};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const REPOSITORY: &str = "clankernative/platform";
const WORKFLOW: &str = ".github/workflows/ci.yml";
const PLAN: &str = "/tmp/day2-ci-artifact-selection.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Role {
    Inputs,
    Tests,
    Common,
    Day2,
    Control,
    Other,
    Day2Result,
    ControlResult,
    OtherResult,
    SimulationResult,
    ParallelResult,
    Mac,
    Reused,
}

impl Role {
    fn prefix(self) -> &'static str {
        match self {
            Self::Inputs => "day2-preparation-inputs",
            Self::Tests => "day2-preparation-tests",
            Self::Common => "day2-verify-common",
            Self::Day2 => "day2-verify-workspace-day2",
            Self::Control => "day2-verify-workspace-control",
            Self::Other => "day2-verify-workspace-other",
            Self::Day2Result => "day2-result-workspace-day2",
            Self::ControlResult => "day2-result-workspace-control",
            Self::OtherResult => "day2-result-workspace-other",
            Self::SimulationResult => "day2-result-simulation",
            Self::ParallelResult => "day2-result-parallel-runtime",
            Self::Mac => "day2-mac-compatibility",
            Self::Reused => "day2-merge-reuse",
        }
    }

    fn job(self) -> &'static str {
        match self {
            Self::Inputs => "verify-prepare-parts (inputs)",
            Self::Tests => "verify-prepare-parts (tests)",
            Self::Common | Self::Day2 | Self::Control | Self::Other => "verify-prepare",
            Self::Day2Result => "verify-shards (workspace-day2)",
            Self::ControlResult => "verify-shards (workspace-control)",
            Self::OtherResult => "verify-shards (workspace-other)",
            Self::SimulationResult => "verify-shards (simulation)",
            Self::ParallelResult => "verify-shards (parallel-runtime)",
            Self::Mac => "verify-mac-compatibility",
            Self::Reused => "verify-queue-receipt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Origin {
    pub(super) attempt: u64,
    artifact: u64,
    digest: String,
    bytes: u64,
    job: u64,
    check: u64,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) consumer: Identity,
    phase: String,
    head: String,
    pub(super) origins: BTreeMap<Role, Origin>,
}

fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .filter(|v| *v > 0)
        .context("positive GitHub identity required")
}

fn sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn roles(phase: &str) -> Result<Vec<Role>> {
    use Role::*;
    Ok(match phase {
        "preparation" => vec![Inputs, Tests],
        "reuse" => vec![Reused],
        "workspace-day2" => vec![Common, Day2],
        "workspace-control" => vec![Common, Control],
        "workspace-other" => vec![Common, Other],
        "simulation" => vec![Common],
        "parallel-runtime" => vec![Common, Day2, Control, Other],
        "compose" => vec![
            Inputs,
            Tests,
            Common,
            Day2,
            Control,
            Other,
            Day2Result,
            ControlResult,
            OtherResult,
            SimulationResult,
            ParallelResult,
            Mac,
        ],
        _ => anyhow::bail!("unknown artifact consumer"),
    })
}

#[derive(Clone, Copy)]
enum Inventory {
    Artifacts { run: u64 },
    Jobs { run: u64, attempt: u64 },
}

impl Inventory {
    fn field(self) -> &'static str {
        match self {
            Self::Artifacts { .. } => "artifacts",
            Self::Jobs { .. } => "jobs",
        }
    }

    fn endpoint(self) -> String {
        match self {
            Self::Artifacts { run } => format!("actions/runs/{run}/artifacts"),
            Self::Jobs { run, attempt } => format!("actions/runs/{run}/attempts/{attempt}/jobs"),
        }
    }
}

// A moving count/list restarts the entire inventory, never just its last page.
// Invalid identities, duplicates and budget overruns still refuse immediately.
fn pages(root: &Path, inventory: Inventory) -> Result<Vec<Value>> {
    let endpoint = inventory.endpoint();
    pages_with(inventory.field(), |page| {
        reuse::api(root, &format!("{endpoint}?per_page=100&page={page}"))
    })
    // This endpoint contains only closed path components and numeric identities.
    .with_context(|| format!("GitHub inventory endpoint={endpoint}"))
}

fn pages_with(field: &str, mut read: impl FnMut(usize) -> Result<Value>) -> Result<Vec<Value>> {
    for _ in 0..3 {
        if let Some(values) = inventory_snapshot(field, &mut read)? {
            return Ok(values);
        }
    }
    anyhow::bail!("GitHub inventory remained inconsistent after three complete-snapshot attempts")
}

// None means that the observed count/list changed; no partial values escape.
fn inventory_snapshot(
    field: &str,
    read: &mut impl FnMut(usize) -> Result<Value>,
) -> Result<Option<Vec<Value>>> {
    let mut values = Vec::new();
    let mut total = None;
    let mut ids = BTreeSet::new();
    for page in 1..=10 {
        let v = read(page)?;
        let count = v["total_count"]
            .as_u64()
            .context("complete GitHub page required")?;
        ensure!(count <= 1000, "GitHub inventory exceeded its budget");
        let items = v[field].as_array().context("GitHub page array required")?;
        ensure!(
            items.len() <= 100 && values.len() + items.len() <= 1000,
            "GitHub inventory page exceeded its budget"
        );
        ensure!(
            items
                .iter()
                .all(|v| number(v, "id").is_ok_and(|id| ids.insert(id))),
            "invalid or duplicate GitHub inventory entry"
        );
        if total.is_some_and(|old| old != count)
            || (items.is_empty() && values.len() as u64 != count)
        {
            return Ok(None);
        }
        total = Some(count);
        values.extend(items.iter().cloned());
        if values.len() as u64 == count {
            return Ok(Some(values));
        }
        if values.len() as u64 > count {
            return Ok(None);
        }
    }
    Ok(None)
}

fn run_identity(run: &Value, expected: &Identity) -> Result<()> {
    ensure!(
        number(run, "id")?.to_string() == expected.run
            && number(run, "run_attempt")?.to_string() == expected.attempt
            && run["repository"]["full_name"] == REPOSITORY
            && run["head_repository"]["full_name"] == REPOSITORY
            && number(&run["repository"], "id")? == number(&run["head_repository"], "id")?
            && run["path"] == WORKFLOW
            && sha(run["head_sha"].as_str().unwrap_or("")),
        "artifact selection requires the exact repository, workflow, run and latest attempt"
    );
    Ok(())
}

fn successful_job<'a>(
    jobs: &'a [Value],
    role: Role,
    run: &Value,
    attempt: u64,
) -> Result<&'a Value> {
    let found: Vec<_> = jobs.iter().filter(|v| v["name"] == role.job()).collect();
    ensure!(
        found.len() == 1,
        "exactly one artifact producer job required: {}",
        role.job()
    );
    let job = found[0];
    ensure!(
        job["run_id"] == run["id"]
            && job["run_attempt"] == attempt
            && job["head_sha"] == run["head_sha"]
            && job["status"] == "completed"
            && job["conclusion"] == "success"
            && job["html_url"]
                == format!(
                    "https://github.com/{REPOSITORY}/actions/runs/{}/job/{}",
                    number(run, "id")?,
                    number(job, "id")?
                ),
        "latest and origin artifact producers must both have succeeded: {}",
        role.job()
    );
    Ok(job)
}

fn select(
    role: Role,
    artifacts: &[Value],
    run: &Value,
    latest_jobs: &[Value],
    origin_jobs: &[Value],
    check: &Value,
) -> Result<Origin> {
    let latest_attempt = number(run, "run_attempt")?;
    successful_job(latest_jobs, role, run, latest_attempt)?;
    let prefix = format!("{}-{}-", role.prefix(), number(run, "id")?);
    let mut candidates = Vec::new();
    let mut attempts = BTreeSet::new();
    for artifact in artifacts {
        if let Some(suffix) = artifact["name"]
            .as_str()
            .and_then(|v| v.strip_prefix(&prefix))
        {
            let attempt = suffix
                .parse::<u64>()
                .context("canonical artifact attempt required")?;
            ensure!(
                attempt > 0 && attempt <= latest_attempt && suffix == attempt.to_string(),
                "foreign or future artifact attempt"
            );
            ensure!(attempts.insert(attempt), "duplicate artifact name");
            candidates.push((attempt, artifact));
        }
    }
    let (attempt, artifact) = candidates
        .into_iter()
        .max_by_key(|(attempt, _)| *attempt)
        .context("successful producer artifact missing")?;
    let job = successful_job(origin_jobs, role, run, attempt)?;
    let workflow_run = &artifact["workflow_run"];
    let digest = artifact["digest"]
        .as_str()
        .context("artifact digest required")?;
    ensure!(
        artifact["expired"] == false
            && number(artifact, "size_in_bytes")? <= 4 * 1024 * 1024 * 1024
            && workflow_run["id"] == run["id"]
            && workflow_run["head_sha"] == run["head_sha"]
            && workflow_run["repository_id"] == run["repository"]["id"]
            && workflow_run["head_repository_id"] == run["head_repository"]["id"]
            && digest.len() == 71
            && digest.starts_with("sha256:")
            && digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
            && artifact["created_at"]
                .as_str()
                .zip(job["started_at"].as_str())
                .is_some_and(|(a, b)| a >= b)
            && artifact["created_at"]
                .as_str()
                .zip(job["completed_at"].as_str())
                .is_some_and(|(a, b)| a <= b),
        "expired, foreign or unbound producer artifact"
    );
    ensure!(
        number(check, "id")? == number(job, "id")?
            && check["name"] == job["name"]
            && check["head_sha"] == run["head_sha"]
            && check["app"]["id"] == 15368
            && check["check_suite"]["id"] == run["check_suite_id"]
            && check["status"] == "completed"
            && check["conclusion"] == "success"
            && check["details_url"] == job["html_url"],
        "authenticated producer check required"
    );
    Ok(Origin {
        attempt,
        artifact: number(artifact, "id")?,
        digest: digest.into(),
        bytes: number(artifact, "size_in_bytes")?,
        job: number(job, "id")?,
        check: number(check, "id")?,
    })
}

fn resolve(root: &Path, expected: &Identity, phase: &str) -> Result<Selection> {
    let run_id = expected.run.parse::<u64>()?;
    let run = reuse::api(root, &format!("actions/runs/{run_id}"))?;
    run_identity(&run, expected)?;
    // Pull requests check out a synthetic merge commit. Authenticate its actual
    // tree and parent, rather than confusing the PR branch SHA with that checkout.
    let commit = reuse::api(root, &format!("git/commits/{}", expected.checkout))?;
    ensure!(
        commit["sha"] == expected.checkout
            && commit["tree"]["sha"] == expected.tree
            && (run["head_sha"] == expected.checkout
                || (run["event"] == "pull_request"
                    && commit["parents"]
                        .as_array()
                        .is_some_and(|p| p.len() == 2 && p[1]["sha"] == run["head_sha"]))),
        "artifact API head does not bind the actual verification checkout"
    );
    let artifacts = pages(root, Inventory::Artifacts { run: run_id })?;
    let attempt = number(&run, "run_attempt")?;
    let latest = pages(
        root,
        Inventory::Jobs {
            run: run_id,
            attempt,
        },
    )?;
    let mut jobs = BTreeMap::from([(attempt, latest.clone())]);
    let mut origins = BTreeMap::new();
    for role in roles(phase)? {
        let prefix = format!("{}-{run_id}-", role.prefix());
        let origin_attempt = artifacts
            .iter()
            .filter_map(|v| {
                v["name"]
                    .as_str()?
                    .strip_prefix(&prefix)?
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .context("required same-run artifact missing")?;
        ensure!(
            origin_attempt > 0 && origin_attempt <= attempt,
            "artifact attempt is outside the current run history"
        );
        if let std::collections::btree_map::Entry::Vacant(entry) = jobs.entry(origin_attempt) {
            entry.insert(pages(
                root,
                Inventory::Jobs {
                    run: run_id,
                    attempt: origin_attempt,
                },
            )?);
        }
        let origin_jobs = &jobs[&origin_attempt];
        let job = successful_job(origin_jobs, role, &run, origin_attempt)?;
        let check = reuse::api(root, &format!("check-runs/{}", number(job, "id")?))?;
        origins.insert(
            role,
            select(role, &artifacts, &run, &latest, origin_jobs, &check)?,
        );
    }
    if let Some(common) = origins.get(&Role::Common) {
        ensure!(
            [Role::Day2, Role::Control, Role::Other]
                .iter()
                .filter_map(|r| origins.get(r))
                .all(|o| o.attempt == common.attempt),
            "binary groups and common metadata must have the same preparation origin"
        );
    }
    let last = reuse::api(root, &format!("actions/runs/{run_id}"))?;
    run_identity(&last, expected)?;
    ensure!(
        last["head_sha"] == run["head_sha"] && last["check_suite_id"] == run["check_suite_id"],
        "run changed during artifact selection"
    );
    Ok(Selection {
        consumer: expected.clone(),
        phase: phase.into(),
        head: run["head_sha"].as_str().unwrap().into(),
        origins,
    })
}

pub(in crate::verification) fn plan(root: &Path, snapshot: &str, phase: &str) -> Result<()> {
    let current = identity(root, snapshot)?;
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("GITHUB_SHA").as_deref() == Ok(current.checkout.as_str()),
        "exact hosted checkout required"
    );
    let selected = resolve(root, &current, phase)?;
    let ids = |wanted: &[Role]| {
        selected
            .origins
            .iter()
            .filter(|(r, _)| wanted.contains(r))
            .map(|(_, o)| o.artifact.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    for (name, wanted) in [
        ("inputs", vec![Role::Inputs]),
        ("tests", vec![Role::Tests]),
        ("common", vec![Role::Common]),
        ("binaries", vec![Role::Day2, Role::Control, Role::Other]),
        (
            "results",
            vec![
                Role::Day2Result,
                Role::ControlResult,
                Role::OtherResult,
                Role::SimulationResult,
                Role::ParallelResult,
            ],
        ),
        ("mac", vec![Role::Mac]),
        ("reuse_artifact", vec![Role::Reused]),
    ] {
        let value = ids(&wanted);
        if !value.is_empty() {
            reuse::output(name, &value)?;
        }
    }
    write(Path::new(PLAN), &selected)?;
    println!("Selected authenticated same-run artifacts; original producer attempts retained");
    Ok(())
}

pub(super) fn read(current: &Identity) -> Result<Selection> {
    let selected: Selection = serde_json::from_value(reuse::read_json(Path::new(PLAN))?)?;
    ensure!(
        selected.consumer == *current,
        "artifact selection belongs to another consumer"
    );
    Ok(selected)
}

pub(super) fn origin(current: &Identity, selected: &Selection, role: Role) -> Result<Identity> {
    ensure!(
        selected.consumer == *current,
        "artifact selection consumer changed"
    );
    let mut expected = current.clone();
    let attempt = selected
        .origins
        .get(&role)
        .context("required producer absent from artifact selection")?
        .attempt;
    ensure!(
        attempt > 0 && attempt <= current.attempt.parse::<u64>()?,
        "producer attempt is outside the current run history"
    );
    expected.attempt = attempt.to_string();
    Ok(expected)
}

pub(super) fn refresh(root: &Path, selected: &Selection) -> Result<()> {
    ensure!(
        *selected == resolve(root, &selected.consumer, &selected.phase)?,
        "artifact producers changed during admission"
    );
    Ok(())
}

fn write(path: &Path, selected: &Selection) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(selected)?)?;
    Ok(())
}

pub(super) fn retain(root: &Path, selected: &Selection) -> Result<()> {
    write(&root.join("artifacts/ci-artifact-selection.json"), selected)
}

#[cfg(test)]
pub(super) fn sample(consumer: &Identity) -> Selection {
    Selection {
        consumer: consumer.clone(),
        phase: "compose".into(),
        head: consumer.checkout.clone(),
        origins: roles("compose")
            .unwrap()
            .into_iter()
            .map(|r| {
                (
                    r,
                    Origin {
                        attempt: consumer.attempt.parse().unwrap(),
                        artifact: 7,
                        digest: format!("sha256:{}", "a".repeat(64)),
                        bytes: 100,
                        job: 1,
                        check: 1,
                    },
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inventory_page(total: u64, ids: impl IntoIterator<Item = u64>) -> Value {
        let items: Vec<_> = ids.into_iter().map(|id| json!({"id":id})).collect();
        json!({"total_count":total,"jobs":items,"artifacts":items})
    }

    #[test]
    fn inventory_refresh_discards_extra_entries_instead_of_truncating_them() -> Result<()> {
        for field in ["jobs", "artifacts"] {
            let mut script = std::collections::VecDeque::from([
                inventory_page(1, [1, 2]),
                inventory_page(2, [3, 4]),
            ]);
            let mut requests = Vec::new();
            let actual = pages_with(field, |page| {
                requests.push(page);
                Ok(script.pop_front().unwrap())
            })?;
            assert_eq!(requests, [1, 1]);
            assert_eq!(actual, [json!({"id":3}), json!({"id":4})]);
            assert!(script.is_empty());
        }
        Ok(())
    }

    #[test]
    fn inventory_count_change_restarts_at_page_one_without_mixing_snapshots() -> Result<()> {
        let mut script = std::collections::VecDeque::from([
            inventory_page(3, [1]),
            inventory_page(4, [2]),
            inventory_page(2, [10, 11]),
        ]);
        let mut requests = Vec::new();
        let actual = pages_with("jobs", |page| {
            requests.push(page);
            Ok(script.pop_front().unwrap())
        })?;
        assert_eq!(requests, [1, 2, 1]);
        assert_eq!(actual, [json!({"id":10}), json!({"id":11})]);
        assert!(script.is_empty());
        Ok(())
    }

    #[test]
    fn inventory_persistent_extra_or_incomplete_pages_still_refuse() {
        for page in [inventory_page(0, [1]), inventory_page(1, [])] {
            let mut requests = Vec::new();
            let error = pages_with("jobs", |number| {
                requests.push(number);
                Ok(page.clone())
            })
            .unwrap_err();
            assert_eq!(requests, [1, 1, 1]);
            assert!(
                error
                    .to_string()
                    .contains("three complete-snapshot attempts")
            );
        }
    }

    #[test]
    fn inventory_malformed_duplicate_and_over_budget_pages_do_not_retry() {
        for page in [
            inventory_page(2, [1, 1]),
            inventory_page(1, [0]),
            inventory_page(1001, []),
            inventory_page(101, 1..=101),
            json!({"jobs":[]}),
            json!({"total_count":1,"jobs":false}),
            json!({"total_count":1,"jobs":[{"id":"1"}]}),
        ] {
            let mut calls = 0;
            assert!(
                pages_with("jobs", |_| {
                    calls += 1;
                    Ok(page.clone())
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn inventory_duplicate_between_pages_refuses_without_refresh() {
        let mut requests = Vec::new();
        assert!(
            pages_with("jobs", |page| {
                requests.push(page);
                Ok(if page == 1 {
                    inventory_page(3, [1])
                } else {
                    inventory_page(3, [1, 2])
                })
            })
            .is_err()
        );
        assert_eq!(requests, [1, 2]);
    }

    #[test]
    fn inventory_accepts_complete_bounds_but_never_accepts_a_partial_inventory() -> Result<()> {
        let mut requests = Vec::new();
        let actual = pages_with("jobs", |page| {
            requests.push(page);
            let first = (page as u64 - 1) * 100 + 1;
            Ok(inventory_page(1000, first..first + 100))
        })?;
        assert_eq!(requests, (1..=10).collect::<Vec<_>>());
        assert_eq!(actual.len(), 1000);
        let mut requests = Vec::new();
        assert!(
            pages_with("jobs", |page| {
                requests.push(page);
                let first = (page as u64 - 1) * 100 + 1;
                Ok(inventory_page(1000, first..first + 99))
            })
            .is_err()
        );
        assert_eq!(requests, (1..=10).cycle().take(30).collect::<Vec<_>>());
        assert!(pages_with("jobs", |_| Ok(inventory_page(0, [])))?.is_empty());
        Ok(())
    }

    #[test]
    fn inventory_transport_errors_preserve_the_primary_error_without_retry() {
        let mut calls = 0;
        let error = pages_with("jobs", |_| {
            calls += 1;
            anyhow::bail!("fixture metadata request failed")
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.to_string(), "fixture metadata request failed");
        assert_eq!(
            Inventory::Jobs {
                run: 123,
                attempt: 2
            }
            .endpoint(),
            "actions/runs/123/attempts/2/jobs"
        );
        assert_eq!(
            Inventory::Artifacts { run: 123 }.endpoint(),
            "actions/runs/123/artifacts"
        );
    }

    fn facts(attempt: u64) -> (Value, Value, Value, Value) {
        let run = json!({"id":123,"run_attempt":2,"head_sha":"a".repeat(40),"path":WORKFLOW,
            "repository":{"id":77,"full_name":REPOSITORY},"head_repository":{"id":77,"full_name":REPOSITORY},"check_suite_id":99});
        let job = json!({"id":100+attempt,"name":Role::Common.job(),"run_id":123,"run_attempt":attempt,
            "head_sha":run["head_sha"],"status":"completed","conclusion":"success",
            "started_at":"2026-11-01T10:00:00Z","completed_at":"2026-11-01T10:02:00Z",
            "html_url":format!("https://github.com/{REPOSITORY}/actions/runs/123/job/{}",100+attempt)});
        let artifact = json!({"id":200+attempt,"name":format!("day2-verify-common-123-{attempt}"),
            "digest":format!("sha256:{}","b".repeat(64)),"expired":false,"size_in_bytes":123,
            "created_at":"2026-11-01T10:01:00Z","workflow_run":{"id":123,"head_sha":run["head_sha"],"repository_id":77,"head_repository_id":77}});
        let check = json!({"id":job["id"],"name":job["name"],"head_sha":run["head_sha"],
            "status":"completed","conclusion":"success","app":{"id":15368},"check_suite":{"id":99},"details_url":job["html_url"]});
        (run, job, artifact, check)
    }

    #[test]
    fn failed_only_rerun_retains_original_producer_and_selects_newest_complete_output() -> Result<()>
    {
        let (run, old, artifact, check) = facts(1);
        let (_, latest, new_artifact, new_check) = facts(2);
        let selected = select(
            Role::Common,
            std::slice::from_ref(&artifact),
            &run,
            std::slice::from_ref(&latest),
            std::slice::from_ref(&old),
            &check,
        )?;
        assert_eq!(selected.attempt, 1);
        assert_eq!(selected.artifact, 201);
        let newer = select(
            Role::Common,
            &[artifact, new_artifact],
            &run,
            std::slice::from_ref(&latest),
            std::slice::from_ref(&latest),
            &new_check,
        )?;
        assert_eq!(newer.attempt, 2);
        assert_eq!(newer.artifact, 202);
        Ok(())
    }

    #[test]
    fn artifact_selection_refuses_foreign_expired_duplicate_unchecked_and_newer_failed_producers()
    -> Result<()> {
        let (run, old, artifact, check) = facts(1);
        let (_, latest, _, _) = facts(2);
        for (pointer, replacement) in [
            ("/workflow_run/id", json!(124)),
            ("/workflow_run/head_sha", json!("c".repeat(40))),
            ("/workflow_run/repository_id", json!(78)),
            ("/workflow_run/head_repository_id", json!(78)),
            ("/expired", json!(true)),
            ("/size_in_bytes", json!(0)),
            ("/digest", json!("")),
            ("/created_at", json!("2026-11-01T09:59:00Z")),
            ("/created_at", json!("2026-11-01T10:03:00Z")),
            ("/name", json!("day2-verify-common-123-3")),
            ("/name", json!("day2-verify-common-123-01")),
            ("/name", json!("day2-verify-common-124-1")),
        ] {
            let mut invalid = artifact.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                select(
                    Role::Common,
                    &[invalid],
                    &run,
                    std::slice::from_ref(&latest),
                    std::slice::from_ref(&old),
                    &check
                )
                .is_err(),
                "{pointer}"
            );
        }
        assert!(
            select(
                Role::Common,
                &[artifact.clone(), artifact.clone()],
                &run,
                std::slice::from_ref(&latest),
                std::slice::from_ref(&old),
                &check
            )
            .is_err()
        );
        for status in ["failure", "cancelled", "skipped"] {
            let mut failed = latest.clone();
            failed["conclusion"] = json!(status);
            assert!(
                select(
                    Role::Common,
                    std::slice::from_ref(&artifact),
                    &run,
                    &[failed],
                    std::slice::from_ref(&old),
                    &check
                )
                .is_err()
            );
        }
        for (pointer, replacement) in [
            ("/app/id", json!(1)),
            ("/check_suite/id", json!(98)),
            ("/head_sha", json!("foreign")),
            ("/details_url", json!("foreign")),
            ("/conclusion", json!("failure")),
            ("/id", json!(999)),
        ] {
            let mut invalid = check.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                select(
                    Role::Common,
                    std::slice::from_ref(&artifact),
                    &run,
                    std::slice::from_ref(&latest),
                    std::slice::from_ref(&old),
                    &invalid
                )
                .is_err(),
                "{pointer}"
            );
        }
        for (pointer, replacement) in [
            ("/run_id", json!(124)),
            ("/head_sha", json!("foreign")),
            ("/run_attempt", json!(2)),
            ("/conclusion", json!("failure")),
        ] {
            let mut invalid = old.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                select(
                    Role::Common,
                    std::slice::from_ref(&artifact),
                    &run,
                    std::slice::from_ref(&latest),
                    &[invalid],
                    &check
                )
                .is_err(),
                "{pointer}"
            );
        }
        Ok(())
    }

    #[test]
    fn selection_binds_latest_attempt_repository_workflow_and_exact_receipt_source() -> Result<()> {
        let (run, _, _, _) = facts(1);
        let mut current = super::super::tests::sample_identity();
        current.run = "123".into();
        current.attempt = "2".into();
        current.checkout = "a".repeat(40);
        run_identity(&run, &current)?;
        for (pointer, replacement) in [
            ("/id", json!(124)),
            ("/run_attempt", json!(3)),
            ("/repository/full_name", json!("foreign/repo")),
            ("/head_repository/id", json!(78)),
            ("/path", json!("other.yml")),
        ] {
            let mut invalid = run.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(run_identity(&invalid, &current).is_err());
        }
        let mut selected = sample(&current);
        selected.origins.get_mut(&Role::Common).unwrap().attempt = 1;
        let original = origin(&current, &selected, Role::Common)?;
        assert_eq!(original.attempt, "1");
        assert_eq!(original.checkout, current.checkout);
        let mut foreign = current.clone();
        foreign.run = "124".into();
        assert!(origin(&foreign, &selected, Role::Common).is_err());
        selected.origins.get_mut(&Role::Common).unwrap().attempt = 3;
        assert!(origin(&current, &selected, Role::Common).is_err());
        Ok(())
    }
}
