//! Bounded GitHub inventory for the private Roc cache-retention recipe. This
//! command only plans numeric deletions; the main-only provider jobs apply them
//! after successful publication, with no write token in a verification job.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const REPOSITORY: &str = "clankernative/platform";
const MAX_CACHES: usize = 1_000;
const MAX_DELETIONS: usize = 16;

#[derive(Clone, Debug, Deserialize)]
struct Cache {
    id: u64,
    key: String,
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Deserialize)]
struct Page {
    total_count: usize,
    actions_caches: Vec<Cache>,
}

#[derive(Clone, Serialize)]
struct Entry {
    id: u64,
    family: String,
    generation: String,
    shared: bool,
    retired: bool,
    canonical: bool,
}

#[derive(Serialize)]
struct Inventory {
    caches: Vec<Entry>,
    publishing: String,
    current: String,
    families: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Deletion {
    id: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    include: Vec<Deletion>,
    deferred: u64,
}

fn sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn generation(value: &str) -> Option<(&str, bool)> {
    let head = value.get(..40)?;
    if !sha(head) {
        return None;
    }
    let tail = &value[40..];
    if tail.is_empty() {
        return Some((head, true));
    }
    let parts: Vec<_> = tail.strip_prefix('-')?.split('-').collect();
    if parts.len() == 2 && parts.iter().all(|p| p.parse::<u64>().is_ok_and(|n| n > 0)) {
        Some((head, false))
    } else {
        None
    }
}

fn compiler(key: &str, platform: &str) -> Option<(String, String, bool)> {
    let prefixes: &[(&str, &str)] = match platform {
        "linux" => &[
            (
                "day2-bazel-actions-v1-Linux-X64-verify-queue-receipt-",
                "linux-bootstrap",
            ),
            (
                "day2-bazel-actions-v1-Linux-X64-verify-prepare-parts-tests-",
                "linux-tests",
            ),
        ],
        "mac" => &[("day2-bazel-mac-actions-v2-macOS-ARM64-", "mac")],
        _ => return None,
    };
    prefixes.iter().find_map(|(prefix, family)| {
        let (head, canonical) = generation(key.strip_prefix(prefix)?)?;
        Some(((*family).into(), head.into(), canonical))
    })
}

fn owned(key: &str, platform: &str) -> bool {
    let target = if platform == "linux" {
        "-Linux-X64-"
    } else {
        "-macOS-ARM64-"
    };
    key.contains(target)
        && [
            "day2-bazel-actions-v1-",
            "day2-bazel-mac-actions-v2-",
            "day2-bazel-downloads-v1-",
            "day2-native-tools-v1-",
            "day2-test-outputs-v2-bazel-",
            "day2-fixtures-v3-bazel-",
            "day2-fixtures-v4-bazel-",
            "day2-tofu-providers-v1-",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

fn retired_endpoint(reference: &str) -> Option<(String, bool)> {
    if let Some(rest) = reference.strip_prefix("refs/heads/gh-readonly-queue/main/pr-") {
        let (number, base) = rest.split_once('-')?;
        if number.parse::<u64>().is_ok_and(|n| n > 0) && sha(base) {
            return Some((
                format!("git/ref/{}", reference.strip_prefix("refs/")?),
                true,
            ));
        }
    }
    if let Some(number) = reference.strip_prefix("refs/pull/")?.strip_suffix("/merge")
        && number.parse::<u64>().is_ok_and(|n| n > 0)
    {
        return Some((format!("pulls/{number}"), false));
    }
    None
}

fn response(raw: &[u8]) -> Result<Option<Value>> {
    let raw = std::str::from_utf8(raw)?;
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .context("complete GitHub response required")?;
    let status = headers.lines().next().context("GitHub status required")?;
    ensure!(status.starts_with("HTTP/"), "GitHub HTTP status required");
    match status.split_whitespace().nth(1) {
        Some("200") => Ok(Some(serde_json::from_str(body)?)),
        Some("404") => Ok(None),
        _ => bail!("GitHub inventory read refused: {status}"),
    }
}

fn api(root: &Path, endpoint: &str, started: Instant) -> Result<Option<Value>> {
    let budget = Duration::from_secs(120)
        .checked_sub(started.elapsed())
        .context("cache inventory budget exhausted")?;
    let file = tempfile::NamedTempFile::new()?;
    let mut command = Command::new("gh");
    command
        .args([
            "api",
            "--hostname",
            "github.com",
            "--include",
            "--method",
            "GET",
            "--header",
            "Cache-Control: no-cache",
        ])
        .arg(format!("repos/{REPOSITORY}/{endpoint}"))
        .env_remove("GH_DEBUG")
        .stdout(Stdio::from(file.reopen()?))
        .stderr(Stdio::null());
    let status =
        crate::command_status_with_budget(root, &mut command, budget.min(Duration::from_secs(30)))
            .map_err(|_| anyhow::anyhow!("cache inventory child did not complete"))?;
    ensure!(
        matches!(status.code(), Some(0 | 1)),
        "cache inventory child failed"
    );
    ensure!(
        file.as_file().metadata()?.len() <= 1024 * 1024,
        "cache metadata byte budget"
    );
    let value = response(&fs::read(file.path())?)?;
    ensure!(
        status.success() || value.is_none(),
        "cache inventory child failed after a response"
    );
    Ok(value)
}

fn collect(mut request: impl FnMut(usize) -> Result<Page>) -> Result<Vec<Cache>> {
    let first = request(1)?;
    let count = first.total_count;
    ensure!(count <= MAX_CACHES, "cache inventory count budget");
    let mut caches = first.actions_caches;
    for page in 2..=count.div_ceil(100) {
        let next = request(page)?;
        ensure!(
            next.total_count == count,
            "cache inventory changed during pagination"
        );
        caches.extend(next.actions_caches);
    }
    let ids: BTreeSet<_> = caches.iter().map(|c| c.id).collect();
    ensure!(
        caches.len() == count
            && ids.len() == count
            && !ids.contains(&0)
            && ids.iter().all(|id| *id <= 9_007_199_254_740_991),
        "complete unique cache inventory required"
    );
    ensure!(
        caches
            .iter()
            .all(|c| c.key.len() <= 512 && c.reference.len() <= 256),
        "cache metadata field budget"
    );
    Ok(caches)
}

fn inventory(root: &Path, platform: &str, preview: bool) -> Result<Inventory> {
    ensure!(
        ["linux", "mac"].contains(&platform),
        "closed cache platform required"
    );
    let started = Instant::now();
    let current = api(root, "git/ref/heads/main", started)?.context("main ref required")?["object"]
        ["sha"]
        .as_str()
        .context("main SHA required")?
        .to_owned();
    ensure!(sha(&current), "exact main SHA required");
    let publishing = if preview {
        current.clone()
    } else {
        ensure!(
            std::env::var("GITHUB_REPOSITORY")? == REPOSITORY
                && std::env::var("GITHUB_EVENT_NAME")? == "push"
                && std::env::var("GITHUB_REF")? == "refs/heads/main",
            "cache retention is main-push only"
        );
        let value = std::env::var("GITHUB_SHA")?;
        ensure!(sha(&value), "exact publishing SHA required");
        value
    };
    let caches = collect(|page| {
        let value = api(
            root,
            &format!("actions/caches?per_page=100&page={page}&sort=created_at&direction=desc"),
            started,
        )?
        .context("cache inventory unavailable")?;
        Ok(serde_json::from_value(value)?)
    })?;
    // Refs and PRs can close before their workflows finish. Preserve every
    // running/waiting allocation as well as refs that still exist.
    let mut active = BTreeSet::new();
    let mut active_pr_branches = BTreeSet::new();
    for event in ["merge_group", "pull_request"] {
        if !caches.iter().any(|cache| {
            owned(&cache.key, platform)
                && retired_endpoint(&cache.reference)
                    .is_some_and(|(_, queue)| queue == (event == "merge_group"))
        }) {
            continue;
        }
        for status in ["in_progress", "queued", "waiting", "pending", "requested"] {
            let value = api(
                root,
                &format!("actions/runs?event={event}&status={status}&per_page=100"),
                started,
            )?
            .context("active CI inventory unavailable")?;
            let runs = value["workflow_runs"]
                .as_array()
                .context("CI run inventory required")?;
            ensure!(
                value["total_count"].as_u64() == Some(runs.len() as u64) && runs.len() <= 100,
                "complete active CI inventory required"
            );
            for run in runs {
                let branch = run["head_branch"]
                    .as_str()
                    .context("CI run branch required")?;
                active.insert(format!("refs/heads/{branch}"));
                if event == "pull_request" {
                    active_pr_branches.insert(branch.to_owned());
                }
            }
        }
    }
    let mut retired = BTreeMap::new();
    let mut entries = Vec::new();
    for cache in caches.into_iter().filter(|c| owned(&c.key, platform)) {
        let (family, generation, canonical) = compiler(&cache.key, platform).unwrap_or_default();
        let shared = cache.reference == "refs/heads/main" && !family.is_empty();
        let closed = if active.contains(&cache.reference) {
            false
        } else if let Some(closed) = retired.get(&cache.reference) {
            *closed
        } else {
            ensure!(retired.len() < 64, "cache ref inspection budget");
            let closed = match retired_endpoint(&cache.reference) {
                Some((endpoint, queue)) => match api(root, &endpoint, started)? {
                    None => queue,
                    Some(value) => {
                        !queue
                            && value["state"] == "closed"
                            && !active_pr_branches.contains(
                                value["head"]["ref"]
                                    .as_str()
                                    .context("PR head ref required")?,
                            )
                    }
                },
                None => false,
            };
            retired.insert(cache.reference, closed);
            closed
        };
        entries.push(Entry {
            id: cache.id,
            family,
            generation,
            canonical,
            shared,
            retired: closed,
        });
    }
    let families = if platform == "linux" {
        vec!["linux-bootstrap".into(), "linux-tests".into()]
    } else {
        vec!["mac".into()]
    };
    Ok(Inventory {
        caches: entries,
        publishing,
        current,
        families,
    })
}

fn emit(plan: &Plan, snapshot: &Inventory, preview: bool) -> Result<()> {
    let ids: BTreeSet<_> = plan.include.iter().map(|c| c.id).collect();
    ensure!(
        ids.len() == plan.include.len() && ids.len() <= MAX_DELETIONS,
        "bounded unique cache plan required"
    );
    ensure!(
        ids.iter().all(|id| snapshot
            .caches
            .iter()
            .any(|c| c.id == *id && (c.shared || c.retired))),
        "unowned cache deletion refused"
    );
    for family in &snapshot.families {
        for head in [&snapshot.current, &snapshot.publishing] {
            let protected: Vec<_> = snapshot
                .caches
                .iter()
                .filter(|c| c.shared && c.family == *family && c.generation == *head)
                .collect();
            ensure!(
                protected.is_empty() || protected.iter().any(|c| !ids.contains(&c.id)),
                "last current compiler cache deletion refused"
            );
        }
    }
    println!(
        "Cache retention plan: {} deletions, {} deferred",
        ids.len(),
        plan.deferred
    );
    if preview {
        println!("{}", serde_json::to_string_pretty(plan)?);
        return Ok(());
    }
    let path = PathBuf::from(std::env::var("GITHUB_OUTPUT")?);
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    ensure!(
        path.starts_with(&temporary)
            && fs::symlink_metadata(&path)?.is_file()
            && path.canonicalize()? == path,
        "runner-owned cache output required"
    );
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    writeln!(
        file,
        "cache_matrix={}",
        serde_json::to_string(&json!({"include": plan.include}))?
    )?;
    writeln!(file, "cache_count={}", ids.len())?;
    Ok(())
}

pub fn execute(root: &Path, platform: &str, preview: bool) -> Result<()> {
    let runner = crate::workflows::build(root)?;
    let mut snapshot = None;
    let mut emitted = false;
    day2::automation::run(
        &runner,
        &["ci-cache-plan", platform],
        |request| match request.action.as_str() {
            "ci-cache-inventory" => {
                let args: BTreeMap<String, String> = request.decode()?;
                ensure!(
                    args.len() == 1
                        && args.get("target").is_some_and(|p| p == platform)
                        && snapshot.is_none(),
                    "closed cache inventory request required"
                );
                let value = inventory(root, platform, preview)?;
                let raw = serde_json::to_value(&value)?;
                snapshot = Some(value);
                Ok(raw)
            }
            "ci-cache-plan-output" => {
                let plan: Plan = request.decode()?;
                let inventory = snapshot
                    .take()
                    .context("cache inventory required before output")?;
                ensure!(!emitted, "cache output may be emitted only once");
                emit(&plan, &inventory, preview)?;
                emitted = true;
                Ok(json!({}))
            }
            _ => bail!("unknown cache planning capability"),
        },
    )?;
    ensure!(emitted, "cache plan output required");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_tokens_are_confined_to_main_jobs_after_publication() {
        let linux = include_str!("../../../.github/workflows/ci.yml");
        let mac = include_str!("../../../.github/workflows/mac-compatibility.yml");
        for (source, name) in [(linux, "cleanup-linux-caches"), (mac, "cleanup-mac-caches")] {
            let rest = source.split_once(&format!("\n  {name}:\n")).unwrap().1;
            let job = rest
                .lines()
                .take_while(|line| !line.starts_with("  ") || line.starts_with("    "))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(job.contains("github.event_name == 'push' && github.ref == 'refs/heads/main'"));
            assert!(job.contains("cache_count != '0'"));
            assert!(job.contains("actions: write") && job.contains("max-parallel: 1"));
            assert!(job.contains("actions/caches/${{ matrix.id }}"));
            assert!(job.contains("Require the newly published shared compiler cache"));
            assert!(job.contains("shared compiler cache not published; cleanup refused"));
        }
        assert!(linux.contains("needs.publish-linux-actions.outputs.published == 'true'"));
        assert!(mac.contains("steps.compiler_cache.outcome == 'success'"));
        assert_eq!(linux.matches("actions: write").count(), 1);
        assert_eq!(mac.matches("actions: write").count(), 1);
    }

    #[test]
    fn only_exact_owned_compiler_generations_are_recognized() {
        let head = "a".repeat(40);
        let base = format!("day2-bazel-actions-v1-Linux-X64-verify-prepare-parts-tests-{head}");
        assert_eq!(
            compiler(&base, "linux"),
            Some(("linux-tests".into(), head.clone(), true))
        );
        assert_eq!(
            compiler(&format!("{base}-123-2"), "linux"),
            Some(("linux-tests".into(), head, false))
        );
        for tail in ["-123", "-0-1", "-1-2-extra", "/../../other"] {
            assert!(compiler(&format!("{base}{tail}"), "linux").is_none());
        }
        assert!(compiler(&base, "mac").is_none());
        assert!(!owned("other-Linux-X64-", "linux"));
    }

    #[test]
    fn only_closed_pr_or_exact_queue_refs_can_be_retired() {
        assert_eq!(
            retired_endpoint("refs/pull/12/merge"),
            Some(("pulls/12".into(), false))
        );
        assert!(
            retired_endpoint(&format!(
                "refs/heads/gh-readonly-queue/main/pr-12-{}",
                "a".repeat(40)
            ))
            .is_some()
        );
        for value in [
            "refs/heads/main",
            "refs/heads/feature",
            "refs/pull/0/merge",
            "refs/pull/12/head",
            "refs/heads/gh-readonly-queue/main/pr-12-bad",
        ] {
            assert!(retired_endpoint(value).is_none());
        }
    }

    #[test]
    fn only_a_real_http_404_proves_absence() -> Result<()> {
        assert!(
            response(b"HTTP/2.0 404 Not Found\r\ncontent-type: application/json\r\n\r\n{}")?
                .is_none()
        );
        for raw in [
            b"HTTP/2.0 403 Forbidden\n\n{\"status\":\"404\"}".as_slice(),
            b"HTTP/2.0 500 Error\n\n{}",
            b"{\"status\":\"404\"}",
        ] {
            assert!(response(raw).is_err());
        }
        Ok(())
    }

    #[test]
    fn incomplete_duplicate_or_changing_inventories_are_refused() {
        let cache = || Cache {
            id: 1,
            key: "key".into(),
            reference: "refs/heads/main".into(),
        };
        assert!(
            collect(|_| Ok(Page {
                total_count: 2,
                actions_caches: vec![cache()]
            }))
            .is_err()
        );
        assert!(
            collect(|_| Ok(Page {
                total_count: 2,
                actions_caches: vec![cache(), cache()]
            }))
            .is_err()
        );
        assert!(
            collect(|n| Ok(Page {
                total_count: if n == 1 { 101 } else { 100 },
                actions_caches: vec![]
            }))
            .is_err()
        );
        assert!(
            collect(|_| Ok(Page {
                total_count: MAX_CACHES + 1,
                actions_caches: vec![]
            }))
            .is_err()
        );
    }

    #[test]
    fn native_guard_preserves_the_last_current_cache_and_unowned_ids() -> Result<()> {
        let snapshot = Inventory {
            caches: vec![Entry {
                id: 1,
                family: "mac".into(),
                generation: "current".into(),
                shared: true,
                retired: false,
                canonical: true,
            }],
            current: "current".into(),
            publishing: "current".into(),
            families: vec!["mac".into()],
        };
        assert!(
            emit(
                &Plan {
                    include: vec![Deletion { id: 1 }],
                    deferred: 0
                },
                &snapshot,
                true
            )
            .is_err()
        );
        assert!(
            emit(
                &Plan {
                    include: vec![Deletion { id: 2 }],
                    deferred: 0
                },
                &snapshot,
                true
            )
            .is_err()
        );
        Ok(())
    }
}
