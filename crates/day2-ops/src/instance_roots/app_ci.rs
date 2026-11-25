//! App CI's forge IDs (docs/INSTANCE.md, "App CI"). With `forge.oidc`, the CLI
//! renders the project root's workload identity federation and each app edge's
//! results bucket, and names the repository each one trusts: `<org>/day2-ci`
//! for the project root, `<org>/<app>` for an app edge. The trust is pinned to
//! the forge's native IDs, which are discovered, never configured: every plan
//! and apply reads them from the forge, as `instance source` reads a binding's
//! repository, and passes them as the root's `forge.tfvars.json`. Without
//! `forge.oidc` no root names a repository and nothing is read.

use super::Request;
use crate::instance_source::Forge;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

/// The variables app CI owns in the project and app-edge stacks: rendered
/// (`app_ci`) and read from the forge (`app_ci_forge`). An instance may commit
/// neither.
pub const OWNED: [&str; 2] = ["app_ci", "app_ci_forge"];

/// Whether a stack has app CI variables.
pub fn stack(stack: &str) -> bool {
    stack == "project" || stack == "app-edge"
}

/// The app CI variables a committed input assigns, on any line, indented or
/// not: an instance never configures its own federation.
pub fn restated(committed: &[u8]) -> Vec<&'static str> {
    let lines: Vec<&[u8]> = committed
        .split(|byte| *byte == b'\n')
        .map(|line| {
            let start = line
                .iter()
                .position(|byte| *byte != b' ' && *byte != b'\t')
                .unwrap_or(line.len());
            &line[start..]
        })
        .collect();
    super::release::restated(&lines.join(&b'\n'), &OWNED)
}

/// App CI is all or nothing: with it, the project root and every app edge name
/// their derived repository in the instance's org and render `app_ci`; without
/// it, no root does either. No root renders the IDs this module reads.
pub fn validate(request: &Request) -> Result<()> {
    let enabled = request
        .roots
        .iter()
        .any(|root| root.app_ci_repository.is_some());
    for root in &request.roots {
        let variables: Value =
            day2::json::decode(root.variables.as_bytes()).context("rendered variables")?;
        let expected = match (enabled, root.stack.as_str(), &root.app_id) {
            (true, "project", None) => Some(format!("{}/day2-ci", org(request)?)),
            (true, "app-edge", Some(app)) => Some(format!("{}/{app}", org(request)?)),
            _ => None,
        };
        ensure!(
            root.app_ci_repository == expected
                && variables.get("app_ci").is_some() == expected.is_some(),
            "{} renders app CI only with forge.oidc, as every project and app-edge root does, \
             and trusts only its derived repository",
            root.label
        );
        ensure!(
            variables.get("app_ci_forge").is_none(),
            "{} renders app_ci_forge, which is read from the forge",
            root.label
        );
    }
    Ok(())
}

fn org(request: &Request) -> Result<&str> {
    Ok(&request
        .releases
        .as_ref()
        .context("app CI needs the instance's forge")?
        .forge
        .org)
}

/// The forge IDs a root's app CI variable is pinned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub repository: u64,
    pub owner: u64,
}

/// The repository's record, which must be exactly `repository` in `org`.
pub(crate) fn read(forge: &mut Forge<'_>, repository: &str, org: &str) -> Result<Ids> {
    let value = forge.repository()?;
    ensure!(
        value["full_name"] == repository && value["owner"]["login"] == org,
        "forge_repository_mismatch"
    );
    let id = |value: &Value| value.as_u64().filter(|id| *id > 0);
    Ok(Ids {
        repository: id(&value["id"]).context("forge_repository_id_invalid")?,
        owner: id(&value["owner"]["id"]).context("forge_owner_id_invalid")?,
    })
}

/// A root's `forge.tfvars.json`: the project root pins the CI repository and
/// its org; an app edge pins its app's repository.
pub fn variables(stack: &str, ids: Ids) -> Result<Vec<u8>> {
    let forge = match stack {
        "project" => json!({
            "repository_id": ids.repository.to_string(),
            "owner_id": ids.owner.to_string(),
        }),
        "app-edge" => json!({"repository_id": ids.repository.to_string()}),
        _ => bail!("{stack} has no app CI"),
    };
    Ok(serde_json::to_vec(&json!({"app_ci_forge": forge}))?)
}
