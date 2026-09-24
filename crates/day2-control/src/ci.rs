//! Central GitHub event ingress. A trusted host supplies the approved build plan
//! and provider binding; webhook bodies never choose a recipe, URL, credential,
//! app, runner or tenant. No Actions workflow is needed in an app repository.
use crate::{
    BuildPlan, Digest, GitOid, Name,
    engine::ExecutionHost,
    source::{CHECK_NAME, GithubBinding},
};
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

pub struct Receiver {
    installation_id: u64,
    repository: GithubBinding,
    approved: BuildPlan,
    secret: Vec<u8>,
}

impl Receiver {
    /// Called by the trusted control host after selecting its installation/app
    /// binding. This is an adapter, not another instance configuration model.
    pub fn new(
        installation_id: u64,
        repository: GithubBinding,
        approved: BuildPlan,
        secret: Vec<u8>,
    ) -> Result<Self> {
        repository.validate()?;
        approved.validate()?;
        ensure!(
            installation_id > 0 && repository.checks.is_some(),
            "GitHub App installation and check binding required"
        );
        ensure!(
            (32..=8192).contains(&secret.len()),
            "webhook secret byte budget"
        );
        ensure!(
            approved.profile.recipe == crate::build::recipe_digest(),
            "central CI requires the platform recipe"
        );
        Ok(Self {
            installation_id,
            repository,
            approved,
            secret,
        })
    }

    pub fn accept(
        &self,
        host: &ExecutionHost,
        delivery: &str,
        event: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<Option<Digest>> {
        let Some(plan) = self.plan(delivery, event, signature, body)? else {
            return Ok(None);
        };
        // The journal deduplicates deliveries, rejects key reuse with a changed
        // SHA/profile, and atomically records the Temporal dispatch outbox.
        host.accept_as(&plan, &format!("github-app:{}", self.installation_id))
            .map(Some)
    }

    pub fn plan(
        &self,
        delivery: &str,
        event: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<Option<BuildPlan>> {
        ensure!(body.len() <= 1_048_576, "webhook byte budget");
        ensure!(
            !delivery.is_empty()
                && delivery.len() <= 80
                && delivery
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid delivery identity"
        );
        let hex = signature
            .strip_prefix("sha256=")
            .context("GitHub SHA-256 signature required")?;
        ensure!(
            hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid signature encoding"
        );
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<std::result::Result<_, _>>()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)?;
        mac.update(body);
        mac.verify_slice(&bytes)
            .context("webhook authentication failed")?;
        let payload: Value = day2::json::decode(body)?;
        ensure!(
            payload["installation"]["id"].as_u64() == Some(self.installation_id),
            "wrong GitHub App installation"
        );
        ensure!(
            payload["repository"]["id"].as_u64() == Some(self.repository.repository_id)
                && payload["repository"]["name"].as_str()
                    == Some(self.repository.repository.as_str())
                && payload["repository"]["owner"]["login"].as_str()
                    == Some(self.repository.owner.as_str()),
            "wrong repository authority"
        );
        // Roc owns trigger policy; only authenticated, repository-bound events
        // reach it. The adapter below retains commit/source/check authority.
        let decision = day2::automation::run(
            &day2::automation::runner()?,
            &[
                "ci-event",
                event,
                payload["action"].as_str().unwrap_or(""),
                if payload["deleted"] == true {
                    "true"
                } else {
                    "false"
                },
            ],
            |_| anyhow::bail!("CI trigger policy must be pure"),
        )?;
        if !decision["run"].as_bool().context("CI trigger decision")? {
            return Ok(None);
        }
        let commit = match event {
            "push" => {
                ensure!(
                    payload["ref"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("refs/heads/")),
                    "CI push must target a branch"
                );
                payload["after"].as_str()
            }
            "pull_request" => {
                // Fork fetching needs an explicit source binding. Do not silently
                // grant a base-repo runner authority to a payload-selected URL.
                ensure!(
                    payload["pull_request"]["head"]["repo"]["id"].as_u64()
                        == Some(self.repository.repository_id)
                        && payload["pull_request"]["base"]["repo"]["id"].as_u64()
                            == Some(self.repository.repository_id),
                    "fork CI needs an approved source binding"
                );
                payload["pull_request"]["head"]["sha"].as_str()
            }
            "merge_group" => payload["merge_group"]["head_sha"].as_str(),
            "check_run" => {
                ensure!(
                    payload["check_run"]["name"] == CHECK_NAME
                        && payload["check_run"]["app"]["id"].as_u64()
                            == self.repository.checks.as_ref().map(|checks| checks.app_id),
                    "rerun check identity mismatch"
                );
                payload["check_run"]["head_sha"].as_str()
            }
            _ => anyhow::bail!("unsupported source event"),
        }
        .context("event lacks exact commit")?;
        ensure!(
            commit != "0000000000000000000000000000000000000000",
            "deleted commit cannot be built"
        );
        let mut plan = self.approved.clone();
        plan.commit = GitOid::try_from(commit.to_owned())?;
        // Body/event are deliberately not in the idempotency key. Reusing a
        // delivery with a changed commit must conflict in the journal.
        plan.request = Name::try_from(
            Digest::of(&(
                "github-delivery-v1",
                self.installation_id,
                self.repository.repository_id,
                delivery,
            ))?
            .as_str()[7..]
                .to_owned(),
        )?;
        Ok(Some(plan))
    }
}
