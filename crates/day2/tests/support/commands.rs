#![allow(dead_code)]
use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
    invocations,
    store::{Fault, Runtime},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

pub struct World {
    pub directory: tempfile::TempDir,
    pub runtime: Runtime,
}
impl World {
    pub fn new() -> Result<Self> {
        Self::artifact("DAY2_TEST_REPORTS_ARTIFACT")
    }
    pub fn artifact(variable: &str) -> Result<Self> {
        let world = Self::uninitialized(variable)?;
        world.runtime.initialize()?;
        Ok(world)
    }
    pub fn uninitialized(variable: &str) -> Result<Self> {
        let artifact = std::env::var_os(variable)
            .map(PathBuf::from)
            .context("run xtask verify-reports with compiled fixtures")?;
        let directory = tempfile::tempdir()?;
        let policy: Value = serde_json::from_str(include_str!(
            "../../../../fixtures/authority-policies/reports.json"
        ))?;
        let (resources, resource_policies) = day2::development::local_resource_fixture(
            "reports",
            &serde_json::from_value(policy.clone())?,
            Some(day2_capabilities::resources::TopicScope::Any),
            None,
        )?;
        let instance = json!({"installation":"commandsco","environment":"test","resources":resources,"apps":{"reports":{
            "artifact":artifact,"readers":["viewer"],"writers":["alice","bob","admin"],"authority":policy,"resource_policies":resource_policies
        }}});
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "reports")?;
        Ok(Self { directory, runtime })
    }
    pub fn submit(&self, id: &str, fault: Fault) -> Result<day2::protocol::Outcome> {
        self.runtime.invoke(
            "reports.submit",
            "alice",
            id,
            &json!({"title":"Quarterly report","text":"first line\nsecond line"}),
            100,
            fault,
        )
    }
    pub fn child(&self, parent: &str) -> Result<String> {
        let children = invocations::children(&self.runtime, parent)?;
        assert_eq!(children.len(), 1);
        Ok(children[0].id.clone())
    }
    pub fn finish(&self, id: &str) -> Result<day2::protocol::Outcome> {
        let mut result = self.runtime.execute(id, Fault::None)?;
        for _ in 0..4 {
            if result.status != "pending" {
                return Ok(result);
            }
            result = self.runtime.execute(id, Fault::None)?;
        }
        anyhow::bail!("invocation did not complete")
    }
    pub fn properties(&self) -> Result<()> {
        day2::properties::require(
            self.runtime.artifact(),
            &self.runtime.inspect()?,
            &self.directory.path().join("properties"),
        )?;
        Ok(())
    }
    pub fn change_policy(&self, change: impl FnOnce(&mut day2::authority::Policy)) -> Result<()> {
        let mut instance = Instance::load(self.runtime.instance_path())?;
        change(
            instance
                .apps
                .get_mut("reports")
                .context("app")?
                .authority
                .as_mut()
                .context("authority")?,
        );
        fs::write(self.runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let active =
            day2::authority_state::current(&rusqlite::Connection::open(self.runtime.db())?)?;
        day2::authority_state::apply_desired(
            &self.runtime,
            &day2::authority_state::LocalOperator::assert_local("test-operator")?,
            &format!("test-policy-{}", active.stamp.revision + 1),
            Some(active.stamp),
        )?;
        Ok(())
    }
    pub fn detail(&self, report: &Value, id: &str) -> Result<Value> {
        let outcome = self.runtime.invoke(
            "reports.detail",
            "alice",
            id,
            &json!({"report_id":report}),
            101,
            Fault::None,
        )?;
        assert_eq!(outcome.status, "success", "{}", outcome.error);
        Ok(outcome.result)
    }
}
