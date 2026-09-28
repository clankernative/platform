#![allow(dead_code)]
use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
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
        let artifact = std::env::var_os("DAY2_TEST_ONCALL_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify-reports with the on-call fixture built")?;
        let directory = tempfile::tempdir()?;
        let policy: Value = serde_json::from_str(include_str!(
            "../../../../fixtures/authority-policies/oncall.json"
        ))?;
        let policy_value: day2::authority::Policy = serde_json::from_value(policy.clone())?;
        let (resources, resource_policies) =
            day2::development::local_resource_fixture("oncall", &policy_value, None, None)?;
        let instance = json!({"installation":"example","environment":"test","resources":resources,"apps":{"oncall":{
            "artifact":artifact,"readers":[],"writers":["alice","admin"],"authority":policy,"resource_policies":resource_policies
        }}});
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "oncall")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }

    pub fn open(&self, id: &str, title: &str, now: i64) -> Result<day2::protocol::Outcome> {
        self.runtime.invoke(
            "oncall.open",
            "alice",
            id,
            &json!({"title":title}),
            now,
            Fault::None,
        )
    }

    pub fn acknowledge(
        &self,
        id: &str,
        request_id: &str,
        version: u64,
        now: i64,
    ) -> Result<day2::protocol::Outcome> {
        self.runtime.invoke(
            "oncall.acknowledge",
            "alice",
            request_id,
            &json!({"incident_id":id,"expected_version":version}),
            now,
            Fault::None,
        )
    }

    pub fn incident(&self, id: &str) -> Result<Value> {
        let mut row = self.runtime.inspect()?["incidents"]
            .as_array()
            .context("incidents")?
            .iter()
            .find(|row| row["id"] == id)
            .cloned()
            .context("incident row")?;
        row["data"] = serde_json::from_str(row["data"].as_str().context("incident data")?)?;
        Ok(row)
    }

    pub fn change_policy(&self, change: impl FnOnce(&mut day2::authority::Policy)) -> Result<()> {
        let mut instance = Instance::load(self.runtime.instance_path())?;
        change(
            instance
                .apps
                .get_mut("oncall")
                .context("app")?
                .authority
                .as_mut()
                .context("authority")?,
        );
        fs::write(self.runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let connection = rusqlite::Connection::open(self.runtime.db())?;
        let active = day2::authority_state::current(&connection)?;
        day2::authority_state::apply_desired(
            &self.runtime,
            &day2::authority_state::LocalOperator::assert_local("test-operator")?,
            &format!("oncall-policy-{}", active.stamp.revision + 1),
            Some(active.stamp),
        )?;
        Ok(())
    }
}
