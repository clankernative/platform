use super::*;
use crate::instance_source::tests::{BUCKET, Fake, REGISTRY, manifest};
use std::fs;

const GOLDEN_INPUTS: &str = include_str!("../../../../cli/fixtures/ci-workflow-inputs.json");

/// The source adapter's fake bucket, with a project number when the
/// credentials may read one.
struct Project(Fake, Option<&'static str>);

impl instance_release::Tools for Project {
    fn describe(&mut self, uri: &str) -> Result<String> {
        self.0.describe(uri)
    }

    fn download(&mut self, uri: &str, generation: &str, destination: &Path) -> Result<()> {
        self.0.download(uri, generation, destination)
    }

    fn create(&mut self, _source: &Path, _uri: &str) -> Result<instance_release::Created> {
        bail!("ci-workflow never publishes")
    }

    fn pull(&mut self, _image: &str) -> Result<()> {
        bail!("ci-workflow never pulls")
    }

    fn image_id(&mut self, _image: &str) -> Result<String> {
        bail!("ci-workflow never inspects images")
    }

    fn project_number(&mut self, project: &str) -> Result<String> {
        assert_eq!(project, "exampleco-tools");
        self.1
            .map(|number| format!("{number}\n"))
            .context("PERMISSION_DENIED")
    }
}

/// An instance whose two apps select the same published release.
struct World {
    fake: Fake,
    directory: tempfile::TempDir,
    sdk: String,
}

impl World {
    fn new() -> Self {
        let fake = Fake::default();
        let release = manifest();
        let reference = BlobIdentity::of(&release);
        fake.0.borrow_mut().objects.insert(
            format!(
                "gs://{BUCKET}/{}/{}",
                instance_release::OBJECTS,
                reference.check(u64::MAX).unwrap()
            ),
            release,
        );
        Self {
            fake,
            directory: tempfile::tempdir().unwrap(),
            sdk: reference.digest,
        }
    }

    fn request(&self, change: impl FnOnce(&mut Value)) -> PathBuf {
        let mut value = json!({
            "project": "exampleco-tools",
            "registry": REGISTRY,
            "bucket": BUCKET,
            "apps": [{"id": "go", "sdk": self.sdk}, {"id": "home", "sdk": self.sdk}],
        });
        change(&mut value);
        let path = self.directory.path().join("request.json");
        fs::write(&path, value.to_string()).unwrap();
        path
    }

    fn effects(&self, number: Option<&'static str>) -> Effects {
        Effects {
            tools: Box::new(Project(self.fake.clone(), number)),
            cache: Some(self.directory.path().join("cache")),
        }
    }

    fn inputs(&self, number: Option<&'static str>) -> Result<Value> {
        let mut session = Session::prepare(&self.request(|_| {}), self.effects(number))?;
        session.step("project")?;
        session.step("releases")
    }
}

#[test]
fn each_apps_tooling_image_is_its_selected_releases() -> Result<()> {
    let world = World::new();
    let report: Report = serde_json::from_value(world.inputs(Some("123456789012"))?)?;
    let tooling = format!("{REGISTRY}/links/day2-tooling@{}", day2::digest(b"tooling"));
    let distribution = BlobIdentity::of(b"distribution").digest;
    assert_eq!(
        report,
        Report {
            format: 1,
            project_number: "123456789012".into(),
            apps: vec![
                Tooling {
                    id: "go".into(),
                    tooling_image: tooling.clone(),
                    distribution: distribution.clone(),
                },
                Tooling {
                    id: "home".into(),
                    tooling_image: tooling,
                    distribution,
                },
            ],
        }
    );
    Ok(())
}

#[test]
fn a_missing_number_or_release_fails_closed() {
    let world = World::new();
    assert!(format!("{:#}", world.inputs(None).unwrap_err()).contains("PERMISSION_DENIED"));
    let world = World::new();
    assert!(format!("{:#}", world.inputs(Some("12a")).unwrap_err()).contains("no project number"));
    // An sdk that was never published.
    let world = World::new();
    let path = world.request(|value| {
        value["apps"][1]["sdk"] = json!(format!("sha256:{}", "0".repeat(64)));
    });
    let mut session = Session::prepare(&path, world.effects(Some("1"))).unwrap();
    session.step("project").unwrap();
    assert!(session.step("releases").is_err());
}

#[test]
fn the_request_is_one_instances_names() {
    let world = World::new();
    for change in [
        json!({"project": "Exampleco"}),
        json!({"bucket": "exampleco-tools-state"}),
        json!({"registry": "us-central1-docker.pkg.dev/other-project"}),
        json!({"apps": []}),
        json!({"apps": [{"id": "home", "sdk": world.sdk}, {"id": "go", "sdk": world.sdk}]}),
        json!({"apps": [{"id": "day2ci", "sdk": world.sdk}]}),
        json!({"apps": [{"id": "go", "sdk": "sha256:short"}]}),
        json!({"extra": 1}),
    ] {
        let path = world.request(|value| {
            for (key, field) in change.as_object().unwrap() {
                value[key] = field.clone();
            }
        });
        assert!(
            Session::prepare(&path, world.effects(Some("1"))).is_err(),
            "{change}"
        );
    }
}

#[test]
fn steps_run_once_in_order() -> Result<()> {
    let world = World::new();
    let mut session = Session::prepare(&world.request(|_| {}), world.effects(Some("7")))?;
    assert!(format!("{:#}", session.step("releases").unwrap_err()).contains("runs project next"));
    session.step("project")?;
    assert!(session.step("project").is_err());
    session.step("releases")?;
    assert!(format!("{:#}", session.step("releases").unwrap_err()).contains("nothing more"));
    Ok(())
}

#[test]
fn the_report_is_the_shape_the_cli_decodes() -> Result<()> {
    let golden: Report = serde_json::from_str(GOLDEN_INPUTS)?;
    assert_eq!(
        serde_json::to_value(&golden)?,
        serde_json::from_str::<Value>(GOLDEN_INPUTS)?
    );
    Ok(())
}
