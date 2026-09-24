//! A closed graph -> OpenTofu JSON adapter. Strings are literals, references are
//! explicit graph edges, resource addresses are stable keys, and the engine is
//! pinned by both version and bytes. No expression strings or provisioners.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub name: String,
    pub kind: String,
    pub value: String,
    pub target: String,
    pub attribute: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub key: String,
    pub inputs: Vec<Input>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub format: u32,
    pub resources: Vec<Resource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Engine {
    path: String,
    version: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    format: u32,
    installation: String,
    environment: String,
    apps: Vec<String>,
    engine: Engine,
}

fn configuration(path: &Path) -> Result<(Configuration, String)> {
    ensure!(
        fs::metadata(path)?.len() <= 65_536,
        "infrastructure configuration budget"
    );
    let bytes = fs::read(path)?;
    let configuration: Configuration = serde_json::from_slice(&bytes)?;
    ensure!(
        configuration.format == 1
            && !configuration.apps.is_empty()
            && configuration.apps.len() <= 32,
        "infrastructure configuration version or app count"
    );
    day2::schema::identifier(&configuration.installation)?;
    day2::schema::identifier(&configuration.environment)?;
    let mut apps = BTreeSet::new();
    for app in &configuration.apps {
        day2::schema::identifier(app)?;
        ensure!(apps.insert(app), "duplicate infrastructure app");
    }
    ensure!(
        configuration.engine.version.split('.').count() == 3
            && configuration
                .engine
                .version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'),
        "numeric engine version required"
    );
    ensure!(
        configuration.engine.sha256.len() == 64
            && configuration
                .engine
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "engine digest required"
    );
    Ok((configuration, day2::digest(&bytes)))
}

pub fn settings(path: &Path) -> Result<Value> {
    let (configuration, digest) = configuration(path)?;
    Ok(
        json!({"installation":configuration.installation,"environment":configuration.environment,"apps":configuration.apps,"configuration_digest":digest}),
    )
}

pub fn render(graph: &Graph, version: &str) -> Result<Value> {
    ensure!(
        graph.format == 1 && !graph.resources.is_empty() && graph.resources.len() <= 64,
        "resource graph version or size"
    );
    let mut resources = BTreeMap::new();
    let mut dependencies: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for resource in &graph.resources {
        day2::schema::identifier(&resource.key)?;
        ensure!(
            !resources.contains_key(&resource.key),
            "duplicate resource address"
        );
        ensure!(
            !resource.inputs.is_empty() && resource.inputs.len() <= 32,
            "resource input count"
        );
        let mut fields = BTreeMap::new();
        let mut edges = BTreeSet::new();
        for input in &resource.inputs {
            day2::schema::identifier(&input.name)?;
            ensure!(
                !fields.contains_key(&input.name),
                "duplicate resource input"
            );
            let value = match input.kind.as_str() {
                "literal" => {
                    ensure!(
                        input.value.len() <= 4096
                            && input.target.is_empty()
                            && input.attribute.is_empty(),
                        "invalid literal"
                    );
                    input.value.replace("${", "$${").replace("%{", "%%{")
                }
                "reference" => {
                    day2::schema::identifier(&input.target)?;
                    ensure!(
                        input.value.is_empty() && input.attribute == "output",
                        "unsupported deferred reference"
                    );
                    edges.insert(input.target.as_str());
                    format!("${{terraform_data.{}.output}}", input.target)
                }
                _ => anyhow::bail!("unsupported graph input"),
            };
            fields.insert(&input.name, value);
        }
        dependencies.insert(&resource.key, edges);
        resources.insert(resource.key.clone(), json!({"input":fields}));
    }
    let mut complete = BTreeSet::new();
    while complete.len() < dependencies.len() {
        let before = complete.len();
        for (key, edges) in &dependencies {
            ensure!(
                edges.iter().all(|edge| dependencies.contains_key(edge)),
                "dangling resource reference"
            );
            if edges.iter().all(|edge| complete.contains(edge)) {
                complete.insert(*key);
            }
        }
        ensure!(complete.len() > before, "cyclic infrastructure graph");
    }
    Ok(
        json!({"terraform":{"required_version":format!("= {version}")},"resource":{"terraform_data":resources}}),
    )
}

/// A private, pinned planning directory. Infra.roc chooses engine operations;
/// the adapter validates the binary/configuration and records successful effects.
pub struct Session {
    configuration: Configuration,
    configuration_path: std::path::PathBuf,
    digest: String,
    graph: Graph,
    rendered: Vec<u8>,
    output: std::path::PathBuf,
    completed: BTreeSet<String>,
}

impl Session {
    pub fn prepare(
        configuration_path: &Path,
        expected: &str,
        graph: &Graph,
        output: &Path,
    ) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let (configuration, digest) = configuration(configuration_path)?;
        ensure!(
            digest == expected,
            "infrastructure configuration changed after description"
        );
        let rendered = render(graph, &configuration.engine.version)?;
        let engine = Path::new(&configuration.engine.path).canonicalize()?;
        let bytes = fs::read(&engine)?;
        ensure!(
            day2::digest(&bytes) == format!("sha256:{}", configuration.engine.sha256),
            "OpenTofu engine digest mismatch"
        );
        fs::create_dir(output).context("infrastructure requires a new output directory")?;
        fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
        let output = output.canonicalize()?;
        let pinned = output.join("tofu");
        fs::write(&pinned, bytes)?;
        fs::set_permissions(&pinned, fs::Permissions::from_mode(0o700))?;
        let rendered = serde_json::to_vec_pretty(&rendered)?;
        fs::write(output.join("main.tf.json"), &rendered)?;
        fs::write(output.join("graph.json"), serde_json::to_vec_pretty(graph)?)?;
        fs::write(output.join("tofurc"), b"disable_checkpoint = true\n")?;
        Ok(Self {
            configuration,
            configuration_path: configuration_path.canonicalize()?,
            digest,
            graph: graph.clone(),
            rendered,
            output,
            completed: BTreeSet::new(),
        })
    }

    fn validate_inputs(&self) -> Result<()> {
        ensure!(
            configuration(&self.configuration_path)?.1 == self.digest,
            "infrastructure configuration changed during plan"
        );
        ensure!(
            day2::digest(&fs::read(self.output.join("tofu"))?)
                == format!("sha256:{}", self.configuration.engine.sha256),
            "pinned engine changed"
        );
        ensure!(
            fs::read(self.output.join("main.tf.json"))? == self.rendered,
            "rendered infrastructure changed"
        );
        Ok(())
    }

    pub fn command(&mut self, name: &str) -> Result<Value> {
        self.validate_inputs()?;
        ensure!(
            !self.completed.contains(name),
            "duplicate infrastructure operation"
        );
        let args: &[&str] = match name {
            "version" => &["version", "-json"],
            "init" => &["init", "-backend=false", "-input=false", "-no-color"],
            "validate" => &["validate", "-json"],
            "plan" => &["plan", "-input=false", "-no-color", "-out=plan.bin"],
            "show" => &["show", "-json", "plan.bin"],
            _ => anyhow::bail!("unknown infrastructure capability"),
        };
        if name != "version" {
            ensure!(
                self.completed.contains("version"),
                "engine version admission required"
            );
        }
        if name == "plan" {
            ensure!(
                self.completed.contains("validate"),
                "configuration validation required"
            );
        }
        let mut command = Command::new(self.output.join("tofu"));
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("CHECKPOINT_DISABLE", "1")
            .env("TF_IN_AUTOMATION", "1")
            .env("TF_CLI_CONFIG_FILE", self.output.join("tofurc"));
        crate::process::run(
            &mut command,
            &self.output,
            &self.output.join(format!("{name}.log")),
            Duration::from_secs(60),
        )?;
        if name == "version" {
            let actual: Value =
                serde_json::from_slice(&fs::read(self.output.join("version.log"))?)?;
            ensure!(
                actual["terraform_version"] == self.configuration.engine.version,
                "OpenTofu version mismatch"
            );
        }
        self.completed.insert(name.to_owned());
        Ok(json!({"operation":name,"log":self.output.join(format!("{name}.log"))}))
    }

    pub fn receipt(&self) -> Result<Value> {
        self.validate_inputs()?;
        ensure!(
            ["version", "init", "validate", "plan", "show"]
                .iter()
                .all(|name| self.completed.contains(*name)),
            "incomplete infrastructure plan"
        );
        let Self {
            configuration,
            digest,
            graph,
            rendered,
            output,
            ..
        } = self;
        let receipt = json!({"format":1,"configuration":digest,"graph":day2::digest(&serde_json::to_vec(graph)?),"configuration_json":day2::digest(rendered),"engine":configuration.engine.sha256,"engine_version":configuration.engine.version,"plan":day2::digest(&fs::read(output.join("plan.bin"))?),"directory":output,"applied":false});
        fs::write(
            output.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> Graph {
        Graph {
            format: 1,
            resources: vec![
                Resource {
                    key: "scope".into(),
                    inputs: vec![Input {
                        name: "value".into(),
                        kind: "literal".into(),
                        value: "${file(\"secret\")}%{if true}".into(),
                        target: String::new(),
                        attribute: String::new(),
                    }],
                },
                Resource {
                    key: "app_reports".into(),
                    inputs: vec![Input {
                        name: "scope".into(),
                        kind: "reference".into(),
                        value: String::new(),
                        target: "scope".into(),
                        attribute: "output".into(),
                    }],
                },
            ],
        }
    }

    #[test]
    fn literal_templates_are_escaped_and_references_keep_stable_addresses() -> Result<()> {
        let mut graph = graph();
        let rendered = render(&graph, "1.11.5")?;
        assert_eq!(
            rendered["resource"]["terraform_data"]["scope"]["input"]["value"],
            "$${file(\"secret\")}%%{if true}"
        );
        assert_eq!(
            rendered["resource"]["terraform_data"]["app_reports"]["input"]["scope"],
            "${terraform_data.scope.output}"
        );
        graph.resources.reverse();
        assert_eq!(render(&graph, "1.11.5")?, rendered);
        Ok(())
    }

    #[test]
    fn rejects_dangling_cyclic_duplicate_and_expression_references() {
        for target in ["absent", "app_reports", "scope.output}"] {
            let mut graph = graph();
            graph.resources[1].inputs[0].target = target.into();
            assert!(render(&graph, "1.11.5").is_err());
        }
        let mut graph = graph();
        graph.resources.push(graph.resources[0].clone());
        assert!(render(&graph, "1.11.5").is_err());
    }
}
