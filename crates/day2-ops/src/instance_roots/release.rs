//! A day2-app root's release inputs: the app's durable selection (or, in a
//! deploy, an explicit candidate), read and checked in-process, and the
//! variables it renders. The instance's deploy controller writes the selection
//! at `gs://<project>-tofu-state/day2/app-releases/<app>/selection.json`; the
//! platform only reads it.
//!
//! - A selection is read at its exact generation. Only a describe that finds
//!   the object absent means "no selection yet"; every other read failure is an
//!   error, never absence, and nothing ever falls back to a committed image.
//! - Its candidate is checked as `instance candidate check` checks a record
//!   (`record::check`, including the instance's forge), then its qualified SDK
//!   release manifest is read through the release cache: it must be the one
//!   supported profile, pinned under the registry, and the candidate's native
//!   admission must name that release's native evidence.
//! - The rendered `release.tfvars.json` holds exactly `image`, `artifact_id`
//!   and `security_requirements`, the values the earlier controller exported.
//! - A committed day2-app input may not set a variable the platform owns.
use crate::instance_candidate::{record, tools::Store};
use crate::instance_release::{self, Cache};
use crate::instance_source;
use anyhow::{Context, Result, bail, ensure};
use day2::python_json::{self, Layout};
use day2::sdk_release::{BlobIdentity, MANIFEST_LIMIT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A selection's fields, exactly.
pub const SELECTION_FIELDS: [&str; 3] = ["version", "status", "candidate"];

/// The variables `release.tfvars.json` sets, after the committed and rendered ones, so they win.
pub const VARIABLES: [&str; 3] = ["image", "artifact_id", "security_requirements"];

/// day2-app variables the platform owns for an instance besides the ones it renders, which a committed input may not
/// set either: the release's native admission; the release-profile switches, with which the stack would ignore the
/// release inputs (the platform deploys only the direct single-app profile); the workload name, from which a deploy
/// derives `day2-<id>`; and the security shell contract, a root the platform does not render yet.
pub const OWNED: [&str; 5] = [
    "security_requirements",
    "release_managed",
    "rolling_deploys",
    "workload_name",
    "security_shell_contract",
];

/// Pin the direct release profile and derived workload identity at OpenTofu's highest
/// variable precedence. The committed-input check supplies the early diagnostic.
pub const PROFILE: [&str; 4] = [
    "-var=release_managed=false",
    "-var=rolling_deploys=false",
    "-var=workload_name=",
    "-var=security_shell_contract=null",
];

/// Where an instance keeps and admits releases, rendered by the CLI from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Releases {
    /// The state bucket, `<project>-tofu-state`.
    pub bucket: String,
    /// The Artifact Registry, `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    pub forge: Forge,
}

/// The instance's forge: `forge.server` and `forge.org`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Forge {
    pub server: String,
    pub org: String,
}

impl Releases {
    /// The bucket and registry must be `project`'s, and the forge a lowercase org on an https host.
    pub fn validate(&self, project: &str) -> Result<()> {
        instance_source::validate_forge(&self.forge.server, &self.forge.org)?;
        ensure!(
            self.bucket == format!("{project}-tofu-state")
                && self
                    .registry
                    .ends_with(&format!("-docker.pkg.dev/{project}"))
                && crate::instance_candidate::registry(&self.registry),
            "the release state bucket and registry must be the instance project's"
        );
        Ok(())
    }

    /// What candidate records are admitted from.
    pub fn scope(&self) -> record::Scope<'_> {
        record::Scope {
            server: &self.forge.server,
            org: &self.forge.org,
            registry: &self.registry,
            bucket: &self.bucket,
        }
    }

    /// `gs://<bucket>/day2/app-releases/<app>/selection.json`.
    pub fn selection_uri(&self, app: &str) -> String {
        format!("{}/{app}/selection.json", record::state(&self.bucket))
    }

    /// `gs://<bucket>/day2/platform-releases/sha256`, the release cache's objects.
    pub fn objects(&self) -> String {
        format!("gs://{}/{}", self.bucket, instance_release::OBJECTS)
    }
}

/// A selection's state: being activated, or deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Activating,
    Ready,
}

/// The app's durable selection, as read.
#[derive(Clone, Debug, PartialEq)]
pub struct Selection {
    pub uri: String,
    /// The exact generation that was read.
    pub generation: String,
    /// `sha256:` of the record's bytes.
    pub digest: String,
    pub status: Status,
    /// The candidate record it names, not yet checked.
    pub candidate: Value,
}

/// A checked release: the candidate a day2-app root deploys and the variables it renders.
#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub candidate: Value,
    /// `sha256:` of the candidate record's bytes (`record::encode`).
    pub digest: String,
    pub commit: String,
    pub image: String,
    pub artifact_id: String,
    /// The binding's tooling image, which a deploy's maintenance request names.
    pub tooling_image: String,
    pub qualified_release: BlobIdentity,
    /// `release.tfvars.json`.
    pub variables: Vec<u8>,
}

/// `sha256:` of a candidate record's bytes, as the controller writes them.
pub fn candidate_digest(candidate: &Value) -> Result<String> {
    Ok(day2::digest(&record::encode(candidate)?))
}

/// The app's selection at its exact generation, or `None` only when the object is absent. Its shape is checked
/// (exact fields, the integer version 1, status `activating` or `ready`), not its candidate. A rolling selection is
/// refused: the platform deploys only the single-app profile.
pub fn read_selection(
    store: &mut dyn Store,
    releases: &Releases,
    app: &str,
) -> Result<Option<Selection>> {
    ensure!(
        instance_source::identifier(app),
        "invalid deployment app ID"
    );
    let uri = releases.selection_uri(app);
    let Some((bytes, generation)) = store
        .read(&uri)
        .context("cannot read the app's release selection")?
    else {
        return Ok(None);
    };
    let value = record::decode(&bytes)?;
    ensure!(
        value.get("rolling").is_none(),
        "rolling releases are not supported: the release selection carries a rolling request"
    );
    ensure!(
        instance_source::object_with(&value, &SELECTION_FIELDS),
        "invalid release selection fields"
    );
    ensure!(
        instance_source::int(&value["version"]) == Some(1),
        "unsupported release selection version"
    );
    let status = match value["status"].as_str() {
        Some("activating") => Status::Activating,
        Some("ready") => Status::Ready,
        _ => bail!("invalid release selection status"),
    };
    ensure!(
        value["candidate"].is_object(),
        "invalid deployment candidate fields"
    );
    Ok(Some(Selection {
        uri,
        generation,
        digest: day2::digest(&bytes),
        status,
        candidate: value["candidate"].clone(),
    }))
}

/// The app's selection must exist and name exactly `candidate`: a deploy's guard before it stops the app, and its
/// apply's `selected` stage just before the locked plan. It only reads the selection.
pub fn selection(
    store: &mut dyn Store,
    releases: &Releases,
    app: &str,
    candidate: &Value,
) -> Result<Selection> {
    let selection = read_selection(store, releases, app)?
        .context("the app has no release selection; deploy only a selected candidate")?;
    ensure!(
        candidate_digest(&selection.candidate)? == candidate_digest(candidate)?,
        "the app's release selection names another candidate"
    );
    Ok(selection)
}

/// A candidate for `app`, checked as `instance candidate check` checks it, then its qualified SDK release: the
/// manifest, through the release cache, must be the one supported profile pinned under the registry, and the
/// candidate's native admission must be that release's native evidence.
pub fn check(
    candidate: &Value,
    app: &str,
    releases: &Releases,
    cache: &Cache,
    tools: &mut dyn instance_release::Tools,
) -> Result<Release> {
    record::check(candidate, app, &releases.scope())?;
    let reference =
        instance_source::blob(&candidate["binding"]["qualified_release"], MANIFEST_LIMIT)?;
    let manifest = instance_release::manifest(cache, &releases.registry, &reference, tools)
        .context("the candidate's qualified SDK release")?;
    ensure!(
        manifest.profile == day2::sdk_release::PROFILE,
        "rolling releases require the rolling delivery controller"
    );
    ensure!(
        candidate["security_requirements"]["containment"]["evidence"]["receipt_digest"]
            == manifest.evidence.native.digest.as_str(),
        "candidate uses another platform qualification"
    );
    let text = |value: &Value| value.as_str().unwrap_or_default().to_owned();
    Ok(Release {
        digest: candidate_digest(candidate)?,
        commit: text(&candidate["source_commit"]),
        image: text(&candidate["image"]),
        artifact_id: text(&candidate["artifact_id"]),
        tooling_image: text(&candidate["binding"]["tooling_image"]),
        qualified_release: reference,
        variables: variables(candidate)?,
        candidate: candidate.clone(),
    })
}

/// `release.tfvars.json`: the candidate's `image`, `artifact_id` and `security_requirements` (values exactly as
/// decoded, integers included), keys sorted, with a final newline.
pub fn variables(candidate: &Value) -> Result<Vec<u8>> {
    let mut fields = serde_json::Map::new();
    for name in VARIABLES {
        let value = candidate
            .get(name)
            .context("invalid deployment candidate fields")?;
        fields.insert(name.to_owned(), value.clone());
    }
    let mut bytes = python_json::dumps(&Value::Object(fields), Layout::Compact)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The names among `names` that a committed `.tfvars` file sets at its top level: a line that starts with the name,
/// bare or quoted, then only spaces or tabs before `=`. The instance's own day2-app tooling refused committed copies of
/// rendered values by the same rule. An indented (nested) field and a comment never match.
pub fn restated<'a>(committed: &[u8], names: &[&'a str]) -> Vec<&'a str> {
    let lines: Vec<&[u8]> = committed.split(|byte| *byte == b'\n').collect();
    names
        .iter()
        .copied()
        .filter(|name| {
            let quoted = format!("\"{name}\"");
            lines.iter().any(|line| {
                [name.as_bytes(), quoted.as_bytes()].iter().any(|key| {
                    line.strip_prefix(*key).is_some_and(|rest| {
                        let rest = rest
                            .iter()
                            .position(|byte| *byte != b' ' && *byte != b'\t')
                            .map_or(&[][..], |start| &rest[start..]);
                        rest.first() == Some(&b'=') && rest.get(1) != Some(&b'=')
                    })
                })
            })
        })
        .collect()
}

/// What a receipt records of a release: where it came from (`selection` or a deploy's `candidate` file, at `record`),
/// the selection it was read from or checked against, and what it renders.
pub fn summary(
    release: &Release,
    source: &str,
    record: &str,
    selection: Option<&Selection>,
) -> Value {
    json!({
        "source": source,
        "record": record,
        "generation": selection.map(|selection| selection.generation.clone()),
        "status": selection.map(|selection| selection.status),
        "digest": selection.map(|selection| selection.digest.clone()),
        "candidate": release.digest,
        "commit": release.commit,
        "image": release.image,
        "artifact_id": release.artifact_id,
        "tooling_image": release.tooling_image,
        "qualified_release": release.qualified_release,
        "variables": day2::digest(&release.variables),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::instance_candidate::tests::selected_candidate;
    use crate::instance_source::tests::{BUCKET, Fake, REGISTRY, SERVER};
    use std::{collections::BTreeMap, path::Path};

    /// Release state by URI: an object and its generation, or a read that fails.
    #[derive(Clone, Default)]
    pub(crate) struct Objects(pub(crate) BTreeMap<String, Option<(Vec<u8>, String)>>);

    impl Store for Objects {
        fn read(&mut self, uri: &str) -> Result<Option<(Vec<u8>, String)>> {
            match self.0.get(uri) {
                None => Ok(None),
                Some(None) => bail!(
                    "cannot read private release state (authentication/network errors are not absence)"
                ),
                Some(Some(object)) => Ok(Some(object.clone())),
            }
        }

        fn write(&mut self, _file: &Path, _uri: &str, _generation: &str) -> Result<()> {
            bail!("a release read never writes")
        }

        fn put(&mut self, _file: &Path, _uri: &str) -> Result<()> {
            bail!("a release read never writes")
        }
    }

    pub(crate) fn releases() -> Releases {
        Releases {
            bucket: BUCKET.into(),
            registry: REGISTRY.into(),
            forge: Forge {
                server: SERVER.into(),
                org: "tools".into(),
            },
        }
    }

    pub(crate) const URI: &str =
        "gs://exampleco-tools-tofu-state/day2/app-releases/links/selection.json";

    pub(crate) fn stored(value: &Value) -> Objects {
        let mut objects = Objects::default();
        objects.0.insert(
            URI.into(),
            Some((record::encode(value).unwrap(), "1700000000000001".into())),
        );
        objects
    }

    fn error<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("accepted"),
            Err(error) => format!("{error:#}"),
        }
    }

    /// A fake release bucket holding the manifest, and a fresh cache.
    pub(crate) fn with_manifest(manifest: &[u8]) -> (tempfile::TempDir, Cache, Fake) {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::open(&directory.path().join("cache"), &releases().objects()).unwrap();
        let fake = Fake::default();
        let identity = BlobIdentity::of(manifest);
        fake.0.borrow_mut().objects.insert(
            format!("{}/{}", releases().objects(), &identity.digest[7..]),
            manifest.to_vec(),
        );
        (directory, cache, fake)
    }

    #[test]
    fn the_releases_must_be_the_instance_project_s() {
        assert_eq!(releases().validate("exampleco-tools").ok(), Some(()));
        assert!(releases().validate("other-project").is_err());
        let mut other = releases();
        other.forge.org = "Tools".into();
        assert!(other.validate("exampleco-tools").is_err());
        assert_eq!(releases().selection_uri("links"), URI);
    }

    #[test]
    fn a_selection_is_read_at_its_generation_and_only_absence_is_none() -> Result<()> {
        let (candidate, _) = selected_candidate();
        let value = json!({"version": 1, "status": "ready", "candidate": candidate});
        let selection = read_selection(&mut stored(&value), &releases(), "links")?.unwrap();
        assert_eq!(selection.uri, URI);
        assert_eq!(selection.generation, "1700000000000001");
        assert_eq!(selection.status, Status::Ready);
        assert_eq!(selection.digest, day2::digest(&record::encode(&value)?));
        assert_eq!(selection.candidate, candidate);
        // Absence is no selection; any other read failure is an error, never absence.
        assert_eq!(
            read_selection(&mut Objects::default(), &releases(), "links")?,
            None
        );
        let mut failing = Objects::default();
        failing.0.insert(URI.into(), None);
        assert!(
            error(read_selection(&mut failing, &releases(), "links"))
                .contains("authentication/network errors are not absence")
        );
        let activating = json!({"version": 1, "status": "activating", "candidate": candidate});
        let read = read_selection(&mut stored(&activating), &releases(), "links")?.unwrap();
        assert_eq!(read.status, Status::Activating);
        Ok(())
    }

    #[test]
    fn a_selection_has_exactly_the_controller_s_shape() {
        let (candidate, _) = selected_candidate();
        let refused = |value: Value, message: &str| {
            assert_eq!(
                error(read_selection(&mut stored(&value), &releases(), "links")),
                message
            );
        };
        let base = json!({"version": 1, "status": "ready", "candidate": candidate});
        for (field, changed, message) in [
            ("version", json!(2), "unsupported release selection version"),
            (
                "version",
                json!(true),
                "unsupported release selection version",
            ),
            (
                "version",
                json!("1"),
                "unsupported release selection version",
            ),
            (
                "status",
                json!("blocked"),
                "invalid release selection status",
            ),
            ("status", json!(null), "invalid release selection status"),
            (
                "candidate",
                json!([]),
                "invalid deployment candidate fields",
            ),
            ("extra", json!(1), "invalid release selection fields"),
            (
                "rolling",
                json!({}),
                "rolling releases are not supported: the release selection carries a rolling request",
            ),
        ] {
            let mut value = base.clone();
            value[field] = changed;
            refused(value, message);
        }
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("status");
        refused(missing, "invalid release selection fields");
        // A duplicate key at any depth is refused before anything is read from it.
        let mut objects = Objects::default();
        objects.0.insert(
            URI.into(),
            Some((
                br#"{"candidate": {}, "status": "ready", "status": "ready", "version": 1}"#
                    .to_vec(),
                "3".into(),
            )),
        );
        assert_eq!(
            error(read_selection(&mut objects, &releases(), "links")),
            "duplicate JSON field"
        );
        assert_eq!(
            error(read_selection(
                &mut Objects::default(),
                &releases(),
                "Links"
            )),
            "invalid deployment app ID"
        );
    }

    #[test]
    fn a_candidate_is_checked_with_its_release_and_renders_its_variables() -> Result<()> {
        let (candidate, manifest) = selected_candidate();
        let (_directory, cache, mut fake) = with_manifest(&manifest);
        let release = check(&candidate, "links", &releases(), &cache, &mut fake)?;
        assert_eq!(release.digest, candidate_digest(&candidate)?);
        assert_eq!(release.commit, candidate["source_commit"]);
        assert_eq!(release.image, candidate["image"]);
        assert_eq!(release.artifact_id, candidate["artifact_id"]);
        assert_eq!(release.tooling_image, candidate["binding"]["tooling_image"]);
        assert_eq!(release.qualified_release, BlobIdentity::of(&manifest));
        let rendered: Value = serde_json::from_slice(&release.variables)?;
        assert_eq!(
            rendered,
            json!({"image": candidate["image"], "artifact_id": candidate["artifact_id"],
                "security_requirements": candidate["security_requirements"]})
        );
        // The second read is a verified cache hit: the bucket is not read again.
        fake.0.borrow_mut().objects.clear();
        assert_eq!(
            check(&candidate, "links", &releases(), &cache, &mut fake)?,
            release
        );
        Ok(())
    }

    #[test]
    fn a_candidate_must_be_the_app_s_on_the_instance_forge_and_its_release_s() {
        let (candidate, manifest) = selected_candidate();
        let (_directory, cache, mut fake) = with_manifest(&manifest);
        let mut refused = |change: &dyn Fn(&mut Value), app: &str, message: &str| {
            let mut value = candidate.clone();
            change(&mut value);
            assert_eq!(
                error(check(&value, app, &releases(), &cache, &mut fake)),
                message
            );
        };
        refused(&|_| {}, "notes", "release belongs to another app");
        refused(
            &|value| value["binding"]["source"]["server"] = json!("https://git.example.org"),
            "links",
            "the binding's source server is not day2.json's forge.server",
        );
        refused(
            &|value| {
                value["binding"]["repository"] = json!("tools/day2-ci");
                value["binding"]["source"]["repository"] = json!("tools/day2-ci");
                value["ci_artifact"]["receipt"]["repository"] = json!("tools/day2-ci");
            },
            "links",
            "the binding's repository is a platform repository (day2-<name>), not an app's",
        );
        refused(
            &|value| {
                value["security_requirements"]["containment"]["evidence"]["receipt_digest"] =
                    json!(day2::digest(b"another qualification"))
            },
            "links",
            "candidate uses another platform qualification",
        );
        // An unreadable release is an error, never skipped.
        let (_empty, cache, mut fake) = with_manifest(&manifest);
        fake.0.borrow_mut().objects.clear();
        assert!(
            error(check(&candidate, "links", &releases(), &cache, &mut fake))
                .starts_with("the candidate's qualified SDK release")
        );
    }

    #[test]
    fn an_incomplete_rolling_or_foreign_release_manifest_is_refused() {
        let (candidate, manifest) = selected_candidate();
        let mut value: Value = serde_json::from_slice(&manifest).unwrap();
        value["profile"] = json!("linux_sqlite_rwo_v1");
        let rolling = serde_json::to_vec(&value).unwrap();
        let (_directory, cache, mut fake) = with_manifest(&rolling);
        assert_eq!(
            error(instance_release::manifest(
                &cache,
                REGISTRY,
                &BlobIdentity::of(&rolling),
                &mut fake
            )),
            "rolling evidence must match the qualified release profile"
        );
        let (_directory, cache, mut fake) = with_manifest(&manifest);
        assert!(
            error(instance_release::manifest(
                &cache,
                "europe-west1-docker.pkg.dev/other",
                &BlobIdentity::of(&manifest),
                &mut fake
            ))
            .starts_with("invalid qualified image identity")
        );
        // A manifest whose bytes differ from the pinned digest is refused.
        let (_directory, cache, mut fake) = with_manifest(&manifest);
        let identity = BlobIdentity::of(&manifest);
        fake.0.borrow_mut().objects.insert(
            format!("{}/{}", releases().objects(), &identity.digest[7..]),
            [manifest.as_slice(), b" "].concat(),
        );
        assert!(check(&candidate, "links", &releases(), &cache, &mut fake).is_err());
    }

    #[test]
    fn a_deploy_s_selection_must_name_exactly_its_candidate() -> Result<()> {
        let (candidate, _) = selected_candidate();
        let value = json!({"version": 1, "status": "activating", "candidate": candidate});
        let selection = selection(&mut stored(&value), &releases(), "links", &candidate)?;
        assert_eq!(selection.status, Status::Activating);
        let mut other = candidate.clone();
        other["source_commit"] = json!("89abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(
            error(super::selection(
                &mut stored(&value),
                &releases(),
                "links",
                &other
            )),
            "the app's release selection names another candidate"
        );
        assert_eq!(
            error(super::selection(
                &mut Objects::default(),
                &releases(),
                "links",
                &candidate
            )),
            "the app has no release selection; deploy only a selected candidate"
        );
        let mut failing = Objects::default();
        failing.0.insert(URI.into(), None);
        assert!(super::selection(&mut failing, &releases(), "links", &candidate).is_err());
        Ok(())
    }

    #[test]
    fn release_variables_keep_values_exactly() -> Result<()> {
        let candidate = json!({"image": "r/links/links@sha256:aa", "artifact_id": "ab",
            "security_requirements": {"version": 1, "bound": 9_007_199_254_740_993_u64, "name": "é"},
            "binding": {}});
        assert_eq!(
            String::from_utf8(variables(&candidate)?)?,
            "{\"artifact_id\":\"ab\",\"image\":\"r/links/links@sha256:aa\",\
             \"security_requirements\":{\"bound\":9007199254740993,\"name\":\"\\u00e9\",\"version\":1}}\n"
        );
        assert!(variables(&json!({"image": "i", "artifact_id": "a"})).is_err());
        Ok(())
    }

    #[test]
    fn committed_inputs_may_not_restate_what_the_platform_owns() {
        let names = [
            "namespace",
            "image",
            "security_requirements",
            "workload_name",
        ];
        let committed = b"# image = \"commented\"\n\
            workload_name  =\"day2-other\"\n\
            security_shell_contract = {\n  namespace = \"nested\"\n  name = \"x\"\n}\n\
            \"security_requirements\"\t= null\n\
            image_repository = \"not image\"\n\
            imagex = 1\n";
        assert_eq!(
            restated(committed, &names),
            ["security_requirements", "workload_name"]
        );
        assert_eq!(
            restated(b"namespace = \"app-links\"\n", &names),
            ["namespace"]
        );
        assert!(restated(b"  namespace = \"nested\"\nname == 1\n", &names).is_empty());
        assert!(restated(b"image == 1\n", &names).is_empty());
        assert!(restated(b"", &names).is_empty());
    }
}
