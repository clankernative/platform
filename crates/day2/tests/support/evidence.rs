use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// An append-only event journal survives abrupt process loss. The complete
/// scenario evidence survives early errors and panics. Each run owns a directory
/// so a passing rerun cannot erase a failing trace.
pub struct Evidence {
    path: PathBuf,
    journal: fs::File,
    document: Value,
}

impl Evidence {
    pub fn start(root: &Path, scenario: Value) -> Result<Self> {
        fs::create_dir_all(root)?;
        let directory = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(root)?
            .keep();
        let journal = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("events.jsonl"))?;
        let evidence = Self {
            path: directory.join("evidence.json"),
            journal,
            document: json!({"scenario":scenario,"status":"running","events":[]}),
        };
        evidence.save()?;
        Ok(evidence)
    }

    fn save(&self) -> Result<()> {
        let parent = self.path.parent().context("evidence directory")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut file, &self.document)?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(&self.path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn event(&mut self, event: Value) -> Result<()> {
        serde_json::to_writer(&mut self.journal, &event)?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        self.document["events"]
            .as_array_mut()
            .context("evidence events")?
            .push(event);
        // `start` persists the running marker and `run` catches both errors and
        // unwinding panics before atomically persisting the complete trace.
        // The append-only journal retains process-loss evidence without
        // rewriting and fsyncing an almost 1 MiB document for each of hundreds
        // of generated-campaign events.
        Ok(())
    }

    pub fn run<T>(&mut self, scenario: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenario(self)));
        self.document["status"] = json!(match &result {
            Ok(Ok(_)) => "passed",
            Ok(Err(_)) => "failed",
            Err(_) => "panicked",
        });
        if let Ok(Err(error)) = &result {
            self.document["error"] = json!(format!("{error:#}"));
        }
        if let Err(payload) = &result {
            self.document["error"] = json!(
                payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic")
            );
        }
        let saved = (|| -> Result<()> {
            self.journal.sync_all()?;
            self.save()
        })();
        match result {
            Ok(result) => {
                if let Err(error) = saved {
                    let context = format!(
                        "save scenario evidence at {}: {error:#}",
                        self.path.display()
                    );
                    return match result {
                        Err(original) => Err(original.context(context)),
                        Ok(_) => Err(error.context(context)),
                    };
                }
                result.with_context(|| format!("scenario evidence: {}", self.path.display()))
            }
            Err(payload) => {
                if let Err(error) = saved {
                    eprintln!("failed to save panic evidence: {error:#}");
                }
                std::panic::resume_unwind(payload)
            }
        }
    }
}

#[test]
fn early_failures_and_panics_retain_evidence_without_overwriting_previous_runs() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut first = Evidence::start(root.path(), json!({"seed":42}))?;
    let result: Result<()> = first.run(|evidence| {
        evidence.event(json!({"attempt":"execute"}))?;
        anyhow::bail!("unexpected execution failure")
    });
    assert!(result.is_err());
    let failed = fs::read(&first.path)?;
    let failed_document: Value = serde_json::from_slice(&failed)?;
    assert_eq!(failed_document["status"], "failed");
    assert_eq!(failed_document["events"], json!([{"attempt":"execute"}]));
    assert_eq!(
        fs::read_to_string(first.path.parent().unwrap().join("events.jsonl"))?,
        "{\"attempt\":\"execute\"}\n"
    );
    let mut second = Evidence::start(root.path(), json!({"seed":42}))?;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        second.run::<()>(|evidence| {
            evidence.event(json!({"attempt":"panic"}))?;
            panic!("early invariant failure")
        })
    }));
    assert!(panic.is_err());
    let panicked: Value = serde_json::from_slice(&fs::read(&second.path)?)?;
    assert_eq!(panicked["status"], "panicked");
    assert_eq!(panicked["events"], json!([{"attempt":"panic"}]));
    assert_eq!(
        fs::read_to_string(second.path.parent().unwrap().join("events.jsonl"))?,
        "{\"attempt\":\"panic\"}\n"
    );
    assert_eq!(fs::read(&first.path)?, failed);
    let planned = Evidence::start(root.path(), json!({"seed":7}))?;
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(planned.path)?)?["status"],
        "running"
    );
    Ok(())
}
