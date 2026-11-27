//! Read-only selection state and the saved recovery block for one application.
use crate::instance_candidate::{record, tools::Store};
use crate::instance_roots::release::{self, Releases, Status};
use crate::instance_source::{app_image, commit, identifier};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    project: String,
    app_id: String,
    releases: Releases,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    version: u32,
    source_commit: String,
    image: String,
}

enum State {
    Unread,
    Activating { commit: String, image: String },
    Finished,
}

pub struct Session {
    request: Request,
    store: Box<dyn Store>,
    state: State,
}

impl Session {
    pub fn new(request: Request, store: Box<dyn Store>) -> Result<Self> {
        request.releases.validate(&request.project)?;
        ensure!(identifier(&request.app_id), "invalid deployment app ID");
        Ok(Self {
            request,
            store,
            state: State::Unread,
        })
    }

    pub fn read(&mut self) -> Result<Value> {
        ensure!(
            matches!(self.state, State::Unread),
            "selection read already attempted"
        );
        self.state = State::Finished;
        let Request {
            app_id, releases, ..
        } = &self.request;
        let selection = release::read_selection(self.store.as_mut(), releases, app_id)?;
        let Some(selection) = selection else {
            return Ok(json!({"app_id": app_id, "selection": null}));
        };
        let candidate = &selection.candidate;
        record::check(candidate, app_id, &releases.scope())?;
        if selection.status == Status::Activating {
            self.state = State::Activating {
                commit: candidate["source_commit"]
                    .as_str()
                    .context("checked commit")?
                    .to_owned(),
                image: candidate["image"]
                    .as_str()
                    .context("checked image")?
                    .to_owned(),
            };
        }
        Ok(json!({
            "app_id": app_id,
            "selection": {
                "status": selection.status,
                "generation": selection.generation,
                "commit": candidate["source_commit"],
                "image": candidate["image"],
                "artifact_id": candidate["artifact_id"],
            }
        }))
    }

    pub fn blocked(&mut self) -> Result<Value> {
        let State::Activating {
            commit: selected_commit,
            image: selected_image,
        } = std::mem::replace(&mut self.state, State::Finished)
        else {
            anyhow::bail!("recovery state requires an activating selection");
        };
        let Request {
            app_id, releases, ..
        } = &self.request;
        let uri = format!(
            "{}/{app_id}/blocked-activation.json",
            record::state(&releases.bucket)
        );
        let Some((bytes, _)) = self.store.read(&uri).context("read blocked activation")? else {
            return Ok(Value::Bool(false));
        };
        let block: Block = serde_json::from_value(record::decode(&bytes)?)
            .context("invalid blocked activation")?;
        ensure!(
            block.version == 1
                && commit(&block.source_commit)
                && app_image(&block.image, &releases.registry, app_id, true),
            "invalid blocked activation"
        );
        Ok(Value::Bool(
            block.source_commit == selected_commit && block.image == selected_image,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance_candidate::tests::selected_candidate;
    use crate::instance_roots::release::tests::{releases, stored};

    fn session(status: &str, block: Option<Value>) -> Session {
        let selection =
            json!({"version": 1, "status": status, "candidate": selected_candidate().0});
        let mut store = stored(&selection);
        if let Some(value) = block {
            store.0.insert(
                format!(
                    "{}/links/blocked-activation.json",
                    record::state(&releases().bucket)
                ),
                Some((record::encode(&value).unwrap(), "1700000000000002".into())),
            );
        }
        Session::new(
            Request {
                project: "exampleco-tools".into(),
                app_id: "links".into(),
                releases: releases(),
            },
            Box::new(store),
        )
        .unwrap()
    }

    #[test]
    fn recovery_block_applies_to_the_exact_activating_candidate() {
        let (candidate, _) = selected_candidate();
        let mut marker = json!({
            "version": 1,
            "source_commit": candidate["source_commit"],
            "image": candidate["image"]
        });
        let mut selected = session("activating", Some(marker.clone()));
        assert_eq!(
            selected.read().unwrap()["selection"]["generation"],
            "1700000000000001"
        );
        assert_eq!(selected.blocked().unwrap(), true);
        marker["source_commit"] = json!("d".repeat(40));
        let mut other = session("activating", Some(marker));
        other.read().unwrap();
        assert_eq!(other.blocked().unwrap(), false);
    }

    #[test]
    fn malformed_marker_fails_closed_and_ready_selections_do_not_read_it() {
        let marker = json!({"version": 1, "source_commit": "wrong", "image": "wrong"});
        let mut ready = session("ready", Some(marker.clone()));
        assert_eq!(ready.read().unwrap()["selection"]["status"], "ready");
        assert_eq!(
            ready.blocked().unwrap_err().to_string(),
            "recovery state requires an activating selection"
        );
        let mut activating = session("activating", Some(marker));
        activating.read().unwrap();
        assert_eq!(
            activating.blocked().unwrap_err().to_string(),
            "invalid blocked activation"
        );
    }
}
