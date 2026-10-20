//! Setup-only decoding of an initially absent derived epoch key selection.
//! Operator metadata remains required; this projection supplies no authority.

use crate::artifact::Instance;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest, Name,
    security_epoch::{AuthorityScope, EpochProvider, EpochStore},
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredEpochMetadata {
    scope: AuthorityScope,
    provider: EpochProvider,
    max_lease_seconds: u32,
}

/// The parent has already checked bounded, duplicate-free raw JSON. Restore all
/// stores before returning typed DATA to its existing repin and strict loader.
pub(super) fn decode(raw: &Value) -> Result<Instance> {
    let mut projection = raw.clone();
    let epochs = projection
        .get_mut("control")
        .and_then(Value::as_object_mut)
        .and_then(|control| control.remove("security_epochs"));
    let Some(epochs) = epochs else {
        return Ok(serde_json::from_value(projection)?);
    };
    let epochs: BTreeMap<Name, Value> = serde_json::from_value(epochs)?;
    ensure!(epochs.len() <= 128, "control binding budget");
    let mut selected = BTreeMap::new();
    for (alias, mut value) in epochs {
        // A present null must fail Digest decoding, rather than become absence.
        let key_set = value
            .as_object_mut()
            .context("security epoch selection must be an object")?
            .remove("key_set")
            .map(serde_json::from_value::<Digest>)
            .transpose()?;
        let metadata: DesiredEpochMetadata = serde_json::from_value(value)?;
        selected.insert(alias, (metadata, key_set));
    }
    // Only the epoch collection is deferred. Do not validate this incomplete
    // projection: bootstrap references require the complete restored stores.
    let mut instance: Instance = serde_json::from_value(projection)?;
    let mut stores = BTreeMap::new();
    for (alias, (metadata, key_set)) in selected {
        let key_set = match key_set {
            Some(key_set) => key_set,
            None => {
                ensure!(
                    metadata.scope.installation.as_str() == instance.installation
                        && metadata.scope.environment.as_str() == instance.environment,
                    "security_epoch_scope_mismatch"
                );
                let app = metadata.scope.app.as_str();
                ensure!(
                    instance
                        .apps
                        .get(app)
                        .is_some_and(|binding| !binding.oauth_connections.is_empty()),
                    "initial_security_epoch_key_set_requires_selected_oauth_app"
                );
                instance.security_key_set(app)?
            }
        };
        let store = EpochStore {
            scope: metadata.scope,
            provider: metadata.provider,
            key_set,
            max_lease_seconds: metadata.max_lease_seconds,
        };
        store.validate()?;
        stores.insert(alias, store);
    }
    instance
        .control
        .as_mut()
        .context("security_epoch_control_catalog_missing")?
        .security_epochs = stores;
    Ok(instance)
}
