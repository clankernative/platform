//! Finite native supplier qualification. Its executable and disposable workload
//! must be explicitly selected. It grants no App/Shell, storage or OAuth success.

use super::{EnrolledProcessRoleOwner, NativeRole, operations};
use crate::{automation, security_epoch::NativeAcquisition};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::time::Duration;

const ACTIONS: &[&str] = &[
    "native-qualification-enroll",
    "native-qualification-current",
    "native-qualification-original-clock",
    "native-qualification-wait",
    "native-qualification-clock-continuity",
    "native-qualification-role-refusal",
    "native-qualification-receipt",
];

pub(super) fn run(role: NativeRole) -> Result<Value> {
    let mut selection = NativeAcquisition::begin(5)?;
    let policy = super::birth::load_policy(&mut selection)?;
    let mut owner = None;
    let mut clock = None;
    let mut previous_sample = None;
    let mut phase = 0;
    let value = automation::run(
        &operations::runner()?,
        &["native-enrollment-qualify"],
        |request| {
            operations::empty(&request)?;
            ensure!(
                ACTIONS.get(phase) == Some(&request.action.as_str()),
                "native_qualification_recipe_order"
            );
            let value = match request.action.as_str() {
                "native-qualification-enroll" => {
                    owner = Some(EnrolledProcessRoleOwner::enroll_current_thread(
                        &policy.bootstrap.scope,
                        role,
                    )?);
                    json!({})
                }
                "native-qualification-current" => {
                    let mut stage = owner.as_mut().unwrap().begin_current_stage()?;
                    stage.check_selection(&policy.bootstrap, &policy.store, role)?;
                    json!({})
                }
                "native-qualification-original-clock" => {
                    let enrolled = owner.as_mut().unwrap();
                    let mut original = enrolled.capture_original_clock(role)?;
                    let mut stage = enrolled.begin_current_stage()?;
                    previous_sample = Some(original.sample(&mut stage)?);
                    clock = Some(original);
                    json!({})
                }
                "native-qualification-wait" => {
                    std::thread::sleep(Duration::from_millis(250));
                    json!({})
                }
                "native-qualification-clock-continuity" => {
                    let mut stage = owner.as_mut().unwrap().begin_current_stage()?;
                    let original = clock.as_mut().unwrap();
                    let sample = original.sample(&mut stage)?;
                    ensure!(
                        sample > previous_sample.unwrap() && original.origin() <= sample,
                        "native_qualification_original_clock"
                    );
                    json!({})
                }
                "native-qualification-role-refusal" => {
                    let enrolled = owner.as_mut().unwrap();
                    let wrong = match role {
                        NativeRole::AppHost => NativeRole::SecurityShell,
                        _ => NativeRole::AppHost,
                    };
                    {
                        let mut stage = enrolled.begin_current_stage()?;
                        ensure!(
                            stage
                                .check_selection(&policy.bootstrap, &policy.store, wrong)
                                .is_err(),
                            "native_qualification_wrong_role_admitted"
                        );
                        ensure!(
                            stage.check().is_err(),
                            "native_qualification_failed_stage_rearmed"
                        );
                    }
                    ensure!(
                        enrolled.begin_current_stage().is_err(),
                        "native_qualification_failed_owner_rearmed"
                    );
                    json!({})
                }
                "native-qualification-receipt" => json!({
                    "format":1,"status":"passed","scope":"native_enrollment_supplier_only",
                    "role":role,"policy":policy.digest()?,"kms_root_version":policy.root.version,
                    "current_role_checked":true,"original_clock_continuity":true,
                    "wrong_role_permanently_refused":true
                }),
                _ => anyhow::bail!("native_qualification_unknown_capability"),
            };
            phase += 1;
            Ok(value)
        },
    )?;
    ensure!(phase == ACTIONS.len(), "native_qualification_incomplete");
    Ok(value)
}
