use anyhow::Result;
use day2::automation;
use serde_json::json;

#[test]
fn supplier_qualification_runs_every_native_obligation_and_stops_at_each_failure() -> Result<()> {
    let expected = [
        "native-qualification-enroll",
        "native-qualification-current",
        "native-qualification-original-clock",
        "native-qualification-wait",
        "native-qualification-clock-continuity",
        "native-qualification-role-refusal",
        "native-qualification-receipt",
    ];
    for fail_at in 0..=expected.len() {
        let mut actions = Vec::new();
        let result = automation::run(
            &automation::runner()?,
            &["native-enrollment-qualify"],
            |request| {
                let input: serde_json::Value = request.decode()?;
                assert_eq!(input, json!({}));
                actions.push(request.action);
                anyhow::ensure!(actions.len() != fail_at + 1, "injected native refusal");
                Ok(json!({"status":"native fixture only"}))
            },
        );
        if fail_at < expected.len() {
            assert!(result.is_err());
            assert_eq!(actions, expected[..=fail_at]);
        } else {
            assert!(result.is_ok());
            assert_eq!(actions, expected);
        }
    }
    Ok(())
}

#[test]
fn provisioner_stops_supervision_on_failed_current_child_check() -> Result<()> {
    let mut actions = Vec::new();
    let result = automation::run(&automation::runner()?, &["native-enrollment"], |request| {
        actions.push(request.action.clone());
        anyhow::ensure!(
            request.action != "native-enrollment-current",
            "child exited"
        );
        Ok(json!({}))
    });
    assert!(result.is_err());
    assert_eq!(
        actions,
        ["native-enrollment-start", "native-enrollment-current"]
    );
    Ok(())
}
