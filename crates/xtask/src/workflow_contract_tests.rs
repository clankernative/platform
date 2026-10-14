use super::*;

#[test]
fn pinned_roc_rejects_operation_input_response_and_host_contract_drift() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let compiler = native_toolchain::load(&root)?.verified_compiler(&root)?;
    let temporary = tempfile::tempdir()?;
    fs::write(
        temporary.path().join("UiCapability.roc"),
        include_bytes!("../../../ops/UiCapability.roc"),
    )?;
    let examples = [
        (
            true,
            "Good",
            "probe! : UiCapability.LockHost => Try(UiCapability.JsonReceipt, Str)\nprobe! = |host| (host.lock!)({ source: \"app\" })",
        ),
        (
            true,
            "GoodHandler",
            "probe : ({} => Try(Str, Str)) -> UiCapability.LockHost\nprobe = |send!| { lock!: |_input| {\n_ = send!({})?\nOk({ json: \"{}\" })\n} }",
        ),
        (
            false,
            "MisspelledOperation",
            "probe! : UiCapability.InstallHost => Try(UiCapability.Inspection, Str)\nprobe! = |host| (host.inpsect!)({})",
        ),
        (
            false,
            "WrongInputField",
            "probe! : UiCapability.LockHost => Try(UiCapability.JsonReceipt, Str)\nprobe! = |host| (host.lock!)({ soucre: \"app\" })",
        ),
        (
            false,
            "WrongInputType",
            "probe! : UiCapability.LockHost => Try(UiCapability.JsonReceipt, Str)\nprobe! = |host| (host.lock!)({ source: 42.U64 })",
        ),
        (
            false,
            "WrongResponse",
            "probe : UiCapability.Inspection\nprobe = { installed: \"yes\" }",
        ),
        (
            false,
            "MissingHandler",
            "probe : UiCapability.LockHost\nprobe = {}",
        ),
        (
            false,
            "WrongHandlerResponse",
            "probe : ({} => Try(Str, Str)) -> UiCapability.LockHost\nprobe = |send!| { lock!: |_input| {\n_ = send!({})?\nOk({ json: Bool.True })\n} }",
        ),
        (
            false,
            "RawEscape",
            "probe! : UiCapability.InstallHost => Try(Str, Str)\nprobe! = |host| (host.request!)(\"{}\")",
        ),
    ];
    for (accepted, name, body) in examples {
        let path = temporary.path().join(format!("{name}.roc"));
        fs::write(
            &path,
            format!("import UiCapability\n\n{name} :: [].{{\n{body}\n}}\n"),
        )?;
        let output = Command::new(&compiler)
            .arg("check")
            .arg(&path)
            .current_dir(temporary.path())
            .output()?;
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.status.success() == accepted,
            "unexpected compiler result for {name}: {diagnostics}"
        );
        if !accepted {
            ensure!(
                diagnostics.contains("type mismatch"),
                "probe failed before type checking: {name}: {diagnostics}"
            );
        }
    }
    Ok(())
}

#[test]
fn stale_generated_contract_is_refused_before_runner_reuse() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("ops"))?;
    contracts(root.path(), true)?;
    contracts(root.path(), false)?;
    fs::write(root.path().join("ops/UiCapability.roc"), b"stale")?;
    assert!(
        contracts(root.path(), false)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    contracts(root.path(), true)?;
    fs::write(root.path().join("ops/UiTransport.roc"), b"stale")?;
    assert!(contracts(root.path(), false).is_err());
    Ok(())
}
