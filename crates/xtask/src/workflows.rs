//! Bootstrap only: compile the private Roc runner using the pinned compiler.
//! Source hashes prevent an old executable silently running a new recipe.
use super::*;

pub fn build(root: &Path) -> Result<PathBuf> {
    let executable = root.join("target/debug/day2-workflows");
    let pin = native_toolchain::load(root)?;
    let roc = pin.verified_compiler(root)?;
    ensure!(
        digest(&fs::read(root.join(pin.target.pin_path()))?)
            == day2::automation::toolchain_digest(),
        "workflow compiler pin changed; rerun cargo"
    );
    for (name, expected) in day2::automation::SOURCES {
        ensure!(
            fs::read(root.join(name))? == *expected,
            "workflow source changed during compilation; rerun cargo: {name}"
        );
    }
    if let Ok(checked) = day2::automation::checked_runner(&executable)
        && native_toolchain::verify_executable_target(pin.target, &checked).is_ok()
    {
        return Ok(checked);
    }
    fs::create_dir_all(executable.parent().context("runner directory")?)?;
    run(
        root,
        Command::new(&roc)
            .arg("build")
            .arg(root.join("ops/Runner.roc"))
            .arg(format!("--output={}", executable.display()))
            .env("ROC_CACHE_DIR", root.join("cli/.cache")),
    )?;
    for (name, expected) in day2::automation::SOURCES {
        ensure!(
            fs::read(root.join(name))? == *expected,
            "workflow source changed while compiling: {name}"
        );
    }
    ensure!(
        digest(&fs::read(root.join(pin.target.pin_path()))?)
            == day2::automation::toolchain_digest(),
        "workflow compiler pin changed while compiling; rerun cargo"
    );
    pin.verified_compiler(root)?;
    native_toolchain::verify_executable_target(pin.target, &executable)?;
    fs::write(
        executable.with_extension("json"),
        serde_json::to_vec_pretty(&day2::automation::Distribution {
            sources: day2::automation::source_digest(),
            toolchain: day2::automation::toolchain_digest(),
            executable: digest(&fs::read(&executable)?),
        })?,
    )?;
    day2::automation::checked_runner(&executable)
}
