//! Disposable qualification task-init. No caller PID, certificate, policy path,
//! key, endpoint or runtime method is accepted.
#![forbid(unsafe_code)]

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 1, "native_qualification_role_required");
    let receipt = day2::deployment::qualify_native_enrollment(&args[0])?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
