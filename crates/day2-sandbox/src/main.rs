//! Restricted launcher entrypoint, invoked only by the platform supervisor.
#![forbid(unsafe_code)]

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let worker = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing worker"))?;
    let parent = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing parent identity"))?;
    anyhow::ensure!(args.next().is_none(), "unexpected launcher argument");
    let parent = parent
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid parent identity"))?
        .parse::<u32>()?;
    day2_sandbox::launch(std::path::Path::new(&worker), parent)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("day2 sandbox refused launch: {error:#}");
            std::process::ExitCode::from(77)
        }
    }
}
