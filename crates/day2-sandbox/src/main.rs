//! Restricted launcher entrypoint, invoked only by the platform supervisor.
#![forbid(unsafe_code)]

fn run() -> anyhow::Result<()> {
    day2_sandbox::mark_refusal_stage(day2_sandbox::RefusalStage::Arguments);
    let mut args = std::env::args_os().skip(1);
    let worker = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing worker"))?;
    let parent = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing parent identity"))?;
    let memory = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing memory limit"))?;
    let cpu = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing CPU limit"))?;
    anyhow::ensure!(args.next().is_none(), "unexpected launcher argument");
    let parent = parent
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid parent identity"))?
        .parse::<u32>()?;
    let memory = memory
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid memory limit"))?
        .parse::<u64>()?;
    let cpu = cpu
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid CPU limit"))?
        .parse::<u64>()?;
    day2_sandbox::launch(std::path::Path::new(&worker), parent, memory, cpu)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let report = day2_sandbox::RefusalReport::from_error(&error);
            if day2_sandbox::refusal_stdout_is_pipe() {
                // A short pipe record is not a nonblocking-write guarantee.
                // The supervisor's existing exchange timeout/kill/wait remains
                // mandatory, including when a peer stops draining this pipe.
                println!("{report}");
            } else {
                eprintln!("{report}");
            }
            std::process::ExitCode::from(77)
        }
    }
}
