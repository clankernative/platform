//! Fixed initial-only Controller executor. No retry/adoption or arbitrary
//! process, file, network, key or operation selection is accepted here.
#![forbid(unsafe_code)]

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [instance, app] => match app.to_str() {
            Some(app) => {
                day2::deployment::run_epoch_controller(std::path::Path::new(instance), app)
            }
            None => Err(anyhow::anyhow!("controller app argument")),
        },
        _ => Err(anyhow::anyhow!("controller arguments")),
    };
    if result.is_err() {
        // Provider errors and private paths must not become public logs.
        eprintln!("day2-epoch-controller refused or stopped");
        std::process::exit(1);
    }
}
