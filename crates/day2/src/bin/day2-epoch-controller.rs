//! Fixed initial-only Controller executor. No retry/adoption or arbitrary
//! process, file, network, key or operation selection is accepted here.
#![forbid(unsafe_code)]

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode, instance, app] if mode == "--observe-preparation-read-only" => match app.to_str() {
            Some(app) => observe_then_idle(
                || {
                    day2::deployment::observe_epoch_controller_preparation(
                        std::path::Path::new(instance),
                        app,
                    )
                },
                hold_after_observation,
            ),
            None => Err(anyhow::anyhow!("controller app argument")),
        },
        [instance, app] => match app.to_str() {
            Some(app) => fail_stop_after_refusal(
                || day2::deployment::run_epoch_controller(std::path::Path::new(instance), app),
                || {
                    eprintln!(
                        "day2-epoch-controller refused or stopped; terminal hold at most 300 seconds"
                    );
                    hold_after_observation()
                },
            ),
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

/// The observation has returned (and dropped every role/storage owner) before
/// idle runs on BOTH outcomes. A Deployment must not immediately restart this
/// process after its one observation. The operator must disable liveness and
/// stop it before this fixed five-minute hold ends; no once-across-restarts or
/// hard OS scheduling bound is supplied.
fn observe_then_idle(
    observe: impl FnOnce() -> anyhow::Result<()>,
    idle: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let result = observe();
    let held = idle();
    result.and(held)
}

fn hold_after_observation() -> anyhow::Result<()> {
    day2::deployment::NativeTerminalHold::prepare()?.wait()
}

fn fail_stop_after_refusal(
    run: impl FnOnce() -> anyhow::Result<()>,
    hold: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    match run() {
        Ok(()) => Ok(()),
        Err(error) => {
            // The executor and its resources have unwound. Do not retain its
            // error payload or retry it while waiting for the operator.
            drop(error);
            hold()?;
            anyhow::bail!("native controller refused")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn one_observation_then_ownerless_idle_runs_on_success_and_refusal() {
        for fails in [false, true] {
            let events = RefCell::new(Vec::new());
            let result = observe_then_idle(
                || {
                    events.borrow_mut().push("observe");
                    if fails {
                        anyhow::bail!("native refusal");
                    }
                    Ok(())
                },
                || {
                    events.borrow_mut().push("ownerless idle");
                    Ok(())
                },
            );
            assert_eq!(result.is_err(), fails);
            assert_eq!(*events.borrow(), ["observe", "ownerless idle"]);
        }
    }

    #[test]
    fn executor_unwinds_before_terminal_hold_and_is_never_repeated() {
        struct Resource<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for Resource<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop actual scope");
            }
        }
        for fails in [false, true] {
            let events = RefCell::new(Vec::new());
            let result = fail_stop_after_refusal(
                || {
                    let _actual = Resource(&events);
                    events.borrow_mut().push("run once");
                    if fails {
                        anyhow::bail!("private fixture failure");
                    }
                    Ok(())
                },
                || {
                    assert_eq!(*events.borrow(), ["run once", "drop actual scope"]);
                    events.borrow_mut().push("terminal hold");
                    Ok(())
                },
            );
            assert_eq!(result.is_err(), fails);
            assert_eq!(events.borrow().len(), if fails { 3 } else { 2 });
        }
    }
}
