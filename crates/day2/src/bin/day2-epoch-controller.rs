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

/// The observation has returned (and dropped every role/storage owner) before
/// idle runs on BOTH outcomes. A Deployment must not immediately restart this
/// process after its one observation. The operator must disable liveness and
/// stop it before this fixed five-minute hold ends; no once-across-restarts or
/// hard OS scheduling bound is supplied.
fn observe_then_idle(
    observe: impl FnOnce() -> anyhow::Result<()>,
    idle: impl FnOnce(),
) -> anyhow::Result<()> {
    let result = observe();
    idle();
    result
}

fn hold_after_observation() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    idle_until(
        || deadline.checked_duration_since(std::time::Instant::now()),
        std::thread::park_timeout,
    );
}

fn idle_until(
    mut remaining: impl FnMut() -> Option<std::time::Duration>,
    mut park: impl FnMut(std::time::Duration),
) {
    while let Some(remaining) = remaining() {
        if remaining.is_zero() {
            break;
        }
        // Recheck after spurious wakeups without repeating the observation.
        park(remaining.min(std::time::Duration::from_secs(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, time::Duration};

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
                || events.borrow_mut().push("ownerless idle"),
            );
            assert_eq!(result.is_err(), fails);
            assert_eq!(*events.borrow(), ["observe", "ownerless idle"]);
        }
    }

    #[test]
    fn spurious_wakeups_only_recheck_hold_deadline_not_observation() {
        let mut times = [
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(200)),
            Some(Duration::ZERO),
        ]
        .into_iter();
        let mut waits = Vec::new();
        idle_until(|| times.next().unwrap(), |duration| waits.push(duration));
        assert_eq!(
            waits,
            [
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_millis(200)
            ]
        );
    }
}
