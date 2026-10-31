//! Bounded cold-publication observations on the actual enrollment original.
//! This loop never admits Pending, renews a clock or retries a refused owner.

use super::issuer_costs::FailureStage;
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    runtime_profile::{ContainerObservation, ContainerPublication},
};
use anyhow::{Context, Result};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_millis(50);
const MAX_OBSERVATIONS: usize = 128;

pub(super) trait Port {
    fn check(&mut self, original: &mut NativeAcquisition) -> Result<()>;
    fn observe(&mut self, original: &mut NativeAcquisition) -> Result<ContainerPublication>;
    fn wait(&mut self, duration: Duration, original: &mut NativeAcquisition) -> Result<()>;
}

pub(super) fn current(
    port: &mut impl Port,
    original: &mut NativeAcquisition,
) -> Result<ContainerObservation> {
    let result = (|| {
        for _ in 0..MAX_OBSERVATIONS {
            check(port, original).context(FailureStage::PublicationBefore)?;
            let observed = port.observe(original);
            let checked = check(port, original).context(FailureStage::PublicationAfterRead);
            let observed = observed?;
            checked?;
            match observed {
                ContainerPublication::Running(observed) => return Ok(observed),
                ContainerPublication::AwaitPublication => {
                    let duration = original.remaining()?.min(INTERVAL);
                    let waited = port
                        .wait(duration, original)
                        .context(FailureStage::PublicationWait);
                    let checked = check(port, original).context(FailureStage::PublicationAfterWait);
                    waited?;
                    checked?;
                    original.remaining()?;
                }
            }
        }
        Err(anyhow::anyhow!("native_enrollment_publication_limit")
            .context(FailureStage::PublicationLimit))
    })();
    if result.is_err() {
        original.refuse();
    }
    result
}

fn check(port: &mut impl Port, original: &mut NativeAcquisition) -> Result<()> {
    original.remaining()?;
    port.check(original)?;
    original.remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::runtime_profile::ContainerFacts;
    use day2_capabilities::Digest;
    use std::collections::VecDeque;

    #[derive(Clone, Copy)]
    enum Observation {
        Pending,
        Running,
        ReadError,
        RefuseThenRunning,
        ExpireThenRunning,
        RewindThenRunning,
    }

    struct Fixture {
        observations: VecDeque<Observation>,
        reads: usize,
        checks: usize,
        waits: Vec<Duration>,
        now: Duration,
        die_at: Option<usize>,
        wait_error: bool,
        oversleep: bool,
        frozen: bool,
    }

    fn fixture(observations: &[Observation]) -> (Fixture, NativeAcquisition) {
        let origin = Duration::from_secs(100);
        (
            Fixture {
                observations: observations.iter().copied().collect(),
                reads: 0,
                checks: 0,
                waits: Vec::new(),
                now: origin,
                die_at: None,
                wait_error: false,
                oversleep: false,
                frozen: false,
            },
            NativeAcquisition::fixture(
                Digest::new(b"publication-original"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            ),
        )
    }

    fn running() -> ContainerPublication {
        ContainerPublication::Running(ContainerObservation {
            facts: ContainerFacts {
                pod_name: "selected".into(),
                pod_uid: "selected-uid".into(),
                node_name: "node".into(),
                container_name: "native".into(),
                container_id: format!("containerd://{}", "7".repeat(64)),
                image: Digest::new(b"image"),
                restart_count: 0,
            },
            owner: serde_json::json!({"name":"replica"}),
        })
    }

    impl Port for Fixture {
        fn check(&mut self, _: &mut NativeAcquisition) -> Result<()> {
            self.checks += 1;
            anyhow::ensure!(self.die_at != Some(self.checks), "fixture_actor_died");
            Ok(())
        }

        fn observe(&mut self, original: &mut NativeAcquisition) -> Result<ContainerPublication> {
            self.reads += 1;
            match self
                .observations
                .pop_front()
                .unwrap_or(Observation::Pending)
            {
                Observation::Pending => Ok(ContainerPublication::AwaitPublication),
                Observation::Running => Ok(running()),
                Observation::ReadError => {
                    Err(anyhow::anyhow!("fixture_read_error").context(FailureStage::PodRead))
                }
                Observation::RefuseThenRunning => {
                    original.refuse();
                    Ok(running())
                }
                Observation::ExpireThenRunning => {
                    let _ = original.fixture_observe(Duration::from_secs(105));
                    Ok(running())
                }
                Observation::RewindThenRunning => {
                    original.fixture_observe(Duration::from_secs(101))?;
                    let _ = original.fixture_observe(Duration::from_secs(100));
                    Ok(running())
                }
            }
        }

        fn wait(&mut self, duration: Duration, original: &mut NativeAcquisition) -> Result<()> {
            self.waits.push(duration);
            if !self.frozen {
                self.now += if self.oversleep {
                    Duration::from_secs(5)
                } else {
                    duration
                };
                original.fixture_observe(self.now)?;
            }
            anyhow::ensure!(!self.wait_error, "fixture_wait_error");
            Ok(())
        }
    }

    #[test]
    fn pending_then_running_keeps_one_original_and_waits_grant_nothing() {
        let (mut port, mut original) = fixture(&[
            Observation::Pending,
            Observation::Pending,
            Observation::Running,
        ]);
        let before = original.historical_interval_observation();
        let result = current(&mut port, &mut original).unwrap();
        let after = original.historical_interval_observation();
        assert_eq!((after.0, after.1, after.2), (before.0, before.1, before.2));
        assert_eq!(after.3, Duration::from_millis(100_100));
        assert_eq!(port.waits, [INTERVAL, INTERVAL]);
        assert_eq!(port.reads, 3);
        assert_eq!(result.facts.pod_uid, "selected-uid");
    }

    #[test]
    fn actual_read_error_is_terminal_and_keeps_primary_over_postcheck_error() {
        let (mut port, mut original) = fixture(&[Observation::ReadError, Observation::Running]);
        port.die_at = Some(2);
        let error = current(&mut port, &mut original).err().unwrap();
        assert_eq!(
            error.downcast_ref::<FailureStage>(),
            Some(&FailureStage::PodRead)
        );
        assert_eq!(port.checks, 2);
        assert_eq!(port.reads, 1);
        assert!(port.waits.is_empty());
        assert!(original.remaining().is_err());
        assert!(current(&mut port, &mut original).is_err());
        assert_eq!(port.reads, 1);
    }

    #[test]
    fn post_read_refusal_expiry_and_rewind_reject_even_running_ok() {
        for observation in [
            Observation::RefuseThenRunning,
            Observation::ExpireThenRunning,
            Observation::RewindThenRunning,
        ] {
            let (mut port, mut original) = fixture(&[observation, Observation::Running]);
            let error = current(&mut port, &mut original).err().unwrap();
            assert_eq!(
                error.downcast_ref::<FailureStage>(),
                Some(&FailureStage::PublicationAfterRead)
            );
            assert!(original.remaining().is_err());
            assert_eq!(port.reads, 1);
            assert!(port.waits.is_empty());
        }
    }

    #[test]
    fn actor_death_after_read_or_wait_never_returns_container() {
        for die_at in [2, 3] {
            let (mut port, mut original) = fixture(&[Observation::Pending, Observation::Running]);
            port.die_at = Some(die_at);
            assert!(current(&mut port, &mut original).is_err());
            assert_eq!(port.reads, 1);
            assert_eq!(port.waits.len(), usize::from(die_at == 3));
            assert!(original.remaining().is_err());
        }
    }

    #[test]
    fn wait_error_and_oversleep_are_terminal_without_another_read() {
        for oversleep in [false, true] {
            let (mut port, mut original) = fixture(&[Observation::Pending, Observation::Running]);
            port.wait_error = !oversleep;
            port.oversleep = oversleep;
            let error = current(&mut port, &mut original).err().unwrap();
            assert_eq!(
                error.downcast_ref::<FailureStage>(),
                Some(&FailureStage::PublicationWait)
            );
            assert_eq!(port.reads, 1);
            assert_eq!(port.waits, [INTERVAL]);
            assert!(original.remaining().is_err());
        }
    }

    #[test]
    fn final_wait_uses_only_remaining_original_budget_and_exact_expiry_refuses() {
        let (mut port, mut original) = fixture(&[Observation::Pending, Observation::Running]);
        port.now = Duration::from_millis(104_975);
        original.fixture_observe(port.now).unwrap();
        assert!(current(&mut port, &mut original).is_err());
        assert_eq!(port.waits, [Duration::from_millis(25)]);
        assert_eq!(port.reads, 1);
        assert!(original.remaining().is_err());
    }

    #[test]
    fn observation_limit_is_bounded_even_if_fixture_time_does_not_advance() {
        let (mut port, mut original) = fixture(&[]);
        port.frozen = true;
        let error = current(&mut port, &mut original).err().unwrap();
        assert_eq!(
            error.downcast_ref::<FailureStage>(),
            Some(&FailureStage::PublicationLimit)
        );
        assert_eq!(port.reads, MAX_OBSERVATIONS);
        assert!(original.remaining().is_err());
    }

    fn loop_wiring(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls {
            events: Vec<String>,
            bad: bool,
        }
        fn named(expression: &syn::Expr, name: &str) -> bool {
            matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    if path.path.is_ident("check") {
                        self.events.push("check".into());
                        self.bad |= call.args.len() != 2
                            || !named(&call.args[0], "port")
                            || !named(&call.args[1], "original");
                    }
                    self.bad |= path.path.segments.iter().any(|segment| {
                        matches!(
                            segment.ident.to_string().as_str(),
                            "begin" | "fixture" | "borrowed" | "owned"
                        )
                    });
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                let method = call.method.to_string();
                if named(&call.receiver, "port") && ["observe", "wait"].contains(&method.as_str()) {
                    self.events.push(method.clone());
                    self.bad |= !call
                        .args
                        .last()
                        .is_some_and(|argument| named(argument, "original"));
                }
                if method == "refuse" && named(&call.receiver, "original") {
                    self.events.push("refuse".into());
                }
                self.bad |= ["narrow", "into_owned", "finish_known"].contains(&method.as_str());
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let syntax = syn::parse_file(source).unwrap();
        let functions = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "current" => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        if functions.len() != 1 {
            return false;
        }
        let mut calls = Calls::default();
        calls.visit_block(&functions[0].block);
        !calls.bad && calls.events == ["check", "observe", "check", "wait", "check", "refuse"]
    }

    #[test]
    fn actual_loop_uses_same_original_and_keeps_postchecks_and_terminal_refusal() {
        let source = include_str!("publication.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        assert!(loop_wiring(source));
        for (before, after) in [
            (
                "check(port, original).context(FailureStage::PublicationAfterRead)",
                "Ok::<(), anyhow::Error>(())",
            ),
            ("port.observe(original)", "port.observe(&mut replacement)"),
            ("original.refuse();", "unrelated.refuse();"),
        ] {
            assert_eq!(source.matches(before).count(), 1);
            let changed = source.replacen(before, after, 1);
            assert!(!loop_wiring(&changed));
        }
        let changed = source.replacen(
            "let result = (|| {",
            "let result = (|| { let _ = NativeAcquisition::begin(5)?;",
            1,
        );
        assert!(!loop_wiring(&changed));
    }
}
