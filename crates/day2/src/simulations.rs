//! Every provider must have a simulation, and this is where that is enforced.
//!
//! The registry in `day2-capabilities` holds contracts only, so it cannot name a
//! simulation type. The binding lives here instead, as one exhaustive match over
//! `Provider::ALL`. Two compile-time properties follow:
//!
//! - **A new provider cannot be added without a decision.** The match has no `_`
//!   arm, so a new `Provider` variant fails to compile until it is answered for.
//! - **A new provider cannot answer "none".** The match returns a world, not an
//!   option. There was briefly a `Grandfathered` answer for the three providers
//!   admitted before this rule; all three now have simulations, and the escape
//!   hatch is gone rather than left empty for someone to reach for again.
//!
//! What the type system cannot do is make a simulation *faithful*. A simulation
//! that exists but lies passes everything here. That is the job of the parity and
//! coverage gates, which enumerate `Action::ALL` and must exercise every action and
//! every failure mode.

use day2_capabilities::resources::Provider;

/// A provider's offline world, shared by every direction of travel. A provider
/// that both makes calls and receives them commits to one file, so a simulated
/// message posted outbound is visible to the inbound delivery that refers to it.
pub trait SimulatedProvider {
    const PROVIDER: Provider;
    /// The store its state commits to, relative to the instance state directory.
    const WORLD: &'static str;
}

macro_rules! simulated {
    ($name:ident => $provider:ident, $world:literal) => {
        pub struct $name;
        impl SimulatedProvider for $name {
            const PROVIDER: Provider = Provider::$provider;
            const WORLD: &'static str = $world;
        }
    };
}

simulated!(Notifications => LocalNotifications, "notifications.sqlite");
// Delegation's world holds recorded answers to delegated reads. A campaign runs
// one application, so the other one is not there to ask -- and running it for
// real would make a caller's determinism depend on a callee's state, which is
// the coupling delegation exists to make visible rather than to hide.
simulated!(Delegation => LocalDelegation, "delegation.simulated.sqlite");
simulated!(Carta => SyntheticCarta, "carta.synthetic.sqlite");
simulated!(GoogleDirectory => SyntheticGoogleDirectory, "google_directory.synthetic.sqlite");
simulated!(Linear => SyntheticLinear, "linear.synthetic.sqlite");
simulated!(OperatorAlerts => SyntheticOperatorAlerts, "operator_alerts.synthetic.sqlite");
// The three adapters admitted live-first. Their worlds are served by
// `integrations::simulated`, at the transport seam, so the offline lane and the
// live lane differ only in the socket.
simulated!(SlackWebhook => SlackWebhook, "slack_webhook.simulated.sqlite");
simulated!(Slack => Slack, "slack.simulated.sqlite");
simulated!(ObjectStore => ObjectStore, "object_store.simulated.sqlite");
simulated!(Snowflake => Snowflake, "snowflake.simulated.sqlite");
simulated!(OpenAi => OpenAi, "openai.simulated.sqlite");
simulated!(LinearWork => LinearWork, "linear_work.simulated.sqlite");
simulated!(GiteaActions => GiteaActions, "gitea_actions.simulated.sqlite");
simulated!(GitHubActions => GitHubActions, "github_actions.simulated.sqlite");

/// The world each provider's simulation commits to. Exhaustive by construction:
/// there is no `_` arm, so adding a provider is a compile error until it is
/// answered here, and the answer is a world rather than an option, so the only
/// thing that can be written is a simulation that exists.
pub const fn simulation(provider: Provider) -> &'static str {
    match provider {
        Provider::LocalNotifications => Notifications::WORLD,
        Provider::LocalDelegation => Delegation::WORLD,
        Provider::SyntheticCarta => Carta::WORLD,
        Provider::SyntheticGoogleDirectory => GoogleDirectory::WORLD,
        Provider::SyntheticLinear => Linear::WORLD,
        Provider::SyntheticOperatorAlerts => OperatorAlerts::WORLD,
        Provider::SlackWebhook => SlackWebhook::WORLD,
        Provider::Slack => Slack::WORLD,
        Provider::ObjectStore => ObjectStore::WORLD,
        Provider::Snowflake => Snowflake::WORLD,
        Provider::OpenAi => OpenAi::WORLD,
        Provider::LinearWork => LinearWork::WORLD,
        Provider::GitHubActions => GitHubActions::WORLD,
        Provider::GiteaActions => GiteaActions::WORLD,
    }
}

/// How a provider's world comes into existence.
///
/// The second completeness property, and the one with no compiler help of its
/// own. `simulation()` above answers *can this declaration fall behind the
/// type* — that has an exhaustive match. It does not answer **can every
/// declared thing actually be supplied**: a `world:` string is data and seeding
/// is a runtime operation, so the compiler sees a name and a function and cannot
/// know the function covers the name.
///
/// A provider could therefore declare a world that nothing can create. That is
/// not hypothetical — it is the same shape as `mount()` deriving its reference
/// from `credential_ref()`, which made a declared signing secret impossible to
/// install: complete-looking, compiling, and unusable at first real use.
///
/// This match closes the half a compiler can reach. It is exhaustive with no `_`
/// arm, so a new provider cannot compile until someone says how its world is
/// supplied. "Created on demand" is a legitimate answer; not answering is not.
/// The other half — that the named path actually works — is behavioural, and
/// lives in `supply_tests.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Supply {
    /// `integrations::simulated::seed`, from a `SimulatedFixture` field.
    SimulatedFixture,
    /// `carta::seed_synthetic`, from an operator-provided capture.
    CartaCapture,
    /// `people_providers::seed_synthetic`.
    SyntheticPeople,
    /// The capability creates the world on first use; no seeding step exists.
    CreatedOnDemand,
}

pub const fn supply(provider: Provider) -> Supply {
    match provider {
        Provider::LocalNotifications => Supply::CreatedOnDemand,
        Provider::SyntheticCarta => Supply::CartaCapture,
        Provider::SyntheticGoogleDirectory
        | Provider::SyntheticLinear
        | Provider::SyntheticOperatorAlerts => Supply::SyntheticPeople,
        Provider::LocalDelegation
        | Provider::SlackWebhook
        | Provider::Slack
        | Provider::Snowflake
        | Provider::OpenAi
        | Provider::ObjectStore
        | Provider::LinearWork
        | Provider::GitHubActions
        | Provider::GiteaActions => Supply::SimulatedFixture,
    }
}

// The mandate. The registry's declared world and the simulation bound here must
// agree, so the two cannot drift into disagreeing about which file a provider
// commits to — and a provider that declares no world at all fails here.
const _: () = {
    let mut index = 0;
    while index < Provider::ALL.len() {
        let provider = Provider::ALL[index];
        let agreed = match provider.world() {
            Some(declared) => konst_str_eq(declared, simulation(provider)),
            None => false,
        };
        assert!(
            agreed,
            "every provider must declare a world that matches its simulation",
        );
        index += 1;
    }
};

const fn konst_str_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_provider_has_a_simulation_and_no_two_share_a_world() {
        let worlds: Vec<_> = Provider::ALL.iter().map(|p| simulation(*p)).collect();
        assert_eq!(worlds.len(), Provider::ALL.len());
        let distinct: std::collections::BTreeSet<_> = worlds.iter().collect();
        // A shared store would let one provider's state answer for another's.
        assert_eq!(distinct.len(), worlds.len());
    }

    #[test]
    fn simulated_worlds_are_exactly_the_enumerated_provider_stores() {
        let worlds: Vec<_> = Provider::ALL.iter().map(|p| simulation(*p)).collect();
        assert_eq!(worlds, crate::capabilities::LOCAL_PROVIDER_DATABASES);
    }

    /// The three that were admitted before the rule now answer like any other.
    #[test]
    fn the_adapters_admitted_live_first_are_served_by_the_transport_simulation() {
        use crate::integrations::simulated;
        assert_eq!(simulation(Provider::Slack), simulated::SLACK_WORLD);
        assert_eq!(simulation(Provider::Snowflake), simulated::SNOWFLAKE_WORLD);
        assert_eq!(simulation(Provider::OpenAi), simulated::OPENAI_WORLD);
    }
}
