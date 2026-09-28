//! The provider registry: one declaration, from which every capability table is
//! generated.
//!
//! Adding a provider used to mean editing five parallel tables — the `Provider`,
//! `ResourceKind` and `Action` enums, three matches over `Action`, the
//! provider/kind pairing, and the read/write capability lists. Nothing tied them
//! together, so a new provider could satisfy the compiler while silently falling
//! through a `matches!` that decided whether its calls counted as writes.
//!
//! This crate holds contracts only, so the declaration here cannot name a
//! simulation type — those live with the runtime. The mandate that every provider
//! *has* one is enforced next to them, over `Provider::ALL`, which this generates.
//!
//! The simulated world belongs to the provider rather than to a direction of
//! travel: a provider that both makes calls and receives them shares one world, so
//! a test can post a message and then receive an interaction referring to it.

macro_rules! providers {
    ($(
        $provider:ident {
            kind: $kind:ident,
            $(world: $world:literal,)?
            actions: { $($action:ident => $capability:literal ($mode:ident)),* $(,)? } $(,)?
        }
    ),* $(,)?) => {
        #[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
        #[serde(rename_all = "snake_case")]
        pub enum Provider { $($provider),* }

        #[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
        #[serde(rename_all = "snake_case")]
        pub enum ResourceKind { $($kind),* }

        #[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
        #[serde(rename_all = "snake_case")]
        pub enum Action { $($($action,)*)* }

        impl Action {
            /// The resource kind an action operates on.
            pub fn kind(self) -> ResourceKind {
                match self { $($(Self::$action => ResourceKind::$kind,)*)* }
            }

            /// The wire capability name an app names through `Api.external`.
            pub fn capability(self) -> &'static str {
                match self { $($(Self::$action => $capability,)*)* }
            }

            /// Whether the action changes provider state. Declared per action in
            /// the table rather than inferred, because a miscategorised write is
            /// admitted without a write budget.
            pub fn is_write(self) -> bool {
                match self { $($(Self::$action => providers!(@write $mode),)*)* }
            }

            /// Whether the action destroys data that cannot be recovered.
            ///
            /// A third mode rather than a flag beside the table, so declaring an
            /// action is the only place its destructiveness can be stated and a
            /// new one cannot default into being harmless. Nothing an
            /// application invokes may be destroying: the same stance rows have
            /// under `docs/DELETION.md`, applied to providers. Removal is an
            /// operator's decision, and an operator does not reach it through an
            /// app's capability grant.
            pub fn destroys_data(self) -> bool {
                match self { $($(Self::$action => providers!(@destroys $mode),)*)* }
            }

            /// Every declared action. Coverage gates enumerate this rather than a
            /// hand-kept list that can fall behind the enum.
            pub const ALL: &'static [Action] = &[$($(Self::$action,)*)*];

            /// The provider that serves this action.
            pub fn provider(self) -> Provider {
                match self { $($(Self::$action => Provider::$provider,)*)* }
            }
        }

        impl Provider {
            pub const ALL: &'static [Provider] = &[$(Self::$provider),*];

            /// The single resource kind this provider serves.
            pub const fn kind(self) -> ResourceKind {
                match self { $(Self::$provider => ResourceKind::$kind),* }
            }

            /// The provider's simulated world file. Declaring one is not optional:
            /// a provider without a world fails to compile in `day2::simulations`,
            /// which binds each variant to the simulation that serves it.
            pub const fn world(self) -> Option<&'static str> {
                match self { $(Self::$provider => providers!(@world $($world)?),)* }
            }

            pub fn name(self) -> &'static str {
                match self { $(Self::$provider => stringify!($provider)),* }
            }
        }

        /// Every provider's simulated store. Backup and the deterministic
        /// campaign enumerate this reviewed set, never arbitrary neighbours.
        pub const LOCAL_PROVIDER_DATABASES: &[&str] = &[$($($world,)?)*];
    };

    (@write read) => { false };
    (@write write) => { true };
    (@write destroys) => { true };
    (@destroys read) => { false };
    (@destroys write) => { false };
    (@destroys destroys) => { true };
    (@world $world:literal) => { Some($world) };
    (@world) => { None };
}

providers! {
    LocalNotifications {
        kind: NotificationMailbox,
        world: "notifications.sqlite",
        actions: {
            NotificationsResolve => "notifications.recipient.v1" (read),
            NotificationsLatest => "notifications.latest.v1" (read),
            NotificationsSend => "notifications.send.v1" (write),
        },
    },
    SyntheticCarta {
        kind: CartaIssuer,
        world: "carta.synthetic.sqlite",
        actions: {
            CartaSnapshot => "carta.snapshot.v1" (read),
            CartaRecord => "carta.record.v1" (read),
        },
    },
    SyntheticGoogleDirectory {
        kind: GoogleDirectory,
        world: "google_directory.synthetic.sqlite",
        actions: {
            GoogleDirectorySnapshot => "google_directory.snapshot.v1" (read),
            GoogleDirectoryRecord => "google_directory.record.v1" (read),
            GoogleDirectoryCreateUser => "google_directory.create_user.v1" (write),
            GoogleDirectoryPatchAttributes => "google_directory.patch_attributes.v1" (write),
            GoogleDirectoryEnsureGroupMember => "google_directory.ensure_group_member.v1" (write),
        },
    },
    // App-to-app delegation. The "provider" is another application in this same
    // instance, which is why it has no connection and no credential: there is
    // nothing to reach. It is a provider anyway because everything a delegated
    // call needs already exists here -- an operator-granted resource naming what
    // may be called, attenuation that can only narrow it, budgets, the audit
    // stream, and a simulated world so a campaign can answer a delegated read
    // without running the other application.
    LocalDelegation {
        kind: AppOperation,
        world: "delegation.simulated.sqlite",
        actions: {
            DelegateQuery => "app.query.v1" (read),
        },
    },
    SyntheticLinear {
        kind: LinearOrganization,
        world: "linear.synthetic.sqlite",
        actions: {
            LinearEnsureAccess => "linear.ensure_access.v1" (write),
            LinearSuspend => "linear.suspend.v1" (write),
        },
    },
    // Work tracking, kept apart from SyntheticLinear on purpose: that provider
    // holds identity authority over an organization's people, this one reads and
    // reassigns issues. See ResourceTarget::LinearIssueSource.
    LinearWork {
        kind: LinearIssueSource,
        world: "linear_work.simulated.sqlite",
        actions: {
            LinearWorkIssues => "linear_work.issues.v1" (read),
            LinearWorkIssueDetail => "linear_work.issue_detail.v1" (read),
            LinearWorkAssignableUsers => "linear_work.assignable_users.v1" (read),
            // The only write. Reassignment changes who owns work in a shared
            // workspace, so it is budgeted and audited as the act it is.
            LinearWorkReassign => "linear_work.reassign.v1" (write),
        },
    },
    // GitHub Actions. Reads only: this application family watches CI, it does
    // not drive it, and re-running somebody's workflow is a different authority
    // from reading whether it passed.
    GitHubActions {
        kind: GitHubRepository,
        world: "github_actions.simulated.sqlite",
        actions: {
            GitHubJob => "github.job.v1" (read),
            // Returns the signed URL GitHub redirects to, not the log itself. A
            // build log is unbounded — it is exactly the kind of payload a
            // 64-KiB observation cannot carry — so the platform hands back an
            // authorization and stays off the data path, as object downloads do.
            GitHubJobLog => "github.job_log.v1" (read),
        },
    },
    GiteaActions {
        kind: GiteaOrganization,
        world: "gitea_actions.simulated.sqlite",
        actions: {
            GiteaRuns => "gitea.runs.v1" (read),
            GiteaRun => "gitea.run.v1" (read),
            GiteaRunJobs => "gitea.run_jobs.v1" (read),
            GiteaJob => "gitea.job.v1" (read),
            GiteaJobLog => "gitea.job_log.v1" (read),
            GiteaRunners => "gitea.runners.v1" (read),
        },
    },
    SyntheticOperatorAlerts {
        kind: OperatorAlertDestination,
        world: "operator_alerts.synthetic.sqlite",
        actions: {
            OperatorAlertsSend => "operator_alerts.send.v1" (write),
        },
    },
    SlackWebhook {
        kind: SlackWebhookDestination,
        world: "slack_webhook.simulated.sqlite",
        actions: { SlackWebhookPost => "slack_webhook.post.v1" (write) },
    },
    Slack {
        kind: SlackChannel,
        world: "slack.simulated.sqlite",
        actions: {
            SlackRead => "slack.read.v1" (read),
            SlackPost => "slack.post.v1" (write),
        },
    },
    // One provider for every S3-compatible store. The instance chooses the vendor
    // by endpoint: real S3, GCS through its XML API, R2 and MinIO all speak this
    // protocol, so a provider per vendor would multiply the simulation mandate by
    // the number of clouds for no gain. Where vendors genuinely differ — multipart
    // preconditions, presign details — the parity gate holds each to a recorded
    // base rather than an abstraction pretending the difference away.
    //
    // Bytes never pass through an application or the worker. Every operation deals
    // in authorizations and metadata, because a 64-KiB observation cannot carry a
    // 300-MiB video, and an application that never holds the bytes cannot leak
    // them. A grant authorizes a transfer the client performs directly.
    ObjectStore {
        kind: ObjectBucket,
        world: "object_store.simulated.sqlite",
        actions: {
            // Authorizing an upload changes nothing in the store, but it is a
            // write: it admits new bytes into a bucket and must be budgeted and
            // audited as the act that did so.
            ObjectStoreGrantUpload => "object_store.grant_upload.v1" (write),
            ObjectStoreGrantDownload => "object_store.grant_download.v1" (read),
            // Unlike the grants, these reach the store. They are still signed the
            // same way and scoped by the same grant check: the URL is the whole
            // authorization, so the secret stays local for these too.
            ObjectStoreHead => "object_store.head.v1" (read),
            // Destroying, so no application can invoke it whatever its grant
            // says. It exists for the operator retention path, which is the only
            // thing in the platform permitted to remove anything.
            ObjectStoreDelete => "object_store.delete.v1" (destroys),
        },
    },
    Snowflake {
        kind: SnowflakeView,
        world: "snowflake.simulated.sqlite",
        actions: {
            SnowflakeRead => "snowflake.read.v1" (read),
        },
    },
    OpenAi {
        kind: OpenAiText,
        world: "openai.simulated.sqlite",
        actions: {
            OpenAiGenerate => "openai.generate.v1" (write),
        },
    },
}

/// A provider serves exactly one resource kind.
pub(crate) fn provider_matches(provider: Provider, kind: ResourceKind) -> bool {
    provider.kind() == kind
}

/// Capability names that only read.
pub static READS: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
    Action::ALL
        .iter()
        .filter(|action| !action.is_write())
        .map(|action| action.capability())
        .collect()
});

/// Capability names that change provider state.
pub static WRITES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
    Action::ALL
        .iter()
        .filter(|action| action.is_write())
        .map(|action| action.capability())
        .collect()
});
