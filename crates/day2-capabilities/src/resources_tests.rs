use super::*;
use serde_json::json;

fn fixture() -> Result<(Catalog, Vec<Attachment>)> {
    let catalog = serde_json::from_value(json!({
        "version":1,
        "connections":{"mailbox":{"revision":1,"provider":"local_notifications"}},
        "resources":{
            "reports":{"revision":1,"connection":{"id":"mailbox","revision":1},"target":{"kind":"notification_mailbox","topics":{"kind":"prefix","prefix":"report_"}}},
            "finance":{"revision":1,"connection":{"id":"mailbox","revision":1},"target":{"kind":"notification_mailbox","topics":{"kind":"only","topics":["finance"]}}}
        },
        "budgets":{"calls":{"revision":1,"scope":"invocation_root","period_seconds":3600,"limits":{"calls":5,"bytes":null,"cost_microunits":null,"concurrency":1}}},
        "policies":{"report_updates":{
            "revision":1,"owner":"owner","delegates":["reviewer"],"actors":["alice","bob"],"allowed_apps":["reports"],"max_duration_seconds":3600,
            "slots":{"notifications":{"kind":"notification_mailbox","allowed_resources":[{"id":"reports","revision":1}],"actions":["notifications_resolve","notifications_send"],
                "limits":{"max_request_bytes":8000,"max_response_bytes":1024,"max_calls_per_invocation":5},"budgets":[{"id":"calls","revision":1}]}}
        }}
    }))?;
    let attachments = serde_json::from_value(json!([{
        "policy":{"id":"report_updates","revision":1},"operation":"reports.notify","bindings":{"notifications":{"id":"reports","revision":1}},"actors":["alice"],"expires_at_ms":3_601_000
    }]))?;
    Ok((catalog, attachments))
}

#[test]
fn resolution_pins_exact_resources_and_attenuates_actors_without_unioning_a_template() -> Result<()>
{
    let (catalog, attachments) = fixture()?;
    let resolved = catalog.resolve("reports", &attachments, 1000)?;
    let grant = &resolved.operations["reports.notify"]["notifications"];
    assert_eq!(grant.actors, BTreeSet::from(["alice".into()]));
    assert_eq!(grant.resource.id, "reports");
    assert_eq!(grant.target, catalog.resources["reports"].target);
    assert_eq!(
        grant.budgets,
        vec![VersionRef {
            id: "calls".into(),
            revision: 1
        }]
    );
    assert_eq!(resolved.budgets.len(), 1);
    assert!(!resolved.operations.contains_key("finance.read"));
    assert!(catalog.resolve("another_app", &attachments, 1000).is_err());
    Ok(())
}

#[test]
fn stale_aliases_actors_actions_duration_and_ambiguous_bindings_fail_closed() -> Result<()> {
    let (catalog, attachments) = fixture()?;
    let deny = |alter: fn(&mut Attachment)| {
        let mut attachments = attachments.clone();
        alter(&mut attachments[0]);
        assert!(catalog.resolve("reports", &attachments, 1000).is_err());
    };
    deny(|attachment| attachment.policy.revision = 2);
    deny(|attachment| attachment.bindings.get_mut("notifications").unwrap().id = "finance".into());
    deny(|attachment| {
        attachment
            .bindings
            .get_mut("notifications")
            .unwrap()
            .revision = 2
    });
    deny(|attachment| attachment.actors = Some(BTreeSet::from(["mallory".into()])));
    deny(|attachment| attachment.expires_at_ms = None);
    deny(|attachment| attachment.expires_at_ms = Some(3_601_001));
    deny(|attachment| attachment.expires_at_ms = Some(999));
    deny(|attachment| attachment.bindings.clear());
    let duplicated = vec![attachments[0].clone(), attachments[0].clone()];
    assert!(catalog.resolve("reports", &duplicated, 1000).is_err());
    let mut changed = catalog.clone();
    changed
        .policies
        .get_mut("report_updates")
        .unwrap()
        .slots
        .get_mut("notifications")
        .unwrap()
        .actions
        .insert(Action::CartaRecord);
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn changing_catalogs_requires_revisions_and_does_not_remap_activated_snapshots() -> Result<()> {
    let (catalog, attachments) = fixture()?;
    let resolved = catalog.resolve("reports", &attachments, 1000)?;
    let mut next = catalog.clone();
    next.resources.get_mut("reports").unwrap().target = ResourceTarget::NotificationMailbox {
        topics: TopicScope::Any,
    };
    assert!(catalog.validate_successor(&next).is_err());
    next.resources.get_mut("reports").unwrap().revision = 2;
    assert!(next.validate().is_err());
    let policy = next.policies.get_mut("report_updates").unwrap();
    policy.revision = 2;
    policy
        .slots
        .get_mut("notifications")
        .unwrap()
        .allowed_resources = BTreeSet::from([VersionRef {
        id: "reports".into(),
        revision: 2,
    }]);
    catalog.validate_successor(&next)?;
    assert!(next.resolve("reports", &attachments, 1000).is_err());
    assert_eq!(
        resolved.operations["reports.notify"]["notifications"].target,
        catalog.resources["reports"].target
    );
    let mut changed_period = catalog.clone();
    let budget = changed_period.budgets.get_mut("calls").unwrap();
    budget.revision = 2;
    budget.period_seconds = 1;
    let policy = changed_period.policies.get_mut("report_updates").unwrap();
    policy.revision = 2;
    policy.slots.get_mut("notifications").unwrap().budgets[0].revision = 2;
    assert!(catalog.validate_successor(&changed_period).is_err());
    Ok(())
}

#[test]
fn topic_scope_attenuation_and_resolved_snapshot_tampering_are_checked() -> Result<()> {
    let prefix = TopicScope::Prefix {
        prefix: "report_".into(),
    };
    assert!(
        TopicScope::Only {
            topics: BTreeSet::from(["report_7".into()])
        }
        .is_subset_of(&prefix)
    );
    assert!(
        !TopicScope::Only {
            topics: BTreeSet::from(["finance".into()])
        }
        .is_subset_of(&prefix)
    );
    assert!(!TopicScope::Any.is_subset_of(&prefix));
    assert!(!TopicScope::Any.contains(""));
    let (catalog, attachments) = fixture()?;
    let mut resolved = catalog.resolve("reports", &attachments, 1000)?;
    resolved
        .operations
        .get_mut("reports.notify")
        .unwrap()
        .get_mut("notifications")
        .unwrap()
        .budgets[0]
        .revision = 2;
    assert!(resolved.validate().is_err());
    let mut aliases = catalog.clone();
    aliases.connections.insert(
        "another_mailbox".into(),
        aliases.connections["mailbox"].clone(),
    );
    assert!(aliases.validate().is_err());
    assert!(serde_json::from_value::<Action>(json!("unrestricted_http")).is_err());
    Ok(())
}

/// The complete provider registry as it stands before consolidation.
///
/// Five parallel tables describe every capability today: the `Action` enum, its
/// `kind`/`capability`/`is_write` matches, `provider_matches`, and the `READS`/
/// `WRITES`/`LOCAL_PROVIDER_DATABASES` lists in `day2::capabilities`. Collapsing
/// them into one declaration is only safe if the result is identical, so this
/// pins the answers first. It is a golden record, not a specification: changing
/// it deliberately is fine, changing it by accident is the thing being prevented.
#[cfg(test)]
mod registry_golden {
    use crate::resources::{Action, Provider, ResourceKind};

    const EVERY_ACTION: &[Action] = &[
        Action::NotificationsResolve,
        Action::NotificationsLatest,
        Action::NotificationsSend,
        Action::CartaSnapshot,
        Action::CartaRecord,
        Action::GoogleDirectorySnapshot,
        Action::GoogleDirectoryRecord,
        Action::GoogleDirectoryCreateUser,
        Action::GoogleDirectoryPatchAttributes,
        Action::GoogleDirectoryEnsureGroupMember,
        Action::LinearEnsureAccess,
        Action::LinearSuspend,
        Action::OperatorAlertsSend,
        Action::SlackRead,
        Action::SlackPost,
        Action::SnowflakeRead,
        Action::OpenAiGenerate,
    ];

    const EVERY_PROVIDER: &[Provider] = &[
        Provider::LocalNotifications,
        Provider::SyntheticCarta,
        Provider::SyntheticGoogleDirectory,
        Provider::SyntheticLinear,
        Provider::SyntheticOperatorAlerts,
        Provider::Slack,
        Provider::Snowflake,
        Provider::OpenAi,
    ];

    /// capability string, resource kind, is_write.
    const EXPECTED: &[(&str, ResourceKind, bool)] = &[
        (
            "notifications.recipient.v1",
            ResourceKind::NotificationMailbox,
            false,
        ),
        (
            "notifications.latest.v1",
            ResourceKind::NotificationMailbox,
            false,
        ),
        (
            "notifications.send.v1",
            ResourceKind::NotificationMailbox,
            true,
        ),
        ("carta.snapshot.v1", ResourceKind::CartaIssuer, false),
        ("carta.record.v1", ResourceKind::CartaIssuer, false),
        (
            "google_directory.snapshot.v1",
            ResourceKind::GoogleDirectory,
            false,
        ),
        (
            "google_directory.record.v1",
            ResourceKind::GoogleDirectory,
            false,
        ),
        (
            "google_directory.create_user.v1",
            ResourceKind::GoogleDirectory,
            true,
        ),
        (
            "google_directory.patch_attributes.v1",
            ResourceKind::GoogleDirectory,
            true,
        ),
        (
            "google_directory.ensure_group_member.v1",
            ResourceKind::GoogleDirectory,
            true,
        ),
        (
            "linear.ensure_access.v1",
            ResourceKind::LinearOrganization,
            true,
        ),
        ("linear.suspend.v1", ResourceKind::LinearOrganization, true),
        (
            "operator_alerts.send.v1",
            ResourceKind::OperatorAlertDestination,
            true,
        ),
        ("slack.read.v1", ResourceKind::SlackChannel, false),
        ("slack.post.v1", ResourceKind::SlackChannel, true),
        ("snowflake.read.v1", ResourceKind::SnowflakeView, false),
        ("openai.generate.v1", ResourceKind::OpenAiText, true),
    ];

    /// Exactly one provider serves each resource kind today.
    const PROVIDER_KIND: &[(Provider, ResourceKind)] = &[
        (
            Provider::LocalNotifications,
            ResourceKind::NotificationMailbox,
        ),
        (Provider::SyntheticCarta, ResourceKind::CartaIssuer),
        (
            Provider::SyntheticGoogleDirectory,
            ResourceKind::GoogleDirectory,
        ),
        (Provider::SyntheticLinear, ResourceKind::LinearOrganization),
        (
            Provider::SyntheticOperatorAlerts,
            ResourceKind::OperatorAlertDestination,
        ),
        (Provider::Slack, ResourceKind::SlackChannel),
        (Provider::Snowflake, ResourceKind::SnowflakeView),
        (Provider::OpenAi, ResourceKind::OpenAiText),
    ];

    #[test]
    fn every_action_keeps_its_capability_kind_and_write_classification() {
        assert_eq!(EVERY_ACTION.len(), EXPECTED.len());
        for (action, (capability, kind, write)) in EVERY_ACTION.iter().zip(EXPECTED) {
            assert_eq!(action.capability(), *capability, "{action:?}");
            assert_eq!(action.kind(), *kind, "{action:?}");
            assert_eq!(action.is_write(), *write, "{action:?}");
        }
    }

    #[test]
    fn capability_strings_are_unique_and_namespaced_by_their_kind() {
        let mut seen = std::collections::BTreeSet::new();
        for action in EVERY_ACTION {
            assert!(seen.insert(action.capability()), "{action:?} duplicates");
            // Every capability is "<namespace>.<name>.v<n>": the wire contract the
            // SDK's Api.external names, so it cannot drift silently.
            let parts: Vec<_> = action.capability().split('.').collect();
            assert!(parts.len() >= 3, "{action:?}");
            assert!(
                parts
                    .last()
                    .is_some_and(|last| last.starts_with('v') && last[1..].parse::<u32>().is_ok()),
                "{action:?} is not versioned"
            );
        }
    }

    #[test]
    fn each_provider_serves_exactly_one_resource_kind() {
        assert_eq!(EVERY_PROVIDER.len(), PROVIDER_KIND.len());
        for (provider, kind) in PROVIDER_KIND {
            assert!(
                crate::resources::provider_matches(*provider, *kind),
                "{provider:?}/{kind:?}"
            );
            // And serves no other kind.
            for (_, other) in PROVIDER_KIND {
                if other != kind {
                    assert!(
                        !crate::resources::provider_matches(*provider, *other),
                        "{provider:?} unexpectedly serves {other:?}"
                    );
                }
            }
        }
    }
}

/// What an object grant does and does not authorize.
///
/// A presigned URL is a bearer capability for exactly the object it names, handed
/// to a client the platform does not control. A key admitted here is access given
/// away irrevocably, so this is the one check in the object store that cannot be
/// compensated for later.
#[cfg(test)]
mod object_grant_scope {
    use crate::resources::ResourceTarget;

    fn grant(prefix: &str) -> ResourceTarget {
        ResourceTarget::ObjectBucket {
            bucket: "exampleco-media".into(),
            key_prefix: prefix.into(),
        }
    }

    #[test]
    fn a_key_beneath_the_prefix_is_authorized() {
        let grant = grant("apps/video-composer/");
        for key in [
            "apps/video-composer/renders/1.mp4",
            "apps/video-composer/a/b/c/deep.bin",
            "apps/video-composer/x",
        ] {
            assert!(
                grant.authorizes_object("exampleco-media", key).is_ok(),
                "{key} was refused"
            );
        }
    }

    #[test]
    fn a_key_outside_the_prefix_is_refused() {
        let grant = grant("apps/video-composer/");
        for key in [
            // Another application's objects in the same bucket.
            "apps/spend/statements/2026-01.pdf",
            // The prefix as a sibling rather than a parent.
            "apps/video-composer-evil/x",
            // Above the prefix entirely.
            "apps/",
            "x",
        ] {
            assert!(
                grant.authorizes_object("exampleco-media", key).is_err(),
                "{key} was authorized"
            );
        }
    }

    #[test]
    fn traversal_cannot_climb_out_of_the_prefix() {
        let grant = grant("apps/video-composer/");
        // To a store a key is a flat string, so `a/../b` addresses a *different*
        // object than `b` rather than the same one. A verifier that normalised
        // before comparing would admit these and then sign something else; they
        // are refused as keys outright.
        for key in [
            "apps/video-composer/../spend/secret.pdf",
            "apps/video-composer/./x",
            "apps/video-composer//x",
            "/apps/video-composer/x",
        ] {
            assert!(
                grant.authorizes_object("exampleco-media", key).is_err(),
                "{key} was authorized"
            );
        }
    }

    #[test]
    fn another_bucket_is_refused_however_well_the_key_matches() {
        let grant = grant("apps/video-composer/");
        assert!(
            grant
                .authorizes_object("someone-elses-bucket", "apps/video-composer/x")
                .is_err(),
            "a matching key authorized the wrong bucket"
        );
    }

    #[test]
    fn an_empty_prefix_grants_the_bucket_but_still_refuses_a_malformed_key() {
        // A grant may legitimately cover a whole bucket; that is a decision an
        // operator makes. It still does not make an unrepresentable key valid.
        let whole = grant("");
        assert!(
            whole
                .authorizes_object("exampleco-media", "anything/at/all")
                .is_ok()
        );
        assert!(whole.authorizes_object("exampleco-media", "").is_err());
        assert!(
            whole
                .authorizes_object("exampleco-media", "../escape")
                .is_err()
        );
    }

    #[test]
    fn a_resource_that_is_not_a_bucket_authorizes_no_object() {
        let mailbox = ResourceTarget::NotificationMailbox {
            topics: crate::resources::TopicScope::Any,
        };
        assert!(
            mailbox
                .authorizes_object("exampleco-media", "apps/x")
                .is_err()
        );
    }
}

/// Every provider can actually be connected the way it is meant to be.
///
/// `validate_connection` pairs a provider with the one `LiveConnection` variant
/// that belongs to it, and a provider missing from that match is refused with
/// `resource_connection_configuration_mismatch` — *including for a perfectly
/// correct configuration*. Nothing else notices, because a catalog is only
/// validated when someone writes one, and a provider nobody has configured yet
/// has no catalog to fail.
///
/// That is exactly how `ObjectStore` shipped unconnectable: the provider, its
/// adapter, its simulation and its capabilities all landed and passed a full
/// verify, while an object-store resource could not be put in a catalog at all.
/// It surfaced only when a second live provider was added months of work later.
///
/// So this enumerates from `Provider::ALL` and drives the real function. The
/// sample below is an exhaustive match with no `_` arm: adding a provider is a
/// compile error here until its author says how it connects.
mod connections {
    use super::*;
    use crate::{integrations::LiveConnection, registry::Provider};

    fn reference(id: &str) -> VersionRef {
        VersionRef {
            id: id.into(),
            revision: 1,
        }
    }

    /// How each provider is connected, or `None` for one served entirely from
    /// local state. Exhaustive on purpose.
    fn sample(provider: Provider) -> Option<LiveConnection> {
        match provider {
            // Served from local or synthetic worlds: no endpoint, no credential,
            // and a connection would be a claim that there is something to reach.
            Provider::LocalNotifications
            | Provider::LocalDelegation
            | Provider::SyntheticCarta
            | Provider::SyntheticGoogleDirectory
            | Provider::SyntheticLinear
            | Provider::SyntheticOperatorAlerts => None,
            Provider::Slack => Some(LiveConnection::Slack {
                credential_ref: reference("slack_token"),
                signing_secret_ref: None,
                workspace_id: "T00000001".into(),
            }),
            Provider::ObjectStore => Some(LiveConnection::ObjectStore {
                credential_ref: reference("object_secret"),
                endpoint: "https://s3.example.com".into(),
                region: "us-east-1".into(),
                bucket: "example-bucket".into(),
                access_key_id: "AKIAEXAMPLE".into(),
            }),
            Provider::GitHubActions => Some(LiveConnection::GitHubActions {
                credential_ref: reference("github_token"),
                endpoint: "https://api.github.com".into(),
            }),
            Provider::LinearWork => Some(LiveConnection::LinearWork {
                credential_ref: reference("linear_token"),
                organization_id: "org-example".into(),
            }),
            Provider::Snowflake => Some(LiveConnection::Snowflake {
                credential_ref: reference("snowflake_token"),
                account: "org-account".into(),
                role: "READER".into(),
                warehouse: "WH".into(),
            }),
            Provider::OpenAi => Some(LiveConnection::OpenAi {
                credential_ref: reference("openai_token"),
                project_id: "proj_example".into(),
                organization_id: None,
            }),
        }
    }

    #[test]
    fn every_provider_accepts_the_connection_it_is_meant_to_have() {
        let mut live = 0;
        for provider in Provider::ALL {
            let sample = sample(*provider);
            live += usize::from(sample.is_some());
            validate_connection(*provider, sample.as_ref()).unwrap_or_else(|error| {
                panic!(
                    "{} cannot be connected as intended: {error:#}. A live provider \
                     must be paired with its LiveConnection variant in \
                     validate_connection, or no catalog can hold it.",
                    provider.name()
                )
            });
        }
        // A gate that found no live providers would pass for exactly the case it
        // exists to catch.
        assert!(live >= 4, "only {live} providers were checked as live");
    }

    #[test]
    fn a_provider_cannot_be_connected_as_something_else() {
        // The pairing is the point: a Slack credential pointed at the object
        // store, or an absent connection for a provider that needs one, are both
        // configurations that would otherwise reach a real adapter.
        for provider in Provider::ALL {
            let Some(connection) = sample(*provider) else {
                // A local provider given an endpoint is claiming a reachable
                // service it does not have.
                assert!(
                    validate_connection(
                        *provider,
                        Some(&LiveConnection::LinearWork {
                            credential_ref: reference("wrong"),
                            organization_id: "org".into(),
                        })
                    )
                    .is_err(),
                    "{} accepted a connection it has no use for",
                    provider.name()
                );
                continue;
            };
            assert!(
                validate_connection(*provider, None).is_err(),
                "{} was accepted with no connection at all",
                provider.name()
            );
            // Hand the connection to a provider it does not belong to.
            let other = Provider::ALL
                .iter()
                .find(|candidate| *candidate != provider && sample(**candidate).is_some())
                .expect("another live provider");
            assert!(
                validate_connection(*other, Some(&connection)).is_err(),
                "{} accepted {}'s connection",
                other.name(),
                provider.name()
            );
        }
    }
}

/// Grant narrowing, which decides whether a resource handle may be used at all.
///
/// `ResourceTarget::is_subset_of` matches on pairs and ends in `_ => false`, so
/// a target kind with no arm is not a compile error — it is a kind that never
/// narrows to itself, and every capability on it is refused with
/// `resource_forbidden` for reasons nothing in the message explains. That is
/// exactly what happened to `ObjectBucket`: the whole object-store family was
/// unusable, and the pairwise match is why nobody noticed.
mod narrowing {
    use super::*;
    use crate::integrations::{LinearWorkSource, OpenAiText, SlackChannel, SnowflakeView};

    /// A target of each kind. Exhaustive on purpose: a new kind does not compile
    /// until it is named here, and naming it enrols it in the gate below.
    fn sample(kind: ResourceKind) -> ResourceTarget {
        match kind {
            ResourceKind::NotificationMailbox => ResourceTarget::NotificationMailbox {
                topics: TopicScope::Prefix {
                    prefix: "alerts.".into(),
                },
            },
            ResourceKind::CartaIssuer => ResourceTarget::CartaIssuer {
                issuer_id: "issuer-1".into(),
            },
            ResourceKind::GoogleDirectory => ResourceTarget::GoogleDirectory {
                customer_id: "C01".into(),
                email_domain: "example.com".into(),
                org_unit_prefix: "/people".into(),
                groups: BTreeMap::from([("role".to_string(), "group@example.com".to_string())]),
            },
            ResourceKind::LinearOrganization => ResourceTarget::LinearOrganization {
                organization_id: "org-1".into(),
                email_domain: "example.com".into(),
            },
            ResourceKind::LinearIssueSource => ResourceTarget::LinearIssueSource {
                source: LinearWorkSource::Label {
                    label: "compliance".into(),
                },
            },
            ResourceKind::GitHubRepository => ResourceTarget::GitHubRepository {
                owner: "exampleco".into(),
                repo: "platform".into(),
            },
            ResourceKind::ObjectBucket => ResourceTarget::ObjectBucket {
                bucket: "evidence".into(),
                key_prefix: "uploads/".into(),
            },
            ResourceKind::AppOperation => ResourceTarget::AppOperation {
                app: "people_ops".into(),
                operation: "people_ops.person".into(),
                schema_digest: format!("sha256:{}", "0".repeat(64)),
            },
            ResourceKind::OperatorAlertDestination => ResourceTarget::OperatorAlertDestination {
                destination: "oncall".into(),
                topics: TopicScope::Any,
            },
            ResourceKind::SlackChannel => ResourceTarget::SlackChannel {
                channel: SlackChannel {
                    channel_id: "C0000001".into(),
                },
            },
            ResourceKind::SnowflakeView => ResourceTarget::SnowflakeView {
                query: SnowflakeView {
                    database: "ANALYTICS".into(),
                    schema: "PUBLIC".into(),
                    view: "PEOPLE".into(),
                    columns: vec!["id".into()],
                    filters: BTreeMap::new(),
                    max_rows: 10,
                },
            },
            ResourceKind::OpenAiText => ResourceTarget::OpenAiText {
                profile: OpenAiText {
                    model: "model-snapshot".into(),
                    max_input_bytes: 1024,
                    max_input_tokens: 10,
                    max_output_tokens: 20,
                    input_nanos_per_token: 1000,
                    output_nanos_per_token: 1000,
                },
            },
        }
    }

    #[test]
    fn every_kind_narrows_to_itself_and_to_nothing_of_another_kind() {
        let kinds: Vec<ResourceKind> = Action::ALL.iter().map(|action| action.kind()).collect();
        assert!(!kinds.is_empty());
        for kind in &kinds {
            let target = sample(*kind);
            assert!(
                target.is_subset_of(&target),
                "{target:?} does not narrow to itself, so every grant on it is \
                 refused as not narrower than the policy it came from"
            );
            for other in &kinds {
                if sample(*other).kind() == target.kind() {
                    continue;
                }
                assert!(
                    !target.is_subset_of(&sample(*other)),
                    "{target:?} narrowed to a target of another kind"
                );
            }
        }
    }

    /// A prefix is the whole of an object grant's authority, so narrowing means
    /// reaching fewer keys — never more, and never a different bucket.
    #[test]
    fn an_object_grant_narrows_by_prefix_and_never_widens() {
        let parent = ResourceTarget::ObjectBucket {
            bucket: "evidence".into(),
            key_prefix: "uploads/".into(),
        };
        let child = ResourceTarget::ObjectBucket {
            bucket: "evidence".into(),
            key_prefix: "uploads/2026/".into(),
        };
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child), "a grant widened its prefix");
        let elsewhere = ResourceTarget::ObjectBucket {
            bucket: "other".into(),
            key_prefix: "uploads/2026/".into(),
        };
        assert!(
            !elsewhere.is_subset_of(&parent),
            "a grant crossed into another bucket"
        );
    }
}
