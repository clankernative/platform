//! Preparation inputs and independent expectations. These are fixture DATA,
//! never a native owner, a successful syscall witness or permission to retry.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum PreparationLeaf {
    Missing,
    File,
    Symlink,
    Directory,
    Hardlink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum PreparationFault {
    None,
    WrongProposal,
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    AfterDirectorySync,
    AfterReadback,
    AfterDecode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(in crate::security_epoch) struct PreparationInput {
    pub leaf: PreparationLeaf,
    pub fault: PreparationFault,
}

impl<'de> Deserialize<'de> for PreparationInput {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            leaf: PreparationLeaf,
            fault: PreparationFault,
        }
        struct MapOnly;
        impl<'de> serde::de::Visitor<'de> for MapOnly {
            type Value = PreparationInput;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a preparation input object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let value = Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(PreparationInput {
                    leaf: value.leaf,
                    fault: value.fault,
                })
            }
        }
        deserializer.deserialize_map(MapOnly)
    }
}

impl PreparationInput {
    pub(super) const SUCCESS: Self = Self {
        leaf: PreparationLeaf::Missing,
        fault: PreparationFault::None,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum PreparationDisposition {
    Prepared,
    RefusedBeforeAttempt,
    RefusedAfterAttempt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum PreparationCheckpoint {
    BeforeAttempt,
    ExclusiveCreate,
    Identity,
    Write,
    FileSync,
    DirectorySync,
    Readback,
    Decode,
    FinalCheck,
}

/// Exact byte observations normalized against the immutable replay image.
/// Prefix stores every byte losslessly via that input, including an empty or
/// first-write-only file. Other never drops a differing byte or hashes it away.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "bytes", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch) enum PreparationBytes {
    InitialPrefix { length: usize },
    Other { contents: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "leaf", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch) enum PreparationNamed {
    Missing,
    File {
        contents: PreparationBytes,
        links: u64,
    },
    SymlinkToForeign,
    Directory,
}

/// Complete owning-outcome observations taken when the actual call returns.
/// These stay historical after later app writes. Current file observations
/// remain separately represented by FileState and the existing actual checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct PreparationObservation {
    pub disposition: PreparationDisposition,
    pub stopped_at: PreparationCheckpoint,
    pub attempted: bool,
    pub descriptor_returned: bool,
    pub anchor_retained: bool,
    pub proposal_retained: bool,
    pub selection_matches_admitted: bool,
    pub named: PreparationNamed,
    pub held: Option<PreparationBytes>,
    pub same_named_and_held: bool,
    pub foreign: Vec<u8>,
}

/// Live complete named/held observations while preparation is pending or
/// refused. Successful preparation leaves this scope; later retained-file
/// continuity is checked by the existing FileState/physical-owner path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct PreparationFiles {
    pub named: PreparationNamed,
    pub held: Option<PreparationBytes>,
    pub foreign: Option<Vec<u8>>,
}

pub(in crate::security_epoch) const FOREIGN_BYTES: &[u8] = b"preserved foreign original";
pub(in crate::security_epoch) const EXISTING_BYTES: &[u8] = b"existing selected leaf";

// Independent specification: no preparation coordinator, file observer or
// actual outcome is supplied to this function. The chunk size is a pinned
// expectation, not a call to the implementation's write-loop decisions.
pub(super) fn expected(input: PreparationInput, image_length: usize) -> PreparationObservation {
    let before = input.fault == PreparationFault::WrongProposal;
    let returned = !before && input.leaf == PreparationLeaf::Missing;
    let prepared = returned && input.fault == PreparationFault::None;
    let length = match input.fault {
        PreparationFault::AfterCreate => 0,
        PreparationFault::AfterWrite => image_length.min(1024 * 1024),
        _ => image_length,
    };
    let held = returned.then_some(PreparationBytes::InitialPrefix { length });
    let named = match input.leaf {
        PreparationLeaf::Missing if returned => PreparationNamed::File {
            contents: held.clone().unwrap(),
            links: 1,
        },
        PreparationLeaf::Missing => PreparationNamed::Missing,
        PreparationLeaf::File => PreparationNamed::File {
            contents: PreparationBytes::Other {
                contents: EXISTING_BYTES.to_vec(),
            },
            links: 1,
        },
        PreparationLeaf::Symlink => PreparationNamed::SymlinkToForeign,
        PreparationLeaf::Directory => PreparationNamed::Directory,
        PreparationLeaf::Hardlink => PreparationNamed::File {
            contents: PreparationBytes::Other {
                contents: FOREIGN_BYTES.to_vec(),
            },
            links: 2,
        },
    };
    PreparationObservation {
        stopped_at: if before {
            PreparationCheckpoint::BeforeAttempt
        } else if !returned {
            PreparationCheckpoint::ExclusiveCreate
        } else {
            match input.fault {
                PreparationFault::AfterCreate => PreparationCheckpoint::ExclusiveCreate,
                PreparationFault::AfterWrite => PreparationCheckpoint::Write,
                PreparationFault::AfterFileSync => PreparationCheckpoint::FileSync,
                PreparationFault::AfterDirectorySync => PreparationCheckpoint::DirectorySync,
                PreparationFault::AfterReadback => PreparationCheckpoint::Readback,
                PreparationFault::AfterDecode => PreparationCheckpoint::Decode,
                PreparationFault::None => PreparationCheckpoint::FinalCheck,
                PreparationFault::WrongProposal => unreachable!(),
            }
        },
        disposition: if before {
            PreparationDisposition::RefusedBeforeAttempt
        } else if prepared {
            PreparationDisposition::Prepared
        } else {
            PreparationDisposition::RefusedAfterAttempt
        },
        attempted: !before,
        descriptor_returned: returned,
        anchor_retained: true,
        proposal_retained: true,
        selection_matches_admitted: !before,
        named,
        held,
        same_named_and_held: returned,
        foreign: FOREIGN_BYTES.to_vec(),
    }
}

#[test]
fn preparation_expectations_distinguish_no_returned_fd_from_no_attempt() {
    for leaf in [
        PreparationLeaf::Missing,
        PreparationLeaf::File,
        PreparationLeaf::Symlink,
        PreparationLeaf::Directory,
        PreparationLeaf::Hardlink,
    ] {
        let original = expected(
            PreparationInput {
                leaf,
                fault: PreparationFault::WrongProposal,
            },
            2_000_000,
        );
        assert_eq!(
            original.disposition,
            PreparationDisposition::RefusedBeforeAttempt
        );
        assert!(!original.attempted && !original.descriptor_returned);
        let attempt = expected(
            PreparationInput {
                leaf,
                fault: PreparationFault::AfterCreate,
            },
            2_000_000,
        );
        assert!(attempt.attempted);
        assert_eq!(
            attempt.descriptor_returned,
            leaf == PreparationLeaf::Missing
        );
        assert_eq!(
            attempt.disposition,
            PreparationDisposition::RefusedAfterAttempt
        );
    }
    let written = expected(
        PreparationInput {
            leaf: PreparationLeaf::Missing,
            fault: PreparationFault::AfterWrite,
        },
        2_000_000,
    );
    assert_eq!(
        written.held,
        Some(PreparationBytes::InitialPrefix {
            length: 1024 * 1024
        })
    );
    assert_eq!(
        expected(PreparationInput::SUCCESS, 100).disposition,
        PreparationDisposition::Prepared
    );
}

#[test]
fn preparation_requires_a_physical_image_before_starting_any_history() {
    for event in [
        Event::PrepareOriginal {
            input: PreparationInput::SUCCESS,
        },
        Event::RestorePreparation {},
    ] {
        let mut program = successful(17);
        program.events = vec![event];
        let error = run(&program).expect_err("preparation without immutable input admitted");
        assert_eq!(
            error.to_string(),
            "preparation event requires original image"
        );
    }
}

#[test]
fn preparation_observations_use_closed_checkpoints_and_lossless_prefixes() -> Result<()> {
    for checkpoint in [
        PreparationCheckpoint::BeforeAttempt,
        PreparationCheckpoint::ExclusiveCreate,
        PreparationCheckpoint::Identity,
        PreparationCheckpoint::Write,
        PreparationCheckpoint::FileSync,
        PreparationCheckpoint::DirectorySync,
        PreparationCheckpoint::Readback,
        PreparationCheckpoint::Decode,
        PreparationCheckpoint::FinalCheck,
    ] {
        let bytes = serde_json::to_vec(&checkpoint)?;
        assert_eq!(
            serde_json::from_slice::<PreparationCheckpoint>(&bytes)?,
            checkpoint
        );
    }
    assert!(crate::json::decode::<PreparationCheckpoint>(br#""new_checkpoint""#).is_err());
    let observed = expected(
        PreparationInput {
            leaf: PreparationLeaf::Missing,
            fault: PreparationFault::AfterWrite,
        },
        2_000_000,
    );
    let image = vec![42; 2_000_000];
    let Some(PreparationBytes::InitialPrefix { length }) = observed.held else {
        panic!("write prefix missing");
    };
    assert_eq!(&image[..length], &image[..1024 * 1024]);
    assert!(serde_json::to_vec(&observed.named)?.len() < 128);
    // This encoding references the retained input exactly, never a hash or
    // silently truncated sample. A complete non-prefix retains all its bytes.
    let other = PreparationBytes::Other {
        contents: vec![0, 1, 2, 3, 255],
    };
    assert_eq!(
        serde_json::from_slice::<PreparationBytes>(&serde_json::to_vec(&other)?)?,
        other
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn program(seed: u64, input: PreparationInput) -> Program {
    let mut program = successful(seed);
    program.physical = Some(crate::security_epoch::storage_authority::FileFixture::initial_image());
    program.events.insert(0, Event::PrepareOriginal { input });
    program
}

#[cfg(target_os = "linux")]
#[test]
fn generated_preparation_outcomes_retain_foreign_bytes_and_refused_owners() -> Result<()> {
    let mut observed = BTreeSet::new();
    for seed in 0..16 {
        let leaves = [
            PreparationLeaf::Missing,
            PreparationLeaf::File,
            PreparationLeaf::Symlink,
            PreparationLeaf::Directory,
            PreparationLeaf::Hardlink,
        ];
        let faults = [
            PreparationFault::None,
            PreparationFault::WrongProposal,
            PreparationFault::AfterCreate,
            PreparationFault::AfterWrite,
            PreparationFault::AfterFileSync,
            PreparationFault::AfterDirectorySync,
            PreparationFault::AfterReadback,
            PreparationFault::AfterDecode,
        ];
        // Every cut is reached, with a paired success, independent of random
        // choice. Seeded leaf/cut combinations additionally vary later history.
        let mut inputs = faults
            .into_iter()
            .map(|fault| PreparationInput {
                leaf: PreparationLeaf::Missing,
                fault,
            })
            .collect::<Vec<_>>();
        inputs.extend(leaves.into_iter().map(|leaf| PreparationInput {
            leaf,
            fault: PreparationFault::None,
        }));
        let mut random = seed;
        inputs.push(PreparationInput {
            leaf: leaves[next(&mut random) as usize % leaves.len()],
            fault: faults[next(&mut random) as usize % faults.len()],
        });
        for input in inputs {
            let mut history = program(seed, input);
            let partial_first_write = seed == 0
                && input.fault == PreparationFault::AfterWrite
                && input.leaf == PreparationLeaf::Missing;
            if partial_first_write {
                history.physical = Some(
                    crate::security_epoch::storage_authority::FileFixture::multi_batch_image(),
                );
            }
            let success = input == PreparationInput::SUCCESS;
            if !success {
                history.events = vec![
                    Event::PrepareOriginal { input },
                    Event::RestorePreparation {},
                    Event::Reopen,
                    Event::RestoreClock,
                    Event::PrepareOriginal {
                        input: PreparationInput::SUCCESS,
                    },
                    Event::FirstHolder { death_cut: None },
                    Event::Bootstrap {
                        stage: 0,
                        operation: Operation::Reserve,
                        fault: Fault::None,
                    },
                    Event::Current {
                        death_cut: None,
                        rewrite_provider: false,
                    },
                ];
            }
            let history: Program = serde_json::from_slice(&serde_json::to_vec(&history)?)?;
            let records = check(&history)?;
            let initial = records[0].state.preparation.as_ref().unwrap();
            assert_eq!(initial.foreign, FOREIGN_BYTES);
            assert_eq!(records[0].accepted, success);
            assert_eq!(
                initial,
                &expected(input, history.physical.as_ref().unwrap().len())
            );
            assert!(initial.anchor_retained && initial.proposal_retained);
            if partial_first_write {
                assert!(history.physical.as_ref().unwrap().len() > 2 * 1024 * 1024);
                assert_eq!(
                    initial.held,
                    Some(PreparationBytes::InitialPrefix {
                        length: 1024 * 1024
                    })
                );
            }
            let final_state = &records.last().unwrap().state;
            if success {
                assert!(final_state.first_holder && final_state.continuation);
                assert_eq!(final_state.current, 3);
                assert_eq!(final_state.counter_posts, 2);
            } else {
                assert!(!final_state.continuation && !final_state.first_holder);
                assert_eq!(
                    (
                        final_state.slot_posts,
                        final_state.counter_posts,
                        final_state.current
                    ),
                    (0, 0, 0)
                );
                assert!(
                    records
                        .iter()
                        .all(|record| record.state.preparation.as_ref() == Some(initial))
                );
                assert!(!records[4].accepted && !records[5].accepted);
                if initial.descriptor_returned {
                    assert!(final_state.file.as_ref().unwrap().held_original);
                    assert!(final_state.file.as_ref().unwrap().image_exact);
                }
            }
            observed.insert(serde_json::to_string(&input)?);
        }
    }
    for fault in [
        PreparationFault::AfterCreate,
        PreparationFault::AfterWrite,
        PreparationFault::AfterFileSync,
        PreparationFault::AfterDirectorySync,
        PreparationFault::AfterReadback,
        PreparationFault::AfterDecode,
    ] {
        assert!(observed.contains(&serde_json::to_string(&PreparationInput {
            leaf: PreparationLeaf::Missing,
            fault
        })?));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn pending_preparation_cannot_send_or_be_repaired_by_a_later_attempt() -> Result<()> {
    for pending in [
        Event::FirstHolder { death_cut: None },
        Event::Bootstrap {
            stage: 0,
            operation: Operation::Reserve,
            fault: Fault::None,
        },
        Event::Current {
            death_cut: None,
            rewrite_provider: false,
        },
    ] {
        let mut history = program(17, PreparationInput::SUCCESS);
        history.events = vec![
            pending,
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
            Event::Reopen,
            Event::RestoreClock,
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
        ];
        let records = check(&history)?;
        assert!(!records[0].accepted && !records[1].accepted && !records[4].accepted);
        for record in records {
            assert!(record.state.preparation.is_none());
            assert_eq!(
                (
                    record.state.slot_posts,
                    record.state.counter_posts,
                    record.state.current
                ),
                (0, 0, 0)
            );
            assert_eq!(
                record.state.file,
                Some(FileState {
                    held_original: false,
                    named_original: false,
                    image_exact: false
                })
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_preparation_cannot_replace_a_successful_or_retained_original() -> Result<()> {
    for retain in [false, true] {
        let mut history = program(71, PreparationInput::SUCCESS);
        history.events = vec![Event::PrepareOriginal {
            input: PreparationInput::SUCCESS,
        }];
        if retain {
            history.events.push(Event::FirstHolder { death_cut: None });
        }
        let cut = history.events.len();
        history.events.extend([
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
            Event::Reopen,
            Event::RestoreClock,
            Event::Current {
                death_cut: None,
                rewrite_provider: false,
            },
        ]);
        let records = check(&history)?;
        assert!(!records[cut].accepted);
        let first = &records[0].state.preparation;
        for record in &records[cut..] {
            assert_eq!(&record.state.preparation, first);
            assert!(!record.state.continuation);
            assert_eq!(
                (
                    record.state.slot_posts,
                    record.state.counter_posts,
                    record.state.current
                ),
                (0, 0, 0)
            );
        }
    }
    Ok(())
}

#[test]
fn preparation_program_rejects_unknown_fields_shapes_and_nested_duplicates() {
    for bytes in [
        br#"{"event":"restore_preparation","unexpected":true}"#.as_slice(),
        br#"{"event":"prepare_original","input":{"leaf":"missing","fault":"none","unexpected":true}}"#,
        br#"{"event":"prepare_original","input":{"leaf":"future","fault":"none"}}"#,
        br#"{"event":"prepare_original","input":{"leaf":"missing","fault":"none","fault":"after_create"}}"#,
        br#"{"event":"prepare_original","input":["missing","none"]}"#,
    ] {
        assert!(crate::json::decode::<Event>(bytes).is_err());
    }
    let bytes = serde_json::to_vec(&Event::RestorePreparation {}).unwrap();
    assert_eq!(
        crate::json::decode::<Event>(&bytes).unwrap(),
        Event::RestorePreparation {}
    );
}
