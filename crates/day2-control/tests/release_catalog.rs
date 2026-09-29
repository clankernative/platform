use anyhow::Result;
use day2_control::journal::Journal;
use day2_control::kernel::CredentialPresence;

#[path = "support/release.rs"]
mod support;
use support::*;

#[test]
fn active_catalog_follows_only_activated_release_receipts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let target = target("alpha");
    configure(&mut journal, &target, &plan("alpha", 1));

    let empty = journal.active_catalog_selection(&target.company, &target.environment)?;
    assert!(empty.releases.is_empty());

    let first_input = approval(&mut journal, "alpha", 1, 0);
    let first = journal.approve_release(&first_input)?;
    assert_eq!(
        journal
            .active_catalog_selection(&target.company, &target.environment)?
            .digest,
        empty.digest
    );
    metadata(&mut journal, &first_input);
    let ready = journal.prepare_release(&first)?;
    let receipt = journal.activate_release(&ready)?;
    let active = journal.active_catalog_selection(&target.company, &target.environment)?;
    assert_eq!(active.releases["reports"], receipt);
    assert_ne!(active.digest, empty.digest);
    assert!(
        journal
            .active_catalog_selection(&name("other"), &target.environment)?
            .releases
            .is_empty()
    );

    let next = approval(&mut journal, "alpha", 2, 1);
    journal.approve_release(&next)?;
    assert_eq!(
        journal
            .active_catalog_selection(&target.company, &target.environment)?
            .digest,
        active.digest,
        "a desired release must not enter discovery"
    );
    Ok(())
}

#[test]
fn enrolled_scope_requires_a_qualified_candidate_at_activation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::open(&directory.path().join("journal.sqlite"))?;
    let target = target("alpha");
    configure(&mut journal, &target, &plan("alpha", 1));
    journal.enable_catalog_scope(&target.company, &target.environment, directory.path())?;
    assert!(journal.catalog_scope_enabled(&target.company, &target.environment)?);
    assert!(!journal.catalog_scope_enabled(&name("other"), &target.environment)?);

    let input = approval(&mut journal, "alpha", 1, 0);
    let release = journal.approve_release(&input)?;
    metadata(&mut journal, &input);
    let ready = journal.prepare_release(&release)?;
    let error = journal.activate_release(&ready).unwrap_err();
    assert!(error.to_string().contains("requires qualified candidate"));
    let active = journal.active_catalog_selection(&target.company, &target.environment)?;
    assert!(
        active.releases.is_empty(),
        "failed qualification must leave selection intact"
    );
    Ok(())
}

#[test]
fn legacy_activation_requires_exact_verified_credential_absence() -> Result<()> {
    for presence in [CredentialPresence::Present, CredentialPresence::Unknown] {
        let directory = tempfile::tempdir()?;
        let mut journal = Journal::open(&directory.path().join("journal.sqlite"))?;
        let target = target("alpha");
        configure(&mut journal, &target, &plan("alpha", 1));
        let input = approval_with_presence(&mut journal, "alpha", 1, 0, presence);
        let release = journal.approve_release(&input)?;
        metadata(&mut journal, &input);
        let ready = journal.prepare_release(&release)?;
        assert!(
            journal
                .activate_release(&ready)
                .unwrap_err()
                .to_string()
                .contains("credential release requires a qualified catalog candidate")
        );
        assert!(
            journal
                .active_catalog_selection(&target.company, &target.environment)?
                .releases
                .is_empty()
        );
    }

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let target = target("alpha");
    configure(&mut journal, &target, &plan("alpha", 1));
    let input = approval(&mut journal, "alpha", 1, 0);
    let release = journal.approve_release(&input)?;
    metadata(&mut journal, &input);
    let ready = journal.prepare_release(&release)?;
    let connection = rusqlite::Connection::open(path)?;
    let body: String = connection.query_row(
        "SELECT observation FROM effects WHERE execution=?1 AND kind='\"verify_artifact\"'",
        [input.build_execution.as_str()],
        |row| row.get(0),
    )?;
    let mut body: serde_json::Value = serde_json::from_str(&body)?;
    body["evidence"]["credential_presence"] = serde_json::json!("present");
    connection.execute(
        "UPDATE effects SET observation=?1 WHERE execution=?2 AND kind='\"verify_artifact\"'",
        rusqlite::params![
            serde_json::to_string(&body)?,
            input.build_execution.as_str()
        ],
    )?;
    assert!(
        journal
            .activate_release(&ready)
            .unwrap_err()
            .to_string()
            .contains("classification differs from approved build evidence")
    );
    assert!(
        journal
            .active_catalog_selection(&target.company, &target.environment)?
            .releases
            .is_empty()
    );
    Ok(())
}
