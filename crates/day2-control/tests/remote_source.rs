use anyhow::Result;
use day2_capabilities::{AppControl, ControlScope, InstallationControl, SourceProvider};
use day2_control::{
    Digest, GitOid, Name,
    local_source::{SourceBundle, SourceChange, SourceControl},
    remote_source::{Credential, RemoteGit},
    service::Service,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

fn git(repository: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Author",
            "-c",
            "user.email=author@example.com",
        ])
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()?;
    anyhow::ensure!(output.status.success(), "git {args:?}");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// A repository somebody pushed to, with one commit of `files`.
fn upstream(root: &Path, files: &[(&str, &str)]) -> Result<(std::path::PathBuf, GitOid)> {
    let work = root.join("upstream");
    fs::create_dir_all(&work)?;
    git(&work, &["init", "-q", "--initial-branch=main"])?;
    for (path, text) in files {
        let path = work.join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, text)?;
    }
    git(&work, &["add", "-A"])?;
    git(&work, &["commit", "-q", "-m", "app"])?;
    let commit = GitOid::try_from(git(&work, &["rev-parse", "HEAD"])?)?;
    Ok((work, commit))
}

fn private(root: &Path) -> Result<std::path::PathBuf> {
    let state = root.join("state");
    fs::create_dir_all(&state)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    }
    Ok(state.join("remote.git"))
}

#[test]
fn exact_commits_are_fetched_once_and_served_from_the_cache() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let (work, commit) = upstream(
        &root,
        &[("App.roc", "app"), ("pages/index.html", "<main/>")],
    )?;
    let owner = Digest::new(b"remote fixture");
    let cache = private(&root)?;
    let source = RemoteGit::open_file_for_tests(&cache, &owner, &work)?;
    let snapshot = source.snapshot(&commit)?;
    assert_eq!(snapshot.files().len(), 2);
    assert_eq!(snapshot.files()["App.roc"], b"app");

    // Once fetched, the commit no longer depends on the host.
    fs::remove_dir_all(&work)?;
    let reopened = RemoteGit::open_file_for_tests(&cache, &owner, &work)?;
    assert_eq!(reopened.snapshot(&commit)?.digest(), snapshot.digest());
    let missing = GitOid::try_from("0".repeat(40))?;
    assert!(
        reopened
            .snapshot(&missing)
            .unwrap_err()
            .to_string()
            .contains("source_fetch_failed")
    );
    Ok(())
}

#[test]
fn remote_sources_are_never_written_and_need_their_credential_to_fetch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let (work, commit) = upstream(&root, &[("App.roc", "app")])?;
    let owner = Digest::new(b"remote fixture");
    let cache = private(&root)?;
    let source = RemoteGit::open_file_for_tests(&cache, &owner, &work)?;
    let change = SourceChange::Export {
        bundle: SourceBundle::from_files(BTreeMap::from([("App.roc".to_owned(), b"x".to_vec())]))?,
    };
    assert!(
        source
            .apply(&owner, &change)
            .unwrap_err()
            .to_string()
            .contains("source_provider_read_only")
    );
    assert!(
        RemoteGit::open(
            &cache,
            &owner,
            "http://git.example.com/a/b.git".into(),
            Credential::None
        )
        .is_err(),
        "plain http is refused"
    );
    // Without a way to resolve its credential, nothing is fetched, but what is
    // already cached is still readable.
    let unresolved = RemoteGit::open(
        &cache,
        &owner,
        "https://git.example.com/internal-tools/app.git".into(),
        Credential::Unavailable,
    )?;
    assert!(
        unresolved
            .snapshot(&commit)
            .unwrap_err()
            .to_string()
            .contains("source_credential_unavailable")
    );
    source.snapshot(&commit)?;
    unresolved.snapshot(&commit)?;
    Ok(())
}

#[test]
fn fetched_commits_obey_the_source_file_rules() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let (work, _) = upstream(&root, &[("App.roc", "app")])?;
    fs::write(work.join("run.sh"), "#!/bin/sh\n")?;
    git(&work, &["add", "--chmod=+x", "run.sh"])?;
    git(&work, &["commit", "-q", "-m", "script"])?;
    let commit = GitOid::try_from(git(&work, &["rev-parse", "HEAD"])?)?;
    let source =
        RemoteGit::open_file_for_tests(&private(&root)?, &Digest::new(b"remote fixture"), &work)?;
    assert!(
        source
            .snapshot(&commit)
            .unwrap_err()
            .to_string()
            .contains("regular non-executable")
    );
    Ok(())
}

#[test]
fn the_service_refuses_exports_to_a_remote_source() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let name = |value: &str| Name::try_from(value.to_owned()).expect("name");
    let configuration = InstallationControl {
        version: 1,
        state_directory: root.join("state").display().to_string(),
        operators: BTreeSet::from(["operator@example.com".to_owned()]),
        sources: BTreeMap::from([(
            name("links-source"),
            SourceProvider::RemoteGit {
                host: "git.example.com".into(),
                namespace: "internal-tools".into(),
                repository: "links".into(),
                credential: None,
            },
        )]),
        apps: BTreeMap::from([(
            name("links"),
            AppControl {
                source: name("links-source"),
                build: None,
                provider_secrets: BTreeMap::new(),
            },
        )]),
        builders: BTreeMap::new(),
        runtimes: BTreeMap::new(),
        secrets: BTreeMap::new(),
        security_epochs: BTreeMap::new(),
    };
    let service = Service::open(
        ControlScope {
            installation: name("example"),
            environment: name("development"),
        },
        configuration,
        ["links"],
    )?;
    let handle = service.authorize("operator@example.com", &name("links"))?;
    let change = SourceChange::Export {
        bundle: SourceBundle::from_files(BTreeMap::from([("App.roc".to_owned(), b"x".to_vec())]))?,
    };
    assert!(
        service
            .submit(&handle, name("first"), change)
            .unwrap_err()
            .to_string()
            .contains("source_provider_read_only")
    );
    Ok(())
}
