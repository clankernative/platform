//! Private store coordination only. A committed authorization or decrypted
//! body is never evidence that a browser received it. No body leaves a child.
use super::*;
use crate::managed_credentials::{crypto::token_selector, store};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DeliveryCut {
    RevealBeforeCommit,
    RevealAfterCommit,
    RevealAfterDecrypt,
    AckBeforeCommit,
    AckAfterCommit,
}

impl DeliveryCut {
    const ALL: [Self; 5] = [Self::RevealBeforeCommit, Self::RevealAfterCommit,
        Self::RevealAfterDecrypt, Self::AckBeforeCommit, Self::AckAfterCommit];
    fn tag(self) -> u8 { match self {
        Self::RevealBeforeCommit => 1, Self::RevealAfterCommit => 2,
        Self::RevealAfterDecrypt => 3, Self::AckBeforeCommit => 4, Self::AckAfterCommit => 5,
    } }
    fn ack(self) -> bool { matches!(self, Self::AckBeforeCommit | Self::AckAfterCommit) }
    fn committed(self) -> bool { matches!(self, Self::RevealAfterCommit | Self::RevealAfterDecrypt | Self::AckAfterCommit) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub(super) profile: Profile,
    cut: DeliveryCut,
    pub(super) seed: u64,
}

pub(super) fn marker(case: Case, cut: Option<DeliveryCut>, kind: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(b"D2DELIV1");
    bytes[8] = case.profile.tag();
    bytes[9] = cut.map_or(0, DeliveryCut::tag);
    bytes[10] = kind;
    bytes
}

pub(super) fn require_marker(bytes: &[u8; 16], case: Case, completion: bool) -> Result<()> {
    // The shared child emits only this closed error frame, never an error Display.
    ensure!(&bytes[..8] != b"D2CRASH1", "delivery child refused before checkpoint");
    ensure!(*bytes == marker(case, (!completion).then_some(case.cut), if completion { 2 } else { 1 }),
        "delivery child checkpoint identity differs");
    Ok(())
}

fn checkpoint(case: Case, at: DeliveryCut, behavior: Behavior) -> Result<()> {
    if at != case.cut || matches!(behavior, Behavior::Complete | Behavior::SkipCheckpoint) { return Ok(()); }
    std::io::stderr().write_all(&marker(case, Some(at), 1))?;
    std::io::stderr().flush()?;
    if matches!(behavior, Behavior::ExitAtCheckpoint) { std::process::exit(0); }
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte)?;
    anyhow::bail!("delivery checkpoint unexpectedly released")
}

// Inputs stand in for an already verified disposable human POST, exactly as in
// the existing store model. They are not a Google/native authentication proof.
fn post(e: &Expected, version: &str, attempt: &str) -> store::VerifiedHumanPost {
    store::VerifiedHumanPost { namespace: e.namespace.clone(), version: version.into(),
        recipient: ACTOR.into(), session: format!("verification-{INVOCATION}"),
        attempt: attempt.into(), now: NOW, security_epoch: 7 }
}

struct Image { snapshot: Snapshot, authorizations: u64 }

fn capture_delivery(db: &Connection, e: &Expected) -> Result<Image> {
    let snapshot = capture_lifecycle(db, e)?;
    let version = head(&snapshot)?;
    let mut query = db.prepare("SELECT attempt,version,recipient,session,authorized_at FROM day2_credential_reveals ORDER BY rowid")?;
    let mut rows = query.query([])?;
    let mut attempts = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let attempt: String = row.get(0)?;
        ensure!(matches!(attempt.as_str(), "first-attempt" | "retry-one" | "retry-two")
            && attempts.insert(attempt) && row.get::<_, String>(1)? == version
            && row.get::<_, String>(2)? == ACTOR
            && row.get::<_, String>(3)? == format!("verification-{INVOCATION}")
            && row.get::<_, i64>(4)? == NOW, "delivery authorization binding differs");
    }
    let (state, reason): (String, String) = db.query_row(
        "SELECT state,closed_reason FROM day2_credential_deliveries", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    ensure!((state == "available" && reason.is_empty()) || (state == "closed" && reason == "acknowledged"),
        "delivery closure identity differs");
    Ok(Image { snapshot, authorizations: attempts.len() as u64 })
}

fn head(snapshot: &Snapshot) -> Result<String> {
    Ok(snapshot.public.as_ref().context("delivery public receipt absent")?["result"]["version"]
        .as_str().context("delivery version absent")?.into())
}

fn model() -> Model {
    let mut model = Model { now: NOW, ..Model::default() };
    assert!(model.apply(Step::Issue));
    model
}

fn check_image(image: &Image, model: &Model, authorizations: u64) -> Result<()> {
    check(model, &image.snapshot.projection)?;
    ensure!(image.authorizations == authorizations, "durable reveal authorization oracle divergence");
    Ok(())
}

fn unchanged_material(before: &Snapshot, after: &Snapshot) -> Result<()> {
    for (table, rows) in &before.private.0 {
        if table != "day2_credential_reveals" && table != "day2_credential_deliveries" {
            ensure!(after.private.0.get(table) == Some(rows), "delivery changed immutable private or product state");
        }
    }
    ensure!(before.public == after.public, "delivery changed public issuance outcome");
    Ok(())
}

fn require_token(db: &Connection, token: &str) -> Result<()> {
    let selector: String = db.query_row("SELECT selector FROM day2_credential_versions", [], |r| r.get(0))?;
    ensure!(token_selector(token)? == selector, "delivery returned different material");
    Ok(())
}

pub(super) fn execute(runtime: &Runtime, case: Case, behavior: Behavior, e: &Expected) -> Result<()> {
    let mut db = crate::store::open(runtime.db())?;
    let initial = capture_delivery(&db, e)?;
    let version = head(&initial.snapshot)?;
    let mut model = model();
    check_image(&initial, &model, 0)?;
    let tx = crate::write_queue::immediate(&mut db)?;
    if case.cut.ack() {
        ensure!(model.apply(Step::Acknowledge) && store::close_delivery(&tx, &version, "acknowledged")?,
            "delivery acknowledgement refused");
        let staged = capture_delivery(&tx, e)?;
        check_image(&staged, &model, 0)?;
        unchanged_material(&initial.snapshot, &staged.snapshot)?;
        checkpoint(case, DeliveryCut::AckBeforeCommit, behavior)?;
        tx.commit()?;
        let committed = capture_delivery(&db, e)?;
        ensure!(committed.snapshot.private == staged.snapshot.private, "acknowledgement commit differs from staged rows");
        checkpoint(case, DeliveryCut::AckAfterCommit, behavior)?;
    } else {
        ensure!(model.apply(Step::Reveal), "reference reveal refused");
        let pending = store::authorize_reveal_in(&tx, post(e, &version, "first-attempt"))?
            .context("delivery authorization refused")?;
        let staged = capture_delivery(&tx, e)?;
        check_image(&staged, &model, 1)?;
        unchanged_material(&initial.snapshot, &staged.snapshot)?;
        checkpoint(case, DeliveryCut::RevealBeforeCommit, behavior)?;
        let permit = pending.commit(tx)?;
        let committed = capture_delivery(&db, e)?;
        ensure!(committed.snapshot.private == staged.snapshot.private, "reveal commit differs from staged rows");
        checkpoint(case, DeliveryCut::RevealAfterCommit, behavior)?;
        let body = permit.into_response_body(&super::super::lease())?;
        require_token(&db, &body)?;
        checkpoint(case, DeliveryCut::RevealAfterDecrypt, behavior)?;
        // Keep the actual body alive across the cut without sending it anywhere.
        require_token(&db, &body)?;
    }
    Ok(())
}

fn issued_fixture(case: Case) -> Result<Fixture> {
    let fixture = Fixture::new(super::Case { profile: case.profile, cut: Cut::AfterCommit, seed: case.seed })?;
    effects::scope(Ports::new(case.seed.wrapping_add(0x1000)), || -> Result<()> {
        let runtime = load_runtime(&fixture.instance, case.seed)?;
        ensure!(runtime.execute(INVOCATION, Fault::None)?.status == "success", "delivery fixture issuance failed");
        let e = expected(&runtime, case.profile)?;
        runtime.sql_read(|db| check(&model(), &capture(db, &e)?.projection))
    })?;
    Ok(fixture)
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Transport { NotObserved }

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(super) struct Observation {
    case: Case,
    child: ChildStatus,
    reopened: Projection,
    reopened_authorizations: u64,
    recovered: Projection,
    recovered_authorizations: u64,
    completed_transport: Transport,
}

fn denied_bindings(db: &mut Connection, e: &Expected, version: &str) -> Result<()> {
    let before = private_image(db)?;
    for field in 0..5 {
        let mut wrong = post(e, version, "denied-attempt");
        match field {
            0 => wrong.recipient = "other@example.com".into(),
            1 => wrong.session = "another-session".into(),
            2 => wrong.security_epoch += 1,
            3 => wrong.namespace.binding_generation += 1,
            _ => wrong.version = "missing-version".into(),
        }
        ensure!(store::authorize_reveal(db, wrong)?.is_none(), "foreign reveal binding accepted");
        ensure!(private_image(db)? == before, "denied reveal changed private rows");
    }
    Ok(())
}

async fn history(case: Case) -> Result<Observation> {
    let fixture = issued_fixture(case)?;
    let before = effects::scope(Ports::new(case.seed.wrapping_add(0x3000)), || -> Result<Snapshot> {
        let runtime = load_runtime(&fixture.instance, case.seed)?;
        runtime.sql_read(|db| capture(db, &expected(&runtime, case.profile)?))
    })?;
    let status = child(&fixture, ChildCase::Delivery(case), Behavior::Pause, true).await?;
    let ports = Ports::new(case.seed.wrapping_add(0x2000));
    effects::scope(ports.clone(), || -> Result<Observation> {
        // Loading the real Runtime runs restored-row validation before the oracle.
        let runtime = load_runtime(&fixture.instance, case.seed)?;
        let e = expected(&runtime, case.profile)?;
        let mut db = crate::store::open(runtime.db())?;
        let reopened = capture_delivery(&db, &e)?;
        let mut model = model();
        let mut authorizations = 0;
        if case.cut.committed() {
            if case.cut.ack() { ensure!(model.apply(Step::Acknowledge), "reference acknowledgement"); }
            else { ensure!(model.apply(Step::Reveal), "reference authorization"); authorizations += 1; }
        }
        check_image(&reopened, &model, authorizations)?;
        unchanged_material(&before, &reopened.snapshot)?;
        denied_bindings(&mut db, &e, &head(&reopened.snapshot)?)?;
        let version = head(&reopened.snapshot)?;
        // The dead process's permit/body cannot be reconstructed from a receipt.
        // A retry calls the actual authorization API with a new verified fixture
        // POST and a new attempt. It is never automatic delivery recovery.
        if !case.cut.ack() {
            let mut previous: Option<String> = None;
            for attempt in ["retry-one", "retry-two"] {
                ensure!(model.apply(Step::Reveal), "retry reference refused");
                let token = store::authorize_reveal(&mut db, post(&e, &version, attempt))?
                    .context("fresh retry authorization absent")?.into_response_body(&super::super::lease())?;
                require_token(&db, &token)?;
                if let Some(previous) = &previous { ensure!(*previous == token, "retry replaced secret material"); }
                previous = Some(token);
                authorizations += 1;
                check_image(&capture_delivery(&db, &e)?, &model, authorizations)?;
            }
        }
        let tx = crate::write_queue::immediate(&mut db)?;
        let was_closed = model.closed;
        ensure!(model.apply(Step::Acknowledge), "acknowledgement reference refused");
        ensure!(store::close_delivery(&tx, &version, "acknowledged")? != was_closed, "acknowledgement retry differed");
        tx.commit()?;
        let closed = capture_delivery(&db, &e)?;
        check_image(&closed, &model, authorizations)?;
        let tx = crate::write_queue::immediate(&mut db)?;
        ensure!(!store::close_delivery(&tx, &version, "acknowledged")?, "repeated acknowledgement changed closure");
        tx.commit()?;
        ensure!(!model.apply(Step::Reveal) && store::authorize_reveal(&mut db, post(&e, &version, "after-close"))?.is_none(),
            "closed delivery reauthorized");
        let recovered = capture_delivery(&db, &e)?;
        ensure!(recovered.snapshot.private == closed.snapshot.private, "terminal acknowledgement retry changed rows");
        unchanged_material(&before, &recovered.snapshot)?;
        ensure!(ports.secret_requests.load(Ordering::SeqCst) == 0, "delivery recovery requested new secret entropy");
        Ok(Observation { case, child: status, reopened: reopened.snapshot.projection,
            reopened_authorizations: reopened.authorizations, recovered: recovered.snapshot.projection,
            recovered_authorizations: recovered.authorizations, completed_transport: Transport::NotObserved })
    })
}

pub(super) async fn checked(case: Case, artifact: &str) -> Result<Observation> {
    let result = async {
        let first = history(case).await?;
        ensure!(history(case).await? == first, "delivery crash history replay differs");
        Ok::<_, anyhow::Error>(first)
    }.await;
    match result {
        Ok(observation) => Ok(observation),
        Err(_) => { retain_failure(ChildCase::Delivery(case), artifact)?;
            anyhow::bail!("delivery crash/reopen diverged; redacted source-bound case retained") }
    }
}

#[tokio::test]
async fn reveal_and_acknowledgement_survive_real_process_loss_without_claiming_delivery() -> Result<()> {
    let artifact = artifact_id()?;
    let mut observations = vec![];
    for profile in [Profile::Client, Profile::Personal] {
        for cut in DeliveryCut::ALL {
            for seed in [1, 19, 401] {
                observations.push(checked(Case { profile, cut, seed }, &artifact).await?);
            }
        }
    }
    let declared: BTreeSet<_> = [Profile::Client, Profile::Personal].into_iter()
        .flat_map(|profile| DeliveryCut::ALL.into_iter().flat_map(move |cut|
            [1, 19, 401].into_iter().map(move |seed| Case { profile, cut, seed }))).collect();
    ensure!(observations.len() == 30 && observations.iter().map(|o| o.case).collect::<BTreeSet<_>>() == declared
        && observations.iter().all(|o| o.child.signal == Some(9) && o.child.eof
            && o.completed_transport == Transport::NotObserved), "declared delivery crash cases did not run");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/credential-crash-reopen");
    fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new().prefix("campaign-").tempdir_in(root)?.keep();
    fs::write(directory.join("receipt.json"), serde_json::to_vec_pretty(&json!({
        "format":2,"status":"passed","scope":"private_store_authorization_not_completed_browser_delivery",
        "implementation":implementation(),"artifact":artifact,"each_history_replayed":true,"observations":observations}))?)?;
    Ok(())
}

#[tokio::test]
async fn delivery_child_guards_require_the_actual_cut_and_signal_death() -> Result<()> {
    for cut in [DeliveryCut::RevealAfterDecrypt, DeliveryCut::AckAfterCommit] {
        let case = Case { profile: Profile::Client, cut, seed: 31 };
        let baseline = issued_fixture(case)?;
        child(&baseline, ChildCase::Delivery(case), Behavior::Pause, true).await?;
        let skipped = issued_fixture(case)?;
        ensure!(child(&skipped, ChildCase::Delivery(case), Behavior::SkipCheckpoint, true).await.is_err(),
            "missing delivery checkpoint accepted");
        let graceful = issued_fixture(case)?;
        let status = child(&graceful, ChildCase::Delivery(case), Behavior::ExitAtCheckpoint, false).await?;
        ensure!(require_killed(&status).is_err(), "normal delivery exit counted as crash");
    }
    Ok(())
}

#[test]
fn delivery_oracle_and_protocol_refuse_wrong_commit_identity_and_extra_authorizations() -> Result<()> {
    let case = Case { profile: Profile::Client, cut: DeliveryCut::RevealAfterCommit, seed: 3 };
    let bytes = marker(case, Some(case.cut), 1);
    require_marker(&bytes, case, false)?;
    for index in [0, 8, 9, 10, 11, 15] {
        let mut wrong = bytes;
        wrong[index] ^= 1;
        ensure!(require_marker(&wrong, case, false).is_err(), "foreign checkpoint accepted");
    }
    let artifact = "delivery-fixture-artifact";
    let mut replay = serde_json::to_value(Replay { format: 2, implementation: implementation(), artifact: artifact.into(), case: ChildCase::Delivery(case) })?;
    ensure!(matches!(decode_replay(&serde_json::to_vec(&replay)?, artifact)?, ChildCase::Delivery(found) if found == case), "valid delivery replay refused");
    replay["case"]["case"]["cut"] = json!("ack_after_decrypt");
    ensure!(decode_replay(&serde_json::to_vec(&replay)?, artifact).is_err(), "unknown delivery cut accepted");
    let mut reference = model();
    let mut p = Projection { product_rows:1,product_receipts:1,lineages:1,versions:1,material:1,deliveries:1,receipts:1,
        revision:1,committed:true,active:true,available:true };
    check(&reference, &p)?;
    reference.apply(Step::Acknowledge);
    ensure!(check(&reference, &p).is_err(), "uncommitted acknowledgement treated as durable");
    p.available = false;
    check(&reference, &p)?;
    p.versions += 1;
    ensure!(check(&reference, &p).is_err(), "delivery oracle ignored extra material");
    Ok(())
}
