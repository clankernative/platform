//! Exact-version disclosure with admission and final current-authority checks.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub name: String,
    pub incarnation: String,
    pub version: u64,
    pub expected_authority: AuthorityStamp,
    #[serde(skip)]
    pub request_id: String,
}

fn selected(db: &Connection, runtime: &Runtime, actor: &str, input: &Selection) -> Result<Target> {
    valid_name(&input.name)?;
    ensure!(
        input.version > 0 && i64::try_from(input.version).is_ok(),
        Failure::InvalidInput
    );
    let (namespace, authority) = namespace_in(db, runtime, actor, Permission::SecretsRead)?;
    ensure!(
        authority == input.expected_authority,
        Failure::AuthorityPolicyChanged
    );
    let selected = stored_secret(db, &input.name)?.context(Failure::NotFound)?;
    ensure!(
        selected.incarnation == input.incarnation
            && selected.version == Some(input.version)
            && !selected.blocked
            && selected.created
            && !selected.deleted,
        Failure::Conflict
    );
    ensure!(
        selected.namespace == namespace_id(&namespace, runtime)?,
        Failure::AuthorityPolicyChanged
    );
    Ok(Target {
        namespace,
        scope: runtime.scope().into(),
        incarnation: selected.incarnation,
        create_request: selected.create_request,
    })
}

pub fn reveal(
    runtime: &Runtime,
    actor: &str,
    input: &Selection,
    provider: &dyn Provider,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        step(Operation::Reveal, State::Admitted)? == Step::AccessVersion,
        "invalid_disclosure_recipe"
    );
    validate_request(&input.request_id)?;
    let (target, mut receipt) = runtime.sql_write(|db| {
        let target = selected(db, runtime, actor, input)?;
        let receipt = Receipt {
            protocol: 2,
            kind: "app-secret-write".into(),
            scope: runtime.scope().into(),
            actor: actor.into(),
            name: input.name.clone(),
            incarnation: input.incarnation.clone(),
            operation: Operation::Reveal,
            request_id: input.request_id.clone(),
            authority: input.expected_authority.clone(),
            state: State::ReadDispatched,
            version: None,
            activation_performed: false,
        };
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_app_secret_requests WHERE id=?1)",
            [&input.request_id],
            |row| row.get(0),
        )?;
        ensure!(!exists, Failure::IdempotencyKeyConflict);
        db.execute(
            "INSERT INTO day2_app_secret_requests(id,receipt) VALUES(?1,?2)",
            params![input.request_id, serde_json::to_string(&receipt)?],
        )?;
        save(db, &receipt, "disclosure_admitted")?;
        Ok((target, receipt))
    })?;
    let value = match provider.access(&target, input.version) {
        Ok(value) if !value.is_empty() && value.len() <= MAX_VALUE => value,
        result => {
            receipt.state = if matches!(result, Err(ProviderFailure::Refused)) {
                State::Refused
            } else {
                State::Unknown
            };
            runtime.sql_write(|db| {
                authority_state::scope_matches(db, runtime)?;
                runtime.check_binding(db)?;
                save(db, &receipt, "disclosure_refused")
            })?;
            return Err(Failure::ExternalAmbiguous.into());
        }
    };
    // No provider call is made under an SQLite transaction. A revocation,
    // namespace change, deletion or rotation during the call withholds bytes.
    runtime.sql_write(|db| {
        selected(db, runtime, actor, input)?;
        receipt.state = State::Revealed;
        receipt.version = Some(input.version);
        save(db, &receipt, "disclosure_prepared")
    })?;
    Ok(value)
}
