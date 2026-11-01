import Api
import CredentialMetadataAccess

# Family declarations are pure product intent. They never contain a token,
# verifier, key reference or permission to issue a credential.
Credential :: [].{
	GrantMetadata : { mode : Str, roots : List(Api.Target) }

	# Type witnesses select an authoring shape; they carry no runtime authority.
	FixedGrantMode :: { value : Bool }.{}

	SelectableGrantMode :: { value : Bool }.{}

	Grant(mode) :: { value : GrantMetadata, witness : List(mode) }.{
		metadata : Grant(mode) -> GrantMetadata
		metadata = |grant| grant.value
	}

	fixed : List(Api.Target) -> Grant(FixedGrantMode)
	fixed = |roots| { value: { mode: "fixed", roots }, witness: [] }

	selectable : List(Api.Target) -> Grant(SelectableGrantMode)
	selectable = |roots| { value: { mode: "selectable", roots }, witness: [] }

	FamilyMetadata : {
		id : Str,
		grant : GrantMetadata,
		lifetime_seconds : U64,
	}

	FamilyOptions(mode) : { id : Str, grant : Grant(mode), lifetime_seconds : U64 }

	ClientFamily(mode) :: { value : FamilyMetadata, witness : List(mode) }.{
		metadata : ClientFamily(mode) -> FamilyMetadata
		metadata = |family| family.value
	}

	PersonalFamily(mode) :: { value : FamilyMetadata, witness : List(mode) }.{
		metadata : PersonalFamily(mode) -> FamilyMetadata
		metadata = |family| family.value
	}

	client_family : FamilyOptions(mode) -> ClientFamily(mode)
	client_family = |options| {
		value: {
			id: options.id,
			grant: options.grant.metadata(),
			lifetime_seconds: options.lifetime_seconds,
		},
		witness: [],
	}

	personal_family : FamilyOptions(mode) -> PersonalFamily(mode)
	personal_family = |options| {
		value: {
			id: options.id,
			grant: options.grant.metadata(),
			lifetime_seconds: options.lifetime_seconds,
		},
		witness: [],
	}

	# Declaration only: the host still applies current policy to the inherited principal.
	metadata_access = |family| CredentialMetadataAccess.define(family.metadata().id)

	issue_access = |family| CredentialMetadataAccess.define_issue(family.metadata().id)

	rotate_access = |family| CredentialMetadataAccess.define_rotate(family.metadata().id)

	revoke_access = |family| CredentialMetadataAccess.define_revoke(family.metadata().id)

	Label :: { value : Str }.{
		from_str : Str -> Try(Label, [InvalidLabel])
		from_str = |value| {
			bytes = value.to_utf8()
			if value.trim().is_empty() or bytes.len() > 128 or !bytes.all(|byte| byte >= 32 and byte != 127) {
				Err(InvalidLabel)
			} else {
				Ok(
					{ value: value },
				)
			}
		}

		to_str : Label -> Str
		to_str = |label| label.value
	}
}
