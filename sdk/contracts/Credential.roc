import Api
import CredentialMetadataAccess

# Family declarations are pure product intent. They never contain a token,
# verifier, key reference or permission to issue a credential.
Credential :: [].{
	GrantMetadata : { mode : Str, roots : List(Api.Target) }

	Grant :: { value : GrantMetadata }.{
		metadata : Grant -> GrantMetadata
		metadata = |grant| grant.value
	}

	fixed : List(Api.Target) -> Grant
	fixed = |roots| { value: { mode: "fixed", roots } }

	selectable : List(Api.Target) -> Grant
	selectable = |roots| { value: { mode: "selectable", roots } }

	FamilyMetadata : {
		id : Str,
		grant : GrantMetadata,
		lifetime_seconds : U64,
	}

	FamilyOptions : { id : Str, grant : Grant, lifetime_seconds : U64 }

	ClientFamily :: { value : FamilyMetadata }.{
		metadata : ClientFamily -> FamilyMetadata
		metadata = |family| family.value
	}

	PersonalFamily :: { value : FamilyMetadata }.{
		metadata : PersonalFamily -> FamilyMetadata
		metadata = |family| family.value
	}

	client_family : FamilyOptions -> ClientFamily
	client_family = |options| {
		value: {
			id: options.id,
			grant: options.grant.metadata(),
			lifetime_seconds: options.lifetime_seconds,
		},
	}

	personal_family : FamilyOptions -> PersonalFamily
	personal_family = |options| {
		value: {
			id: options.id,
			grant: options.grant.metadata(),
			lifetime_seconds: options.lifetime_seconds,
		},
	}

	# Declaration only: the host still applies current policy to the inherited principal.
	metadata_access = |family| CredentialMetadataAccess.define(family.metadata().id)

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
