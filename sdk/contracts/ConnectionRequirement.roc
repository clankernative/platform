import ConnectionAccess

# Pure product intent. Deployment addresses, registrations, provider scopes and
# credentials belong to instance qualification and the private host.
ConnectionRequirement :: [].{
	Metadata : {
		logical_id : Str,
		revision : U32,
		capability : Str,
		actions : List(Str),
		owner : Str,
		account_policy : Str,
		usage : Str,
	}

	HumanAccount :: { value : Str }.{
		metadata : HumanAccount -> Str
		metadata = |account| account.value
	}

	company_account : HumanAccount
	company_account = { value: "mapped_human" }

	explicit_external_account : HumanAccount
	explicit_external_account = { value: "explicit_external_account" }

	CurrentHuman :: { value : Metadata }.{
		metadata : CurrentHuman -> Metadata
		metadata = |requirement| requirement.value
	}

	Installation :: { value : Metadata }.{
		metadata : Installation -> Metadata
		metadata = |requirement| requirement.value
	}

	for_current_human : {
		id : Str,
		revision : U32,
		access : ConnectionAccess,
		account : HumanAccount,
		usage : Str,
	} -> CurrentHuman
	for_current_human = |options| {
		access = options.access.metadata()
		{
			value: {
				logical_id: options.id,
				revision: options.revision,
				capability: access.capability,
				actions: access.actions,
				owner: "current_human",
				account_policy: options.account.metadata(),
				usage: options.usage,
			},
		}
	}

	for_installation : { id : Str, revision : U32, access : ConnectionAccess, usage : Str } -> Installation
	for_installation = |options| {
		access = options.access.metadata()
		{
			value: {
				logical_id: options.id,
				revision: options.revision,
				capability: access.capability,
				actions: access.actions,
				owner: "installation",
				account_policy: "installation_account",
				usage: options.usage,
			},
		}
	}
}
