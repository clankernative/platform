# Sealed declaration witness. Its family is checked against App registrations.
CredentialMetadataAccess :: { family : Str, action : Str }.{
	define : Str -> CredentialMetadataAccess
	define = |family| { family: family, action: "metadata" }

	define_issue : Str -> CredentialMetadataAccess
	define_issue = |family| { family: family, action: "issue" }

	define_rotate : Str -> CredentialMetadataAccess
	define_rotate = |family| { family: family, action: "rotate" }

	define_revoke : Str -> CredentialMetadataAccess
	define_revoke = |family| { family: family, action: "revoke" }

	family : CredentialMetadataAccess -> Str
	family = |access| access.family

	action : CredentialMetadataAccess -> Str
	action = |access| access.action
}
