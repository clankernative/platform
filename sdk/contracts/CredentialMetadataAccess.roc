# Sealed declaration witness. Its family is checked against App registrations.
CredentialMetadataAccess :: { family : Str, action : Str }.{
	define : Str -> CredentialMetadataAccess
	define = |credential_family| { family: credential_family, action: "metadata" }

	define_issue : Str -> CredentialMetadataAccess
	define_issue = |credential_family| { family: credential_family, action: "issue" }

	define_rotate : Str -> CredentialMetadataAccess
	define_rotate = |credential_family| { family: credential_family, action: "rotate" }

	define_revoke : Str -> CredentialMetadataAccess
	define_revoke = |credential_family| { family: credential_family, action: "revoke" }

	family : CredentialMetadataAccess -> Str
	family = |access| access.family

	action : CredentialMetadataAccess -> Str
	action = |access| access.action
}
