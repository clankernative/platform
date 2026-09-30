# Sealed declaration witness. Its family is checked against App registrations.
CredentialMetadataAccess :: { family : Str }.{
	define : Str -> CredentialMetadataAccess
	define = |family| { family: family }

	family : CredentialMetadataAccess -> Str
	family = |access| access.family
}
