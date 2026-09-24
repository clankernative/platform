## Semantic failures determine their own code, exit status, and recovery hint.
Problem := [
	UnknownCommand,
	MissingCommand,
	MissingArgument,
	InvalidArguments(Str),
	UnknownOption(Str),
	MissingOptionValue(Str),
	DuplicateOption(Str),
	ConflictingOptions(Str),
	InvalidAppName(Str),
	InvalidOperationName(Str),
	ContextRequired,
	InvalidContext(Str),
	ContextUnavailable,
	MetadataUnreadable(Str),
	AppNotFound(Str, List(Str)),
	OperationNotFound(Str, List(Str)),
	InvalidInstance(Str),
	InvalidArtifact(Str),
	InvalidCatalog(Str),
	UnsupportedArtifact(U64),
	MetadataTooLarge,
].{
	Dto : { code : Str, message : Str, hint : Str, exit_code : I32, retryable : Bool }

	exit_code : Problem -> I32
	exit_code = |problem| match problem {
		UnknownCommand
		| MissingCommand
		| MissingArgument
		| InvalidArguments(_)
		| UnknownOption(_)
		| MissingOptionValue(_)
		| DuplicateOption(_)
		| ConflictingOptions(_)
		| InvalidAppName(_)
		| InvalidOperationName(_) => 2
		ContextRequired | InvalidContext(_) | ContextUnavailable | MetadataUnreadable(_) => 3
		AppNotFound(_, _) | OperationNotFound(_, _) => 4
		InvalidInstance(_) | InvalidArtifact(_) | InvalidCatalog(_) | UnsupportedArtifact(_) | MetadataTooLarge => 5
	}

	code : Problem -> Str
	code = |problem| match problem {
		UnknownCommand => "unknown_command"
		MissingCommand => "missing_command"
		MissingArgument => "missing_argument"
		InvalidArguments(_) => "invalid_arguments"
		UnknownOption(_) => "unknown_option"
		MissingOptionValue(_) => "missing_option_value"
		DuplicateOption(_) => "duplicate_option"
		ConflictingOptions(_) => "conflicting_options"
		InvalidAppName(_) => "invalid_app_name"
		InvalidOperationName(_) => "invalid_operation_name"
		ContextRequired => "context_required"
		InvalidContext(_) => "invalid_context"
		ContextUnavailable => "context_unavailable"
		MetadataUnreadable(_) => "metadata_unreadable"
		AppNotFound(_, _) => "app_not_found"
		OperationNotFound(_, _) => "operation_not_found"
		InvalidInstance(_) => "invalid_instance"
		InvalidArtifact(_) => "invalid_artifact"
		InvalidCatalog(_) => "invalid_catalog"
		UnsupportedArtifact(_) => "unsupported_artifact"
		MetadataTooLarge => "metadata_too_large"
	}

	message : Problem -> Str
	message = |problem| match problem {
		UnknownCommand => "This spike implements one command: app describe <app>."
		MissingCommand => "Describe options require the command app describe <app>."
		MissingArgument => "An app name is required."
		InvalidArguments(detail) => "Invalid arguments: ${detail}"
		UnknownOption(flag) => "Unknown option: ${Json.to_str(flag)}."
		MissingOptionValue(flag) => "${flag} needs a nonempty value."
		DuplicateOption(flag) => "${flag} was supplied more than once."
		ConflictingOptions(detail) => detail
		InvalidAppName(name) => "Invalid app name: ${Json.to_str(name)}."
		InvalidOperationName(name) => "Invalid operation name: ${Json.to_str(name)}."
		ContextRequired => "Choose an instance to describe this app."
		InvalidContext(detail) => "Invalid instance context: ${detail}"
		ContextUnavailable => "The current directory is unavailable or is not a supported UTF-8 path."
		MetadataUnreadable(path) => "Cannot read a regular UTF-8 metadata file at ${Json.to_str(path)}."
		AppNotFound(name, _) => "App ${Json.to_str(name)} is not installed in this source."
		OperationNotFound(name, _) => "Operation ${Json.to_str(name)} is not in this app's catalog."
		InvalidInstance(detail) => "Invalid instance metadata: ${detail}"
		InvalidArtifact(detail) => "Invalid artifact JSON: ${detail}"
		InvalidCatalog(detail) => "Invalid operation catalog: ${detail}"
		UnsupportedArtifact(version) => "Unsupported artifact format ${version.to_str()} for this installed platform."
		MetadataTooLarge => "Metadata exceeds the 1 MiB limit."
	}

	hint : Problem -> Str
	hint = |problem| match problem {
		ContextRequired => "Pass --instance <path>, set DAY2_INSTANCE, or use --demo."
		AppNotFound(_, names) => "Available apps: ${Str.join_with(names, ", ")}"
		OperationNotFound(_, names) => "Available operations: ${Str.join_with(names, ", ")}"
		MetadataUnreadable(
			_,
		) => "Check the path, permissions, and UTF-8 encoding. Use a regular file, not a symlink or special file."
		InvalidInstance(_)
		| InvalidArtifact(_)
		| InvalidCatalog(_)
		| UnsupportedArtifact(_)
		| MetadataTooLarge => "Select valid metadata from a supported Day2 artifact, or use --demo."
		InvalidAppName(_) => "Use a lowercase identifier up to 48 bytes; day2_ and sqlite_ prefixes are reserved."
		InvalidOperationName(_) => "Use dot-separated lowercase identifiers, at most 80 bytes in total."
		_ => "Run day2 app describe --help for usage and examples."
	}

	dto : Problem -> Dto
	dto =
		|
			problem,
		|
			{
				code: code(problem),
				message: message(problem),
				hint: hint(problem),
				exit_code: exit_code(problem),
				retryable: Bool.False,
			}
}
