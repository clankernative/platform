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
	InvalidSpec(Str),
	InvalidArtifact(Str),
	InvalidCatalog(Str),
	UnsupportedArtifact(U64),
	MetadataTooLarge,
	PlanFailed(Str),
	ApplyFailed(Str),
	ReleaseFailed(Str),
	SourceFailed(Str),
	SourceUnavailable(Str),
	CandidateFailed(Str),
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
		InvalidInstance(_)
		| InvalidSpec(_)
		| InvalidArtifact(_)
		| InvalidCatalog(_)
		| UnsupportedArtifact(_)
		| MetadataTooLarge => 5
		PlanFailed(_) | ApplyFailed(_) | ReleaseFailed(_) | SourceFailed(_) | CandidateFailed(_) => 6
		SourceUnavailable(_) => 7
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
		InvalidSpec(_) => "invalid_spec"
		InvalidArtifact(_) => "invalid_artifact"
		InvalidCatalog(_) => "invalid_catalog"
		UnsupportedArtifact(_) => "unsupported_artifact"
		MetadataTooLarge => "metadata_too_large"
		PlanFailed(_) => "plan_failed"
		ApplyFailed(_) => "apply_failed"
		ReleaseFailed(_) => "release_failed"
		SourceFailed(_) => "source_failed"
		SourceUnavailable(_) => "source_unavailable"
		CandidateFailed(_) => "candidate_failed"
	}

	message : Problem -> Str
	message = |problem| match problem {
		UnknownCommand => "This CLI implements app describe <app> and instance check|render|plan|apply|release|source|candidate <directory>."
		MissingCommand => "Describe options require the command app describe <app>."
		MissingArgument => "A required argument is missing."
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
		InvalidSpec(detail) => "Invalid instance spec: ${detail}"
		InvalidArtifact(detail) => "Invalid artifact JSON: ${detail}"
		InvalidCatalog(detail) => "Invalid operation catalog: ${detail}"
		UnsupportedArtifact(version) => "Unsupported artifact format ${version.to_str()} for this installed platform."
		MetadataTooLarge => "Metadata exceeds the 1 MiB limit."
		PlanFailed(detail) => "The instance plan failed: ${detail}"
		ApplyFailed(detail) => "The instance apply failed: ${detail}"
		ReleaseFailed(detail) => "The instance release failed: ${detail}"
		# The host's own message, exactly, which the deploy controller records.
		SourceFailed(detail) | SourceUnavailable(detail) | CandidateFailed(detail) => detail
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
		InvalidSpec(
			_,
		) => "Fix day2.json: every field is required, unknown fields are rejected, and lists and apps are sorted."
		PlanFailed(
			_,
		) => "Plan with a CLI built from day2.json's platform commit, OpenTofu 1.12.3 on PATH, Google credentials and a new output directory outside the instance; a failed root keeps its logs there."
		ApplyFailed(
			_,
		) => "Apply as an operator with a CLI built from day2.json's platform commit, OpenTofu 1.12.3 on PATH and a new output directory outside the instance. A failed or refused root keeps its logs there; a plan that deletes, replaces or forgets a resource is never applied."
		ReleaseFailed(
			_,
		) => "Publish as an operator with gcloud and docker signed in for the instance project; fetch with read access to its state bucket. Published objects are never replaced, and a cached blob or operator file that changed is refused, never repaired."
		SourceFailed(
			_,
		) => "Read with AUTODEPLOY_SOURCE_TOKEN or GITEA_TOKEN set for the instance forge. This refusal is permanent for these inputs: fix the binding, the source or its CI, then run again."
		SourceUnavailable(
			_,
		) => "A forge read failed transiently or the exact main commit's CI run did not finish in time. Nothing was written; retry later."
		CandidateFailed(
			_,
		) => "Run from the instance's CI job image with the apply identity's credentials and the forge token. This refusal is permanent for these inputs: a build's private evidence is in the instance's release state; fix the cause, then run again."
		InvalidAppName(_) => "Use a lowercase identifier up to 48 bytes; day2_ and sqlite_ prefixes are reserved."
		InvalidOperationName(_) => "Use dot-separated lowercase identifiers, at most 80 bytes in total."
		_ => "Run day2 --help for usage and examples."
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
				retryable: match problem {
					SourceUnavailable(_) => Bool.True
					_ => Bool.False
				},
			}
}
