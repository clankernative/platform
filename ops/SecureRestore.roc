# Planning DATA only. No host callback, authority, credential, receipt or
# execution entrypoint. The protected accepting command is not yet connected.
# Native atomicity and the same-owner accepting turn must not be split into
# independent per-step capability calls when this skeleton becomes executable.
SecureRestore :: [].{
	Step : { name : Str, boundary : Str }

	sequence : List(Step)
	sequence = [
		{ name: "authorize_qualification_resources", boundary: "operator" },
		{ name: "select_exact_archive_target_epoch_custody_and_keys", boundary: "preflight" },
		{ name: "approve_with_current_registry_uv_and_bound_server_challenge", boundary: "approval" },
		{ name: "sign_and_publish_exact_single_use_one_hour_grant", boundary: "approval" },
		{ name: "authenticate_current_executor_and_capture_original", boundary: "accepting_turn" },
		{ name: "retain_exclusion_files_and_historical_keys", boundary: "accepting_turn" },
		{ name: "commit_grant_keyed_attempt_before_reservation_send", boundary: "accepting_turn" },
		{ name: "freeze_and_drain_all_outstanding_authority", boundary: "accepting_turn" },
		{ name: "consume_grant_and_reserve_epoch_atomically_with_known_readback", boundary: "accepting_turn" },
		{ name: "reset_archive_and_activate_exact_writer", boundary: "accepting_turn" },
		{ name: "install_controller_and_app_with_actual_acknowledgements", boundary: "accepting_turn" },
		{ name: "complete_actual_final_transport_and_settlement", boundary: "accepting_turn" },
		{ name: "exercise_fresh_controller_current_and_restored_host", boundary: "qualification" },
		{ name: "exercise_refusal_matrix_on_separate_disposable_cases", boundary: "qualification" },
		{ name: "retain_protected_evidence_and_guarded_cleanup", boundary: "operator" },
	]

	refusal_cases : List(Str)
	refusal_cases = [
		"child_death_and_uncertain_commit",
		"wrong_target_key_epoch_or_executor",
		"expired_or_consumed_grant",
		"removed_registry_key",
		"late_peer_death",
		"final_output_failure",
	]

	# This preview cannot advance the sequence or authorize any listed action.
	plan : {} -> Str
	plan = |_| Json.to_str({
		status: "planning_only_execution_unavailable",
		sequence: sequence,
		refusal_cases: refusal_cases,
	})
}
