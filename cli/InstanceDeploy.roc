import Cli
import InstanceSpec
import Problem
import "fixtures/deploy-receipt.json" as golden_receipt : Str

## A non-rolling deployment takes its instance names from day2.json and its release from a checked candidate.
InstanceDeploy :: [].{
	File : { path : Str, digest : Str, bytes : U64 }

	Copied : { objects : U64, bytes : U64 }

	Receipt : {
		format : U64,
		mode : Str,
		app_id : Str,
		commit : Str,
		image : Str,
		artifact_id : Str,
		tooling_image : Str,
		request_id : Str,
		path : Str,
		operator : { release : Str, cli : Str },
		activation : Try({ request_digest : Str, target_instance_digest : Str, record : Try(Str, [Null]) }, [Null]),
		archive : Try({ uri : Str, before : Try(Copied, [Null]), after : Try(Copied, [Null]) }, [Null]),
		apply : { roots : Try(File, [Null]) },
		readback : { generation : U64, revision : Str, image_id : Str, instance_digest : Str },
	}

	Report : { receipt : Receipt, text : Str }

	request : InstanceSpec, Cli.Deploy -> Str
	request = |spec, deploy| {
		names = spec.derived()
		Json.to_str({
			instance: {
				project: names.gcp_project,
				zone: names.gcp_zone,
				cluster: names.cluster.name,
				registry: names.artifact_registry,
				bucket: names.tofu_state_bucket,
				server: names.forge_server,
				org: names.forge_org,
				apply_identity: names.apply_identity,
				apps: names.apps.map(|entry| { id: entry.id, sdk: entry.sdk, verification: entry.verification }),
			},
			directory: deploy.directory.to_str(),
			checkout: deploy.checkout.to_str(),
			app_id: deploy.app_id,
			candidate: deploy.candidate.to_str(),
			output: deploy.output.to_str(),
			deadline: deploy.deadline,
		})
	}

	receipt : Str, Str -> Try(Report, [InvalidReceipt])
	receipt = |text, app_id| {
		decoded : Receipt
		decoded = Json.parse(text).map_err(|_| InvalidReceipt)?
		if
			decoded.format
				== 1
				and decoded.mode
					== "deploy"
					and decoded.app_id == app_id and valid_path(decoded) and decoded.apply.roots.is_ok()
				{
					Ok({ receipt: decoded, text })
				}
					else
						{
							Err(InvalidReceipt)
						}
	}

	problem : Str -> Problem
	problem = |error| {
		if error.starts_with("fenced: ") {
			Problem.DeployFenced(error.drop_prefix("fenced: "))
		} else if error.starts_with("retryable: ") {
			Problem.DeployUnavailable(error.drop_prefix("retryable: "))
		} else {
			Problem.DeployFailed(error)
		}
	}
}

valid_path : InstanceDeploy.Receipt -> Bool
valid_path = |receipt| match receipt.path {
	"fresh" => receipt.activation.is_ok() and receipt.archive.is_ok()
	"activated" | "serving" | "install" => receipt.activation.is_err() and receipt.archive.is_err()
	_ => Bool.False
}

expect match InstanceDeploy.receipt(golden_receipt, "links") {
	Ok(report) => report.text == golden_receipt and report.receipt.apply.roots.map_ok(|file| file.bytes) == Ok(2048)
	Err(_) => Bool.False
}

expect InstanceDeploy.receipt(golden_receipt, "another") == Err(InvalidReceipt)
expect InstanceDeploy.problem("fenced: could not read back the rollout").exit_code() == 8
expect InstanceDeploy.problem("retryable: reached deadline").dto().retryable
