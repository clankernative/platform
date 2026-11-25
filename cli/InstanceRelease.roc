import Cli
import InstanceSpec
import "fixtures/release-receipt.json" as golden_receipt : Str

## `day2 instance release publish|fetch`: the request the CLI hands the platform host, rendered from day2.json, and the
## receipt the host returns. A release lives in the instance's derived state bucket (InstanceSpec's
## tofu_state_bucket), and its images must be digest-pinned in the project's Artifact Registry (InstanceSpec's
## artifact_registry), in any one repository there, since instances mirror SDK images into app repositories.
InstanceRelease :: [].{

	## The host's receipt (crates/day2-ops/src/instance_release.rs `Receipt`): what the CLI prints and the paths a
	## caller uses. The host owns the shape; cli/fixtures/release-receipt.json pins it for both sides. `files` holds
	## the manifest file (the new file a publication wrote, or the cached blob a fetch verified) and, for a fetch, the
	## cached distribution and evidence. Only a fetch has a cache and an operator CLI.
	Receipt : {
		format : U64,
		mode : Str,
		reference : Cli.Reference,
		platform_commit : Str,
		profile : Str,
		target : Str,
		runtime_image : Str,
		tooling_image : Str,
		objects : Str,
		files : {
			manifest : Str,
			distribution : Try(Str, [Null]),
			native : Try(Str, [Null]),
			strict : Try(Str, [Null]),
		},
		cache : Try(Str, [Null]),
		cli : Try(Str, [Null]),
	}

	## A decoded receipt and the host's exact text, which `--agent` output carries verbatim.
	Report : { receipt : Receipt, text : Str }

	## The request a release command hands its recipe. The host validates every field again and refuses a request
	## whose mode differs from the command that started it.
	request : InstanceSpec, Cli.ReleaseAction -> Str
	request = |spec, action| {
		names = spec.derived()
		none : Try(Str, [Null])
		none = Err(Null)
		unreferenced : Try(Cli.Reference, [Null])
		unreferenced = Err(Null)
		Json.to_str({
			mode: action.verb(),
			bucket: names.tofu_state_bucket,
			registry: names.artifact_registry,
			publication: match action {
				Cli.ReleaseAction.Publish(paths) => Ok(paths.request.to_str())
				Cli.ReleaseAction.Fetch(_) => none
			},
			output: match action {
				Cli.ReleaseAction.Publish(paths) => Ok(paths.output.to_str())
				Cli.ReleaseAction.Fetch(_) => none
			},
			reference: match action {
				Cli.ReleaseAction.Publish(_) => unreferenced
				Cli.ReleaseAction.Fetch(reference) => Ok(reference)
			},
		})
	}

	## A receipt is accepted only in format 1, for the command that was run: a fetch reports the reference it was
	## asked for, its cached distribution and evidence, a cache and an operator CLI; a publication reports none of them.
	receipt : Str, Cli.ReleaseAction -> Try(Report, [InvalidReceipt])
	receipt = |text, action| {
		parsed : Try(Receipt, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReceipt)?
		installed =
			match (decoded.files.distribution, decoded.files.native, decoded.files.strict, decoded.cache, decoded.cli) {
				(Ok(_), Ok(_), Ok(_), Ok(_), Ok(_)) => Fetched
				(Err(Null), Err(Null), Err(Null), Err(Null), Err(Null)) => Published
				_ => Mixed
			}
		matches = match (action, installed) {
			(Cli.ReleaseAction.Publish(_), Published) => Bool.True
			(Cli.ReleaseAction.Fetch(approved), Fetched) => approved == decoded.reference
			_ => Bool.False
		}
		if decoded.format == 1 and decoded.mode == action.verb() and matches {
			Ok({ receipt: decoded, text })
		} else {
			Err(InvalidReceipt)
		}
	}
}

sample : Str
sample =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools",
	\\"oidc":"https://git-oidc.example.com"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
	\\"extension":null,"owners":["ada@example.com"],"size":"standard","verification":4,"schedules":"enabled"}}}

golden : Cli.Reference
golden = { digest: "sha256:cc689326c54b7a9cba772211381d9e7442a3e4d7137a3ede128593d6e0e76432", bytes: 1236 }

# The request carries the derived bucket and registry and only its mode's fields.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		fetch = InstanceRelease.request(spec, Cli.ReleaseAction.Fetch(golden))
		fetch.contains("\"bucket\":\"exampleco-tools-tofu-state\"")
			and fetch.contains("\"registry\":\"us-central1-docker.pkg.dev/exampleco-tools\"")
				and fetch.contains("\"mode\":\"fetch\"")
					and fetch.contains("\"publication\":null")
						and fetch.contains("\"bytes\":1236")
	}
	Err(_) => Bool.False
}

# The host's golden fetch receipt decodes, keeps its exact text and names every cached file.
expect match InstanceRelease.receipt(golden_receipt, Cli.ReleaseAction.Fetch(golden)) {
	Ok(report) => {
		receipt = report.receipt
		report.text
			== golden_receipt
			and receipt.platform_commit == "93aba94790df7ad80d6a45103788e3604ad06b7e"
				and receipt.files.native
					== Ok(
						"/opt/day2-platform-releases/8748b64e1accafa295b213e9980822c66d7f4a38f9a813a8597eed4003fc3b11",
					)
					and receipt.cli
						== Ok(
							"/opt/day2-platform-releases/bd1e1954064cbbfa82bc16dd23d0ef19b804ff8c0b5eb78b90ee4ad128ed5b23.operator/cli/day2",
						)
	}
	Err(_) => Bool.False
}

# A fetch receipt must report the reference it was asked for and every cached file.
expect InstanceRelease.receipt(golden_receipt, Cli.ReleaseAction.Fetch({ ..golden, bytes: 1237 })).is_err()
expect
	InstanceRelease.receipt(
		golden_receipt.replace_first("\"cache\": \"/opt/day2-platform-releases\",", "\"cache\": null,"),
		Cli.ReleaseAction.Fetch(golden),
	)
		.is_err()
expect InstanceRelease.receipt(
	golden_receipt.replace_first("\"format\": 1", "\"format\": 2"),
	Cli.ReleaseAction.Fetch(golden),
)
	.is_err()
