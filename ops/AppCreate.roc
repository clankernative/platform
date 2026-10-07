import Build
import Capability

# Optional authoring recipe. UI selection and file composition are Roc decisions;
# native capabilities capture approved bytes and publish only a verified fresh app.
AppCreate :: [].{
	Options : { destination : Str, name : Str, ui : Str, bundle : Str, bundle_sha256 : Str }

	parse : List(Str) -> Try(Options, Str)
	parse = |args| match args {
		[destination, name, .. as rest] if !destination.starts_with("--") and !name.starts_with("--") =>
			flags(rest, { destination, name, ui: "", bundle: "", bundle_sha256: "" }, [])
		_ => Err(
			"usage: day2 platform app-create NEW_DIRECTORY NAME [--ui none|html|clanker] [--bundle DIRECTORY --bundle-sha256 SHA256]",
		)
	}

	flags : List(Str), Options, List(Str) -> Try(Options, Str)
	flags = |args, options, seen| match args {
		[] => {
			if !["", "none", "html", "clanker"].contains(options.ui) {
				return Err("UI must be none, html or clanker")
			}
			if options.bundle.is_empty() != options.bundle_sha256.is_empty() {
				return Err("bundle directory and approved manifest SHA-256 are required together")
			}
			if options.ui == "clanker" and options.bundle.is_empty() {
				return Err("Clanker requires an explicitly approved already-installed bundle")
			}
			if ["none", "html"].contains(options.ui) and !options.bundle.is_empty() {
				return Err("bundle is only used with Clanker UI")
			}
			Ok(options)
		}
		[flag, value, .. as rest] if !seen.contains(flag) => {
			next = match flag {
				"--ui" => { ..options, ui: value }
				"--bundle" => { ..options, bundle: value }
				"--bundle-sha256" => { ..options, bundle_sha256: value }
				_ => return Err("unknown app-create option")
			}
			flags(rest, next, seen.append(flag))
		}
		_ => Err("duplicate or incomplete app-create option")
	}

	run! : List(Str), (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |args, host!| {
		if args == ["--help"] {
			return Ok(
				Json.to_str({
					usage: "day2 platform app-create NEW_DIRECTORY NAME [--ui none|html|clanker]",
					approval: "Clanker requires --bundle DIRECTORY --bundle-sha256 sha256:MANIFEST_DIGEST; this grants execution of only the reviewed manifest compiler.",
					default_package: "The installed bundle must contain @clanker/vanilla; its name/version and schema-1 lock are preserved.",
					guarantees: "Fresh destination only, rollback on failure, ordinary build and mandatory verification before publication; no install, fetch, credentials or app scripts.",
				}),
			)
		}
		options = parse(args)?
		ui = if options.ui.is_empty() {
			if !answer!("Will this app have a UI?", host!)? {
				"none"
			} else if
				answer!("Use optional Clanker (recommended; approved installed vanilla bundle required)?", host!)?
					{
						"clanker"
					}
						else
							"html"
		} else options.ui
		# Revalidate prompted choices exactly as noninteractive arguments.
		checked = flags([], { ..options, ui }, [])?
		raw = Capability.call!("app-create-begin", Json.to_str(checked), host!)?
		stage : { source : Str }
		stage = Json.parse(raw).map_err(|_| "invalid app staging receipt")?
		_ = Capability.call!("app-create-write", Json.to_str({ files: files(checked) }), host!)?
		_ = Capability.call!(
			"app-create-identity",
			Json.to_str({ table: "starter_records", roc_type: "Models.StarterRecord" }),
			host!,
		)?
		built = Build.source!(stage.source, host!)?
		Capability.call!("app-create-publish", Json.to_str(built), host!)
	}

	answer! : Str, (Str => Try(Str, Str)) => Try(Bool, Str)
	answer! = |question, host!| {
		raw = Capability.call!(
			"app-create-answer",
			Json.to_str(
				{
					question
				},
			),
			host!,
		)?
		response : { yes : Bool }
		response = Json.parse(raw).map_err(|_| "invalid prompt answer")?
		Ok(response.yes)
	}

	File : { path : Str, content : Str }

	files : Options -> List(File)
	files = |options| {
		with_ui = options.ui != "none"
		route_imports = if with_ui "import Routes\n" else ""
		pages = if with_ui "{ welcome: Routes.welcome.register() }" else "{}"
		style = if with_ui "app.css" else ""
		operator_guidance =
			if
				options.ui == "clanker"
				"\n## Reviewed operator tool configuration\n\nFuture build and local-dev require the separately reviewed installed provider-pin.json through\nDAY2_UI_PROVIDER_PIN_JSON. The creation receipt identifies its durable absolute path. Set that\noperator environment variable for your terminal/session before ordinary builds; the app lock\ndoes not authorize execution. Do not point it at an app-owned pin or a staged temporary path.\nRestore/relocate the tool separately through the reviewed bundle installer if it moves.\nThe local vanilla package in .ui-dependencies/vanilla is locked build input, never served.\nVerified project/third-party notices are retained separately in .ui-dependencies/legal.\nRetain them with redistributed package CSS/JS/assets; app-owned code keeps its own rights.\n"
			else
				""
		core = [
			{
				path: "App.roc",
				content: "import Welcome\nimport StarterInvariants\n${route_imports}\nApp :: [].{\n\tdefinition = {\n\t\tnamespace: \"${
					options
						.name
				}\",\n\t\toperations: { welcome: Welcome.definition },\n\t\tpages: ${pages},\n\t\tproperties: { starter_records: StarterInvariants.ownership },\n\t\terrors: {},\n\t\texamples: [],\n\t\tpresentation: { stylesheet: \"${style}\", script: \"\" },\n\t}\n}\n",
			},
			{
				path: "storage/Models.roc",
				content: "import pf.Table\n\n# Educational storage only: replace with your own nominal models and identities.\nModels :: [].{\n\tStarterRecord := { owner : Str }.{\n\t\ttable : Table(StarterRecord, _)\n\t\ttable = Table.keyed(|_row| {})\n\t}\n}\n",
			},
			{
				path: "queries/welcome/WelcomeTypes.roc",
				content: "WelcomeTypes :: [].{\n\tInput : {}\n}\n",
			},
			{
				path: "queries/welcome/Welcome.roc",
				content: "import pf.Api\nimport pf.Handler\nimport pf.Query\nimport pf.Context\nimport WelcomeTypes\n\nWelcome :: [].{\n\tdefinition = Api.query({\n\t\thandler: Handler.local(handle),\n\t\tcontract: {\n\t\t\ttitle: \"Welcome\",\n\t\t\tusage: {\n\t\t\t\tpurpose: \"Read this starter artifact's welcome message without changing application state.\",\n\t\t\t\tuse_when: [\"Confirming that the new app is admitted and reachable.\"],\n\t\t\t\tavoid_when: [\"Reading or changing business data; add an app-owned operation instead.\"],\n\t\t\t\tpreconditions: [],\n\t\t\t\teffects: [],\n\t\t\t\tresult: \"The starter welcome message.\",\n\t\t\t},\n\t\t\tinputs: {},\n\t\t\toutputs: { message: \"A fixed message owned by this starter artifact.\" },\n\t\t\texample: |_| Ok({ input: {}, output: { message: \"Welcome to your app.\" } }),\n\t\t\tinput_sources: |_| [],\n\t\t\tfollow_ups: [],\n\t\t\tdeprecated: Bool.False,\n\t\t\terrors: [],\n\t\t},\n\t\tverification: {\n\t\t\tinput: |_snapshot, _seed| Ok({}),\n\t\t\tcheck: |before, output, after| Ok(before == after and output.message == \"Welcome to your app.\"),\n\t\t},\n\t})\n\n\thandle : Context, WelcomeTypes.Input -> Query({ message : Str })\n\thandle = |_context, _input| Query.succeed({ message: \"Welcome to your app.\" })\n}\n",
			},
			{
				path: "verification/StarterInvariants.roc",
				content: "import pf.Api\nimport Data\n\nStarterInvariants :: [].{\n\townership = Api.invariant(\n\t\tData.starter_records,\n\t\t\"Every starter record has a nonblank actor owner.\",\n\t\tData.snapshot,\n\t\t|state| state.starter_records.all(|row| !row.value.owner.trim().is_empty()),\n\t)\n}\n",
			},
			{
				path: "AGENTS.md",
				content: guidance,
			},
			{
				path: "README.md",
				content: "# ${
					options
						.name
				}\n\nCreated by Platform's optional AppCreate recipe. The welcome query is pure and read-only.\nStarterRecord exists only because current admission requires a nominal model and its property;\nit is not a suggested business domain. Replace it using the ordinary identity authoring operations.\nNo demo data, external connections, credentials, scripts or network permissions are granted.\nUse day2 platform build . and day2 platform local-dev . from this app directory.\nKeep model-identities.json committed.\n${operator_guidance}",
			},
		]
		if !with_ui return core
		clanker = options.ui == "clanker"
		declaration =
			if
				clanker
				"<cui-card><cui-slot name=\"body\"><a href=\"{{ routes.welcome() }}\">Welcome</a></cui-slot></cui-card>"
			else
				""
		ui_files = [
			{
				path: "pages/Routes.roc",
				content: "import pf.Page\nimport WelcomeTypes\nimport Reads\nimport Templates\n\nRoutes :: [].{\n\twelcome : Page(WelcomeTypes.Input)\n\twelcome = Page.route({ title: \"Welcome\", path: \"/\", template: Templates.welcome }, Reads.welcome)\n\t\t.with_defaults({})\n}\n",
			},
			{
				path: "ui/pages/welcome.html",
				content: "<main class=\"app-welcome\"><h1>{{ welcome.message }}</h1><p>Your app owns this page. Add your own operations and presentation when ready.</p>${declaration}</main>\n",
			},
			{
				path: "ui/app.css",
				content: ":root { --app-ink: #202020; --app-paper: #fafafa; }\n.app-welcome { color: var(--app-ink); background: var(--app-paper); font-family: system-ui, sans-serif; max-width: 48rem; margin: 4rem auto; padding: 2rem; }\n",
			},
			{
				path: "ui/AGENTS.md",
				content: "# App presentation\n\nOwn HTML templates, CSS theme tokens and native browser JS here. Roc supplies typed view data,\nnot markup. Keep forms bound to generated command/input contracts and values escaped.\nNo npm, app build scripts, server JS or remote imports. Platform admits the complete resource graph.\nClanker, if selected, is a build-time adapter only: no component-specific runtime callbacks.\nKeep schema-1 ui.lock.json and update package inputs through reviewed operator setup.\n",
			},
		]
		theme = if clanker [
			{
				path: "ui/clanker-theme.css",
				content: ":root { --cui-text: #202020; --cui-surface: #fafafa; --cui-button-radius: 0.375rem; }\n",
			},
		] else []
		core.concat(ui_files).concat(theme)
	}

	guidance =
		"# App authoring\n\nFollow Platform docs/APP-LAYOUT.md and the canonical Reports example. Pure Roc owns business decisions.\nEach operation owns its request types, handler, complete contract, typed example and independent\nverification in its own commands/ or queries/ folder. App.definition registers each once.\nKeep nominal persistent models under storage/ and commit model-identities.json; register, rename\nand retire them through the Platform identity authoring capabilities. Never author generated modules.\nProperties evaluate complete bounded snapshots and must check actual app invariants, not placeholders.\nThe educational ownership-only StarterRecord is not a business-domain recommendation.\nNo arbitrary I/O, callbacks, app jobs, build scripts or credentials. UI-free and ordinary HTML\nare first-class. UI/theme belongs to this app; company branding remains instance-owned.\nUse ordinary Platform build and required verification; never bypass admission or compiler pins.\n"
}

expect AppCreate.parse(["new-app", "hello", "--ui", "none"]).is_ok()
expect AppCreate.parse(["new-app", "hello", "--ui", "clanker"]).is_err()
expect AppCreate.parse(["new-app", "hello", "--ui", "html", "--ui", "none"]).is_err()
expect AppCreate.parse(["new-app", "hello", "--ui", "other"]).is_err()
