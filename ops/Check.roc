import Capability
import Build

Check :: [].{
	Step : { operation : Str, input : Str }

	Example : { name : Str, steps : List(Step), error : Str }

	Sample : { generator : Str, operation : Str, seed : Str, input : Str, error : Str }

	Settings : { artifact : Str, output : Str, example : Str, seed : Str, count : U64 }

	run! : Str, U64, U64, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |source, seed, count, host!| {
		built = Build.source!(source, host!)?
		campaign!({ artifact: built.artifact, output: "", example: "", seed: seed.to_str(), count }, host!)
	}

	campaign! : Settings, (Str => Try(Str, Str)) => Try(Str, Str)
	campaign! = |settings, host!| {
		_ = Capability.call!("dev-create", Json.to_str(settings), host!)?
		exercise!(settings.example, settings.count, host!)
	}

	exercise! : Str, U64, (Str => Try(Str, Str)) => Try(Str, Str)
	exercise! = |example_name, count, host!| {
		_ = Capability.call!("dev-properties", "{}", host!)?
		raw = Capability.call!("dev-examples", "{}", host!)?
		examples : List(Example)
		examples = Json.parse(raw).map_err(|_| "invalid example catalog")?
		selected = examples.keep_if(|example| example_name.is_empty() or example.name == example_name)
		if !example_name.is_empty() and selected.is_empty() {
			return Err("unknown example: ${example_name}")
		}
		for example in selected {
			_ = Capability.call!("dev-example", Json.to_str({ name: example.name }), host!)?
			for step in example.steps {
				step!(step, host!)?
			}
		}
		if count > 0 {
			generated = Capability.call!("dev-samples", "{}", host!)?
			samples : List(Sample)
			samples = Json.parse(generated).map_err(|_| "invalid generated cases")?
			for _sample in samples {
				prepared = Capability.call!("dev-prepare-sample", "{}", host!)?
				step : Step
				step = Json.parse(prepared).map_err(|_| "invalid prepared verification input")?
				step!(step, host!)?
			}
		}
		_ = Capability.call!("dev-errors", "{}", host!)?
		Capability.call!("dev-finish", "{}", host!)
	}

	step! : Step, (Str => Try(Str, Str)) => Try({}, Str)
	step! = |step, host!| {
		_ = Capability.call!("dev-invoke", Json.to_str(step), host!)?
		_ = Capability.call!("dev-assert", "{}", host!)?
		_ = Capability.call!("dev-replay", "{}", host!)?
		_ = Capability.call!("dev-duplicate", "{}", host!)?
		_ = Capability.call!("dev-invalid", "{}", host!)?
		_ = Capability.call!("dev-properties", "{}", host!)?
		_ = Capability.call!("dev-drain", "{}", host!)?
		_ = Capability.call!("dev-properties", "{}", host!)?
		_ = Capability.call!("dev-step-complete", "{}", host!)?
		Ok({})
	}
}
