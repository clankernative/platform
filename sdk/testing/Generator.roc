import Write

# A deterministic domain generator. Host-supplied seeds are values, not ambient
# randomness. Failures are explicit and cannot count as executed test cases.
Generator :: { name : Str, operation : Str, generate : U64 -> Try(Str, Str) }.{
	command : Str, Write(a, b), (U64 -> Try(a, Str)) -> Generator
	command = |name, command, generate| {
		name,
		operation: command.name(),
		generate: |seed| generate(seed).map_ok(|input| command.encode_input(input)),
	}

	encode : List(Generator), Str -> Str
	encode = |generators, raw| {
		parts = raw.split_on(":")
		(seed_text, count_text) = match parts {
			["generate", seed, count] => (seed, count)
			_ => return "[]"
		}
		seed = match U64.from_str(seed_text) {
			Ok(value) => value
			Err(_) => return "[]"
		}
		count = match U64.from_str(count_text) {
			Ok(value) if value > 0 and value <= 100 => value
			_ => return "[]"
		}
		if parts.len() != 3 or generators.len() > 16 {
			return "[]"
		}
		var $samples = []
		for index in U64.until(0, count) {
			for generator in generators {
				case_seed = seed.plus_wrap(index)
				case = match (generator.generate)(case_seed) {
					Ok(input) => {
						generator: generator.name,
						operation: generator.operation,
						seed: case_seed.to_str(),
						input,
						error: "",
					}
					Err(error) => {
						generator: generator.name,
						operation: generator.operation,
						seed: case_seed.to_str(),
						input: "",
						error,
					}
				}
				$samples = $samples.append(case)
			}
		}
		Json.to_str($samples)
	}
}
