# App-owned snapshot assertions, evaluated by explicit checks and simulation tests.
# Registration does not install a database constraint or an automatic commit hook.
Property :: { name : Str, check : Str -> Try(Bool, Str) }.{
	Check : { name : Str, passed : Bool, error : Str }

	invariant : Str, (Str -> Try(a, Str)), (a -> Bool) -> Property
	invariant = |name, decode, predicate| {
		name,
		check: |raw| {
			value = decode(raw)?
			Ok(predicate(value))
		},
	}

	name : Property -> Str
	name = |property| property.name

	evaluate : Property, Str -> Check
	evaluate = |property, snapshot| match (property.check)(snapshot) {
		Ok(passed) => { name: property.name, passed, error: "" }
		Err(error) => { name: property.name, passed: Bool.False, error }
	}
}
