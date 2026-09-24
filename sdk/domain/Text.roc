import TextSpec

# The generated Domains factories are the sole construction boundary. Standard
# rules drive this constructor, host validation, API schemas, and form helpers.
Text(domain) :: { value : Str, witness : List(domain) }.{
	from_spec : TextSpec(domain), Str -> Try(Text(domain), Str)
	from_spec = |definition, value| {
		rules = definition.metadata()
		if
			rules.maximum_bytes
				< 1
				or rules.maximum_bytes
					> 16_384
					or value.count_utf8_bytes() > rules.maximum_bytes or (rules.nonblank and value.trim().is_empty())
				{
					Err("invalid_domain_value")
				}
					else
						{
							Ok({ value, witness: [] })
						}
	}

	to_str : Text(domain) -> Str
	to_str = |text| text.value
}
