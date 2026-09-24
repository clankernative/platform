WebUrl :: { value : Str }.{
	from_str : Str -> Try(WebUrl, [InvalidUrl])
	from_str = |value| {
		if
			value.starts_with("https://")
				and value.count_utf8_bytes() <= 2048 and value.count_utf8_bytes() > 8 and value.trim() == value
				{
					Ok({ value: value })
				}
					else
						{
							Err(InvalidUrl)
						}
	}

	to_str : WebUrl -> Str
	to_str = |url| url.value
}
