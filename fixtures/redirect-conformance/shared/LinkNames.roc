# Link names and wildcard resolution, a small model of GoLinks' rules: a name is
# slash-separated lowercase segments, and a wildcard's last segment is %s, which
# captures one request segment.
LinkNames :: [].{
	valid : Str -> Bool
	valid = |name| {
		segments = name.split_on("/")
		wildcards = segments.keep_if(|segment| segment == "%s").len()
		!name.is_empty() and segments.all(|segment| segment == "%s" or plain(segment))
			and (wildcards == 0 or (wildcards == 1 and segments.len() > 1 and ends_in_wildcard(segments)))
	}

	# The wildcard name that could resolve this path, and the segment it captures.
	wildcard : Str -> [None, Some({ name : Str, capture : Str })]
	wildcard = |path| {
		segments = path.split_on("/")
		match segments.last() {
			Ok(last) if segments.len() > 1 => {
				name = Str.join_with(segments.take_first(segments.len() - 1).append("%s"), "/")
				Some({ name, capture: last })
			}
			_ => None
		}
	}

	interpolate : Str, Str -> Str
	interpolate = |url, capture| Str.join_with(url.split_on("%s"), encode(capture.to_utf8()))
}

plain : Str -> Bool
plain = |segment| {
	bytes = segment.to_utf8()
	!bytes.is_empty() and bytes.all(|byte| (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57) or byte == 45)
}

ends_in_wildcard : List(Str) -> Bool
ends_in_wildcard = |segments| match segments.last() {
	Ok(last) => last == "%s"
	Err(_) => Bool.False
}

# Percent-encode everything but RFC 3986 unreserved characters.
encode : List(U8) -> Str
encode = |bytes| Str.join_with(
	bytes.map(
		|byte| {
			if (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57)
				or byte == 45 or byte == 46 or byte == 95 or byte == 126 {
				Str.from_utf8_lossy([byte])
			} else {
				Str.from_utf8_lossy([37, hex_digit(byte // 16), hex_digit(byte % 16)])
			}
		},
	),
	"",
)

hex_digit : U8 -> U8
hex_digit = |digit| if digit < 10 digit + 48 else digit + 55

expect LinkNames.valid("docs")
expect LinkNames.valid("docs/%s")
expect !LinkNames.valid("%s")
expect !LinkNames.valid("Docs")
expect !LinkNames.valid("docs/%s/more")
expect LinkNames.wildcard("docs/Read Me") == Some({ name: "docs/%s", capture: "Read Me" })
expect LinkNames.wildcard("docs") == None
expect LinkNames.interpolate("https://example.com/search?q=%s", "Read Me/é")
	== "https://example.com/search?q=Read%20Me%2F%C3%A9"
