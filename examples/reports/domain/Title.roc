import pf.TextSpec

# Nominal domain identity and its one executable declaration.
Title :: { marker : Bool }.{
	rules : TextSpec(Title)
	rules =
		TextSpec.define({
			maximum_bytes: 200,
			nonblank: Bool.True,
			description: "The display title chosen by the report's author.",
		})
}
