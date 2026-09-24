import pf.TextSpec

Document :: { marker : Bool }.{
	rules : TextSpec(Document)
	rules =
		TextSpec.define({
			maximum_bytes: 8000,
			nonblank: Bool.True,
			description: "Report document text with its original newlines preserved.",
		})
}
