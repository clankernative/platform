import pf.TextSpec

Title := { marker : Bool }.{
	rules : TextSpec(Title)
	rules = TextSpec.define({ maximum_bytes: 200, nonblank: Bool.True, description: "A nonblank deal title." })
}
