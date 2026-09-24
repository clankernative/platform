import pf.TextSpec

Title := { marker : Bool }.{
	rules : TextSpec(Title)
	rules =
		TextSpec.define({ maximum_bytes: 200, nonblank: Bool.True, description: "The display title for a saved link." })
}
