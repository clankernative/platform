import pf.TextSpec

# The app explicitly permits blank text; the operator's stricter policy must reject it.
Title := { marker : Bool }.{
	rules : TextSpec(Title)
	rules =
		TextSpec.define({
			maximum_bytes: 200,
			nonblank: Bool.False,
			description: "The display title for a saved link; operator policy can restrict it further.",
		})
}
