SweepReportsTypes :: [].{
	# A schedule has no caller and no request, so there is nothing to derive an
	# input from. The input is empty rather than carrying a timestamp: the
	# occurrence is the platform's to know, and a sweep that read the clock would
	# not replay identically.
	Input := {}

	Result := { reconciled : U64, remaining : Bool }
}
