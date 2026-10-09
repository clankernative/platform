import pf.RowVersion

UpdateSampleTypes :: [].{
	Input := {
		sample_time : I64,
		expected_version : RowVersion,
		value : I64,
		missing : Bool,
	}
	Output : { time : I64, version : RowVersion }
}
