import pf.Model
import Models
import Data

ReportScenarios :: [].{
	first : Str -> Try(Model.Entity(Models.Report), Str)
	first =
		|
			raw,
		|
			Data.verification_snapshot(raw)?
				.live
				.reports
				.first()
				.map_err(|_| "seed a report before checking this operation")
}
