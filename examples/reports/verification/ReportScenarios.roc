import pf.Model
import Models
import Data

ReportScenarios :: [].{
	first : Str -> Try(Model.Entity(Models.Report), Str)
	first = |raw| Data.snapshot(raw)?.reports.first().map_err(|_| "seed a report before checking this operation")
}
