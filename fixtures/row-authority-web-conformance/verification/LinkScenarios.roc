import pf.Model
import Models
import Data

LinkScenarios :: [].{
	first : Str -> Try(Model.Entity(Models.Link), Str)
	first = |raw| Data.verification_snapshot(raw)?.live.links.first().map_err(|_| "seed a link first")
}
