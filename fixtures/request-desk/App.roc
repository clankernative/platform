import RequestStock
import RequestProgress
import RequestInvariants
import RequestHome
import RequestRoutes

App :: [].{
	definition = {
		namespace: "request_desk",
		operations: {
			request: RequestStock.definition,
			progress: RequestProgress.definition,
			home: RequestHome.definition,
		},
		pages: { home: RequestRoutes.home.register() },
		properties: { requests: RequestInvariants.ownership },
		errors: {},
		examples: [],
		presentation: { stylesheet: "", script: "requests.js" },
	}
}
