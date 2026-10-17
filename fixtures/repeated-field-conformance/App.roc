import TagThing
import ListThings
import Routes
import ThingInvariants
import Demo

App :: [].{
	definition = {
		namespace: "things",
		operations: { tag: TagThing.definition, list: ListThings.definition },
		pages: { things: Routes.directory.register(), native_controls: Routes.native_controls.register() },
		properties: { things: ThingInvariants.things },
		errors: {},
		examples: [Demo.definition],
		presentation: { stylesheet: "app.css", script: "" },
	}
}
