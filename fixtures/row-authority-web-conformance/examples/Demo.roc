import pf.Example
import Commands
import Domains
import pf.WebUrl

Demo :: [].{
	definition : Example
	definition = Example.define("demo", steps({}))

	steps : {} -> Try(List(Example.Step), Str)
	steps = |_| {
		title = Domains.title("Example link")?
		destination = WebUrl.from_str("https://example.com/").map_err(|_| "invalid demo URL")?
		Ok([Example.Step.command(Commands.create, { title, destination })])
	}
}
