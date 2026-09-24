Attribute :: { name : Str, value : Str }.{
	attribute : Str, Str -> Attribute
	attribute = |key, content| { name: key, value: content }

	metadata : Attribute -> { name : Str, value : Str }
	metadata = |attr| { name: attr.name, value: attr.value }

	class = |content| attribute("class", content)

	id = |content| attribute("id", content)

	href = |content| attribute("href", content)

	type = |content| attribute("type", content)

	name = |content| attribute("name", content)

	value = |content| attribute("value", content)

	placeholder = |content| attribute("placeholder", content)

	title = |content| attribute("title", content)

	role = |content| attribute("role", content)

	for_ = |content| attribute("for", content)

	style = |content| attribute("style", content)

	min = |content| attribute("min", content)

	max = |content| attribute("max", content)

	step = |content| attribute("step", content)

	rows = |content| attribute("rows", content)

	width = |content| attribute("width", content)

	height = |content| attribute("height", content)

	required = |content| attribute("required", content)

	disabled = |content| attribute("disabled", content)

	hidden = |content| attribute("hidden", content)
}
