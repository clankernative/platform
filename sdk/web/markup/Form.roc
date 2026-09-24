import Html
import Attribute
import Field
import Write

Form(a) :: { html : Html, fields : List({ name : Str, label : Str }), witness : List(a) }.{
	node : Html -> Form(a)
	node = |html| { html, fields: [], witness: [] }

	input : Field(a), List(Attribute) -> Form(a)
	input =
		|
			field,
			attrs,
		|
			{
				html: Html.field_node("input", field.name(), attrs, []),
				fields: [{ name: field.name(), label: "" }],
				witness: [],

			}

	textarea : Field(a), List(Attribute), Str -> Form(a)
	textarea =
		|
			field,
			attrs,
			value,
		|
			{
				html: Html.field_node("textarea", field.name(), attrs, [Html.text(value)]),
				fields: [{ name: field.name(), label: "" }],
				witness: [],

			}

	select : Field(a), List(Attribute), List(Html) -> Form(a)
	select =
		|
			field,
			attrs,
			options,
		|
			{
				html: Html.field_node("select", field.name(), attrs, options),
				fields: [{ name: field.name(), label: "" }],
				witness: [],

			}

	element : Str, List(Attribute), List(Form(a)) -> Form(a)
	element =
		|
			tag,
			attrs,
			children,
		|
			{
				html: Html.element(tag, attrs, children.map(|child| child.html)),
				fields: children.map(|child| child.fields).join(),
				witness: [],

			}

	command : Write(a, b), List(Attribute), List(Form(a)) -> Html
	command =
		|
			write,
			attrs,
			children,
		|
			Html.command_node(
				write.name(),
				"{}",
				children.map(|child| child.fields).join(),
				attrs,
				children.map(|child| child.html),
			)

	bound : Write(a, b), a, List(Attribute), List(Html) -> Html
	bound =
		|
			write,
			input_value,
			attrs,
			children,
		| Html.command_node(write.name(), write.encode_input(input_value), [], attrs, children)
}
