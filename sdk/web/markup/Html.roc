import Control
import Write
import WebUrl
import Asset
import Button
import Attribute

Html :: { nodes : List(Node) }.{
	text : Str -> Html
	text = |value| { nodes: [{ ..empty, kind: "text", text: value }] }

	element : Str, List(Attribute), List(Html) -> Html
	element =
		|
			tag,
			attrs,
			children,
		|
			{
				nodes: [{ ..empty, kind: "open", text: tag, attrs: attrs.map(Attribute.metadata) }]
					.concat(children.map(|child| child.nodes).join())
					.concat([{ ..empty, kind: "close" }]),

			}

	void_element : Str, List(Attribute) -> Html
	void_element = |tag, attrs| { nodes: [{ ..empty, kind: "void", text: tag, attrs: attrs.map(Attribute.metadata) }] }

	concat : List(Html) -> Html
	concat = |children| { nodes: children.map(|child| child.nodes).join() }

	div = |attrs, children| element("div", attrs, children)

	section = |attrs, children| element("section", attrs, children)

	main = |attrs, children| element("main", attrs, children)

	header = |attrs, children| element("header", attrs, children)

	footer = |attrs, children| element("footer", attrs, children)

	nav = |attrs, children| element("nav", attrs, children)

	aside = |attrs, children| element("aside", attrs, children)

	article = |attrs, children| element("article", attrs, children)

	h1 = |attrs, children| element("h1", attrs, children)

	h2 = |attrs, children| element("h2", attrs, children)

	h3 = |attrs, children| element("h3", attrs, children)

	p = |attrs, children| element("p", attrs, children)

	span = |attrs, children| element("span", attrs, children)

	strong = |attrs, children| element("strong", attrs, children)

	em = |attrs, children| element("em", attrs, children)

	a = |attrs, children| element("a", attrs, children)

	button = |attrs, children| element("button", attrs, children)

	label = |attrs, children| element("label", attrs, children)

	fieldset = |attrs, children| element("fieldset", attrs, children)

	legend = |attrs, children| element("legend", attrs, children)

	ul = |attrs, children| element("ul", attrs, children)

	ol = |attrs, children| element("ol", attrs, children)

	li = |attrs, children| element("li", attrs, children)

	table = |attrs, children| element("table", attrs, children)

	thead = |attrs, children| element("thead", attrs, children)

	tbody = |attrs, children| element("tbody", attrs, children)

	tr = |attrs, children| element("tr", attrs, children)

	th = |attrs, children| element("th", attrs, children)

	td = |attrs, children| element("td", attrs, children)

	option = |attrs, children| element("option", attrs, children)

	dialog = |attrs, children| element("dialog", attrs, children)

	details = |attrs, children| element("details", attrs, children)

	summary = |attrs, children| element("summary", attrs, children)

	pre = |attrs, children| element("pre", attrs, children)

	code = |attrs, children| element("code", attrs, children)

	svg = |attrs, children| element("svg", attrs, children)

	input = |attrs| void_element("input", attrs)

	br = |attrs| void_element("br", attrs)

	hr = |attrs| void_element("hr", attrs)

	link : WebUrl, Str -> Html
	link = |url, caption| { nodes: [{ ..empty, kind: "link", url: url.to_str(), text: caption }] }

	image : Asset, Str -> Html
	image = |asset, alt| { nodes: [{ ..empty, kind: "image", asset: asset.key(), text: alt, variant: "content" }] }

	image_with_attributes : Asset, Str, List(Attribute) -> Html
	image_with_attributes =
		|
			asset,
			alt,
			attrs,
		|
			{
				nodes: [
					{
						..empty,
						kind: "image",
						asset: asset.key(),
						text: alt,
						variant: "content",
						attrs: attrs.map(Attribute.metadata),
					},
				],

			}

	icon : Asset -> Html
	icon = |asset| { nodes: [{ ..empty, kind: "image", asset: asset.key(), variant: "icon" }] }

	icon_with_attributes : Asset, List(Attribute) -> Html
	icon_with_attributes =
		|
			asset,
			attrs,
		|
			{
				nodes: [
					{
						..empty,
						kind: "image",
						asset: asset.key(),
						variant: "icon",
						attrs: attrs.map(Attribute.metadata),
					},
				],

			}

	company_name : {} -> Html
	company_name = |_| { nodes: [{ ..empty, kind: "company" }] }

	sign_out : List(Attribute), List(Html) -> Html
	sign_out =
		|
			attrs,
			children,
		|
			{
				nodes: [{ ..empty, kind: "signout", attrs: attrs.map(Attribute.metadata) }]
					.concat(children.map(|child| child.nodes).join())
					.concat([{ ..empty, kind: "close" }]),

			}

	field_node : Str, Str, List(Attribute), List(Html) -> Html
	field_node = |tag, name, attrs, children| {
		start = { ..empty, kind: "field", text: name, variant: tag, attrs: attrs.map(Attribute.metadata) }
		if tag == "input" {
			{ nodes: [start] }
		}
			else {
				{ nodes: [start].concat(children.map(|child| child.nodes).join()).concat([{ ..empty, kind: "close" }]) }
			}
	}

	command_node : Str, Str, List({ name : Str, label : Str }), List(Attribute), List(Html) -> Html
	command_node =
		|
			operation,
			bound,
			fields,
			attrs,
			children,
		|
			{
				nodes: [{ ..empty, kind: "command", operation, bound, fields, attrs: attrs.map(Attribute.metadata) }]
					.concat(children.map(|child| child.nodes).join())
					.concat([{ ..empty, kind: "close" }]),

			}

	form : Write(a, b), List(Control(a)), Button -> Html
	form = |write, fields, button_value| {
		presentation = button_value.metadata()
		{
			nodes: [
				{
					..empty,
					kind: "form",
					operation: write.name(),
					bound: "{}",
					fields: fields.map(Control.metadata),
					text: presentation.label,
					variant: presentation.tone,
					asset: presentation.asset,
				},
			],
		}
	}

	submit : Write(a, b), a, Button -> Html
	submit = |write, input_value, button_value| {
		presentation = button_value.metadata()
		{
			nodes: [
				{
					..empty,
					kind: "form",
					operation: write.name(),
					bound: write.encode_input(input_value),
					text: presentation.label,
					variant: presentation.tone,
					asset: presentation.asset,
				},
			],
		}
	}

	next : I64 -> Html
	next = |after| { nodes: [{ ..empty, kind: "next", text: after.to_str() }] }

	encode : Html -> Str
	encode = |html| Json.to_str(html.nodes)
}

Node : {
	kind : Str,
	text : Str,
	variant : Str,
	url : Str,
	operation : Str,
	bound : Str,
	asset : Str,
	fields : List({ name : Str, label : Str }),
	attrs : List({ name : Str, value : Str }),
}

empty : Node
empty = { kind: "", text: "", variant: "", url: "", operation: "", bound: "", asset: "", fields: [], attrs: [] }
