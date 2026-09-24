import Asset

Button :: { label : Str, tone : Str, asset : Str }.{
	primary : Str -> Button
	primary = |label| { label, tone: "primary", asset: "" }

	secondary : Str -> Button
	secondary = |label| { label, tone: "secondary", asset: "" }

	danger : Str -> Button
	danger = |label| { label, tone: "danger", asset: "" }

	with_icon : Button, Asset -> Button
	with_icon = |button, asset| { ..button, asset: asset.key() }

	metadata : Button -> { label : Str, tone : Str, asset : Str }
	metadata = |button| { label: button.label, tone: button.tone, asset: button.asset }
}
