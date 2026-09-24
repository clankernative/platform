import Field

Control(a) :: { field : Field(a), label : Str }.{
	text : Field(a), Str -> Control(a)
	text = |field, label| { field, label }

	metadata : Control(a) -> { name : Str, label : Str }
	metadata = |control| { name: control.field.name(), label: control.label }
}
