# Generated field selectors retain both the containing type and field identity.
Path(root, value) :: { path : Str, root_witness : List(root), value_witness : List(value) }.{
	define : Str -> Path(root, value)
	define = |path| { path, root_witness: [], value_witness: [] }

	name : Path(root, value) -> Str
	name = |selector| selector.path
}
