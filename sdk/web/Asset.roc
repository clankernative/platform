Asset :: { key : Str }.{
	define : Str -> Asset
	define = |key| { key: key }

	key : Asset -> Str
	key = |asset| asset.key
}
