Asset :: { key : Str }.{
	define : Str -> Asset
	define = |asset_key| { key: asset_key }

	key : Asset -> Str
	key = |asset| asset.key
}
