# Generated app page identity. It carries no URL, bearer material or authority.
ProductReturnRef :: { page : Str }.{
	define : Str -> ProductReturnRef
	define = |page| { page: page }

	name : ProductReturnRef -> Str
	name = |reference| reference.page
}
