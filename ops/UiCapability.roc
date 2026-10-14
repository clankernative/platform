# Generated from the native workflow contract; edit its Rust definitions.
UiCapability :: [].{
	Empty : {}

	Extracted : {
		extracted : Bool,
	}

	Fetched : {
		fetched : Bool,
	}

	Inspection : {
		installed : Bool,
	}

	JsonReceipt : {
		json : Str,
	}

	LockInput : {
		source : Str,
	}

	Published : {
		published : Bool,
	}

	Verified : {
		verified : Bool,
	}

	InstallHost : {
		inspect! : Empty => Try(Inspection, Str),
		fetch! : Empty => Try(Fetched, Str),
		extract! : Empty => Try(Extracted, Str),
		verify! : Empty => Try(Verified, Str),
		publish! : Empty => Try(Published, Str),
		receipt! : Empty => Try(JsonReceipt, Str),
	}

	LockHost : {
		lock! : LockInput => Try(JsonReceipt, Str),
	}

}
