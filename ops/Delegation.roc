import Capability

# Build the exporter before resolving the caller's exact operation contract.
Delegation :: [].{
	build! : (Str => Try(Str, Str)) => Try(Str, Str)
	build! = |host!| {
		_ = Capability.call!("verify-build", Json.to_str({ fixture: "delegation-peer" }), host!)?
		Capability.call!("verify-build", Json.to_str({ fixture: "delegation" }), host!)
	}

	business! : (Str => Try(Str, Str)) => Try(Str, Str)
	business! = |host!| {
		_ = Capability.call!("verify-build", Json.to_str({ fixture: "stock-ledger" }), host!)?
		_ = Capability.call!("verify-build", Json.to_str({ fixture: "request-desk" }), host!)?
		_ = Capability.call!("verify-build", Json.to_str({ fixture: "app-ownership" }), host!)?
		Capability.call!("verify-build", Json.to_str({ fixture: "notifications" }), host!)
	}
}
