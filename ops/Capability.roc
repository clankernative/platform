# Private effect vocabulary. The Rust supervisor supplies the callback and
# independently validates every operation. This is not part of the app SDK.
Capability :: [].{
	call! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	call! = |action, input, host!| host!(Json.to_str({ protocol: 1.U32, action, input }))
}
