# Generated from the native workflow contract; edit its Rust definitions.
import UiCapability

UiTransport :: [].{
	install : (Str => Try(Str, Str)) -> UiCapability.InstallHost
	install = |send!| {
		inspect!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-inspect", input: Json.to_str(input) }))?
			result : UiCapability.Inspection
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-inspect response")?
			Ok(result)
		},
		fetch!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-fetch", input: Json.to_str(input) }))?
			result : UiCapability.Fetched
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-fetch response")?
			Ok(result)
		},
		extract!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-extract", input: Json.to_str(input) }))?
			result : UiCapability.Extracted
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-extract response")?
			Ok(result)
		},
		verify!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-verify", input: Json.to_str(input) }))?
			result : UiCapability.Verified
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-verify response")?
			Ok(result)
		},
		publish!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-publish", input: Json.to_str(input) }))?
			result : UiCapability.Published
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-publish response")?
			Ok(result)
		},
		receipt!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-dependency-receipt", input: Json.to_str(input) }))?
			result : UiCapability.JsonReceipt
			result = Json.parse(raw).map_err(|_| "invalid ui-dependency-receipt response")?
			Ok(result)
		},
	}

	lock : (Str => Try(Str, Str)) -> UiCapability.LockHost
	lock = |send!| {
		lock!: |input| {
			raw = send!(Json.to_str({ protocol: 1.U32, action: "ui-lock", input: Json.to_str(input) }))?
			result : UiCapability.JsonReceipt
			result = Json.parse(raw).map_err(|_| "invalid ui-lock response")?
			Ok(result)
		},
	}

}
