import UiCapability

# A Platform release selects and approves this build dependency. Apps select only
# locked package content; they cannot supply download URLs or executables.
UiDependency :: [].{
	install! : UiCapability.InstallHost => Try(UiCapability.JsonReceipt, Str)
	install! = |host| {
		status = (host.inspect!)({})?
		if !status.installed {
			_ = (host.fetch!)({})?
			_ = (host.extract!)({})?
			_ = (host.verify!)({})?
			_ = (host.publish!)({})?
		}
		(host.receipt!)({})
	}

	lock! : Str, UiCapability.LockHost => Try(UiCapability.JsonReceipt, Str)
	lock! = |source, host| (host.lock!)({ source: source })
}
