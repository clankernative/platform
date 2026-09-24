platform "day2-pure"
	requires {
		step : Str -> Str
	}
	exposes []
	packages {}
	provides { "day2_step": step_for_host }
	targets: {
		inputs_dir: "targets/",
		arm64mac: { inputs: ["libhost.a", app] },
		arm64glibc: {
			inputs: ["Scrt1.o", "crti.o", "libhost.a", app, "crtn.o", "libc.so.6", "libm.so.6", "libgcc_s.so.1"],
		},
		x64glibc: {
			inputs: ["Scrt1.o", "crti.o", "libhost.a", app, "crtn.o", "libc.so.6", "libm.so.6", "libgcc_s.so.1"],
		},
	}

step_for_host : Str -> Str
step_for_host = |input| step(input)
