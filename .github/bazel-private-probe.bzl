"""Public fixed metadata action; no app, SDK, Rust or provider input."""

def _marker_impl(ctx):
    case = ctx.var.get("DAY2_PUBLIC_PROBE", "outside")
    if case not in ["outside", "nested", "outer"]:
        fail("closed public probe case required")
    out = ctx.actions.declare_file("marker-" + case)
    ctx.actions.run(
        executable = "/usr/bin/touch",
        arguments = [out.path],
        outputs = [out],
        mnemonic = "PublicMarker",
    )
    return [DefaultInfo(files = depset([out]))]

public_marker = rule(implementation = _marker_impl)
