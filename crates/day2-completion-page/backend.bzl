"""Compile the selected rustix producer's ACTUAL cfg flags into kernel tests."""
load("@rules_rust//rust/private:providers.bzl", "BuildInfo")

def _flags_impl(ctx):
    flags = ctx.attr.producer[BuildInfo].flags
    if flags == None:
        fail("rustix backend has no actual build-script flags")
    # Rust include_str reads this fixed source file, not an environment dump.
    result = ctx.actions.declare_file("selected_rustix_backend.txt")
    ctx.actions.symlink(output = result, target_file = flags)
    return [DefaultInfo(files = depset([result]))]

selected_backend_flags = rule(
    implementation = _flags_impl,
    attrs = {"producer": attr.label(mandatory = True, providers = [BuildInfo])},
)
