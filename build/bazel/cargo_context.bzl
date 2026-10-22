"""Explicit native dependency contexts for the platform build graph.

Build-script executables run in the exec configuration, but their features
belong to the crate being built. Keep those owner variants separate rather
than selecting their features after the exec transition.
"""

load("@rules_rust//cargo:defs.bzl", _cargo_build_script = "cargo_build_script")
load("@rules_rust//rust:defs.bzl", _rust_library = "rust_library")
load(":cargo_contexts.bzl", "CARGO_CONTEXTS")

_PLATFORMS = ["linux_x86_64", "linux_aarch64", "macos_aarch64"]

def _context_impl(ctx):
    return [config_common.FeatureFlagInfo(
        value = "host" if ctx.configuration.is_tool_configuration() else "target",
    )]

cargo_dependency_context = rule(implementation = _context_impl)

def _variants(name, version):
    key = name + "@" + version
    result = []
    for platform in _PLATFORMS:
        if key in CARGO_CONTEXTS[platform]:
            for context, values in CARGO_CONTEXTS[platform][key].items():
                result.append((platform + "_" + context, values))
    if not result:
        fail("No reviewed native Cargo dependency context for " + key)
    return result

def cargo_context_rust_library(name, version, crate_features, deps = [], proc_macro_deps = [], aliases = {}, visibility = None, **kwargs):
    crate_name = kwargs.pop("crate_name", name)
    actual = {}
    for context, model in _variants(crate_name, version):
        variant = name + "__cargo_" + context
        _rust_library(
            name = variant,
            crate_name = crate_name,
            version = version,
            crate_features = model["features"],
            deps = model["deps"],
            proc_macro_deps = model["proc_macro_deps"],
            aliases = model["aliases"],
            visibility = ["//visibility:private"],
            **kwargs
        )
        actual["@@//build/bazel:" + context] = ":" + variant
    # No generated feature-union fallback: an unmodeled platform/role refuses.
    native.alias(name = name, actual = select(actual), visibility = visibility)

def cargo_context_build_script(name, pkg_name, version, crate_features, deps = [], proc_macro_deps = [], aliases = {}, visibility = None, **kwargs):
    if name != "_bs":
        fail("Unreviewed generated build-script name: " + name)
    # Preserve the generated `_bs` compiler's original empty crate-name input.
    env = dict(kwargs.pop("rustc_env", {}))
    if "CARGO_CRATE_NAME" not in env:
        env["CARGO_CRATE_NAME"] = ""
    kwargs["rustc_env"] = env
    actual = {}
    for context, model in _variants(pkg_name.replace("-", "_"), version):
        variant = name + "__cargo_" + context
        _cargo_build_script(
            name = variant,
            pkg_name = pkg_name,
            version = version,
            crate_features = model["features"],
            deps = model["build_deps"],
            proc_macro_deps = model["build_proc_macro_deps"],
            aliases = model["build_aliases"],
            visibility = ["//visibility:private"],
            **kwargs
        )
        actual["@@//build/bazel:" + context] = ":" + variant
    native.alias(name = name, actual = select(actual), visibility = visibility)

_ContextProof = provider(fields = ["context", "selected"])

def _probe_impl(ctx):
    context = ctx.attr.context[config_common.FeatureFlagInfo].value
    if context != ctx.attr.expected or ctx.attr.selected != [ctx.attr.expected]:
        fail("Cargo dependency context or feature select failed: " + ctx.label.name)
    return [_ContextProof(context = context, selected = ctx.attr.selected)]

cargo_context_probe = rule(
    implementation = _probe_impl,
    attrs = {
        "context": attr.label(default = "@@//build/bazel:dependency_context"),
        "expected": attr.string(mandatory = True),
        "selected": attr.string_list(mandatory = True),
    },
)

def _controls_impl(ctx):
    normal = ctx.attr.normal[_ContextProof]
    tool = ctx.attr.tool[_ContextProof]
    if normal.context != "target" or tool.context != "host":
        fail("Cargo dependency context transition control failed")
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode({
        "normal": normal.context,
        "normal_select": normal.selected,
        "exec": tool.context,
        "exec_select": tool.selected,
        "rust_compilation_or_runtime_executed": False,
    }) + "\n")
    return [DefaultInfo(files = depset([output]))]

cargo_context_controls = rule(
    implementation = _controls_impl,
    attrs = {
        "normal": attr.label(mandatory = True, cfg = "target"),
        "tool": attr.label(mandatory = True, cfg = "exec"),
    },
)
