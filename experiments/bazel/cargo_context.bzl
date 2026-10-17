"""Experiment-only Cargo dependency contexts for the selected Linux graph.

Build-script executables run in the exec configuration, but their features
belong to the crate being built. Keep those owner variants separate rather
than selecting their features after the exec transition.
"""

load("@rules_rust//cargo:defs.bzl", _cargo_build_script = "cargo_build_script")
load("@rules_rust//rust:defs.bzl", _rust_library = "rust_library")
load(":cargo_contexts.bzl", "CARGO_CONTEXTS")

_HOST = "@@//experiments/bazel:linux_exec_context"
_TARGET = "@@//experiments/bazel:linux_target_context"

def _context_impl(ctx):
    return [config_common.FeatureFlagInfo(
        value = "host" if ctx.configuration.is_tool_configuration() else "target",
    )]

cargo_dependency_context = rule(implementation = _context_impl)

def _model(name, version):
    key = name + "@" + version
    if key not in CARGO_CONTEXTS:
        fail("No reviewed Cargo dependency context for " + key)
    return CARGO_CONTEXTS[key]

def cargo_context_rust_library(name, version, crate_features, deps = [], proc_macro_deps = [], aliases = {}, visibility = None, **kwargs):
    crate_name = kwargs.pop("crate_name", name)
    model = _model(crate_name, version)
    for context in ["target", "host"]:
        _rust_library(
            name = name + "__cargo_" + context,
            crate_name = crate_name,
            version = version,
            crate_features = model[context]["features"],
            deps = model[context]["deps"],
            proc_macro_deps = model[context]["proc_macro_deps"],
            aliases = model[context]["aliases"],
            visibility = ["//visibility:private"],
            **kwargs
        )
    _rust_library(
        name = name + "__generated",
        crate_name = crate_name,
        version = version,
        crate_features = crate_features,
        deps = deps,
        proc_macro_deps = proc_macro_deps,
        aliases = aliases,
        visibility = ["//visibility:private"],
        **kwargs
    )
    native.alias(
        name = name,
        actual = select({
            _HOST: ":" + name + "__cargo_host",
            _TARGET: ":" + name + "__cargo_target",
            "//conditions:default": ":" + name + "__generated",
        }),
        visibility = visibility,
    )

def cargo_context_build_script(name, pkg_name, version, crate_features, deps = [], proc_macro_deps = [], aliases = {}, visibility = None, **kwargs):
    model = _model(pkg_name.replace("-", "_"), version)
    # Each call passes literal owner features to both build-script compilation
    # and execution. Its build dependencies still take the normal exec edge.
    for context in ["target", "host"]:
        _cargo_build_script(
            name = name + "__cargo_" + context,
            pkg_name = pkg_name,
            version = version,
            crate_features = model[context]["features"],
            deps = model[context]["build_deps"],
            proc_macro_deps = model[context]["build_proc_macro_deps"],
            aliases = model[context]["build_aliases"],
            visibility = ["//visibility:private"],
            **kwargs
        )
    # Other platforms retain the original generated rule. This Linux experiment
    # provides no feature-equivalence or runtime qualification for those hosts.
    _cargo_build_script(
        name = name + "__generated",
        pkg_name = pkg_name,
        version = version,
        crate_features = crate_features,
        deps = deps,
        proc_macro_deps = proc_macro_deps,
        aliases = aliases,
        visibility = ["//visibility:private"],
        **kwargs
    )
    native.alias(
        name = name,
        actual = select({
            _HOST: ":" + name + "__cargo_host",
            _TARGET: ":" + name + "__cargo_target",
            "//conditions:default": ":" + name + "__generated",
        }),
        visibility = visibility,
    )

_ContextProof = provider(fields = ["context", "selected"])

def _probe_impl(ctx):
    context = ctx.attr.context[config_common.FeatureFlagInfo].value
    if context != ctx.attr.expected or ctx.attr.selected != [ctx.attr.expected]:
        fail("Cargo dependency context or feature select failed: " + ctx.label.name)
    return [_ContextProof(context = context, selected = ctx.attr.selected)]

cargo_context_probe = rule(
    implementation = _probe_impl,
    attrs = {
        "context": attr.label(default = "@@//experiments/bazel:dependency_context"),
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
