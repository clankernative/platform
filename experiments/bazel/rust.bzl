"""Isolated Rust feasibility targets; operational recipes remain in ops/*.roc."""

load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

def _attributes(crate_name, internal_deps, linux_deps, own_library, dev, rustc_env):
    package = native.package_name()
    env = {
        # Existing tools resolve the workspace relative to their manifest. A
        # runtime feasibility test must use the checked-out workspace as cwd.
        # This is explicitly not a remotely executable Roc action yet.
        "CARGO_MANIFEST_DIR": package,
        "CARGO_PKG_NAME": package.rsplit("/", 1)[-1],
        "CARGO_PKG_VERSION": "0.1.0",
    }
    env.update(rustc_env)
    deps = internal_deps + all_crate_deps(normal = True, normal_dev = dev, package_name = package)
    if own_library:
        deps = deps + [own_library]
    if linux_deps:
        deps = deps + select({"@platforms//os:linux": linux_deps, "//conditions:default": []})
    return {
        "crate_name": crate_name,
        "edition": "2024",
        "version": "0.1.0",
        "aliases": aliases(normal = True, normal_dev = dev, package_name = package),
        "deps": deps,
        "proc_macro_deps": all_crate_deps(proc_macro = True, proc_macro_dev = dev, package_name = package),
        # Match the workspace's dev/test optimization and retain its checks.
        # Third-party targets inherit opt-level 2 from the registered toolchain.
        "rustc_flags": ["-Copt-level=1", "-Cdebuginfo=0", "-Cdebug-assertions=on", "-Coverflow-checks=on"],
        "rustc_env": env,
    }

def platform_rust_library(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_library(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, False, rustc_env), **kwargs))

def platform_rust_binary(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_binary(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, False, rustc_env), **kwargs))

def platform_rust_test(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_test(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, True, rustc_env), **kwargs))
