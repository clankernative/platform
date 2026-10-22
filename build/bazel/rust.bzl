"""Platform Rust targets. Roc recipes retain operational step order."""

load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_doc_test", "rust_library", "rust_static_library", "rust_test")

def _attributes(crate_name, internal_deps, linux_deps, own_library, dev, rustc_env):
    package = native.package_name()
    env = {
        "CARGO_MANIFEST_DIR": package,
        "CARGO_PKG_NAME": {"cli/checks": "day2-cli-checks", "crates/worker": "day2-roc-worker"}.get(package, package.rsplit("/", 1)[-1]),
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
        # Preserve workspace dev/test optimization and all safety checks. Rust
        # dependencies use the pinned toolchain's separately declared level.
        "rustc_flags": select({
            "//build/bazel:release": ["-Copt-level=3", "-Cdebuginfo=0", "-Cpanic=abort", "-Cdebug-assertions=off", "-Coverflow-checks=off"],
            "//conditions:default": ["-Copt-level=1", "-Cdebuginfo=0", "-Cdebug-assertions=on", "-Coverflow-checks=on"],
        }),
        "rustc_env": env,
    }

def platform_rust_library(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_library(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, False, rustc_env), **kwargs))
    rust_doc_test(name = name + "_doc", crate = ":" + name, tags = ["manual"], size = "large")

def platform_rust_static_library(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_static_library(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, False, rustc_env), **kwargs))

def platform_rust_binary(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, **kwargs):
    rust_binary(name = name, **dict(_attributes(crate_name, internal_deps, linux_deps, own_library, False, rustc_env), **kwargs))

def platform_rust_test(name, crate_name, internal_deps = [], linux_deps = [], own_library = None, rustc_env = {}, program_data = [], **kwargs):
    env = dict(rustc_env)
    for program in program_data:
        env["CARGO_BIN_EXE_" + program.rsplit(":", 1)[-1]] = "build-out/bin/" + program.rsplit(":", 1)[-1]
    attributes = _attributes(crate_name, internal_deps, linux_deps, own_library, True, env)
    # Keep current Linux harness LLVM partitioning and no-LTO memory behavior.
    attributes["rustc_flags"] = attributes["rustc_flags"] + ["-Cpanic=unwind"] + select({
        "@platforms//os:linux": ["-Ccodegen-units=256", "-Clto=off"],
        "//conditions:default": [],
    })
    rust_test(name = name, data = program_data, size = "large", **dict(attributes, **kwargs))
