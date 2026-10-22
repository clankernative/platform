load("@rules_rust//rust:defs.bzl", "rust_binary")

config_setting(name = "inside", define_values = {"DAY2_PUBLIC_PROBE": "inside"})
rust_binary(
    name = "hello",
    srcs = select({":inside": ["inside.rs"], "//conditions:default": ["outside.rs"]}),
    crate_root = select({":inside": "inside.rs", "//conditions:default": "outside.rs"}),
    edition = "2024",
    rustc_flags = ["-Copt-level=3", "-Cdebuginfo=0", "-Cpanic=abort", "-Cdebug-assertions=off", "-Coverflow-checks=off"],
)
exports_files([
    "rules-rust-0.74.0-child-status.patch",
    "rules-rust-0.74.0-platform-profiles.patch",
    "rules-rust-0.74.0-build-script-inputs.patch",
    "rules-rust-0.74.0-clippy-enforcement.patch",
])
