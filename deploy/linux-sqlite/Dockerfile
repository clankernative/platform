# syntax=docker/dockerfile:1
ARG TARGETARCH
FROM scratch AS bazel-amd64
ADD --checksum=sha256:d302d22ed77ee5658b87857249baa579db84300ecebe0a1e9a357b5b20f80eb8 --chmod=0555 https://github.com/bazelbuild/bazel/releases/download/9.3.0/bazel-9.3.0-linux-x86_64 /bazel
FROM scratch AS bazel-arm64
ADD --checksum=sha256:615cc2509819047e4930fe6643c5f01ebd705ccadf75e8f0b85f9b83cc6a6ca0 --chmod=0555 https://github.com/bazelbuild/bazel/releases/download/9.3.0/bazel-9.3.0-linux-arm64 /bazel
FROM bazel-${TARGETARCH} AS bazel
# Platform-owned images. Apps supply no Dockerfile or install/build hooks.
# The source tooling and runtime use the same pinned Debian/glibc family.
FROM rust@sha256:620dbcd124499c59e2406d3741574b5c5838cf9eb9656f0c3a03948f79b02959 AS tooling
COPY --from=bazel /bazel /usr/local/bin/bazel
WORKDIR /workspace/platform
# The disposable tooling image keeps executable behavior and assertions while
# avoiding multi-gigabyte debug symbols and incremental caches in image layers.
COPY . .
RUN ["bazel", "--batch", "run", "//crates/xtask:xtask", "--", "install-verifier"]
RUN ["build-out/bin/xtask", "build-tooling-image"]
RUN ["build-out/bin/xtask", "bootstrap"]
RUN ["build-out/bin/xtask", "cli"]
# One-shot operator tooling uses the same non-root state-volume ownership as
# the runtime, including when provisioning is the volume's first consumer.
RUN ["install", "-d", "-o", "10001", "-g", "10001", "-m", "0700", "/srv/day2/.state"]

FROM tooling AS runtime-build
# Enrollment reads every executable byte at each observation. Remove linker
# symbols before selecting Linux runtime digests; keep all fresh identity checks.
RUN ["build-out/bin/xtask", "build-runtime-image-programs"]
RUN ["install", "-d", "-o", "10001", "-g", "10001", "-m", "0700", "/runtime-state"]

# Distroless Debian 13: the same glibc release family as the tooling image (a
# binary built against a newer glibc would not run on an older one), with
# libgcc, libssl, libcrypto and the CA bundle, and no shell, coreutils or
# package manager. Pure workers may only read the smaller exact DSO allowlist
# enforced by day2-sandbox; they cannot read arbitrary image files. Anything
# that needs to look inside a running container uses day2-inspect.
# day2-backup takes and verifies an online backup beside a serving day2-serve
# (scheduled off-cluster backups); it runs no app code.
# day2-provision-credentials registers reviewed provider credential mounts
# before the app starts (GKE init container); it contacts no provider.
FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750 AS runtime
# Distroless ships its own packages' notices under /usr/share/doc; no native
# library is copied in from the build image any more. Add the notices for the
# locked Rust/vendored/browser components embedded in the platform executables.
COPY --from=runtime-build /workspace/platform/LICENSE /usr/share/doc/day2/LICENSE
COPY --from=runtime-build /workspace/platform/THIRD-PARTY-NOTICES.txt /usr/share/doc/day2/THIRD-PARTY-NOTICES.txt
COPY --from=runtime-build /workspace/platform/dependency-inventory.json /usr/share/doc/day2/dependency-inventory.json
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-serve /usr/local/bin/day2-serve
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-security-shell /usr/local/bin/day2-security-shell
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-native-enrollment /usr/local/bin/day2-native-enrollment
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-epoch-controller /usr/local/bin/day2-epoch-controller
COPY --from=runtime-build /workspace/platform/build-out/bin/day2-workflows /usr/local/lib/day2/day2-workflows
COPY --from=runtime-build /workspace/platform/build-out/bin/day2-workflows.json /usr/local/lib/day2/day2-workflows.json
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-health /usr/local/bin/day2-health
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-inspect /usr/local/bin/day2-inspect
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-backup /usr/local/bin/day2-backup
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-provision-credentials /usr/local/bin/day2-provision-credentials
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-sandbox /usr/local/bin/day2-sandbox
COPY --from=runtime-build /workspace/platform/build-out/release/bin/day2-sandbox-probe /usr/local/bin/day2-sandbox-probe
COPY --from=runtime-build --chown=10001:10001 /runtime-state /srv/day2/.state
WORKDIR /srv/day2
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/day2-serve"]
