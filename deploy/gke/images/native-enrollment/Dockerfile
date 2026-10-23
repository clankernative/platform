# syntax=docker/dockerfile:1
ARG TARGETARCH
FROM scratch AS bazel-amd64
ADD --checksum=sha256:d302d22ed77ee5658b87857249baa579db84300ecebe0a1e9a357b5b20f80eb8 --chmod=0555 https://github.com/bazelbuild/bazel/releases/download/9.3.0/bazel-9.3.0-linux-x86_64 /bazel
FROM scratch AS bazel-arm64
ADD --checksum=sha256:615cc2509819047e4930fe6643c5f01ebd705ccadf75e8f0b85f9b83cc6a6ca0 --chmod=0555 https://github.com/bazelbuild/bazel/releases/download/9.3.0/bazel-9.3.0-linux-arm64 /bazel
FROM bazel-${TARGETARCH} AS bazel
# Native Linux amd64 build. No app artifact, shell, provider credential or root
# private key belongs in this image. Match the platform's pinned Debian family.
FROM rust@sha256:620dbcd124499c59e2406d3741574b5c5838cf9eb9656f0c3a03948f79b02959 AS build
COPY --from=bazel /bazel /usr/local/bin/bazel
WORKDIR /workspace/platform
COPY . .
RUN ["bazel", "--batch", "--output_base=/workspace/platform/.cache/bazel-executor", "run", "//crates/xtask:xtask", "--", "install-verifier"]
RUN ["build-out/bin/xtask", "build-enrollment-image-programs"]
RUN ["build-out/bin/xtask", "bootstrap"]
RUN ["build-out/bin/xtask", "workflows"]

FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750 AS runtime
COPY --from=build /workspace/platform/LICENSE /usr/share/doc/day2/LICENSE
COPY --from=build /workspace/platform/THIRD-PARTY-NOTICES.txt /usr/share/doc/day2/THIRD-PARTY-NOTICES.txt
COPY --from=build /workspace/platform/dependency-inventory.json /usr/share/doc/day2/dependency-inventory.json
COPY --from=build /workspace/platform/build-out/release/bin/day2-native-enrollment /usr/local/bin/day2-native-enrollment
COPY --from=build /workspace/platform/build-out/release/bin/day2-native-enrollment-qualify /usr/local/bin/day2-native-enrollment-qualify
COPY --from=build /workspace/platform/build-out/bin/day2-workflows /usr/local/lib/day2/day2-workflows
COPY --from=build /workspace/platform/build-out/bin/day2-workflows.json /usr/local/lib/day2/day2-workflows.json
WORKDIR /etc/day2
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/day2-native-enrollment"]
