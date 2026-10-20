# Native Linux amd64 build. No app artifact, shell, provider credential or root
# private key belongs in this image. Match the platform's pinned Debian family.
FROM rust@sha256:620dbcd124499c59e2406d3741574b5c5838cf9eb9656f0c3a03948f79b02959 AS build
RUN ["rustup", "toolchain", "install", "1.98.1", "--profile", "minimal", "--component", "rustfmt", "--component", "clippy"]
WORKDIR /workspace/platform
ENV CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
COPY . .
RUN ["cargo", "build", "--locked", "--release", "-p", "day2", "--bin", "day2-native-enrollment", "--bin", "day2-native-enrollment-qualify", "-p", "xtask", "--bin", "xtask"]
RUN ["target/release/xtask", "bootstrap"]
RUN ["target/release/xtask", "workflows"]

FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750 AS runtime
COPY --from=build /workspace/platform/LICENSE /usr/share/doc/day2/LICENSE
COPY --from=build /workspace/platform/THIRD-PARTY-NOTICES.txt /usr/share/doc/day2/THIRD-PARTY-NOTICES.txt
COPY --from=build /workspace/platform/dependency-inventory.json /usr/share/doc/day2/dependency-inventory.json
COPY --from=build /workspace/platform/target/release/day2-native-enrollment /usr/local/bin/day2-native-enrollment
COPY --from=build /workspace/platform/target/release/day2-native-enrollment-qualify /usr/local/bin/day2-native-enrollment-qualify
COPY --from=build /workspace/platform/target/debug/day2-workflows /usr/local/lib/day2/day2-workflows
COPY --from=build /workspace/platform/target/debug/day2-workflows.json /usr/local/lib/day2/day2-workflows.json
WORKDIR /etc/day2
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/day2-native-enrollment"]
