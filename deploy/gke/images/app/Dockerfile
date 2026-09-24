# syntax=docker/dockerfile:1
#
# Deploy image for one day2 app: the platform-owned day2 linux-sqlite runtime
# image with that app's qualified native artifact baked in read-only.
#
# This adds no entrypoint, package or script. It exists only because the
# Kubernetes workload has no equivalent of the Compose bundle's read-only
# ./artifacts bind mount; baking the artifact into the image keeps it on the
# read-only root filesystem, which day2-serve's kernel_guards accept.
#
# Build on a host of the artifact's architecture (see ../README.md):
#   docker build \
#     --build-arg DAY2_RUNTIME_IMAGE=<registry>/<path>/day2-runtime@sha256:<DIGEST> \
#     --build-arg ARTIFACT_ID=<64 hex> \
#     -f Dockerfile -t <app>:candidate <context>
# where <context>/artifacts/<ARTIFACT_ID>/ is a directory qualify-linux wrote
# (for example the one its artifacts/owned-current.json names). Before
# building, write-protect the tree:
#   chmod -R a-w,a+rX <context>/artifacts/<ARTIFACT_ID>
ARG DAY2_RUNTIME_IMAGE
FROM ${DAY2_RUNTIME_IMAGE}
ARG ARTIFACT_ID
# Root-owned, no write bits (COPY keeps the context's modes). The worker must
# stay executable and must not be group/other-writable (day2-sandbox checks
# mode & 0o6022 == 0).
COPY --chown=0:0 artifacts/${ARTIFACT_ID}/ /srv/day2/artifacts/${ARTIFACT_ID}/
LABEL dev.day2.artifact-id="${ARTIFACT_ID}"
