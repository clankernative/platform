# Platform-owned shell image. Context contains only the selected admitted Linux
# artifacts, never app databases, state, client credentials or custody secrets.
# Preserve their reviewed read-only modes and executable worker modes.
ARG DAY2_RUNTIME_IMAGE
FROM ${DAY2_RUNTIME_IMAGE}
COPY --chown=0:0 artifacts/ /srv/day2/artifacts/
ENTRYPOINT ["/usr/local/bin/day2-security-shell"]
