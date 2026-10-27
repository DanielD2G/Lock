# Minimal image with just the static lock binary, meant to be copied into
# other images:
#
#   COPY --from=ghcr.io/danield2g/lock:latest /lock /usr/local/bin/lock
#
# Built by the release workflow from the musl binaries in dist/.
FROM scratch
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/DanielD2G/Lock"
LABEL org.opencontainers.image.description="lock: encrypted, signed environment variables you can commit"
COPY dist/lock-linux-${TARGETARCH} /lock
ENTRYPOINT ["/lock"]
