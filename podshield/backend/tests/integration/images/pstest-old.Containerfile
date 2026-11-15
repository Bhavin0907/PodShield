# pstest fixture: PS-005 only. Identical to golden; the harness builds it with
# `--timestamp 1609459200` (2021-01-01) so the image looks years old.
ARG BASE=registry.access.redhat.com/ubi9/ubi-minimal:latest
FROM ${BASE}
LABEL org.opencontainers.image.authors="pstest@example.invalid" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://example.invalid/pstest" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/ubi-minimal"
COPY harden.sh /tmp/harden.sh
RUN bash /tmp/harden.sh clean
RUN bash /tmp/harden.sh finish
USER 1001
HEALTHCHECK --interval=30s CMD ["/usr/bin/true"]
CMD ["/usr/bin/sleep", "300"]
