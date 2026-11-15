# pstest fixture: PS-009 only. 128 KiB left behind in the dnf cache (the rule needs >= 64 KiB).
ARG BASE=registry.access.redhat.com/ubi9/ubi-minimal:latest
FROM ${BASE}
LABEL org.opencontainers.image.authors="pstest@example.invalid" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://example.invalid/pstest" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/ubi-minimal"
COPY harden.sh /tmp/harden.sh
RUN bash /tmp/harden.sh clean
RUN mkdir -p /var/cache/dnf && dd if=/dev/zero of=/var/cache/dnf/pstest-metadata.bin bs=1024 count=128
RUN bash /tmp/harden.sh finish
USER 1001
HEALTHCHECK --interval=30s CMD ["/usr/bin/true"]
CMD ["/usr/bin/sleep", "300"]
