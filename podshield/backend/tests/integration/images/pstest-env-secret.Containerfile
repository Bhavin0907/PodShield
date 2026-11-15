# pstest fixture: PS-003 only. A (fake, AWS-documented) credential baked into ENV.
ARG BASE=registry.access.redhat.com/ubi9/ubi-minimal:latest
FROM ${BASE}
LABEL org.opencontainers.image.authors="pstest@example.invalid" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://example.invalid/pstest" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/ubi-minimal"
COPY harden.sh /tmp/harden.sh
RUN bash /tmp/harden.sh clean
RUN bash /tmp/harden.sh finish
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
USER 1001
HEALTHCHECK --interval=30s CMD ["/usr/bin/true"]
CMD ["/usr/bin/sleep", "300"]
