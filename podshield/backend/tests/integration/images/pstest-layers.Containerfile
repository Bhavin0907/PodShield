# pstest fixture: PS-008 only. Ten extra layers; the suite's limit is 12 layers, which the
# golden image (ubi-minimal plus three layers) stays under.
ARG BASE=registry.access.redhat.com/ubi9/ubi-minimal:latest
FROM ${BASE}
LABEL org.opencontainers.image.authors="pstest@example.invalid" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://example.invalid/pstest" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/ubi-minimal"
COPY harden.sh /tmp/harden.sh
RUN bash /tmp/harden.sh clean
RUN mkdir -p /opt/pstest && echo 1 > /opt/pstest/layer-01
RUN echo 2 > /opt/pstest/layer-02
RUN echo 3 > /opt/pstest/layer-03
RUN echo 4 > /opt/pstest/layer-04
RUN echo 5 > /opt/pstest/layer-05
RUN echo 6 > /opt/pstest/layer-06
RUN echo 7 > /opt/pstest/layer-07
RUN echo 8 > /opt/pstest/layer-08
RUN echo 9 > /opt/pstest/layer-09
RUN echo 10 > /opt/pstest/layer-10
RUN bash /tmp/harden.sh finish
USER 1001
HEALTHCHECK --interval=30s CMD ["/usr/bin/true"]
CMD ["/usr/bin/sleep", "300"]
