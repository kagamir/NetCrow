# Supply tested static Linux release binaries using scripts/prepare-docker.py.
# BuildKit sets TARGETARCH from --platform; no target code runs during the build.
FROM scratch
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/kagamir/NetCrow" \
      org.opencontainers.image.title="NetCrow" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --chmod=0755 docker-bin/${TARGETARCH}/netcrow /netcrow
COPY LICENSE /LICENSE
WORKDIR /etc/netcrow
STOPSIGNAL SIGINT
ENTRYPOINT ["/netcrow"]
CMD ["--help"]
