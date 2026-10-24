# acme-steward container image.
#
#   docker build -f Containerfile -t acme-steward .
#
# Runs as an unprivileged user: when started as root, the acme-steward
# wrapper (container/acme-steward.sh) takes ownership of the data directory
# and then drops privileges. Mount a persistent volume at
# /var/lib/acme-steward and provide the config, DigitalOcean token and SSH
# credentials (see README).

FROM golang:1.26.10-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/acme-steward ./cmd/acme-steward

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssh-client rsync \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 acme \
 && useradd --uid 10001 --gid acme --home-dir /var/lib/acme-steward --no-create-home --shell /usr/sbin/nologin acme \
 && install -d -o acme -g acme -m 0700 /var/lib/acme-steward \
 && install -d -m 0755 /etc/acme-steward
COPY --from=build /out/acme-steward /usr/local/libexec/acme-steward/acme-steward
COPY container/acme-steward.sh /usr/local/bin/acme-steward

ENV ACME_STEWARD_CONFIG=/etc/acme-steward/config.yaml \
    ACME_STEWARD_DATA_DIR=/var/lib/acme-steward
VOLUME /var/lib/acme-steward
HEALTHCHECK --interval=5m --timeout=10s --start-period=30m CMD ["acme-steward", "healthcheck"]
ENTRYPOINT ["acme-steward"]
CMD ["run"]
