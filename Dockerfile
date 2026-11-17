# xinproof in a container. It restores backups in sibling Docker containers,
# so it needs the host's Docker socket:
#
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#     -v "$PWD/receipts:/work/receipts" -v "$HOME/.xinproof:/root/.xinproof" \
#     ghcr.io/praxin/xinproof verify s3://bucket/prefix/
#
# Receipts are written to /work/receipts; the signing key lives in /root/.xinproof.
FROM golang:1.26-alpine AS build
ARG VERSION=0.1.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /xinproof ./cmd/xinproof

FROM alpine:3.22
RUN apk add --no-cache ca-certificates docker-cli tzdata
COPY --from=build /xinproof /usr/local/bin/xinproof
COPY LICENSE /usr/share/doc/xinproof/LICENSE
WORKDIR /work
ENTRYPOINT ["xinproof"]
CMD ["--help"]
