# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build

WORKDIR /src

# Dependencies first so a source-only change keeps the cached layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

# CGO is off so the result is a static binary that runs on a distroless base.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/cs-routeros-sync-bouncer ./cmd/cs-routeros-sync-bouncer

# distroless/static carries the CA bundle needed to reach a TLS LAPI, and
# nothing else: no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/cs-routeros-sync-bouncer /usr/local/bin/cs-routeros-sync-bouncer

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cs-routeros-sync-bouncer"]
CMD ["-config", "/etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml"]
