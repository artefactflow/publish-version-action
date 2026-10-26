# Build a static publish-version binary and ship it on a minimal runtime.
#
# The runtime image carries CA certificates: the action makes outbound HTTPS calls to the ArtefactFlow API, so a bare scratch image would fail TLS verification. distroless static provides them at a fraction of the size of a full base image.
#
# There is deliberately no USER instruction. A container action runs as root on the runner, and the runner's workspace and file-command files are owned accordingly: an unprivileged user cannot append to $GITHUB_OUTPUT, nor read a vulnerabilities file the checkout step wrote.
FROM golang:1.26 AS build
WORKDIR /src

# Module metadata first for layer caching. The module has no external dependencies, so this is effectively a no-op today, but it keeps the cache warm if any are added later.
COPY go.mod ./
RUN go mod download

COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/publish-version ./cmd/publish-version

FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=build /out/publish-version /usr/local/bin/publish-version
ENTRYPOINT ["/usr/local/bin/publish-version"]
