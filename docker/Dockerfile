# Multi-stage build for the bannin CLI binary.
#
# Deferred: this only builds the CLI itself. Bundling the external
# scanner binaries (Semgrep, Trivy, OSV Scanner, Gitleaks, ...) into the
# image is orchestration/packaging work that belongs to the milestones
# that add each plugin, not to the Milestone 1 skeleton.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/bannin ./cmd/bannin

FROM alpine:3.20
COPY --from=build /out/bannin /usr/local/bin/bannin
ENTRYPOINT ["bannin"]
