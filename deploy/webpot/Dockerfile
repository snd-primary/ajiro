# Build from the repository root:
#   docker build -f deploy/webpot/Dockerfile -t ajiro-webpot .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webpot ./cmd/webpot

# distroless static: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/webpot /webpot
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/webpot", "-addr", ":8080"]
