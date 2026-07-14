FROM golang:1.25.12-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /port-map-check ./cmd/port-map-check

FROM scratch
COPY --from=build /port-map-check /port-map-check
ENTRYPOINT ["/port-map-check"]
