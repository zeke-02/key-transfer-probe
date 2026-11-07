# syntax=docker/dockerfile:1.19@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6
# Same recipe as fount-mail-edge. tinfoil-go needs go.sum, so dependencies are
# downloaded first. The digest that gets measured comes from Build Image.
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
WORKDIR /src
COPY go.mod go.sum ./
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN go mod download
COPY *.go ./
RUN go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o /probe .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /probe /probe
EXPOSE 8080
ENTRYPOINT ["/probe"]
