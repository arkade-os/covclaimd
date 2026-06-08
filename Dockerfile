FROM golang:1.26.3 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /app/bin/covclaimd ./cmd/covclaimd

FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"

EXPOSE 7070 7071

ENTRYPOINT ["covclaimd"]
