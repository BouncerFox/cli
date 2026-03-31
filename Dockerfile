FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /bf ./cmd/bouncerfox

FROM alpine:3.21
RUN adduser -D -u 1000 bouncerfox
COPY --from=builder /bf /usr/local/bin/bf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER bouncerfox
ENTRYPOINT ["entrypoint.sh"]
