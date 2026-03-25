FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /bf ./cmd/bouncerfox

FROM alpine:3.19
RUN adduser -D -u 1000 bouncerfox
COPY --from=builder /bf /usr/local/bin/bf
USER bouncerfox
ENTRYPOINT ["bf"]
