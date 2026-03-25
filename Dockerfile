FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /bf ./cmd/bouncerfox

FROM alpine:3.19
COPY --from=builder /bf /usr/local/bin/bf
ENTRYPOINT ["bf"]
