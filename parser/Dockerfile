FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /dmarc-parser .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /dmarc-parser /dmarc-parser
ENTRYPOINT ["/dmarc-parser"]
