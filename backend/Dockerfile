# ---- Build stage ----
FROM docker.arvancloud.ir/golang:1.22-alpine AS builder

WORKDIR /app

ENV GOPROXY=https://mirror-go.runflare.com,direct

# RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/secure-clipboard ./cmd/server

# ---- Runtime stage ----
FROM docker.arvancloud.ir/alpine:3.20

# RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /bin/secure-clipboard .

EXPOSE 8080

USER nobody

ENTRYPOINT ["./secure-clipboard"]