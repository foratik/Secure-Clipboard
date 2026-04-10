.PHONY: build run dev tidy lint migrate keygen

BINARY  := secure-clipboard
CMD     := ./cmd/server

## build: compile the binary
build:
	go build -o bin/$(BINARY) $(CMD)

## run: build and run (requires .env)
run: build
	./bin/$(BINARY)

## dev: run with hot-reload using 'air' (go install github.com/air-verse/air@latest)
dev:
	air

## tidy: update go.sum and remove unused dependencies
tidy:
	go mod tidy

## lint: run golangci-lint (go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
lint:
	golangci-lint run ./...

## test: run all unit tests
test:
	go test -race -cover ./...

## migrate: apply the initial schema to DATABASE_URL
migrate:
	psql "$(DATABASE_URL)" -f migrations/001_init.sql

## keygen: generate a fresh AES-256 key for ENCRYPTION_KEY
keygen:
	@openssl rand -hex 32
