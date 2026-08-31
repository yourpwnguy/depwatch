# depwatch — Makefile
#
# Self-documenting: run `make help` to see all targets.
# The build produces a static binary (pure Go, CGO_ENABLED=0) so it runs
# anywhere without external shared libraries.

BINARY   := depwatch
PKG      := ./cmd/depwatch

# Version from git, stripped of the leading 'v' for SemVer compliance.
# Falls back to "dev" for untagged builds.
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
LDFLAGS  := -s -w
ifneq ($(VERSION),)
  LDFLAGS += -X main.version=$(VERSION)
endif

# Golangci-lint version — pinned for reproducible CI.
GOLANGCI_VERSION := v2.1.6

.PHONY: build test test-race lint fmt vet check bench fuzz clean help run

## build: compile the binary with version info
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: run all tests
test:
	go test ./...

## test-race: run all tests with race detector
test-race:
	go test -race ./...

## lint: run golangci-lint (installs if missing)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_VERSION)
	golangci-lint run ./...

## fmt: format all Go files
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## check: the single CI gate — fmt, vet, lint, test-race, build
check: fmt vet lint test-race build

## bench: run benchmarks
bench:
	go test -bench=. -benchmem ./...

## fuzz: run fuzz tests (if any)
fuzz:
	go test -fuzz=. -fuzztime=30s ./...

## clean: remove build artifacts
clean:
	rm -f $(BINARY) depwatch.db

## run: build and scan
run: build
	./$(BINARY) scan

## help: show this help
help:
	@echo "depwatch targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
