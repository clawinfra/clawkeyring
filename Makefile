.PHONY: build test coverage lint clean proto tidy

BINARY      := clawkeyring
BUILD_DIR   := build
COVERAGE    := coverage.out
COVERAGE_HTML := coverage.html
MIN_COVERAGE := 90

GO          := go
GOFLAGS     := -trimpath
LDFLAGS     := -s -w

all: test build

## Build the binary.
build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/clawkeyring/

## Run tests with race detector.
test:
	$(GO) test -race -count=1 ./...

## Run tests with coverage report.
coverage:
	$(GO) test -race -coverprofile=$(COVERAGE) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE) -o $(COVERAGE_HTML)
	@echo ""
	@$(GO) tool cover -func=$(COVERAGE) | tail -1

## Enforce minimum coverage gate (CI).
coverage-gate: coverage
	@TOTAL=$$($(GO) tool cover -func=$(COVERAGE) | tail -1 | awk '{print $$3}' | tr -d '%'); \
	echo "Coverage: $${TOTAL}%"; \
	if [ $$(echo "$${TOTAL} < $(MIN_COVERAGE)" | bc -l) -eq 1 ]; then \
		echo "FAIL: coverage $${TOTAL}% is below minimum $(MIN_COVERAGE)%"; \
		exit 1; \
	else \
		echo "PASS: coverage meets $(MIN_COVERAGE)% requirement"; \
	fi

## Run golangci-lint.
lint:
	golangci-lint run ./...

## Tidy go modules.
tidy:
	$(GO) mod tidy

## Clean build artefacts.
clean:
	rm -rf $(BUILD_DIR) $(COVERAGE) $(COVERAGE_HTML)

## Build for linux/amd64 and linux/arm64.
cross:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/clawkeyring/
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/clawkeyring/

## Generate mTLS certs for local development.
certs:
	./scripts/gen-certs.sh ~/.clawkeyring/certs

## Show help.
help:
	@grep -E '^##' Makefile | sed 's/## //'
