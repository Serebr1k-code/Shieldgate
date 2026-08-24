BINARY := shieldgate
GO ?= $(shell which go)

.PHONY: all build test vet lint run clean web-dev web-build

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/shieldgate

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

lint: vet

run: build
	sudo ./$(BINARY) -config shieldgate.yaml

test-integration: ## requires root (nftables + NFQUEUE)
	sudo $(GO) test ./internal/engine/nfqueue -tags integration -v
web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

clean:
	rm -f $(BINARY)
	rm -rf web/node_modules web/dist
