.PHONY: build install test clean

BINARY := mlsgit
BUILD_DIR := bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/mlsgit

install: build
	cp $(BUILD_DIR)/$(BINARY) $(GOPATH)/bin/$(BINARY) 2>/dev/null || \
	cp $(BUILD_DIR)/$(BINARY) $(HOME)/go/bin/$(BINARY)

test:
	go test ./internal/... -v

test-integration:
	go test ./test/... -v -timeout 120s

test-all: test test-integration

clean:
	rm -rf $(BUILD_DIR)
