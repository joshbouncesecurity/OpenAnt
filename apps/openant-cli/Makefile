BINARY_NAME=openant
BUILD_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/knostic/open-ant-cli/cmd.version=$(VERSION)"

.PHONY: build clean test lint install

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./main.go

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

lint:
	go vet ./...

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
