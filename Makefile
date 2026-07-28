.PHONY: build clean install run

BINARY_NAME=mmw-agent
BUILD_DIR=build

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/mmw-agent

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

run:
	go run ./cmd/mmw-agent

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy
