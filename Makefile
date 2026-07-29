.PHONY: build clean install run

BINARY_NAME=relaydock-agent
BUILD_DIR=build

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/relaydock-agent

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

run:
	go run ./cmd/relaydock-agent

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy
