.PHONY: all build test

all: lint test build

lint:
	go mod tidy
	golint ./...
	go vet ./...

test:
	go test ./...
	go vet ./...

build:
	go build -v ./...

install:
	go install