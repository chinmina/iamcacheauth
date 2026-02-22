.PHONY: all agent build test format vet fix test-integration clean

all: build

agent: format fix vet build test

format:
	gofmt -w .

fix:
	go fix ./...

vet:
	go vet ./...

build:
	go build ./...

test:
	go test -race ./...

test-integration:
	go test -tags=integration -race -v -timeout 10m ./...

clean:
	go clean -testcache
