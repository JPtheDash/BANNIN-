.PHONY: build test vet fmt run clean

build:
	go build -o bin/bannin ./cmd/bannin

test:
	go test ./... -v

vet:
	go vet ./...

fmt:
	gofmt -l -s -w .

run: build
	./bin/bannin

clean:
	rm -rf bin/
