BIN_DIR=_output/cmd/bin

PACKAGES = $(shell go list ./... | grep -v 'mock')

deps:
	dep ensure

all: init build test

test-jiva:
	sudo -E env "PATH=${PATH}" go test -v ./mock/

test:
	go test ${PACKAGES}

build: init
	go build -o ${BIN_DIR}/gotgt gotgt.go

build-nocgo: init
	CGO_ENABLED=0 go build -o ${BIN_DIR}/gotgt gotgt.go

verify:
	hack/verify-gofmt.sh

init:
	mkdir -p ${BIN_DIR}
clean:
	rm -fr ${BIN_DIR}

.PHONY: clean

