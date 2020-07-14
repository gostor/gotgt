BIN_DIR=_output/cmd/bin

all: init build

deps:
	go mod download

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

