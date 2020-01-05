BIN_DIR=_output/cmd/bin

all: init build

ARCH ?= amd64
OS ?= linux
VERSION ?= 0.1

deps:
	dep ensure

build: init
	GOOS=${OS} GOARCH=${ARCH} go build -o ${BIN_DIR}/gotgt gotgt.go

build-nocgo: init
	GOOS=${OS} GOARCH=${ARCH} CGO_ENABLED=0 go build -o ${BIN_DIR}/gotgt gotgt.go

verify:
	hack/verify-gofmt.sh

init:
	mkdir -p ${BIN_DIR}
clean:
	rm -fr ${BIN_DIR}

docker: build
	docker build -t gotgt-${ARCH}:${VERSION} .
.PHONY: clean

