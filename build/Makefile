GOPATH=$(shell pwd)/../
SOURCEDIR=../
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

BINARY=./server

LDFLAGS=

.DEFAULT_GOAL: $(BINARY)

$(BINARY): $(SOURCES)
	GOPATH=$(GOPATH) go build ${LDFLAGS} -o ${BINARY} cyberGo/main

.PHONY: install
install:
	go install ${LDFLAGS} cyberGo/main

run:
	go run src/cyberGo/main/main.go

test:
	GOPATH=$(GOPATH) go test cyberGo/store cyberGo/parser cyberGo/main


.PHONY: clean
clean:
	rm -rf ${BINARY}
